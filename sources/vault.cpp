#include <utility>
#include <vault.hpp>

PassVaultConfig::PassVaultConfig(const std::string& db_filename, const std::string& mk_filename, float pw_weak_lvl) {
    
    auto homedir = get_user_home_dir();
    auto data_dir = homedir / std::filesystem::path{DATA_DIR};
    if (!std::filesystem::exists(data_dir)) {
        std::filesystem::create_directory(data_dir);
    }
    auto db = data_dir /  std::filesystem::path{db_filename};
    auto mk = data_dir /  std::filesystem::path{mk_filename};
    this->database_filename = db.string();
    this->master_key_filename = mk.string();
    this->password_weakness_level = pw_weak_lvl;
}

std::filesystem::path PassVaultConfig::get_user_home_dir() const {
    std::filesystem::path default_dir{"/root/"};
#ifdef WIN32
    if (const char* home_dir = std::getenv("USERPROFILE"))
        return std::filesystem::path{home_dir};
    if (const char* homedrive = std::getenv("HOMEDRIVE") and const char* homepath = std::getenv("HOMEPATH"))
        return std::filesystem::path{homedrive} + fs::path{homepath};
    default_dir = std::filesystem::path{"C:/"};
#endif
    if (const char* home_dir = std::getenv("HOME"))
        return std::filesystem::path{home_dir};
    return default_dir;
}

PassVault::PassVault(PassVaultConfig  pv_cfg, bool run_init) : cfg(std::move(pv_cfg)) {
    if (!run_init) {
        if (!std::filesystem::exists(cfg.master_key_filename) and
            !std::filesystem::exists(cfg.database_filename)) {
            throw std::logic_error("master key file and db not found, maybe you should run --init");
        }
            load_db();
    }
    else {
        this->init();
    }
}

PassVault::~PassVault() {
    dump_db();
}

// maybe add feature to check DB for identical passwords
void PassVault::examine() {
    const auto v_sep = "|";
    const auto sep = "+";
    std::cout << "Amount of services = " << this->_vault.size() << std::endl;
    std::cout << v_sep << std::setw(15) << "Service"
              << v_sep << std::setw(25) << "Login"
              << v_sep << std::setw(10) << "Entropy(R)"
              << v_sep << std::setw(10) << "Entropy(U)"
              << v_sep << std::setw(20) << "Password Strength" << v_sep << std::endl;
    std::function<void()> print_delimiter = [sep]() { 
        for (size_t i = 0; i < 86; ++i) std::cout << sep;
        std::cout << std::endl;
    };
    print_delimiter();
    for (const auto& [service, ve] : this->_vault) {
        std::string strength = (ve.rand_entropy < cfg.password_weakness_level or ve.choice_entropy < cfg.password_weakness_level) ? "Weak" : "Strong";
        std::cout << v_sep << std::setw(15) << service
                  << v_sep << std::setw(25) << ve.login
                  << v_sep << std::setw(10) << ve.rand_entropy
                  << v_sep << std::setw(10) << ve.choice_entropy
                  << v_sep << std::setw(20) << strength << v_sep << std::endl;
        print_delimiter();
    }
}

std::string read_string_binary(std::ifstream& ifs) {
    size_t str_size;
    ifs.read(util::as_bytes(str_size), sizeof(size_t));
    char buf[str_size + 1];
    ifs.read(buf, str_size);
    buf[str_size] = '\0';
    return std::string{buf};
}

void write_string_binary(std::ofstream& ofs, const std::string& in_str) {
    auto str_size = in_str.size();
    ofs.write(util::as_bytes(str_size), sizeof(str_size));
    ofs.write(in_str.c_str(), in_str.size());
}

// mb add checksum for db(hash)
// add magic header for file and check
void PassVault::load_db() {
    std::ifstream ifs(this->cfg.database_filename, std::ios::binary);
    if (!ifs.is_open()) {
        std::cout << "Failed to open DB" << std::endl;
    }
    size_t records;
    ifs.read(util::as_bytes(records), sizeof(records));
    for (size_t i = 0; i < records; ++i) {
        VaultEntity ve{};
        std::string service = read_string_binary(ifs);
        ve.login = read_string_binary(ifs);
        ifs.read(util::as_bytes(ve.pass_len), sizeof(ve.pass_len));
        ifs.read(util::as_bytes(ve.enc_password), BUFFER_SIZE);
        ifs.read(util::as_bytes(ve.enc_pass_key), KEY_SIZE);
        ifs.read(util::as_bytes(ve.iv), IV_SIZE);
        ifs.read(util::as_bytes(ve.hmac), HMAC_SIZE);
        ifs.read(util::as_bytes(ve.rand_entropy), sizeof(float));
        ifs.read(util::as_bytes(ve.choice_entropy), sizeof(float));
        _vault[service] = ve;
    }
    ifs.read(util::as_bytes(master_key_hmac), sizeof(master_key_hmac));
}

void PassVault::dump_db() {
    std::ofstream ofs(this->cfg.database_filename, std::ios::binary);
    if (!ofs.is_open()) {
        std::cout << "Failed to save DB" << std::endl;
    }

    auto entries = _vault.size();
    ofs.write(util::as_bytes(entries), sizeof(entries));
    for (auto& [service, ve] : _vault) {
        write_string_binary(ofs, service);
        write_string_binary(ofs, ve.login);
        ofs.write(util::as_bytes(ve.pass_len), sizeof(ve.pass_len));
        ofs.write(util::as_bytes(ve.enc_password), BUFFER_SIZE);
        ofs.write(util::as_bytes(ve.enc_pass_key), KEY_SIZE);
        ofs.write(util::as_bytes(ve.iv), IV_SIZE);
        ofs.write(util::as_bytes(ve.hmac), HMAC_SIZE);
        ofs.write(util::as_bytes(ve.rand_entropy), sizeof(float));
        ofs.write(util::as_bytes(ve.choice_entropy), sizeof(float));
    }
    ofs.write(util::as_bytes(master_key_hmac), sizeof(master_key_hmac));
}

VaultEntity PassVault::create_vault_entity(const std::string& login) {
    VaultEntity ve{};
    ve.login = login;

    encrypt_vault_entity_secrets(ve);

    return ve;
}

void PassVault::save_pass(const std::string& service, const std::string& login) {
        auto ve = create_vault_entity(login);
        _vault.insert_or_assign(service, ve);
}

void PassVault::del_pass(const std::string& service) {
    this->_vault.erase(service);
}
void PassVault::get_pass(std::string& service) {
    auto ve = this->_vault.at(service);
    decrypt_vault_entity_secrets(ve);
    std::cout << "Login for service " << service << ":"<< ve.login << std::endl;
    std::cout << "Password saved to clipboard" << std::endl;
}

std::string PassVault::get_password_from_clipboard() {
    std::string password;
    clip::get_text(password);
    return password;
}
void PassVault::save_password_to_clipboard(const std::string& password) {
    clip::set_text(password);
}

void PassVault::encrypt_vault_entity_secrets(VaultEntity& ve) {
    secrets::password::input_master_password(this->_master_pass);
    auto password = get_password_from_clipboard();


    ve.pass_len = password.size();
    ve.rand_entropy = secrets::password::get_generated_password_entropy(
            password, 
            secrets::password::detect_pass_alphabet(password));
    ve.choice_entropy = secrets::password::get_user_selected_password_entropy(password);

    uint8_t hmac_and_master_key_decryption_keys[DOUBLE_KEY_SIZE];
    secrets::gen_key_from_password(hmac_and_master_key_decryption_keys, DOUBLE_KEY_SIZE, this->_master_pass.c_str());


    uint8_t encrypted_master_key[KEY_SIZE];
    util::load_bytes_from_file(encrypted_master_key, KEY_SIZE, this->cfg.master_key_filename);
    uint8_t master_key[KEY_SIZE];
    secrets::decrypt_master_key(hmac_and_master_key_decryption_keys, encrypted_master_key, master_key);

    uint8_t master_key_check_hmac[HMAC_SIZE];
    secrets::compute_hmac_from_data(hmac_and_master_key_decryption_keys + KEY_SIZE, master_key, KEY_SIZE, master_key_check_hmac);
    if (!std::equal(master_key_check_hmac, master_key_check_hmac + HMAC_SIZE, this->master_key_hmac)) {
        throw std::domain_error("wrong password");
    }

    secrets::gen_random_bytes(ve.iv, IV_SIZE);
    uint8_t pass_encryption_key[KEY_SIZE];
    secrets::gen_random_bytes(pass_encryption_key, KEY_SIZE);

    secrets::compute_hmac_vault_entity(master_key, ve.iv, pass_encryption_key,
                                       ve.hmac);

    secrets::encrypt_bytes(pass_encryption_key, (uint8_t *)ve.iv, (uint8_t*)password.c_str(), ve.pass_len, (uint8_t *)ve.enc_password);
    secrets::encrypt_bytes(master_key, (uint8_t *)ve.iv, pass_encryption_key, KEY_SIZE, (uint8_t *)ve.enc_pass_key);
    //util::print_bytes(std::as_bytes(std::span{ve.enc_password}));
}

void PassVault::decrypt_vault_entity_secrets(VaultEntity& ve) {
    try {
        secrets::password::input_master_password(this->_master_pass);

        uint8_t master_key_decryption_key[KEY_SIZE];
        secrets::gen_key_from_password(master_key_decryption_key, KEY_SIZE, _master_pass.c_str());

        uint8_t pass_key[KEY_SIZE];
        uint8_t encrypted_master_key[KEY_SIZE];
        util::load_bytes_from_file(encrypted_master_key, KEY_SIZE, this->cfg.master_key_filename);
        uint8_t master_key[KEY_SIZE];
        secrets::decrypt_master_key(master_key_decryption_key, encrypted_master_key, master_key);


        secrets::decrypt_bytes(master_key, (uint8_t *)ve.iv, (uint8_t *)ve.enc_pass_key, KEY_SIZE, (uint8_t *)pass_key);

        uint8_t computed_hmac[HMAC_SIZE];
        secrets::compute_hmac_vault_entity(master_key, ve.iv, pass_key, computed_hmac);

        if (!std::equal(ve.hmac, ve.hmac + HMAC_SIZE, computed_hmac)) {
            throw std::domain_error("wrong password");
        }

        char* tmp = new char[4096];
        secrets::decrypt_bytes(pass_key, (uint8_t *)ve.iv, (uint8_t *)ve.enc_password, sizeof(ve.enc_password), (uint8_t *)tmp);
        tmp[ve.pass_len] = '\0';
        std::string out = tmp;
        delete[] tmp;
        save_password_to_clipboard(out);
    }
    catch (std::exception& e) {
        std::cout << e.what() << std::endl;
    }
}

void PassVault::change_master_password() {
    secrets::password::input_master_password(this->_master_pass, "Enter old master password");
    uint8_t hmac_and_master_key_decryption_keys[DOUBLE_KEY_SIZE];
    secrets::gen_key_from_password(hmac_and_master_key_decryption_keys, DOUBLE_KEY_SIZE, _master_pass.c_str());

    uint8_t encrypted_master_key[KEY_SIZE];
    util::load_bytes_from_file(encrypted_master_key, KEY_SIZE, this->cfg.master_key_filename);
    uint8_t master_key[KEY_SIZE];
    secrets::decrypt_master_key(hmac_and_master_key_decryption_keys, encrypted_master_key, master_key);

    uint8_t master_key_check_hmac[HMAC_SIZE];
    secrets::compute_hmac_from_data(hmac_and_master_key_decryption_keys + KEY_SIZE, master_key, KEY_SIZE, master_key_check_hmac);
    if (!std::equal(master_key_check_hmac, master_key_check_hmac + HMAC_SIZE, master_key_hmac)) {
        throw std::domain_error("Wrong master password");
    }
    _master_pass = secrets::password::create_change_password();
    std::memset(hmac_and_master_key_decryption_keys, 0, sizeof hmac_and_master_key_decryption_keys);
    secrets::gen_key_from_password(hmac_and_master_key_decryption_keys, DOUBLE_KEY_SIZE, _master_pass.c_str());
    std::memset(encrypted_master_key, 0, sizeof encrypted_master_key);
    secrets::encrypt_master_key(hmac_and_master_key_decryption_keys, master_key, encrypted_master_key);
    util::save_bytes_to_file(encrypted_master_key, KEY_SIZE, this->cfg.master_key_filename);
    secrets::compute_hmac_from_data(hmac_and_master_key_decryption_keys + KEY_SIZE, master_key, KEY_SIZE, master_key_hmac);
    dump_db();
}

void PassVault::init() {
    _master_pass = secrets::password::create_change_password();

    uint8_t master_key[KEY_SIZE];
    secrets::gen_random_bytes(master_key, KEY_SIZE);

    uint8_t hmac_and_master_key_decryption_keys[DOUBLE_KEY_SIZE];
    secrets::gen_key_from_password(hmac_and_master_key_decryption_keys, DOUBLE_KEY_SIZE, _master_pass.c_str());

    uint8_t encrypted_master_key[KEY_SIZE];
    secrets::encrypt_master_key(hmac_and_master_key_decryption_keys, master_key, encrypted_master_key);
    util::save_bytes_to_file(encrypted_master_key, KEY_SIZE, this->cfg.master_key_filename);

    secrets::compute_hmac_from_data(hmac_and_master_key_decryption_keys + KEY_SIZE,
                                    master_key, KEY_SIZE, this->master_key_hmac);
    dump_db();
}
