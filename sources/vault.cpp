#include <utility>
#include <vault.hpp>

PassVault::PassVault(PassVaultConfig  pv_cfg, bool run_init) : cfg(std::move(pv_cfg)) {
    if (!run_init) {
        if (!std::filesystem::exists(cfg.master_key_path) and
            !std::filesystem::exists(cfg.db_path)) {
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
        std::string strength = (ve.rand_entropy < cfg.weak_password_entropy_level or ve.choice_entropy < cfg.weak_password_entropy_level) ? "Weak" : "Strong";
        std::cout << v_sep << std::setw(15) << service
                  << v_sep << std::setw(25) << ve.login
                  << v_sep << std::setw(10) << ve.rand_entropy
                  << v_sep << std::setw(10) << ve.choice_entropy
                  << v_sep << std::setw(20) << strength << v_sep << std::endl;
        print_delimiter();
    }
}

// mb add checksum for db(hash)
// add magic header for file and check
void PassVault::load_db() {
    std::ifstream ifs(this->cfg.db_path, std::ios::binary);
    if (!ifs.is_open()) {
        std::cout << "Failed to open DB" << std::endl;
    }
    size_t records;
    ifs.read(util::as_bytes(records), sizeof(records));
    char* tmp = new char[BUFFER_SIZE + 1];
    for (size_t i = 0; i < records; ++i) {
        std::string service;
        size_t service_str_size;
        ifs.read(util::as_bytes(service_str_size), sizeof(size_t));

        ifs.read(tmp, service_str_size);
        tmp[service_str_size] = '\0';
        service = tmp;

        VaultEntity ve{};
        ifs.read(util::as_bytes(ve), sizeof(ve));
        _vault[service] = ve;
    }
    delete[] tmp;
    ifs.read(util::as_bytes(master_key_hmac), sizeof(master_key_hmac));
}

void PassVault::dump_db() {
    std::ofstream ofs(this->cfg.db_path, std::ios::binary);
    if (!ofs.is_open()) {
        std::cout << "Failed to save DB" << std::endl;
    }

    auto entries = _vault.size();
    ofs.write((const char*)&entries, sizeof(entries));
    for (auto& [service, ve] : _vault) {
        auto service_str_size = service.size();
        ofs.write(util::as_bytes(service_str_size), sizeof(service_str_size));
        ofs.write(service.c_str(), service.size());
        ofs.write(util::as_bytes(ve), sizeof(ve));
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
    util::load_bytes_from_file(encrypted_master_key, KEY_SIZE, this->cfg.master_key_path);
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
        util::load_bytes_from_file(encrypted_master_key, KEY_SIZE, this->cfg.master_key_path);
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
    util::load_bytes_from_file(encrypted_master_key, KEY_SIZE, this->cfg.master_key_path);
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
    util::save_bytes_to_file(encrypted_master_key, KEY_SIZE, this->cfg.master_key_path);
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
    util::save_bytes_to_file(encrypted_master_key, KEY_SIZE, this->cfg.master_key_path);

    secrets::compute_hmac_from_data(hmac_and_master_key_decryption_keys + KEY_SIZE,
                                    master_key, KEY_SIZE, this->master_key_hmac);
    dump_db();
}
