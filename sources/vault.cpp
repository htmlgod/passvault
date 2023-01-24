#include <vault.hpp>

PassVault::PassVault(const std::string& pass) {
    _master_pass = pass;
    if (std::filesystem::exists(DB_PATH.data())){
        load_db();
    } 
}

// mb add checksum for db(hash)
// add magic header for file and check
void PassVault::load_db() {
    std::ifstream ifs(DB_PATH.data(), std::ios::binary);
    if (!ifs.is_open()) {
        std::cout << "Failed to open DB" << std::endl;
    }
    size_t records;
    ifs.read(util::as_bytes(records), sizeof(records));
    std::cout << records << std::endl;
    char* tmp = new char[BUFFER_SIZE + 1];
    for (size_t i = 0; i < records; ++i) {
        std::string service;
        size_t service_str_size;
        ifs.read(util::as_bytes(service_str_size), sizeof(size_t));

        ifs.read(tmp, service_str_size);
        tmp[service_str_size] = '\0';
        service = tmp;

        std::cout << service << std::endl;
        VaultEntity ve{};
        ifs.read(util::as_bytes(ve), sizeof(ve));
        _vault[service] = ve;
    }
    delete[] tmp;
}

void PassVault::dump_db() {
    std::ofstream ofs(DB_PATH.data(), std::ios::binary);
    if (!ofs.is_open()) {
        std::cout << "Failed to save DB" << std::endl;
    }
    std::cout << "SAVING DB" << std::endl;

    auto entries = _vault.size();
    ofs.write((const char*)&entries, sizeof(entries));
    for (auto& [service, ve] : _vault) {
        auto service_str_size = service.size();
        ofs.write(util::as_bytes(service_str_size), sizeof(service_str_size));
        ofs.write(service.c_str(), service.size());
        ofs.write(util::as_bytes(ve), sizeof(ve));
    }
}


void PassVault::save_pass(std::string& service, std::string& password) {
    _vault.insert_or_assign(service, encrypt(password));
}


std::string PassVault::get_pass(std::string& service) {
    std::cout << "get_pass START" << std::endl;
    return decrypt(_vault.at(service));
}

VaultEntity PassVault::encrypt(std::string& password) {
    VaultEntity ve{};
    ve.pass_len = password.size();

    uint8_t master_hmac_keys[DOUBLE_KEY_SIZE];
    uint8_t pass_key[KEY_SIZE];
    secrets::gen_key_from_password(master_hmac_keys, DOUBLE_KEY_SIZE, _master_pass.c_str());

    secrets::gen_random_bytes(ve.iv, IV_SIZE);
    secrets::gen_random_bytes(pass_key, KEY_SIZE);

    secrets::compute_hmac(master_hmac_keys + KEY_SIZE, ve.iv, pass_key, ve.hmac);

    secrets::encrypt_bytes(pass_key, (uint8_t *)ve.iv, (uint8_t*)password.c_str(), ve.pass_len, (uint8_t *)ve.enc_password);
    secrets::encrypt_bytes(master_hmac_keys, (uint8_t *)ve.iv, pass_key, KEY_SIZE, (uint8_t *)ve.enc_pass_key);
    std::cout << "master_key = ";
    util::print_bytes(std::as_bytes(std::span{master_hmac_keys}));
    std::cout << "iv = ";
    util::print_bytes(std::as_bytes(std::span{ve.iv}));
    std::cout << "enc_pass = ";
    util::print_bytes(std::as_bytes(std::span{ve.enc_password}));
    return ve;
}

std::string PassVault::decrypt(VaultEntity& ve) {
    std::cout << "DECR START" << std::endl;
    uint8_t master_hmac_keys[DOUBLE_KEY_SIZE];
    uint8_t pass_key[KEY_SIZE];

    secrets::gen_key_from_password(master_hmac_keys, DOUBLE_KEY_SIZE, _master_pass.c_str());

    secrets::decrypt_bytes(master_hmac_keys, (uint8_t *)ve.iv, (uint8_t *)ve.enc_pass_key, KEY_SIZE, (uint8_t *)pass_key);

    uint8_t computed_hmac[HMAC_SIZE];
    secrets::compute_hmac(master_hmac_keys + KEY_SIZE, ve.iv, pass_key, computed_hmac);

    if (!std::equal(ve.hmac, ve.hmac + HMAC_SIZE, computed_hmac)) {
        throw std::domain_error("wrong password");
    }

    char* tmp = new char[4096];
    secrets::decrypt_bytes(pass_key, (uint8_t *)ve.iv, (uint8_t *)ve.enc_password, sizeof(ve.enc_password), (uint8_t *)tmp);
    tmp[ve.pass_len] = '\0';
    std::string out = tmp;
    delete[] tmp;
    std::cout << "master_key = ";
    util::print_bytes(std::as_bytes(std::span{master_hmac_keys}));
    std::cout << "iv = ";
    util::print_bytes(std::as_bytes(std::span{ve.iv}));
    std::cout << "enc_pass = ";
    util::print_bytes(std::as_bytes(std::span{ve.enc_password}));
    return out;
}

PassVault::~PassVault() {
    dump_db();
}

