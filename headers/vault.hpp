#pragma once

#include <algorithm>
#include <span>
#include <filesystem>
#include <map>
#include <stdexcept>
#include <string>

#include <secrets.hpp>

struct VaultEntity {
    size_t login_str_len;
    uint8_t login[BUFFER_SIZE];
    size_t pass_len;
    uint8_t enc_password[BUFFER_SIZE];
    uint8_t enc_pass_key[KEY_SIZE];
    uint8_t iv[IV_SIZE];
    uint8_t hmac[HMAC_SIZE];
};
const std::string_view DB_PATH = "test.db"; // move to config
                                            //

class PassVault {
public:
    explicit PassVault(const std::string& pass);
    void save_pass(std::string& service, std::string& password);
    std::string get_pass(std::string& service);
    void dump_db();
    void load_db();
    ~PassVault();
private:
    VaultEntity encrypt(std::string& password);
    std::string decrypt(VaultEntity& ve);

    std::map<std::string, VaultEntity> _vault;
    std::string _db_path;
    std::string _config_path;
    std::string _master_pass; // tmp
};
