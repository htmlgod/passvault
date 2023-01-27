#pragma once

#include <algorithm>
#include <filesystem>
#include <map>
#include <stdexcept>
#include <string>

#include <clip/clip.h>
#include <secrets.hpp>

const constexpr char* VERSION = "v0.1";
const constexpr char* CONFIG_FILE_NAME = "passvault_config.cfg";

struct PassVaultConfig {
    std::string db_path;
    unsigned int weak_password_entropy_level;
    std::string master_key_path;
};

struct VaultEntity {
    size_t login_str_len;
    std::string login;
    size_t pass_len;
    uint8_t enc_password[BUFFER_SIZE];
    uint8_t enc_pass_key[KEY_SIZE];
    uint8_t iv[IV_SIZE];
    uint8_t hmac[HMAC_SIZE];
};

class PassVault {
public:
    PassVault(const PassVaultConfig& pv_cfg);
    void save_pass(const std::string& service, const std::string& login);
    void get_pass(std::string& service);
    void del_pass(const std::string& service);
    void dump_db();
    void load_db();
    void examine();
    ~PassVault();
private:
    // create_master_key and master password procedure
    VaultEntity create_vault_entity(const std::string& login);
    void encrypt_vault_entity_secrets(VaultEntity& ve);
    void decrypt_vault_entity_secrets(VaultEntity& ve);

    std::string get_password_from_clipboard() const;
    void save_password_to_clipboard(const std::string& password) const;

    std::map<std::string, VaultEntity> _vault;
    std::string _master_pass; // tmp
    PassVaultConfig cfg;
};
