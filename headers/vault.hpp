#pragma once

#include <algorithm>
#include <filesystem>
#include <functional>
#include <map>
#include <stdexcept>
#include <string>

#include <clip/clip.h>
#include <secrets.hpp>

const constexpr char* VERSION = "v0.1";
const constexpr char* CONFIG_FILE_NAME = "passvault_config.cfg";

struct PassVaultConfig {
    std::string db_path;
    std::string master_key_path;
    float weak_password_entropy_level;
    size_t password_length;
};

struct VaultEntity {
    std::string login;
    size_t pass_len;
    uint8_t enc_password[BUFFER_SIZE];
    uint8_t enc_pass_key[KEY_SIZE];
    uint8_t iv[IV_SIZE];
    uint8_t hmac[HMAC_SIZE];
    float rand_entropy;
    float choice_entropy;
};

class PassVault {
public:
    explicit PassVault(const PassVaultConfig& pv_cfg);
    void save_pass(const std::string& service, const std::string& login);
    void get_pass(std::string& service);
    void del_pass(const std::string& service);
    void dump_db();
    void load_db();
    void examine();
    void change_master_password();
    void init();
    ~PassVault();
private:
    // create_master_key and master password procedure
    VaultEntity create_vault_entity(const std::string& login);
    void encrypt_vault_entity_secrets(VaultEntity& ve);
    void decrypt_vault_entity_secrets(VaultEntity& ve);

    static std::string get_password_from_clipboard() ;
    static void save_password_to_clipboard(const std::string& password) ;

    std::map<std::string, VaultEntity> _vault;
    std::string _master_pass;
    uint8_t magic_check_header[256/8];
    PassVaultConfig cfg;
    uint8_t MAGIC_HEADER [256/8] = {
        0xDE, 0xAD, 0xC0, 0xDE,
        0xDE, 0xAD, 0xC0, 0xDE,
        0xDE, 0xAD, 0xC0, 0xDE,
        0xDE, 0xAD, 0xC0, 0xDE
    };
};
