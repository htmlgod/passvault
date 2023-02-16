#pragma once
#include <cstddef>
#include <span>
#include <fstream>
#include <iostream>
#include <sstream>
#include <iomanip>
#include <random>
#include <string>

#include <cppcrypto/kuznyechik.h>
#include <cppcrypto/hmac.h>
#include <cppcrypto/ctr.h>
#include <cppcrypto/pbkdf2.h>
#include <cppcrypto/streebog.h>

#ifndef WIN32
#include <termios.h>
#include <unistd.h>
#else
#include "windows.h"
#endif

const size_t DOUBLE_KEY_SIZE = 64;// 512/8;
const size_t BUFFER_SIZE = 256;
const size_t BLOCK_SIZE = 16; // 128/8;
const size_t KEY_SIZE = 32;// 256/8; 
const size_t HMAC_SIZE = 32;// 256/8;
const size_t IV_SIZE = 16; //128/8;

namespace util {
    [[maybe_unused]] void print_bytes(std::span<const std::byte> bytes);
    void toggle_console_echo(bool on);

    void save_bytes_to_file(uint8_t* bytes, size_t size, const std::string& file_name);
    void load_bytes_from_file(uint8_t* bytes, size_t size, const std::string& file_name);

    template<typename T>
    char* as_bytes(T& i) {
        void* addr = &i;
        return static_cast<char*>(addr);
    }
    //template<typename T> // is_pointer
    //char* as_bytes(T& i) {
    //    void* addr = &i;
    //    return static_cast<char*>(addr);
    //}
}

namespace secrets {
    void compute_hmac_vault_entity(uint8_t* hmac_key, uint8_t* iv, uint8_t* key, uint8_t* hash);
    void compute_hmac_from_data(uint8_t* hmac_key, uint8_t* data, size_t size, uint8_t* hash);
    void gen_random_bytes(uint8_t* buff, size_t len);
    void gen_key_from_password(uint8_t* blob, size_t blob_size, const char* pass);
    void encrypt_bytes(uint8_t* key, uint8_t* iv, uint8_t* bytes, size_t size, uint8_t* enc_bytes);
    void decrypt_bytes(uint8_t* key, uint8_t* iv, uint8_t* bytes, size_t size, uint8_t* enc_bytes);
    void encrypt_master_key(uint8_t* key, uint8_t* master_key, uint8_t* encrypted_key);
    void decrypt_master_key(uint8_t* key, uint8_t* encrypted_master_key, uint8_t* decrypted_master_key);
}
namespace secrets::password {
    enum class Alphabet {
        numbers,
        az,
        AZ,
        az09,
        AZ09,
        azAZ,
        azAZ09, // any(isalpha, isdigit)
        ASCII_PRINTABLE, // isgraph
        //Byte,
        // Dice ware
    };
    // std::string get_random_password(Alphabet type, size_t pass_len);
    std::string create_change_password();
    void input_master_password(std::string& pass, const std::string& msg = "Enter master pass: ");
    float get_user_selected_password_entropy(const std::string& pass);
    float get_generated_password_entropy(const std::string& pass, Alphabet alph);
    Alphabet detect_pass_alphabet(const std::string& pass);
}
