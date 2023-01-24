#pragma once
#include <span>
#include <fstream>
#include <iostream>
#include <sstream>
#include <iomanip>
#include <cppcrypto/kuznyechik.h>
#include <cppcrypto/hmac.h>
#include <cppcrypto/ctr.h>
#include <cppcrypto/pbkdf2.h>
#include <cppcrypto/streebog.h>

const size_t DOUBLE_KEY_SIZE = 64;// 512/8;
const size_t BUFFER_SIZE = 256;
const size_t KEY_SIZE = 32;// 256/8;
const size_t HMAC_SIZE = 32;// 256/8;
const size_t IV_SIZE = 16; //128/8;

namespace util {
    void print_bytes(const std::span<const std::byte> bytes);

    template<typename T>
    char* as_bytes(T& i) {
        void* addr = &i;
        return static_cast<char*>(addr);
    }
}

namespace secrets {
    void compute_hmac(uint8_t* hmac_key, uint8_t* iv, uint8_t* key, uint8_t* hash);
    void gen_random_bytes(uint8_t* buff, size_t len);
    void gen_key_from_password(uint8_t* blob, size_t blob_size, const char* pass);
    void encrypt_bytes(uint8_t* key, uint8_t* iv, uint8_t* bytes, size_t size, uint8_t* enc_bytes);
    void decrypt_bytes(uint8_t* key, uint8_t* iv, uint8_t* bytes, size_t size, uint8_t* enc_bytes);
}
