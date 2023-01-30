#include <secrets.hpp>

void util::save_bytes_to_file(uint8_t* bytes, size_t size, const std::string& file_name) {
    std::ofstream ofs(file_name, std::ios::binary);
    if (ofs) {
        ofs.write(as_bytes(*bytes), size);
    }
}

void util::load_bytes_from_file(uint8_t* bytes, size_t size, const std::string& file_name) {
    std::ifstream ifs(file_name, std::ios::binary);
    if (ifs) {
        ifs.read(as_bytes(*bytes), size);
    }
}

void secrets::password::input_master_password(std::string& pass, const std::string& msg) {
    util::toggle_console_echo(false);
    std::cout << msg;
    std::getline(std::cin, pass);
    std::cout << std::endl;
    util::toggle_console_echo(true);
}

void util::toggle_console_echo(bool on)
{
#ifdef WIN32
	DWORD  mode = 0;
	HANDLE hConIn = GetStdHandle(STD_INPUT_HANDLE);
	GetConsoleMode(hConIn, &mode);
	mode = on ? (mode | ENABLE_ECHO_INPUT) : (mode & (~ENABLE_ECHO_INPUT));
	SetConsoleMode(hConIn, mode);
#else
	struct termios settings{};
	tcgetattr(STDIN_FILENO, &settings);
	settings.c_lflag = on ? (settings.c_lflag | ECHO) : (settings.c_lflag & (~ECHO));
	tcsetattr(STDIN_FILENO, TCSANOW, &settings);
#endif
}
void util::print_bytes(const std::span<const std::byte> bytes) {
    std::cout << std::hex << std::uppercase << std::setfill('0');
    for (const auto b : bytes) {
        std::cout << std::setw(2) << std::to_integer<int>(b) << ' ';
    }
    std::cout << std::dec << std::endl;
}

void secrets::gen_random_bytes(uint8_t* bytes, size_t len) {
    uint8_t buf[DOUBLE_KEY_SIZE*8];
#ifdef WIN32
	HCRYPTPROV prov = 0;
	if (!CryptAcquireContext(&prov, 0, 0, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT | CRYPT_SILENT))
		throw runtime_error("Cannot acquire crypto context!");
	if (!CryptGenRandom(prov, sizeof(buf), buf)){
		CryptReleaseContext(prov, 0);
		throw runtime_error("Cannot generate random bytes!");
	}
	if (!CryptReleaseContext(prov, 0))
		throw runtime_error("Cannot release crypto context!");
#else
    std::ifstream urandom("/dev/urandom", std::ios::in|std::ios::binary);
	urandom.read((std::ifstream::char_type*)buf, sizeof(buf));
	urandom.close();
#endif

	cppcrypto::streebog streebog(len*8);
	streebog.hash_string(buf, sizeof(buf), bytes);
}
void secrets::gen_key_from_password(uint8_t* blob, size_t blob_size, const char* pass) {
    cppcrypto::hmac hmac(cppcrypto::streebog(256), pass);
    cppcrypto::pbkdf2(hmac, (const uint8_t*)"salt", 4, 10000, blob, blob_size);
}

void secrets::encrypt_bytes(uint8_t* key, uint8_t* iv, uint8_t* bytes, size_t size, uint8_t* enc_bytes) {
    cppcrypto::kuznyechik kuz;
    cppcrypto::ctr cipher(kuz);
    cipher.init(key, KEY_SIZE, iv, IV_SIZE);
    cipher.encrypt(bytes, size, enc_bytes);
}
void secrets::decrypt_bytes(uint8_t* key, uint8_t* iv, uint8_t* bytes, size_t size, uint8_t* enc_bytes) {
    cppcrypto::kuznyechik kuz;
    cppcrypto::ctr cipher(kuz);
    cipher.init(key, KEY_SIZE, iv, IV_SIZE);
    cipher.decrypt(bytes, size, enc_bytes);
}
void secrets::compute_hmac(uint8_t* hmac_key, uint8_t* iv, uint8_t* key, uint8_t* hash) {
    cppcrypto::hmac hmac(cppcrypto::streebog(HMAC_SIZE*8), hmac_key, KEY_SIZE);
    hmac.init();
    hmac.update(iv, IV_SIZE);
    hmac.update(key, KEY_SIZE);
    hmac.final(hash);
}

void secrets::encrypt_master_key(uint8_t* key, uint8_t* master_key, uint8_t* encrypted_key) {
    cppcrypto::kuznyechik kuz{};
    kuz.init(key, cppcrypto::block_cipher::encryption);
    kuz.encrypt_block(master_key, encrypted_key);
    kuz.encrypt_block(master_key + kuz.blocksize()/8, encrypted_key + kuz.blocksize()/8);
}
void secrets::decrypt_master_key(uint8_t* key, uint8_t* encrypted_master_key, uint8_t* decrypted_master_key) {
    cppcrypto::kuznyechik kuz{};
    kuz.init(key, cppcrypto::block_cipher::decryption);
    kuz.decrypt_block(encrypted_master_key, decrypted_master_key);
    kuz.decrypt_block(encrypted_master_key + kuz.blocksize()/8, decrypted_master_key + kuz.blocksize()/8);
}


float secrets::password::get_user_selected_password_entropy(const std::string &pass) {
    auto pass_len = pass.length();
    if (pass_len == 0) {
        return 0;
    }
    float entropy = 4;
    if (pass_len < 9) entropy += (pass_len - 1) * 2; 
    else entropy += 14;

    if (pass_len > 8 and pass_len < 21) {
        entropy += (pass_len - 8) * 1.5;
    }
    if (pass_len > 20) entropy += (pass_len - 20);

    bool has_special_symbols = std::any_of(pass.begin(), pass.end(), [](unsigned char c){ return std::ispunct(c); });
    bool has_uppercase = std::any_of(pass.begin(), pass.end(), [](unsigned char c){ return std::isupper(c); });
    if (has_special_symbols or has_uppercase) {
        entropy += 6;
    }
    return entropy;
}

secrets::password::Alphabet secrets::password::detect_pass_alphabet(const std::string &pass) {
    if (std::all_of(pass.begin(), pass.end(), [](unsigned char c){ return std::isdigit(c); })) {
        return Alphabet::numbers;
    }
    if (std::all_of(pass.begin(), pass.end(), [](unsigned char c){ return std::islower(c); })) {
        return Alphabet::az;
    }
    if (std::all_of(pass.begin(), pass.end(), [](unsigned char c){ return std::isupper(c); })) {
        return Alphabet::AZ;
    }
    if (std::all_of(pass.begin(), pass.end(), [](unsigned char c){ return std::isalpha(c); })) {
        return Alphabet::azAZ;
    }
    bool contain_az = std::any_of(pass.begin(), pass.end(), [](unsigned char c){ return std::islower(c); });
    bool contain_AZ = std::any_of(pass.begin(), pass.end(), [](unsigned char c){ return std::isupper(c); });
    bool contain_alph = std::any_of(pass.begin(), pass.end(), [](unsigned char c){ return std::isalpha(c); });
    bool contain_number = std::any_of(pass.begin(), pass.end(), [](unsigned char c){ return std::isdigit(c); });
    bool contain_special_symbols = std::any_of(pass.begin(), pass.end(), [](unsigned char c){ return std::ispunct(c); });
    if (contain_az and contain_number and not contain_special_symbols) {
        return Alphabet::az09;
    }
    if (contain_AZ and contain_number and not contain_special_symbols) {
        return Alphabet::AZ09;
    }
    if (contain_alph and contain_number and not contain_special_symbols) {
        return Alphabet::azAZ09;
    }
    if (contain_alph and contain_number and contain_special_symbols) {
        return Alphabet::ASCII_PRINTABLE;
    }
    return Alphabet::ASCII_PRINTABLE;
}

float secrets::password::get_generated_password_entropy(const std::string &pass, Alphabet alph) {
    switch(alph) {
        case Alphabet::numbers: return pass.length() * 3.322f;
        case Alphabet::az: return pass.length() * 4.7f;
        case Alphabet::AZ: return pass.length() * 4.7f;
        case Alphabet::az09: return pass.length() * 5.170f;
        case Alphabet::AZ09: return pass.length() * 5.170f;
        case Alphabet::azAZ: return pass.length() * 5.7f;
        case Alphabet::azAZ09: return pass.length() * 5.954;
        case Alphabet::ASCII_PRINTABLE: return pass.length() * 6.570;
    }
}
