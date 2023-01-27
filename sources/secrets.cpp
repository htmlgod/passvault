#include <secrets.hpp>

void util::save_bytes_to_file(uint8_t* bytes, size_t size, const std::string& file_name) {
    std::ofstream ofs(file_name, std::ios::binary);
    if (ofs) {
        ofs.write(as_bytes(*bytes), size); // IDK WHAT IS HAPPENING HERE
        std::cout << "WRITTEN TO " << file_name << std::endl;
    }
}

void util::load_bytes_from_file(uint8_t* bytes, size_t size, const std::string& file_name) {
    std::ifstream ifs(file_name, std::ios::binary);
    if (ifs) {
        ifs.read(as_bytes(*bytes), size);
        std::cout << "READ FROM " << file_name << std::endl;
    }
}

void util::input_master_password(std::string& pass) {
    util::toggle_console_echo(false);
    std::cout << "Enter master pass: ";
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
