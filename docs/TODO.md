## TODO
- [x] CMakeLists.txt
- [x] boost program_options
- [x] clipboard
- [x] cross-platform
- [x] class vault for passwords
- [x] HMAC (imitovstavka)
- [x] encryption(kuznechik?)
- [x] configure program_options for login and other
- [x] Config
- [x] Config file
- [x] master key creation
- [x] first run config
- [x] pass entropy check
- [x] master pass check (проверять при добавлении в базу, ибо мастер пасс
        является солью)
- [x] add build instructions
- [ ] ASLR!!!!!
- [ ] CPACK
- [ ] Refactor
- [ ] Pass gen (from random bytes)
- [ ] Pass gen (from alph)

## Further Extensions
1. Diceware for password gen as option
2. OpenSSL
  1. RSA key pair instead of using only one generated master key
3. Enable salting for records (PIN)
4. Interactive mode (shell)
5. Password creation date control
6. DB integrity control
