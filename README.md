# passvault

## Dist package:
1. Binary passvault
2. Config file.cfg

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
- [ ] master key creation
- [ ] first run config
- [ ] pass entropy check
- [ ] Pass gen
- [ ] CPACK
- [ ] add build instructions
- [ ] Refactor


## REFS

1. [program_options](https://www.boost.org/doc/libs/1_81_0/doc/html/program_options.html)
2. [HUNTER](https://hunter.readthedocs.io/en/latest/quick-start/boost-components.html#)
3. [clip](https://github.com/dacap/clip/wiki#who-is-using-clip)
4. [cppcrypto](https://cppcrypto.sourceforge.net/)


## Further Extensions
1. Diceware for password gen as option
2. OpenSSL
  1. RSA key pair instead of using only one generated master key
3. Enable salting for records (PIN)
4. Interactive mode (shell)
5. Password creation date control
6. DB integrity control
