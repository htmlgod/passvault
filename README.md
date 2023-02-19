# passvault

passvault – minimalistic CLI app for managing your passwords

## Reqirements

- YASM
- C++20

## Build

Tested on macOS, Debian.
```bash
#==============LINUX
apt install yasm libx11-dev# or with another package manager
git clone --recurse-submodules https://github.com/htmlgod/passvault
cd passvault
cd third_party/cppcrypto/
make
cd ../..
cmake -S. -B_build -DCMAKE_BUILD_TYPE=Release
sudo cmake --build _build --install
#==============macOS
brew install yasm
git clone --recurse-submodules https://github.com/htmlgod/passvault
cd passvault
cd third_party/cppcrypto/
make
cd ../..
cmake -S. -B_build -DCMAKE_BUILD_TYPE=Release
sudo cmake --build _build --install
#==============Windows
TODO
```

## Configuration
```bash
#==============LINUX and MACOS
$ cat /etc/passvault/passvault_config.cfg
# PASSVAULT CONFIG FILE
# UNCOMMENT AND EDIT SETTINGS

# database_filename=TEST.DB
# password_weakness_level=11
# master_key_filename=MASTER.KEY

$ passvault --init
#==============Windows
TODO
```

## Usage

## REFS

1. [program_options](https://www.boost.org/doc/libs/1_81_0/doc/html/program_options.html)
2. [HUNTER](https://hunter.readthedocs.io/en/latest/quick-start/boost-components.html#)
3. [clip](https://github.com/dacap/clip/wiki#who-is-using-clip)
4. [cppcrypto](https://cppcrypto.sourceforge.net/)

## License

[MIT](https://choosealicense.com/licenses/mit/)
