# passvault

passvault – minimalistic CLI app for managing your passwords

## Reqirements

- YASM
- C++20

## Build

```bash
#==============LINUX
apt install yasm # or with another package manager
git clone --recurse-submodules https://github.com/htmlgod/passvault
cd passvault
cd third_party/cppcrypto/
make
cd ../..
cmake -S. -B_build
cmake --build _build
#==============macOS
brew install yasm
git clone --recurse-submodules https://github.com/htmlgod/passvault
cd passvault
cd third_party/cppcrypto/
make
cd ../..
cmake -S. -B_build
cmake --build _build
#==============Windows
```

## Configuration

## Usage

## REFS

1. [program_options](https://www.boost.org/doc/libs/1_81_0/doc/html/program_options.html)
2. [HUNTER](https://hunter.readthedocs.io/en/latest/quick-start/boost-components.html#)
3. [clip](https://github.com/dacap/clip/wiki#who-is-using-clip)
4. [cppcrypto](https://cppcrypto.sourceforge.net/)
