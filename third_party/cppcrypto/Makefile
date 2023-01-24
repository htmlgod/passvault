ifeq ($(OS),Windows_NT)
  UNAME ?= Windows
else
  UNAME := $(shell uname -s)
endif

VERSION=.0
SOSUFFIX = .so
SOVERSION=$(SOSUFFIX)$(VERSION)
LIBPREFIX = lib
YASM64FLAGS = -DLINUX
LDEXTRALIBS = -lm -lc

ifeq ($(UNAME),Darwin)
# OS X
PREFIX       ?= /usr/local
LIBDIR       ?= $(PREFIX)/lib
OBJ32FORMAT  := macho32
OBJ64FORMAT  := macho64
INLINE_AS := 1
CC=clang
CXX=clang++
SOSUFFIX = .dylib
SOVERSION=$(VERSION)$(SOSUFFIX)
SODIR=$(LIBDIR)
LDFLAGS=-lc++ -dynamiclib -Wl
endif

ifeq ($(UNAME),Linux)
# Linux
PREFIX       ?= /usr
ifeq ($(shell getconf LONG_BIT), 64)
ifneq ($(wildcard $(PREFIX)/lib64/.),)
LIBDIR       ?= $(PREFIX)/lib64
else
LIBDIR       ?= $(PREFIX)/lib
endif
else
LIBDIR       ?= $(PREFIX)/lib
endif
OBJ32FORMAT  := elf32
OBJ64FORMAT  := elf64
INLINE_AS := 1
SODIR=$(LIBDIR)
LDFLAGS=-Wl,-z,now -Wl,-z,relro -Wl,-soname,libcppcrypto$(SOVERSION)
CC=gcc
CXX=g++
endif

ifeq ($(UNAME),FreeBSD)
PREFIX       ?= /usr
LIBDIR       ?= $(PREFIX)/lib
OBJ32FORMAT  := elf32
OBJ64FORMAT  := elf64
SODIR=$(LIBDIR)
LDFLAGS=-lc++
CC=clang
CXX=clang++
endif

ifeq ($(UNAME),SunOS)
# Solaris
PREFIX       ?= /usr
LIBDIR       ?= $(PREFIX)/lib
OBJ32FORMAT  := elf32
OBJ64FORMAT  := elf64
SODIR=$(LIBDIR)
CC=cc
CXX=CC
MAKE_DIR=ginstall -d
INSTALL_DATA=ginstall
endif

ifeq ($(UNAME),Windows)
define \n


endef
$(error Windows build is supported only via Visual C++ project files,$(\n)or run 'make UNAME=Cygwin' to build for Cygwin)
endif

ifeq ($(UNAME),Cygwin)
PREFIX       ?= /usr
LIBDIR       ?= $(PREFIX)/lib
SODIR        ?= /bin
OBJ32FORMAT  := win32
OBJ64FORMAT  := win64
LDEXTRALIBS=-lm -lc -lssp
SOSUFFIX = .dll
SOVERSION=$(VERSION)$(SOSUFFIX)
CC=gcc
CXX=g++
LIBPREFIX = cyg
YASM64FLAGS = -DWINABI -DWIN_ABI -DWIN64
LDFLAGS=-Wl,--out-implib=libcppcrypto.dll.a -Wl,--export-all-symbols -Wl,--enable-auto-import 
endif

ifndef OBJ64FORMAT
$(error Unsupported platform $(UNAME), please edit the makefile)
endif

INCLUDEDIR   ?= $(PREFIX)/include/cppcrypto
MAKE_DIR     ?= install -d
INSTALL_DATA ?= install

CFLAGS=-O2 -Wall -g -fstack-protector -DNDEBUG -msse2
CXXFLAGS=-O2 -Wall -g -fstack-protector -fpermissive -std=gnu++11 -DNDEBUG -msse2

ifeq ($(shell getconf LONG_BIT), 64)
PLATFORM64BIT=1
else
PLATFORM64BIT=0
endif

ifeq ($(UNAME),SunOS)
CFLAGS=-O5 -xipo=2 -g -DNDEBUG -xarch=sse2 -fopenmp
CXXFLAGS=-O5 -xipo=2 -g -std=c++11 -DNDEBUG -xarch=sse2 -fopenmp
ifeq ($(shell isainfo -v 2>&1 | grep -q "64-bit" && echo 64bit || echo 32bit), 64bit)
PLATFORM64BIT=1
CFLAGS += -m64
CXXFLAGS += -m64
LDFLAGS += -m64
endif
ARCHSSSE3=-xarch=ssse3
ARCHSSE41=-xarch=sse4_1
ARCHAES=-xarch=aes
ARCHAVX2=-xarch=avx2
else
ARCHSSSE3=-mssse3
ARCHSSE41=-msse4.1
ARCHAES=-msse4.1 -maes
ARCHAVX2=-maes -mavx2
endif

cc-name = $(shell $(CC) -v 2>&1 | grep -q "clang version" && echo clang || echo gcc)
ifeq ($(cc-name),clang)
NOASFLAGS=-no-integrated-as
endif

OBJS= cpuinfo.o crypto_hash.o \
      cbc.o hmac.o pbkdf2.o ctr.o \
      block_cipher.o \
      streebog.o gost3411-2012-sse41.o \
      kuznyechik.o \
      ctr-sse41.o

OBJS64 = gost3411-2012-sse2.o

ifdef INLINE_AS
CXXFLAGS += -DINLINE_AS
endif

ifeq ($(PLATFORM64BIT), 1)
   CFLAGS += -fPIC -D_M_X64
   CXXFLAGS += -fPIC -D_M_X64
   OBJS += $(OBJS64)
endif

all: $(LIBPREFIX)cppcrypto$(SOVERSION)

$(LIBPREFIX)cppcrypto$(SOVERSION): $(OBJS) 
	$(CXX) $(LDFLAGS) -shared -o $(LIBPREFIX)cppcrypto$(SOVERSION)  $(OBJS) $(LDEXTRALIBS)
	ar rcs libcppcrypto.a  $(OBJS)


clean:
	rm -f *.o 3rdparty/*.o libcppcrypto.* $(LIBPREFIX)cppcrypto.*

install: $(LIBPREFIX)cppcrypto$(SOVERSION)
	$(MAKE_DIR) $(DESTDIR) $(DESTDIR)$(PREFIX) $(DESTDIR)$(LIBDIR) $(DESTDIR)$(INCLUDEDIR)
	$(INSTALL_DATA) -pm 0755 $(LIBPREFIX)cppcrypto$(SOVERSION) $(DESTDIR)$(SODIR)
	cd $(DESTDIR)$(SODIR) && ln -s -f $(LIBPREFIX)cppcrypto$(SOVERSION) $(DESTDIR)$(SODIR)/$(LIBPREFIX)cppcrypto$(SOSUFFIX)
	$(INSTALL_DATA) -pm 0644 *.h  $(DESTDIR)$(INCLUDEDIR)
	$(INSTALL_DATA) -pm 0644 libcppcrypto*.a $(DESTDIR)$(LIBDIR)

gost3411-2012-sse2.o: 3rdparty/gost3411-2012-sse2.c
	$(CC) -c $(CFLAGS) 3rdparty/gost3411-2012-sse2.c

gost3411-2012-sse41.o: 3rdparty/gost3411-2012-sse41.c
	$(CC) -c $(CFLAGS) $(ARCHSSE41) 3rdparty/gost3411-2012-sse41.c

ctr-sse41.o: ctr-sse41.cpp
	$(CXX) -c $(CXXFLAGS) $(ARCHSSE41) ctr-sse41.cpp

