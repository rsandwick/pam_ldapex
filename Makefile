# pam_ldapex.so Makefile
#
ARCH := $(shell getconf LONG_BIT)
DESTDIR ?=
PAMDIR_32 := /lib/security
PAMDIR_64 := /lib64/security
PAMDIR ?= $(PAMDIR_$(ARCH))

INSTALL		:= install
INSTALL_DIR	:= $(INSTALL) -m 755 -d
INSTALL_PROGRAM	:= $(INSTALL) -m 755
INSTALL_LIBRARY	:= $(INSTALL) -m 644
RM		:= rm -rf

GCC ?= gcc
CXX ?= g++
CFLAGS ?= -O2

CFLAGS += -Wall -Wextra
LDFLAGS	+= -Wl,-z,relro

all: library

library: pam_ldapex.o
	$(GCC) $(CFLAGS) -shared -o pam_ldapex.so pam_ldapex.o -lldap $(LDFLAGS)

pam_ldapex.o: pam_ldapex.c
	$(GCC) $(CFLAGS) -c -fPIC -o pam_ldapex.o pam_ldapex.c

install:
	$(INSTALL_DIR) $(DESTDIR)$(PAMDIR)
	$(INSTALL_LIBRARY) pam_ldapex.so $(DESTDIR)$(PAMDIR)

clean:
	$(RM) *.o pam_ldapex.so
