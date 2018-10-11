# pam_ldapex.so Makefile
#
ARCH := $(shell getconf LONG_BIT)
DESTDIR ?=
PAMDIR_32 := /lib/security
PAMDIR_64 := /lib64/security
PAMDIR ?= $(PAMDIR_$(ARCH))

INSTALL		:= install
INSTALL_DIR	:= $(INSTALL) -m 755 -d
INSTALL_LIBRARY	:= $(INSTALL) -m 644
RM		:= rm -rf

CC ?= gcc
CFLAGS ?= -O2

CFLAGS += -Wall -Wextra
LDFLAGS	+= -Wl,-z,relro

all: library

library: pam_ldapex.o
	$(CC) $(CFLAGS) -shared -o pam_ldapex.so pam_ldapex.o -lldap $(LDFLAGS)

%.o: %.c
	$(CC) $(CFLAGS) -c -fPIC -o $@ $<

install:
	$(INSTALL_DIR) $(DESTDIR)$(PAMDIR)
	$(INSTALL_LIBRARY) pam_ldapex.so $(DESTDIR)$(PAMDIR)

clean:
	$(RM) *.o pam_ldapex.so
