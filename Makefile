# qlogin / qlogind - suckless-style build. `make` builds bin/qlogin and bin/qlogind, `make test` runs ./run, `make install` is explicit and never run by the tests.
CC      ?= cc
CFLAGS  ?= -O2
CFLAGS  += -std=gnu11 -Wall -Wextra -Isrc/mods
PREFIX  ?= /usr/local
DESTDIR ?=

all: bin/qlogin bin/qlogind

bin/qlogin: src/qlogin.c src/mods/greeter.h src/mods/qdbus.h
	@mkdir -p bin
	$(CC) $(CFLAGS) src/qlogin.c -lpam -o $@

bin/qlogind: src/qlogind.c src/mods/login1.h src/mods/qdbus.h
	@mkdir -p bin
	$(CC) $(CFLAGS) src/qlogind.c -o $@

test:
	./run

# Installs only the two binaries and the man pages. PAM stack, D-Bus policy and service files stay examples in contrib/ (review them first).
install: all
	mkdir -p $(DESTDIR)$(PREFIX)/bin $(DESTDIR)$(PREFIX)/sbin $(DESTDIR)$(PREFIX)/share/man/man1 $(DESTDIR)$(PREFIX)/share/man/man8
	install -m 755 bin/qlogin $(DESTDIR)$(PREFIX)/bin/qlogin
	install -m 755 bin/qlogind $(DESTDIR)$(PREFIX)/sbin/qlogind
	install -m 644 src/qlogin.1 $(DESTDIR)$(PREFIX)/share/man/man1/qlogin.1
	install -m 644 src/qlogind.8 $(DESTDIR)$(PREFIX)/share/man/man8/qlogind.8

uninstall:
	rm -f $(DESTDIR)$(PREFIX)/bin/qlogin $(DESTDIR)$(PREFIX)/sbin/qlogind $(DESTDIR)$(PREFIX)/share/man/man1/qlogin.1 $(DESTDIR)$(PREFIX)/share/man/man8/qlogind.8

clean:
	rm -f bin/qlogin bin/qlogind

.PHONY: all test install uninstall clean
