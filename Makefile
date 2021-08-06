STRICT_COMPILE ?= 1

LZIP_LIBS=-llz
LZIP_LDFLAGS=
LZIP_CFLAGS=-DLZIP=1


CFLAGS ?= -g -ggdb
CFLAGS += -O3 -Wall -std=gnu99
ifeq ($(STRICT_COMPILE),1)
CFLAGS += -Werror -pedantic
CFLAGS += -D_FORTIFY_SOURCE=2
CFLAGS += -fstack-protector-strong
CFLAGS += -fPIE -pie
CFLAGS += -Wl,-z,noexecstack
CFLAGS += -Wl,-z,relro
CFLAGS += -Wl,-z,now
CFLAGS += -fstrength-reduce -Wstrict-prototypes
CFLAGS += -Wextra
CFLAGS += -Wold-style-definition
CFLAGS += -Wmissing-prototypes
CFLAGS += -fno-common
CFLAGS += -ffunction-sections -fdata-sections
CFLAGS += -Wformat -Wformat-security -Werror=format-security
CFLAGS += -Wno-parentheses
CFLAGS += -Wmissing-declarations -Wmissing-include-dirs
CFLAGS += -Wstrict-aliasing
CFLAGS += -Winit-self
CFLAGS += -pedantic-errors
CFLAGS += -Wformat=2 -Wno-format-nonliteral -Wshadow -Wpointer-arith -Wcast-qual -Wmissing-prototypes -Wno-missing-braces
CFLAGS += -Wswitch-default
#CFLAGS += -Wswitch-enum
endif # STRICT_COMPILE=1

all: imidj

imidj: imidj.o analyzer.o chidx.o chunker.o differ.o patcher.o chblo.o compressor.o chidx-digest.o
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS) $(LZIP_LDFLAGS) $$(pkg-config --libs glib-2.0) $$(pkg-config libcrypto --libs) $(LZIP_LIBS) $$(pkg-config --libs libcurl)

chunker.o: chunker.c
	$(CC) $(CFLAGS) -c $< -o $@ 

clean:
	rm -f *.o imidj

install:
	install -d -m 0755 $(DESTDIR)/usr/bin
	install -m 0755 imidj $(DESTDIR)/usr/bin/


chblo.o: chblo.c chblo.h chidx.h compressor.h chidx-digest.h
	$(CC) $(CFLAGS) $$(pkg-config --cflags glib-2.0) -c $< -o $@

chidx-digest.o: chidx-digest.c chidx-digest.h
	$(CC) $(CFLAGS) $$(pkg-config --cflags glib-2.0) $$(pkg-config libcrypto --cflags) -c $< -o $@

chidx.o: chidx.c chidx.h imidj.h chblo.h chidx-digest.h
	$(CC) $(CFLAGS) $$(pkg-config --cflags glib-2.0) -c $< -o $@

analyzer.o: analyzer.c analyzer.h imidj.h chidx.h chidx-digest.h
	$(CC) $(CFLAGS) $$(pkg-config --cflags glib-2.0) -c $< -o $@

imidj.o: imidj.c imidj.h chidx.h analyzer.h differ.h
	$(CC) $(CFLAGS) $$(pkg-config --cflags glib-2.0) -c $< -o $@

differ.o: differ.c differ.h imidj.h chidx.h chidx-digest.h
	$(CC) $(CFLAGS) $$(pkg-config --cflags glib-2.0) -c $< -o $@

patcher.o: patcher.c patcher.h imidj.h chidx.h compressor.h chidx-digest.h
	$(CC) $(CFLAGS) $$(pkg-config --cflags glib-2.0) $$(pkg-config --cflags libcurl) -c $< -o $@
compressor.o: compressor.c compressor.h 
	$(CC) $(CFLAGS) $$(pkg-config --cflags glib-2.0) $(LZIP_CFLAGS) -c $< -o $@



