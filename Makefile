WITH_LZMA ?= 0
WITH_LZIP ?= 1
STRICT_COMPILE ?= 1

ifeq ($(WITH_LZMA),1)
LZMA_LIBS=$$(pkg-config --libs liblzma)
LZMA_LDFLAGS=
LZMA_CFLAGS=-DLZMA=1
endif

ifeq ($(WITH_LZIP),1)
LZIP_LIBS=-llz
LZIP_LDFLAGS=
LZIP_CFLAGS=-DLZIP=1
endif


CFLAGS ?= -g
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

imidj: imidj.o chunker.o
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS) $(LZIP_LDFLAGS) $$(pkg-config --libs glib-2.0) $$(pkg-config libcrypto --libs) $(LZMA_LIBS) $(LZIP_LIBS) $$(pkg-config --libs libcurl)

chunker.o: chunker.c
	$(CC) $(CFLAGS) -c $< -o $@ 

imidj.o: main.c
	$(CC) $(CFLAGS) $(LZMA_CFLAGS) $(LZIP_CFLAGS) $$(pkg-config --cflags glib-2.0) $$(pkg-config --cflags libcurl) -c $< -o $@

clean:
	rm -f *.o imidj

install:
	install -d -m 0755 $(DESTDIR)/usr/bin
	install -m 0755 imidj $(DESTDIR)/usr/bin/
