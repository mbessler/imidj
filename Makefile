WITH_LZMA ?= 1

ifeq ($(WITH_LZMA),1)
LZMA_LIBS=$$(pkg-config --libs liblzma)
LZMA_CFLAGS=-DLZMA=1
endif

CFLAGS = -Werror -Wall -pedantic -std=gnu99 -g

all: imidj

imidj: imidj.o chunker.o
	gcc $(CFLAGS) -o $@ $^ $$(pkg-config --libs glib-2.0) $$(pkg-config libcrypto --libs) $(LZMA_LIBS) $$(pkg-config --libs libcurl)

chunker.o: chunker.c
	gcc $(CFLAGS) -c $< -o $@ 

imidj.o: main.c
	gcc $(CFLAGS) $(LZMA_CFLAGS) $$(pkg-config --cflags glib-2.0) $$(pkg-config --cflags libcurl) -c $< -o $@

clean:
	rm -f *.o imidj

install:
	install -d -m 0755 $(DESTDIR)/usr/bin
	install -m 0755 imidj $(DESTDIR)/usr/bin/
