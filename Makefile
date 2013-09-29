all:brute server client
CFLAGS+=-Wall -Werror -g -O2
LDLIBS+=-pthread -lcrypt
