CC = gcc
CFLAGS = -Wall -Werror -O2 -g

OBJS = cipher.o bf_skey.o bf_enc.o bf_cfb64.o

all: cipher

cipher: $(OBJS)
	$(CC) $(CFLAGS) -o cipher $(OBJS)

cipher.o: cipher.c blowfish.h
	$(CC) $(CFLAGS) -c cipher.c
bf_skey.o: bf_skey.c blowfish.h bf_locl.h bf_pi.h
	$(CC) $(CFLAGS) -c bf_skey.c
bf_enc.o: bf_enc.c blowfish.h bf_locl.h
	$(CC) $(CFLAGS) -c bf_enc.c
bf_cfb64.o: bf_cfb64.c blowfish.h bf_locl.h
	$(CC) $(CFLAGS) -c bf_cfb64.c

clean:
	-rm cipher $(OBJS)
