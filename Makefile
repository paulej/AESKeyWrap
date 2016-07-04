#
# Makefile
#
# Copyright (C) 2015
# Paul E. Jones <paulej@packetizer.com>
#
# Description
#       Builds the aes_key_wrap_test utility to exercise the
#       AES Key Wrap and AES Key Wrap with Padding logic.
#

CC	= gcc

CFLAGS	= -O2 -Wall

LIBS	= -l crypto

OBJS	= aes_key_wrap_test.o AESKeyWrap.o

aes_key_wrap_test: $(OBJS)
	$(CC) $(CFLAGS) -o $@ $^ $(LIBS)

%.o: %.c
	$(CC) $(CFLAGS) -c $*.c

clean:
	$(RM) *.o aes_key_wrap_test

