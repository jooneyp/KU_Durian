#!/bin/sh

rm libebdcrypto.a
rm ./Test/libebdcrypto.a

gcc -O3 -m32 -c aes.c sha2.c hash_drbg.c

ar r libebdcrypto.a aes.o sha2.o hash_drbg.o

cp libebdcrypto.a ./Test

rm aes.o
rm sha2.o
rm hash_drbg.o
