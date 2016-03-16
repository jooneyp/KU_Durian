#!/bin/sh

rm test

gcc -O3 -m32 -o test testmain.c aes_test.c sha2_test.c hash_drbg_test.c libebdcrypto.a
