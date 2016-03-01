#!/bin/sh

gcc -o main -m32 -w main.c BN.c ecdsa.c entropy.c GFP.c GFP_EC.c sha1.c sha2__.c
