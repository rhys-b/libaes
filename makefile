aes.so: aes.c aes.h
	gcc -shared -Wno-incompatible-pointer-types -fPIC -o libaes.so aes.c
