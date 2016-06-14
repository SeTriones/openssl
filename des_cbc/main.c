#include <stdlib.h>
#include <stdio.h>
#include "des_cbc.h"

int main(int argc, char* argv[]) {
	unsigned char key[8] = {'1', '2', '3', '4', '5', '6', '7', '8'};
	unsigned char src[3] = {'a', 'b', 'c'};
	unsigned char* des = (unsigned char*)malloc(1033);
	int len = mdes_cbc_encrypt(key, src, des, sizeof(src));
	unsigned char* dd = (unsigned char*)malloc(len);
	len = mdes_cbc_decrypt(key, des, dd, len);
	fprintf(stderr, "decrypt result=%s\n", (char*)dd);
	return 0;
}
