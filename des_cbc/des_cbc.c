#include "des_cbc.h"
#include <string.h>
#include <openssl/des.h>
#include <stdio.h>

const unsigned char iv[8] = {'1', '2', '3', '4', '5', '6', '7', '8'};

int mdes_cbc_encrypt(unsigned char key[8], unsigned char* src, unsigned char* des, int src_len) {
	// pkcs5 padding
	int padding = 8 - src_len % 8; 
	int new_len = src_len + padding + 1;
	unsigned char* after_padding = (unsigned char*)malloc(new_len);
	memcpy(after_padding, src, src_len);
	int i = 0;
	for (i = 0; i < padding; i++) {
		after_padding[src_len + i] = padding;
	}
	after_padding[new_len] = 0;

	DES_cblock dkey;
	memcpy(&dkey, key, sizeof(DES_cblock));
	DES_key_schedule key_schedule;
	DES_set_key_unchecked(&dkey, &key_schedule);

	DES_cblock ivec;
	memcpy(&ivec, iv, sizeof(ivec));

	DES_ncbc_encrypt(after_padding, des, new_len - 1, &key_schedule, &ivec, 1);
	des[new_len] = 0;
	fprintf(stderr, "new_len=%d\n", new_len - 1);	
	for (i = 0; i < new_len - 1; i++) {
		fprintf(stderr, "%02X ", des[i]);
	}
	fprintf(stderr, "\n");
	return new_len - 1;
}

int mdes_cbc_decrypt(unsigned char key[8], unsigned char* src, unsigned char* des, int src_len) {
	DES_cblock dkey;
	memcpy(&dkey, key, sizeof(DES_cblock));
	DES_key_schedule key_schedule;
	DES_set_key_unchecked(&dkey, &key_schedule);

	DES_cblock ivec;
	memcpy(&ivec, iv, sizeof(ivec));

	DES_ncbc_encrypt(src, des, src_len, &key_schedule, &ivec, 0);
	unsigned char padding = des[src_len - 1];
	des[src_len - padding] = 0;
	return src_len - padding;
}
