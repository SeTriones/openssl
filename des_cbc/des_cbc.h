#include <stdlib.h>
#include <stdio.h>

int mdes_cbc_encrypt(unsigned char key[8], unsigned char* src, unsigned char* des, int src_len);
int mdes_cbc_decrypt(unsigned char key[8], unsigned char* src, unsigned char* des, int src_len);
