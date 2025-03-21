#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include "aes.h"


int test_encrypt_ecb(void);
int test_decrypt_ecb(void);
int test_encrypt_cbc(void);
int test_decrypt_cbc(void);
int test_encrypt_ctr(void);
int test_decrypt_ctr(void);
int test_encrypt_AES_GCM(void);
int test_decrypt_AES_GCM(void);
int test_encrypt_AES_CCM(void);
int test_decrypt_AES_CCM(void);

int main(void)
{
    int exit;

#if defined(AES256)
	printf("\nTesting AES256\n\n");
#elif defined(AES192)
	printf("\nTesting AES192\n\n");
#elif defined(AES128)
	printf("\nTesting AES128\n\n");
#else
	printf("You need to specify a symbol between AES128, AES192 or AES256. Exiting");
	return 0;
#endif
	exit =  test_encrypt_cbc() + test_decrypt_cbc() + 
		test_encrypt_ctr() + test_decrypt_ctr() + 
		test_decrypt_ecb() + test_encrypt_ecb() + 
		test_encrypt_AES_CCM() + test_decrypt_AES_CCM()+
		test_encrypt_AES_GCM() + test_decrypt_AES_GCM(); 
	return exit;
}


int test_encrypt_ecb(void)
{
    	// Example values (for testing purposes)
    	// -------------------------------------
	#if defined(AES256)
    	uint8_t key[] = {0x60,0x3d,0xeb,0x10,0x15,0xca,0x71,0xbe,0x2b,0x73,0xae,0xf0,0x85,0x7d,0x77,0x81,0x1f,0x35,0x2c,0x07,0x3b,0x61,0x08,0xd7,0x2d,0x98,0x10,0xa3,0x09,0x14,0xdf,0xf4 };
    	uint8_t C[] = {0xf3,0xee,0xd1,0xbd,0xb5,0xd2,0xa0,0x3c,0x06,0x4b,0x5a,0x7e,0x3d,0xb1,0x81,0xf8,0xf3,0xee,0xd1,0xbd,0xb5,0xd2,0xa0,0x3c,0x06,0x4b,0x5a,0x7e,0x3d,0xb1,0x81,0xf8,0x4c,0x45,0xdf,0xb3,0xb3,0xb4,0x84,0xec,0x35,0xb0,0x51,0x2d,0xc8,0xc1,0xc4,0xd6  };
	#elif defined(AES192)
    	uint8_t key[] = {0x8e,0x73,0xb0,0xf7,0xda,0x0e,0x64,0x52,0xc8,0x10,0xf3,0x2b,0x80,0x90,0x79,0xe5,0x62,0xf8,0xea,0xd2,0x52,0x2c,0x6b,0x7b };
   	uint8_t C[] = {0xbd,0x33,0x4f,0x1d,0x6e,0x45,0xf2,0x5f,0xf7,0x12,0xa2,0x14,0x57,0x1f,0xa5,0xcc,	0xbd,0x33,0x4f,0x1d,0x6e,0x45,0xf2,0x5f,0xf7,0x12,0xa2,0x14,0x57,0x1f,0xa5,0xcc,0xda,0xa0,0xaf,0x07,0x4b,0xd8,0x08,0x3c,0x8a,0x32,0xd4,0xfc,0x56,0x3c,0x55,0xcc};
	#elif defined(AES128)
    	uint8_t key[] = {0x2b,0x7e,0x15,0x16,0x28,0xae,0xd2,0xa6,0xab,0xf7,0x15,0x88,0x09,0xcf,0x4f,0x3c };
    	uint8_t C[] = {0x3a,0xd7,0x7b,0xb4,0x0d,0x7a,0x36,0x60,0xa8,0x9e,0xca,0xf3,0x24,0x66,0xef,0x97,	0x3a,0xd7,0x7b,0xb4,0x0d,0x7a,0x36,0x60,0xa8,0x9e,0xca,0xf3,0x24,0x66,0xef,0x97,0xa2,0x54,0xbe,0x88,0xe0,0x37,0xdd,0xd9,0xd7,0x9f,0xb6,0x41,0x1c,0x3f,0x9d,0xf8 };
	#endif
	int nbytes_P=32;
    	uint8_t P[] = {0x6b,0xc1,0xbe,0xe2,0x2e,0x40,0x9f,0x96,0xe9,0x3d,0x7e,0x11,0x73,0x93,0x17,0x2a,0x6b,0xc1,0xbe,0xe2,0x2e,0x40,0x9f,0x96,0xe9,0x3d,0x7e,0x11,0x73,0x93,0x17,0x2a};
    	// -------------------------------------
    
    	//Padding
	int nblocks_Cout=add_padding_size(nbytes_P);	
	uint8_t* Cout=malloc(nblocks_Cout*AES_BLOCKLEN*sizeof(uint8_t));
    	add_PCKS7(P, nbytes_P, Cout);
    
	//Encrypt ECB
	AES_ECB_encrypt(Cout, nblocks_Cout, key);
	
	//Compare result (in) with precalculated output (out)
    	printf("ECB encrypt: ");
	if (0 == memcmp(C, Cout, nblocks_Cout*AES_BLOCKLEN)) {
		printf("SUCCESS!\n");
		return(0);
	} 
	else {
		printf("FAILURE!\n");
		return(1);
	}
	free(Cout);
}

int test_decrypt_ecb(void)
{
    	// Example values (for testing purposes)
    	// -------------------------------------
	int nblocks_C=3;
	#if defined(AES256)
	uint8_t key[] = {0x60,0x3d,0xeb,0x10,0x15,0xca,0x71,0xbe,0x2b,0x73,0xae,0xf0,0x85,0x7d,0x77,0x81,0x1f,0x35,0x2c,0x07,0x3b,0x61,0x08,0xd7,0x2d,0x98,0x10,0xa3,0x09,0x14,0xdf,0xf4 };
    	uint8_t C[] = {0xf3,0xee,0xd1,0xbd,0xb5,0xd2,0xa0,0x3c,0x06,0x4b,0x5a,0x7e,0x3d,0xb1,0x81,0xf8,	0xf3,0xee,0xd1,0xbd,0xb5,0xd2,0xa0,0x3c,0x06,0x4b,0x5a,0x7e,0x3d,0xb1,0x81,0xf8,	0x4c,0x45,0xdf,0xb3,0xb3,0xb4,0x84,0xec,0x35,0xb0,0x51,0x2d,0xc8,0xc1,0xc4,0xd6  };
	#elif defined(AES192)
   	uint8_t key[] = {0x8e,0x73,0xb0,0xf7,0xda,0x0e,0x64,0x52,0xc8,0x10,0xf3,0x2b,0x80,0x90,0x79,0xe5,0x62,0xf8,0xea,0xd2,0x52,0x2c,0x6b,0x7b };
   	uint8_t C[] = {0xbd,0x33,0x4f,0x1d,0x6e,0x45,0xf2,0x5f,0xf7,0x12,0xa2,0x14,0x57,0x1f,0xa5,0xcc,	0xbd,0x33,0x4f,0x1d,0x6e,0x45,0xf2,0x5f,0xf7,0x12,0xa2,0x14,0x57,0x1f,0xa5,0xcc,	0xda,0xa0,0xaf,0x07,0x4b,0xd8,0x08,0x3c,0x8a,0x32,0xd4,0xfc,0x56,0x3c,0x55,0xcc};
	#elif defined(AES128)
    	uint8_t key[] = {0x2b,0x7e,0x15,0x16,0x28,0xae,0xd2,0xa6,0xab,0xf7,0x15,0x88,0x09,0xcf,0x4f,0x3c };
   	uint8_t C[] = {0x3a,0xd7,0x7b,0xb4,0x0d,0x7a,0x36,0x60,0xa8,0x9e,0xca,0xf3,0x24,0x66,0xef,0x97,0x3a,0xd7,0x7b,0xb4,0x0d,0x7a,0x36,0x60,0xa8,0x9e,0xca,0xf3,0x24,0x66,0xef,0x97,0xa2,0x54,0xbe,0x88,0xe0,0x37,0xdd,0xd9,0xd7,0x9f,0xb6,0x41,0x1c,0x3f,0x9d,0xf8 };
	#endif
    	uint8_t P[] = {0x6b,0xc1,0xbe,0xe2,0x2e,0x40,0x9f,0x96,0xe9,0x3d,0x7e,0x11,0x73,0x93,0x17,0x2a,0x6b,0xc1,0xbe,0xe2,0x2e,0x40,0x9f,0x96,0xe9,0x3d,0x7e,0x11,0x73,0x93,0x17,0x2a};
    	// -------------------------------------
    	
	//Decrypt ECB
    	AES_ECB_decrypt(C, nblocks_C, key);
	//Remove padding
	int nbytes_P=remove_PCKS7(C, nblocks_C);
		
	//Compare result (in) with precalculated output (out)
	printf("ECB decrypt: ");
	if (nbytes_P==0) {
		printf("Incorrect padding! FAILURE\n");
		return(1);
	}
	else {
		if (0 == memcmp(P, C, nbytes_P)) {
			printf("SUCCESS!\n");
			return(0);
		} 
		else {
			printf("FAILURE!\n");
			return(1);
		}
	}
}

int test_encrypt_cbc(void)
{
    	// Example values (for testing purposes)
    	// -------------------------------------
	#if defined(AES256)
    	uint8_t key[] = {0x60,0x3d,0xeb,0x10,0x15,0xca,0x71,0xbe,0x2b,0x73,0xae,0xf0,0x85,0x7d,0x77,0x81,0x1f,0x35,0x2c,0x07,0x3b,0x61,0x08,0xd7,0x2d,0x98,0x10,0xa3,0x09,0x14,0xdf,0xf4 };
    	uint8_t C[] = {0xf5,0x8c,0x4c,0x04,0xd6,0xe5,0xf1,0xba,0x77,0x9e,0xab,0xfb,0x5f,0x7b,0xfb,0xd6,0x9c,0xfc,0x4e,0x96,0x7e,0xdb,0x80,0x8d,0x67,0x9f,0x77,0x7b,0xc6,0x70,0x2c,0x7d,0x3a,0x3a,0xa5,0xe0,0x21,0x3d,0xb1,0xa9,0x90,0x1f,0x90,0x36,0xcf,0x51,0x02,0xd2};
	#elif defined(AES192)
    	uint8_t key[] = {0x8e,0x73,0xb0,0xf7,0xda,0x0e,0x64,0x52,0xc8,0x10,0xf3,0x2b,0x80,0x90,0x79,0xe5,0x62,0xf8,0xea,0xd2,0x52,0x2c,0x6b,0x7b };
    	uint8_t C[] = {0x4f,0x02,0x1d,0xb2,0x43,0xbc,0x63,0x3d,0x71,0x78,0x18,0x3a,0x9f,0xa0,0x71,0xe8,0xb4,0xd9,0xad,0xa9,0xad,0x7d,0xed,0xf4,0xe5,0xe7,0x38,0x76,0x3f,0x69,0x14,0x5a,0xc8,0x1c,0xa9,0x9c,0x3a,0x1e,0x88,0x3f,0xa8,0xd8,0x34,0x31,0x6a,0x22,0x75,0xec };                     
	#elif defined(AES128)
    	uint8_t key[] = {0x2b,0x7e,0x15,0x16,0x28,0xae,0xd2,0xa6,0xab,0xf7,0x15,0x88,0x09,0xcf,0x4f,0x3c };
    	uint8_t C[] = {0x76,0x49,0xab,0xac,0x81,0x19,0xb2,0x46,0xce,0xe9,0x8e,0x9b,0x12,0xe9,0x19,0x7d,0x50,0x86,0xcb,0x9b,0x50,0x72,0x19,0xee,0x95,0xdb,0x11,0x3a,0x91,0x76,0x78,0xb2,0x55,0xe2,0x1d,0x71,0x00,0xb9,0x88,0xff,0xec,0x32,0xfe,0xea,0xfa,0xf2,0x35,0x38 };                                     
	#endif
    	int nbytes_P=32;
    	uint8_t iv[]  = {0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f };
    	uint8_t P[]  = {0x6b,0xc1,0xbe,0xe2,0x2e,0x40,0x9f,0x96,0xe9,0x3d,0x7e,0x11,0x73,0x93,0x17,0x2a,0xae,0x2d,0x8a,0x57,0x1e,0x03,0xac,0x9c,0x9e,0xb7,0x6f,0xac,0x45,0xaf,0x8e,0x51};
    	// -------------------------------------

    	//Padding
	int nblocks_Cout=add_padding_size(nbytes_P);	
	uint8_t* Cout=malloc(nblocks_Cout*AES_BLOCKLEN*sizeof(uint8_t));
    	add_PCKS7(P, nbytes_P, Cout);

	//Encrypt CBC
    	AES_CBC_encrypt(Cout, nblocks_Cout, iv, key);

	//Compare result (in) with precalculated output (out)
	printf("CBC encrypt: ");
	if (0 == memcmp( C, Cout, nblocks_Cout*AES_BLOCKLEN)) {
	        printf("SUCCESS!\n");
		return(0);
    	} 
    	else {
        	printf("FAILURE!\n");
		return(1);
    	}
}

int test_decrypt_cbc(void)
{
    	// Example values (for testing purposes)
    	// -------------------------------------
	#if defined(AES256)
    	uint8_t key[] = {0x60,0x3d,0xeb,0x10,0x15,0xca,0x71,0xbe,0x2b,0x73,0xae,0xf0,0x85,0x7d,0x77,0x81,0x1f,0x35,0x2c,0x07,0x3b,0x61,0x08,0xd7,0x2d,0x98,0x10,0xa3,0x09,0x14,0xdf,0xf4 };
    	uint8_t C[] = {0xf5,0x8c,0x4c,0x04,0xd6,0xe5,0xf1,0xba,0x77,0x9e,0xab,0xfb,0x5f,0x7b,0xfb,0xd6,0x9c,0xfc,0x4e,0x96,0x7e,0xdb,0x80,0x8d,0x67,0x9f,0x77,0x7b,0xc6,0x70,0x2c,0x7d,0x3a,0x3a,0xa5,0xe0,0x21,0x3d,0xb1,0xa9,0x90,0x1f,0x90,0x36,0xcf,0x51,0x02,0xd2};
	#elif defined(AES192)
    	uint8_t key[] = {0x8e,0x73,0xb0,0xf7,0xda,0x0e,0x64,0x52,0xc8,0x10,0xf3,0x2b,0x80,0x90,0x79,0xe5,0x62,0xf8,0xea,0xd2,0x52,0x2c,0x6b,0x7b };
    	uint8_t C[] = {0x4f,0x02,0x1d,0xb2,0x43,0xbc,0x63,0x3d,0x71,0x78,0x18,0x3a,0x9f,0xa0,0x71,0xe8,0xb4,0xd9,0xad,0xa9,0xad,0x7d,0xed,0xf4,0xe5,0xe7,0x38,0x76,0x3f,0x69,0x14,0x5a,0xc8,0x1c,0xa9,0x9c,0x3a,0x1e,0x88,0x3f,0xa8,0xd8,0x34,0x31,0x6a,0x22,0x75,0xec };                     
	#elif defined(AES128)
    	uint8_t key[] = {0x2b,0x7e,0x15,0x16,0x28,0xae,0xd2,0xa6,0xab,0xf7,0x15,0x88,0x09,0xcf,0x4f,0x3c };
    	uint8_t C[] = {0x76,0x49,0xab,0xac,0x81,0x19,0xb2,0x46,0xce,0xe9,0x8e,0x9b,0x12,0xe9,0x19,0x7d,0x50,0x86,0xcb,0x9b,0x50,0x72,0x19,0xee,0x95,0xdb,0x11,0x3a,0x91,0x76,0x78,0xb2,0x55,0xe2,0x1d,0x71,0x00,0xb9,0x88,0xff,0xec,0x32,0xfe,0xea,0xfa,0xf2,0x35,0x38 };                                      
	#endif
	int nblocks_C=3;
    	uint8_t iv[] = {0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f };
    	uint8_t P[] = {0x6b,0xc1,0xbe,0xe2,0x2e,0x40,0x9f,0x96,0xe9,0x3d,0x7e,0x11,0x73,0x93,0x17,0x2a,0xae,0x2d,0x8a,0x57,0x1e,0x03,0xac,0x9c,0x9e,0xb7,0x6f,0xac,0x45,0xaf,0x8e,0x51};	
    	// -------------------------------------
    	
    	//Decrypt CBC
	AES_CBC_decrypt(C, nblocks_C, iv, key);
	
	//Remove padding
	int nbytes_P=remove_PCKS7(C, nblocks_C);
	
	//Compare result (in) with precalculated output (out)
	printf("CBC decrypt: ");
	if (nbytes_P==0) {
		printf("Incorrect padding! FAILURE\n");
		return(1);
	}
	else {
		if (0 == memcmp( P, C, nbytes_P)) {
			printf("SUCCESS!\n");
			return(0);
		} 
		else {
			printf("FAILURE!\n");
			return(1);
		}
	}
}

int test_xcrypt_ctr(const char* xcrypt)
{
    	// Example values (for testing purposes)
    	// -------------------------------------
	#if defined(AES256)
	uint8_t key[] = {0x60,0x3d,0xeb,0x10,0x15,0xca,0x71,0xbe,0x2b,0x73,0xae,0xf0,0x85,0x7d,0x77,0x81,0x1f,0x35,0x2c,0x07,0x3b,0x61,0x08,0xd7,0x2d,0x98,0x10,0xa3,0x09,0x14,0xdf,0xf4 };
	uint8_t in[]  = {0x60,0x1e,0xc3,0x13,0x77,0x57,0x89,0xa5,0xb7,0xa7,0xf5,0x04,0xbb,0xf3,0xd2,0x28,0xf4,0x43,0xe3,0xca,0x4d,0x62,0xb5,0x9a,0xca,0x84,0xe9,0x90,0xca,0xca,0xf5,0xc5,0x2b,0x09,0x30,0xda,0xa2,0x3d,0xe9,0x4c,0xe8,0x70,0x17,0xba,0x2d,0x84,0x98,0x8d,0xdf,0xc9,0xc5,0x8d,0xb6,0x7a,0xad,0xa6,0x13,0xc2,0xdd,0x08,0x45,0x79,0x41,0xa6 };
	#elif defined(AES192)
	uint8_t key[] = {0x8e,0x73,0xb0,0xf7,0xda,0x0e,0x64,0x52,0xc8,0x10,0xf3,0x2b,0x80,0x90,0x79,0xe5,0x62,0xf8,0xea,0xd2,0x52,0x2c,0x6b,0x7b };
	uint8_t in[]  = {0x1a,0xbc,0x93,0x24,0x17,0x52,0x1c,0xa2,0x4f,0x2b,0x04,0x59,0xfe,0x7e,0x6e,0x0b,0x09,0x03,0x39,0xec,0x0a,0xa6,0xfa,0xef,0xd5,0xcc,0xc2,0xc6,0xf4,0xce,0x8e,0x94,0x1e,0x36,0xb2,0x6b,0xd1,0xeb,0xc6,0x70,0xd1,0xbd,0x1d,0x66,0x56,0x20,0xab,0xf7,0x4f,0x78,0xa7,0xf6,0xd2,0x98,0x09,0x58,0x5a,0x97,0xda,0xec,0x58,0xc6,0xb0,0x50 };
	#elif defined(AES128)
 	uint8_t key[] = {0x2b,0x7e,0x15,0x16,0x28,0xae,0xd2,0xa6,0xab,0xf7,0x15,0x88,0x09,0xcf,0x4f,0x3c };
    	uint8_t in[]  = {0x87,0x4d,0x61,0x91,0xb6,0x20,0xe3,0x26,0x1b,0xef,0x68,0x64,0x99,0x0d,0xb6,0xce,0x98,0x06,0xf6,0x6b,0x79,0x70,0xfd,0xff,0x86,0x17,0x18,0x7b,0xb9,0xff,0xfd,0xff,0x5a,0xe4,0xdf,0x3e,0xdb,0xd5,0xd3,0x5e,0x5b,0x4f,0x09,0x02,0x0d,0xb0,0x3e,0xab,0x1e,0x03,0x1d,0xda,0x2f,0xbe,0x03,0xd1,0x79,0x21,0x70,0xa0,0xf3,0x00,0x9c,0xee };
	#endif
    	uint8_t iv[]  = {0xf0,0xf1,0xf2,0xf3,0xf4,0xf5,0xf6,0xf7,0xf8,0xf9,0xfa,0xfb,0xfc,0xfd,0xfe,0xff };
    	uint8_t out[] = {0x6b,0xc1,0xbe,0xe2,0x2e,0x40,0x9f,0x96,0xe9,0x3d,0x7e,0x11,0x73,0x93,0x17,0x2a,0xae,0x2d,0x8a,0x57,0x1e,0x03,0xac,0x9c,0x9e,0xb7,0x6f,0xac,0x45,0xaf,0x8e,0x51,0x30,0xc8,0x1c,0x46,0xa3,0x5c,0xe4,0x11,0xe5,0xfb,0xc1,0x19,0x1a,0x0a,0x52,0xef,0xf6,0x9f,0x24,0x45,0xdf,0x4f,0x9b,0x17,0xad,0x2b,0x41,0x7b,0xe6,0x6c,0x37,0x10 };
        int nbytes_in=64;
    	// -------------------------------------

	//Encrypt or Decrypt CBC
	AES_CTR_xcrypt(in, nbytes_in, iv, key);
  
	//Compare result (in) with precalculated output (out)
	printf("CTR %s: ", xcrypt);
	if (0 == memcmp(out, in, nbytes_in)) {
		printf("SUCCESS!\n");
		return(0);
	} 
	else {
		printf("FAILURE!\n");
		return(1);
	}
}

int test_encrypt_ctr(void)
{
	return test_xcrypt_ctr("encrypt");
}

int test_decrypt_ctr(void)
{
	return test_xcrypt_ctr("decrypt");
}

int test_encrypt_AES_GCM(void)
{
	// Example values (for testing purposes)
	// -------------------------------------
	#if defined(AES256)
	uint8_t key[] =	{0xFE,0xFF,0xE9,0x92,0x86,0x65,0x73,0x1C,0x6D,0x6A,0x8F,0x94,0x67,0x30,0x83,0x08,0xFE,0xFF,0xE9,0x92,0x86,0x65,0x73,0x1C,0x6D,0x6A,0x8F,0x94,0x67,0x30,0x83,0x08};
    	uint8_t C[] = {0x52,0x2D,0xC1,0xF0,0x99,0x56,0x7D,0x07,0xF4,0x7F,0x37,0xA3,0x2A,0x84,0x42,0x7D,0x64,0x3A,0x8C,0xDC,0xBF,0xE5,0xC0,0xC9,0x75,0x98,0xA2,0xBD,0x25,0x55,0xD1,0xAA,
    			0x8C,0xB0,0x8E,0x48,0x59,0x0D,0xBB,0x3D,0xA7,0xB0,0x8B,0x10,0x56,0x82,0x88,0x38,0xC5,0xF6,0x1E,0x63,0x93,0xBA,0x7A,0x0A,0xBC,0xC9,0xF6,0x62,0x89,0x80,0x15,0xAD};
        uint8_t Tout[] = { 0xC0,0x6D,0x76,0xF3,0x19,0x30,0xFE,0xF3,0x7A,0xCA,0xE2,0x3E,0xD4,0x65,0xAE,0x62 };
	#elif defined(AES192)
	uint8_t key[] = {0xFE,0xFF,0xE9,0x92,0x86,0x65,0x73,0x1C,0x6D,0x6A,0x8F,0x94,0x67,0x30,0x83,0x08,0xFE,0xFF,0xE9,0x92,0x86,0x65,0x73,0x1C};
    	uint8_t C[] = {0x39,0x80,0xCA,0x0B,0x3C,0x00,0xE8,0x41,0xEB,0x06,0xFA,0xC4,0x87,0x2A,0x27,0x57,0x85,0x9E,0x1C,0xEA,0xA6,0xEF,0xD9,0x84,0x62,0x85,0x93,0xB4,0x0C,0xA1,0xE1,0x9C,0x7D,0x77,0x3D,0x00,0xC1,0x44,0xC5,0x25,0xAC,0x61,0x9D,0x18,0xC8,0x4A,0x3F,0x47,0x18,0xE2,0x44,0x8B,0x2F,0xE3,0x24,0xD9,0xCC,0xDA,0x27,0x10,0xAC,0xAD,0xE2,0x56 };
        uint8_t Tout[] = {0x3B,0x91,0x53,0xB4,0xE7,0x31,0x8A,0x5F,0x3B,0xBE,0xAC,0x10,0x8F,0x8A,0x8E,0xDB };
	#elif defined(AES128)    	
        uint8_t key[] = {0xFE,0xFF,0xE9,0x92,0x86,0x65,0x73,0x1C,0x6D,0x6A,0x8F,0x94,0x67,0x30,0x83,0x08};
    	uint8_t C[] = {0x42,0x83,0x1e,0xc2,0x21,0x77,0x74,0x24,0x4b,0x72,0x21,0xb7,0x84,0xd0,0xd4,0x9c,0xe3,0xaa,0x21,0x2f,0x2c,0x02,0xa4,0xe0,0x35,0xc1,0x7e,0x23,0x29,0xac,0xa1,0x2e,0x21,0xd5,0x14,0xb2,0x54,0x66,0x93,0x1c,0x7d,0x8f,0x6a,0x5a,0xac,0x84,0xaa,0x05,0x1b,0xa3,0x0b,0x39,0x6a,0x0a,0xac,0x97,0x3d,0x58 ,0xe0,0x91,0x47,0x3f,0x59,0x85  };
        uint8_t Tout[] = {0x64,0xc0,0x23,0x29,0x04,0xaf,0x39,0x8a,0x5b,0x67,0xc1,0x0b,0x53,0xa5,0x02,0x4d};
	#endif
    	int nbytes_P=64;
    	uint8_t P[]  = {0xD9,0x31,0x32,0x25,0xF8,0x84,0x06,0xE5,0xA5,0x59,0x09,0xC5,0xAF,0xF5,0x26,0x9A,0x86,0xA7,0xA9,0x53,0x15,0x34,0xF7,0xDA,0x2E,0x4C,0x30,0x3D,0x8A,0x31,0x8A,0x72,0x1C,0x3C,0x0C,0x95,0x95,0x68,0x09,0x53,0x2F,0xCF,0x0E,0x24,0x49,0xA6,0xB5,0x25,0xB1,0x6A,0xED,0xF5,0xAA,0x0D,0xE6,0x57,0xBA,0x63,0x7B,0x39,0x1A,0xAF,0xD2,0x55};
    	int nbytes_iv=12;
    	uint8_t iv[]  = {0xCA,0xFE,0xBA,0xBE,0xFA,0xCE,0xDB,0xAD,0xDE,0xCA,0xF8,0x88};
    	int nbytes_A=64;
        uint8_t A[]  = {0x3A,0xD7,0x7B,0xB4,0x0D,0x7A,0x36,0x60,0xA8,0x9E,0xCA,0xF3,0x24,0x66,0xEF,0x97,0xF5,0xD3,0xD5,0x85,0x03,0xB9,0x69,0x9D,0xE7,0x85,0x89,0x5A,0x96,0xFD,0xBA,0xAF,0x43,0xB1,0xCD,0x7F,0x59,0x8E,0xCE,0x23,0x88,0x1B,0x00,0xE3,0xED,0x03,0x06,0x88,0x7B,0x0C,0x78,0x5E,0x27,0xE8,0xAD,0x3F,0x82,0x23,0x20,0x71,0x04,0x72,0x5D,0xD4};
       uint8_t T[16];
	// -------------------------------------
        
	AES_GCM_encrypt(P, nbytes_P, iv, nbytes_iv, key, A, nbytes_A, T);
	printf("AES-GCM encrypt: ");
	if ((0 == memcmp(C, P, nbytes_P)) &&  (0 == memcmp(Tout, T, AES_BLOCKLEN)))	{
		printf("SUCCESS!\n");
		return(0);
	} 
	else {
		printf("FAILURE!\n");
		return(1);
	}
}

int test_decrypt_AES_GCM(void)
{
	// Example values (for testing purposes)
	int nbytes_C=64;
	#if defined(AES256)
	uint8_t key[] =	{ 0xFE,0xFF,0xE9,0x92,0x86,0x65,0x73,0x1C,0x6D,0x6A,0x8F,0x94,0x67,0x30,0x83,0x08,0xFE,0xFF,0xE9,0x92,0x86,0x65,0x73,0x1C,0x6D,0x6A,0x8F,0x94,0x67,0x30,0x83,0x08 };
    	uint8_t C[] = { 0x52,0x2D,0xC1,0xF0,0x99,0x56,0x7D,0x07,0xF4,0x7F,0x37,0xA3,0x2A,0x84,0x42,0x7D,0x64,0x3A,0x8C,0xDC,0xBF,0xE5,0xC0,0xC9,0x75,0x98,0xA2,0xBD,0x25,0x55,0xD1,0xAA,0x8C,0xB0,0x8E,0x48,0x59,0x0D,0xBB,0x3D,0xA7,0xB0,0x8B,0x10,0x56,0x82,0x88,0x38,0xC5,0xF6,0x1E,0x63,0x93,0xBA,0x7A,0x0A,0xBC,0xC9,0xF6,0x62,0x89,0x80,0x15,0xAD };
        uint8_t T[] = { 0xC0,0x6D,0x76,0xF3,0x19,0x30,0xFE,0xF3,0x7A,0xCA,0xE2,0x3E,0xD4,0x65,0xAE,0x62 };
	#elif defined(AES192)
	uint8_t key[] = { 0xFE,0xFF,0xE9,0x92,0x86,0x65,0x73,0x1C,0x6D,0x6A,0x8F,0x94,0x67,0x30,0x83,0x08,0xFE,0xFF,0xE9,0x92,0x86,0x65,0x73,0x1C};
    	uint8_t C[] = { 0x39,0x80,0xCA,0x0B,0x3C,0x00,0xE8,0x41,0xEB,0x06,0xFA,0xC4,0x87,0x2A,0x27,0x57,0x85,0x9E,0x1C,0xEA,0xA6,0xEF,0xD9,0x84,0x62,0x85,0x93,0xB4,0x0C,0xA1,0xE1,0x9C,0x7D,0x77,0x3D,0x00,0xC1,0x44,0xC5,0x25,0xAC,0x61,0x9D,0x18,0xC8,0x4A,0x3F,0x47,0x18,0xE2,0x44,0x8B,0x2F,0xE3,0x24,0xD9,0xCC,0xDA,0x27,0x10,0xAC,0xAD,0xE2,0x56 };
        uint8_t T[] = { 0x3B,0x91,0x53,0xB4,0xE7,0x31,0x8A,0x5F,0x3B,0xBE,0xAC,0x10,0x8F,0x8A,0x8E,0xDB };
	#elif defined(AES128)    	
        uint8_t key[] = { 0xFE,0xFF,0xE9,0x92,0x86,0x65,0x73,0x1C,0x6D,0x6A,0x8F,0x94,0x67,0x30,0x83,0x08 };
    	uint8_t C[] = { 0x42,0x83,0x1e,0xc2,0x21,0x77,0x74,0x24,0x4b,0x72,0x21,0xb7,0x84,0xd0,0xd4,0x9c,0xe3,0xaa,0x21,0x2f,0x2c,0x02,0xa4,0xe0,0x35,0xc1,0x7e,0x23,0x29,0xac,0xa1,0x2e,0x21,0xd5,0x14,0xb2,0x54,0x66,0x93,0x1c,0x7d,0x8f,0x6a,0x5a,0xac,0x84,0xaa,0x05,0x1b,0xa3,0x0b,0x39,0x6a,0x0a,0xac,0x97,0x3d,0x58,0xe0,0x91,0x47,0x3f,0x59,0x85 };
        uint8_t T[] = { 0x64,0xc0,0x23,0x29,0x04,0xaf,0x39,0x8a,0x5b,0x67,0xc1,0x0b,0x53,0xa5,0x02,0x4d };
	#endif	
    	uint8_t P[]  = { 0xD9,0x31,0x32,0x25,0xF8,0x84,0x06,0xE5,0xA5,0x59,0x09,0xC5,0xAF,0xF5,0x26,0x9A,0x86,0xA7,0xA9,0x53,0x15,0x34,0xF7,0xDA,0x2E,0x4C,0x30,0x3D,0x8A,0x31,0x8A,0x72,0x1C,0x3C,0x0C,0x95,0x95,0x68,0x09,0x53,0x2F,0xCF,0x0E,0x24,0x49,0xA6,0xB5,0x25,0xB1,0x6A,0xED,0xF5,0xAA,0x0D,0xE6,0x57,0xBA,0x63,0x7B,0x39,0x1A,0xAF,0xD2,0x55 };
	
    	int nbytes_iv=12;
    	uint8_t iv[] = { 0xCA,0xFE,0xBA,0xBE,0xFA,0xCE,0xDB,0xAD,0xDE,0xCA,0xF8,0x88};
    	int nbytes_A=64;
        uint8_t A[] = { 0x3A,0xD7,0x7B,0xB4,0x0D,0x7A,0x36,0x60,0xA8,0x9E,0xCA,0xF3,0x24,0x66,0xEF,0x97,0xF5,0xD3,0xD5,0x85,0x03,0xB9,0x69,0x9D,0xE7,0x85,0x89,0x5A,0x96,0xFD,0xBA,0xAF,0x43,0xB1,0xCD,0x7F,0x59,0x8E,0xCE,0x23,0x88,0x1B,0x00,0xE3,0xED,0x03,0x06,0x88,0x7B,0x0C,0x78,0x5E,0x27,0xE8,0xAD,0x3F,0x82,0x23,0x20,0x71,0x04,0x72,0x5D,0xD4 };
	// -------------------------------------
        
	int valid=AES_GCM_decrypt(C, nbytes_C, iv, nbytes_iv, key, A, nbytes_A, T);
	printf("Plaintext: ");
	print_c(C, nbytes_C);

	printf("\nAES-GCM decrypt: ");
	if (!valid)	{
		printf("TAG IS NOT VALID!\n");
		return(1);
	}
	else {
		if (0 == memcmp(P, C, nbytes_C)) {
			printf("SUCCESS!\n");
			return(0);
		} 
		else {
			printf("FAILURE!\n");
			return(1);
		}
	}
	return 0;
}

int test_encrypt_AES_CCM(void)
{
	// Example values (for testing purposes)
	// -------------------------------------
	// printf("principio de test encrypt AES CCM\n");
	#if defined(AES256)
	uint8_t key[] = { 0x40,0x41,0x42,0x43,0x44,0x45,0x46,0x47,0x48,0x49,0x4A,0x4B,0x4C,0x4D,0x4E,0x4F,0x50,0x51,0x52,0x53,0x54,0x55,0x56,0x57, ,0x58,0x59,0x5A,0x5B,0x5C,0x5D,0x5E,0x5F};
    	uint8_t C[] = { 0x8A,0xB1,0xA8,0x74,0x95,0xFC,0x08,0x20, 0xF2,0xBA,0xF3,0x40};
	#elif defined(AES192)
        uint8_t key[] = { 0x40,0x41,0x42,0x43,0x44,0x45,0x46,0x47,0x48,0x49,0x4A,0x4B,0x4C,0x4D,0x4E,0x4F,0x50,0x51,0x52,0x53,0x54,0x55,0x56,0x57};
    	uint8_t C[] = { 0x18,0xEE,0x17,0x30,0xC8,0xC3,0x26,0xD5,0x08,0xC8,0xA3,0xCE };
	#elif defined(AES128)    	
        uint8_t key[] = { 0x40,0x41,0x42,0x43,0x44,0x45,0x46,0x47,0x48,0x49,0x4A,0x4B,0x4C,0x4D,0x4E,0x4F };
    	uint8_t C[] = { 0x71,0x62,0x01,0x5B,0x4D,0xAC,0x25,0x5D,0x60,0x84,0x34,0x1B };
	#endif
    	int nbytes_P=4;
    	uint8_t P[]  = { 0x20,0x21,0x22,0x23 };
    	int nbytes_nonce=7;
        uint8_t nonce[]={0x10,0x11,0x12,0x13,0x14,0x15,0x16};
    	int nbytes_A=8;
        uint8_t A[]  = {0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07};
       	int nbytes_T=4;
       	// -------------------------------------

	int nbytes_C=nbytes_T+nbytes_P;
	uint8_t* Cout=calloc(nbytes_C,sizeof(uint8_t));
	AES_CCM_encrypt(P, nbytes_P, nonce, nbytes_nonce, key, A, nbytes_A, nbytes_T, Cout);
	printf("AES-CCM encrypt: ");
	if (0 == memcmp(Cout, C, nbytes_C)) {
		printf("SUCCESS!\n");
		return(0);
	} 
	else {
		printf("FAILURE!\n");
		return(1);
	}
	// printf("final de test encrypt AES CCM\n");
	free(Cout); 
}

int test_decrypt_AES_CCM(void)
{
	// Example values (for testing purposes)
	// -------------------------------------
  	int nbytes_nonce = 7;
        uint8_t nonce[]={0x10,0x11,0x12,0x13,0x14,0x15,0x16};
    	int nbytes_A = 8;
        uint8_t A[]  = {0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07};
    	int nbytes_C=8;
       	int nbytes_T = 4;
	#if defined(AES256)
	uint8_t key[] = { 0x40,0x41,0x42,0x43,0x44,0x45,0x46,0x47,0x48,0x49,0x4A,0x4B,0x4C,0x4D,0x4E,0x4F,0x50,0x51,0x52,0x53,0x54,0x55,0x56,0x57, ,0x58,0x59,0x5A,0x5B,0x5C,0x5D,0x5E,0x5F};
    	uint8_t C[] = { 0x8A,0xB1,0xA8,0x74,0x95,0xFC,0x08,0x20,0xF2,0xBA,0xF3,0x40 };
	#elif defined(AES192)
        uint8_t key[] = { 0x40,0x41,0x42,0x43,0x44,0x45,0x46,0x47,0x48,0x49,0x4A,0x4B,0x4C,0x4D,0x4E,0x4F,0x50,0x51,0x52,0x53,0x54,0x55,0x56,0x57};
    	uint8_t c[] = { 0x18,0xEE,0x17,0x30,0xC8,0xC3,0x26,0xD5,0x08,0xC8,0xA3,0xCE };
	#elif defined(AES128)    	
        uint8_t key[] = { 0x40,0x41,0x42,0x43,0x44,0x45,0x46,0x47,0x48,0x49,0x4A,0x4B,0x4C,0x4D,0x4E,0x4F };
    	uint8_t C[] = { 0x71,0x62,0x01,0x5B,0x4D,0xAC,0x25,0x5D,0x60,0x84,0x34,0x1B };
	#endif
    	uint8_t P[]  = { 0x20,0x21,0x22,0x23 };

	// -------------------------------------
        
	uint8_t* Pout=calloc(nbytes_C-nbytes_T,sizeof(uint8_t));
	int nbytes_Pout=AES_CCM_decrypt(C, nbytes_C, nonce, nbytes_nonce, key, A, nbytes_A, nbytes_T, Pout);
	printf("AES-CCM decrypt: ");
	if (nbytes_Pout==0)	{
		printf("TAG IS NOT VALID!\n");
		return(1);
	}
	else {
		if (0 == memcmp(Pout, P, nbytes_Pout)) {
			printf("SUCCESS!\n");
			return(0);
		} 
		else {
			printf("FAILURE!\n");
			return(1);
		}
	}
	
	free(Pout);
}
