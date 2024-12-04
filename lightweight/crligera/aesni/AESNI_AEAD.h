#ifndef _AES_H_
#define _AES_H_

#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>
#include <math.h>
#include <string.h>  
#include "libaesni/iaesni.h"

//SELECT THE DESIRED AES MODE: AES-128, AES-192 or AES-256
#define AES128 1
//#define AES192 1
//#define AES256 1

#if defined(AES256) && (AES256 == 1)
    #define AES_KEYLEN 32
#elif defined(AES192) && (AES192 == 1)
    #define AES_KEYLEN 24
#else
    #define AES_KEYLEN 16   // Key length in bytes
#endif

#define AES_BLOCKLEN 16 // Block length in bytes - AES is 128b block only

// ----------------GENERAL------------------
void xor(uint8_t* a, const uint8_t* b, int len);
// -------------------------------------

// ----------------GCM------------------
// NOTES: you need to set IV in ctx via AES_init_ctx_iv() or AES_ctx_set_iv()
// no IV should ever be reused with the same key 
void AES_GCM_encrypt(uint8_t* buf, int nbytes_buf, const uint8_t* iv, int nbytes_iv, uint8_t* key, const uint8_t* A, int nbytes_A, uint8_t* T);
int AES_GCM_decrypt(uint8_t* buf, int nbytes_buf, const uint8_t* iv, int nbytes_iv, uint8_t* key, const uint8_t* A, int nbytes_A, const uint8_t* T);
// -------------------------------------

// ----------------CCM------------------
// NOTES: you need to set IV in ctx via AES_init_ctx_iv() or AES_ctx_set_iv()
// no IV should ever be reused with the same key 
void AES_CCM_encrypt(uint8_t* P, int nbytes_P, const uint8_t* nonce, int nbytes_nonce, uint8_t* key, const uint8_t* A, int nbytes_A, int nbytes_T, uint8_t* C);
int AES_CCM_decrypt(uint8_t* C, int nbytes_C, const uint8_t* nonce, int nbytes_nonce, uint8_t* key, const uint8_t* A, int nbytes_A, int nbytes_T, uint8_t* P);
// -------------------------------------

#endif // _AES_H_
