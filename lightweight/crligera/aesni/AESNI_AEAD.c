/*
This is an implementation of the AES algorithm, specifically ECB, CTR, CBC, GCM and CCM mode.
Key size can be chosen in aes.h - available choices are AES128, AES192, AES256.

The implementation is verified against the test vectors in:
National Institute of Standards and Technology Special Publication 800-38A 2001 ED
*/

/*****************************************************************************/
/* Includes:                                                                 */
/*****************************************************************************/
#include "AESNI_AEAD.h"

/*****************************************************************************/
/* Defines:                                                                  */
/*****************************************************************************/
// The number of columns comprising a state in AES. This is a constant in AES. Value=4
#define Nb 4
#if defined(AES256) && (AES256 == 1)
	#define Nk 8
	#define Nr 14
#elif defined(AES192) && (AES192 == 1)
	#define Nk 6
	#define Nr 12
#else
	#define Nk 4        // The number of 32 bit words in a key.
	#define Nr 10       // The number of rounds in AES Cipher.
#endif

// ----------------GENERAL------------------
//Calculate xor or two pointers a and b for length len
//Store result in a
void xor(uint8_t* a, const uint8_t* b, const int len)
{
	uint8_t i;
	for (i=0; i<len; ++i)
		a[i] ^= b[i];
}

//Store value n in pointer buf in q bytes starting from lsb last_index 
static void n_in_q_bytes(uint8_t* buf, int last_index, int n, int q)
{
	int i;
	for (i=0; i<q; i++) {	
		buf[last_index-i] = (uint8_t)n;
		n = n>>8;
	}
}
// -------------------------------------

// ----------------GCM------------------
// Multiply two 128-bit values in GF(2^128)
static void gf_mul(uint8_t *X, const uint8_t *Y) 
{
	// Reduction polynomial only define the first byte to speed the process
	uint8_t R_0 = 0xe1; 
	
	//Initiliaze Z to 0^128
	uint8_t* Z = calloc(AES_BLOCKLEN,sizeof(uint8_t));
	
	// Load Y into V
	uint8_t* V = calloc(AES_BLOCKLEN,sizeof(uint8_t)); 	
	memcpy(V, Y, AES_BLOCKLEN);
		
	int i, j, rem, q;
	for (i = 0; i < 128; ++i) //Iterate for each bit
	{
		j = i/8; //bit to byte conversion
		rem = i%8; //bit to byte conversion
		if ((X[j] & (1<<(7-rem)))!=0) //if xi!=0 update Z
			xor(Z, V, AES_BLOCKLEN); 
		//else if xi no change to Z
		if ((V[AES_BLOCKLEN-1] & 1)==1) {
			//V>>1
			for (q = AES_BLOCKLEN-1; q >= 0 ; q--) {
				if (q==0) 
					V[0] = (V[0]>>1);
				else 
					V[q] = (((V[q-1] & 1)<<7) | (V[q]>>1));
			}
			V[0]^=R_0; //only the msb byte of V is xor-ed with R since all the rest of R is 0
		}
		else {
			//V>>1
			for (q = AES_BLOCKLEN-1; q >= 0 ; q--) {
				if (q==0) 
					V[0] = (V[0]>>1);
				else 
					V[q] = (((V[q-1] & 1)<<7) | (V[q]>>1));
			}
		}
	}
	
	// Store the result
	memcpy(X, Z, AES_BLOCKLEN);
	
	free(Z); free(V);
}

static void GHASH(const uint8_t* X, int nblocks, const uint8_t* H, uint8_t *result)
{
	//Inicializar un buffer Y
	uint8_t* Y = calloc(AES_BLOCKLEN, sizeof(uint8_t));
	
	// Process each 128-bit block in X
	int i;
	for (i = 0; i < nblocks; i++) {
		xor(Y, X, AES_BLOCKLEN); 
		gf_mul(Y, H);
		X += AES_BLOCKLEN;
	}
	
	//Copy in result the contents in Y
	memcpy(result, Y, AES_BLOCKLEN);
	
	free(Y);
}

static void calculate_J0(const uint8_t* iv, int nbytes_iv, const uint8_t* H, uint8_t* J0)
{
	//iv==96 bits
	if (nbytes_iv==12) {  
		memcpy(J0, iv, nbytes_iv);
		J0[AES_BLOCKLEN-1] += 1; //iv=inc32(J0))
	}
	//iv!=96 bits
	else {
		uint32_t s_bytes = 16*(nbytes_iv/16)-nbytes_iv;
		uint32_t nbytes_temp1 = nbytes_iv+s_bytes+8+8;
		uint8_t* temp1 = calloc(nbytes_temp1,sizeof(uint8_t));
		memcpy(temp1, iv, nbytes_iv);
		// the middle bits are already set to zero with calloc of temp
		n_in_q_bytes(temp1, (nbytes_temp1-1), nbytes_iv*8, 8); // number of bits in 8 bytes
		GHASH (temp1, nbytes_temp1/AES_BLOCKLEN, H, J0);
		free(temp1);
	}
}

static void calculate_S(const uint8_t* C, int nbytes_C, const uint8_t* A, int nbytes_A, const uint8_t* H, uint8_t* S)
{
 	//Estimate temp2 as concatenation of of A, C, nbytes_C, nbytes_A
	 //Estimate padding for P
	int u = 0;
	if (nbytes_C%AES_BLOCKLEN!=0)
		u = AES_BLOCKLEN-nbytes_C%AES_BLOCKLEN;
	int v = 0;
	if (nbytes_A%AES_BLOCKLEN!=0)
		v = AES_BLOCKLEN-nbytes_A%AES_BLOCKLEN; 
	int nbytes_temp2 = nbytes_A+v+nbytes_C+u+8+8;
	uint8_t* temp2 = calloc(nbytes_temp2, sizeof(uint8_t));
	memcpy(temp2, A, nbytes_A);
	memcpy(temp2+nbytes_A+v, C, nbytes_C);
	n_in_q_bytes(temp2, (nbytes_temp2-1), nbytes_C*8, 8); // number of bits in 8 bytes
	n_in_q_bytes(temp2, (nbytes_temp2-8-1), nbytes_A*8, 8); // number of bits in 8 bytes
	
	//Calculate S as GHASH of temp2 with key H.
	GHASH(temp2, nbytes_temp2/AES_BLOCKLEN, H, S);	
	
	free(temp2); 
}

void AES_GCM_encrypt(uint8_t* buf, int nbytes_buf, const uint8_t* iv, int nbytes_iv, uint8_t* key, const uint8_t* A, int nbytes_A, uint8_t* T)
{
	uint8_t* H = calloc(AES_BLOCKLEN, sizeof(uint8_t)); // Initialize H to 0
	
	//***************************************************************
	//TASK1: implement this lines for AESNI
	//AES_ECB_encrypt(H, 1, key); //Calculate AES_K(0^128)
	//***************************************************************
	
	//Calculate J0 dependiendo de la longitud de iv
	uint8_t* J0=calloc(AES_BLOCKLEN,sizeof(uint8_t)); // Initialize J0 to 0
	calculate_J0(iv, nbytes_iv, H, J0);

	//ENCRYPT CTR (iv=inc32(J0))
	J0[AES_BLOCKLEN-1]++;
	
	//***************************************************************
	//TASK2: implement this lines for AESNI
	//AES_CTR_xcrypt(buf, nbytes_buf, J0, key);
	//***************************************************************
	
	//CALCULAR TAG
	//Calculate S as GHASH of temp2 with key H.
	uint8_t* S=calloc(AES_BLOCKLEN, sizeof(uint8_t));
	calculate_S(buf, nbytes_buf, A, nbytes_A, H, S);
	//Encrypt S to obtain calculated tag. The calculated tag is stored in S
	J0[AES_BLOCKLEN-1] -= 1; //revert inc32(J0) 
	
	//***************************************************************
	//TASK3: implement this lines for AESNI
	//AES_CTR_xcrypt(S, AES_BLOCKLEN, J0, key);
	//***************************************************************
	
	//Store result in T
	memcpy(T, S, AES_BLOCKLEN);
	
	free(H); free(J0); free(S);
}

int AES_GCM_decrypt(uint8_t* buf, int nbytes_buf, const uint8_t* iv, int nbytes_iv, uint8_t* key, const uint8_t* A, int nbytes_A, const uint8_t* T)
{
	//CALCULATE H
	uint8_t* H = calloc(AES_BLOCKLEN, sizeof(uint8_t)); // Initialize H to 0
	
	//***************************************************************
	//TASK4: implement this lines for AESNI
	//use intel_AES_encxxx
	//AES_ECB_encrypt(H, 1, key); //Calculate AES_K(0^128)
	//***************************************************************
	
	//Calculate J0 dependiendo de la longitud de iv
	uint8_t* J0=calloc(AES_BLOCKLEN, sizeof(uint8_t)); // Initialize J0 to 0
	calculate_J0(iv, nbytes_iv, H, J0);
	
	//CALCULAR TAG
	 //Calculate S as GHASH of temp2 with key H.
	uint8_t* S=calloc(AES_BLOCKLEN, sizeof(uint8_t));
	calculate_S(buf, nbytes_buf, A, nbytes_A, H, S);
	//Encrypt S to obtain calculated tag. The calculated tag is stored in S
	
	//***************************************************************
	//TASK5: implement this lines for AESNI
	//AES_CTR_xcrypt(S, AES_BLOCKLEN, J0, key);
	//***************************************************************
	
	//Check if calculated tag (S) is equal to received tag (T)
	int valid;
	if (0 == memcmp((char*) S, (char*) T, AES_BLOCKLEN)) { //SUCESS
		//DECRYPT CTR (iv=inc32(J0))
		J0[AES_BLOCKLEN-1] += 1;

		//***************************************************************
		//TASK6: implement this lines for AESNI
		//AES_CTR_xcrypt(buf, nbytes_buf, J0, key);
		//***************************************************************
		
		valid=1;
	} 
	else { //FAILURE 
		memset(buf,0,nbytes_buf);
		valid=0;		
	}
	free(H); free(J0); free(S); 
	return valid;
}
// -------------------------------------

// ----------------CCM------------------
static int estimate_nbytes_B(int nbytes_A, int nbytes_P)
{
	int nbytes_asize=0;
	//Determine the size required to store nytes_A in B
	if (nbytes_A==0) {
		nbytes_asize=0;
	}
	else if (nbytes_A>0 && nbytes_A<(pow(2,16)-pow(2,8))) {	
	 	nbytes_asize=2;
	}
	else if ( nbytes_A>=(pow(2,16)-pow(2,8)) && nbytes_A<(pow(2,32))) {
		nbytes_asize=6;
	}
	else if (nbytes_A>=(pow(2,32)) && nbytes_A<(pow(2,64))) {
		nbytes_asize=10;
	}
	else {	
		return 0;
	}
	
	//Estimate A padding
	int nbytes_apad = 0;
	if ((nbytes_A+nbytes_asize)%AES_BLOCKLEN!=0)
		nbytes_apad = 16-(nbytes_A+nbytes_asize)%AES_BLOCKLEN;
	
	//Estimate P padding
	int nbytes_ppad = 0;
	if (nbytes_P%AES_BLOCKLEN!=0)
		nbytes_ppad = 16-(nbytes_P%AES_BLOCKLEN);	
	
	//Return size of B for encryption or decryption with CCM
	return (16 + nbytes_P + nbytes_ppad + nbytes_A + nbytes_apad + nbytes_asize);
}

static void CCM_formating_B(const uint8_t* P, int nbytes_P, const uint8_t* nonce, int nbytes_nonce, const uint8_t* A, int nbytes_A, int nbytes_T, uint8_t* B)
{
	//ind keeps track of the data being added to B
	int ind = 0;
	
	//CALCULATE B0
	 //add FLAGS in B0
	if (nbytes_A!=0) {
		B[0] |= 1<<6;
	}
	B[0] |= (((nbytes_T-2)/2) & 0x7) << 3;
	int q = 15-nbytes_nonce;
	B[0] |= ((q-1) & 0x7) << 0;
	 // add N in B0
	memcpy(B+1,nonce,15-q);
 	 // add Q in B0
	uint8_t* Q = calloc(q, sizeof(uint8_t));
	n_in_q_bytes(Q, q-1, nbytes_P, q);
	memcpy(B+16-q, Q, q);
	 //add a in B1
	int nbytes_apad = 0;
	ind += AES_BLOCKLEN;
	if (nbytes_A>0 && nbytes_A<(pow(2,16)-pow(2,8))) {
		n_in_q_bytes(B, ind+2-1, nbytes_A, 2); //last 16 bits
		ind += 2;
	 	nbytes_apad = 16-(nbytes_A+2)%AES_BLOCKLEN;
	}
	else if (nbytes_A>=(pow(2,16)-pow(2,8)) && nbytes_A<(pow(2,32))) {
		B[ind] = 0xff; 
		B[ind+1] = 0xfe;
		n_in_q_bytes(B, ind+6-1, nbytes_A, 4); //last 32 bits
		ind += 6;
	 	nbytes_apad = 16-(nbytes_A+6)%AES_BLOCKLEN;
	}
	else if (nbytes_A>=(pow(2,32)) && nbytes_A<(pow(2,64))) {
		B[ind] = 0xff; 
		B[ind+1] = 0xff;
		n_in_q_bytes(B, ind+10-1, nbytes_A, 8); //last 64 bits	
		ind += 10;
	 	nbytes_apad = 16-(nbytes_A+10)%AES_BLOCKLEN;
	}
	
	//Calculate B1,...Bn
	//Add A and padding for a in B
	memcpy(B+ind, A, nbytes_A);
	ind += nbytes_A + nbytes_apad;
	
	//Add plaintext (automatic padding) 
	memcpy(B+ind, P, nbytes_P);
	
	free(Q);
}

static void calculate_iv_AES_CCM(const uint8_t* nonce, int n, uint8_t* iv)
{
	//initialize iv to 0
	memset(iv, 0, AES_BLOCKLEN);
	
	//[q-1]3 in FLAGS first 16 bytes of iv
	int q = 15-n;
	iv[0] = ((q-1) & 0x7) << 0 ; 
	
	//Copy nonce to iv
	memcpy(iv+1, nonce, 15-q);
	
	// the last 16-1.. 15 bytes are initialized to 0 with calloc	
}

static void calculate_tag_AES_CCM(uint8_t* B, int nblocks_B, uint8_t* key, uint8_t* T, int t)
{
	//*************************************************************** 
	//TASK7: implement this lines for AESNI
	//Remember CBC with iv of zeros, Tag is msb of last block
	//***************************************************************
}

void AES_CCM_encrypt(uint8_t* P, int nbytes_P, const uint8_t* nonce, int nbytes_nonce, uint8_t* key, const uint8_t* A, int nbytes_A, int nbytes_T, uint8_t* C)
{
	//Calculate nbytes_B
	int nbytes_B = estimate_nbytes_B(nbytes_A, nbytes_P);
	
	//Calculate B
	uint8_t* B = calloc(nbytes_B, sizeof(uint8_t));
	CCM_formating_B(P, nbytes_P, nonce, nbytes_nonce, A, nbytes_A, nbytes_T, B);
	
	//CALCULATE T
	uint8_t* T = malloc(nbytes_T*sizeof(uint8_t));
	calculate_tag_AES_CCM(B, nbytes_B/AES_BLOCKLEN, key, T, nbytes_T);
	
	//Calculate iv=CTR0
	uint8_t* iv = calloc(AES_BLOCKLEN, sizeof(uint8_t));
	calculate_iv_AES_CCM(nonce, nbytes_nonce, iv);

	//CTR encrypt of T with iv
	//***************************************************************
	//TASK8: implement this lines for AESNI
	//AES_CTR_xcrypt(T, nbytes_T, iv, key);
	//***************************************************************
	
	//inc32(iv), copy plaintext in C and encrypt to obtain encrypted C
	iv[AES_BLOCKLEN-1]++;
	
	//***************************************************************
	//TASK9: implement this lines for AESNI
	//memcpy(C, P, nbytes_P);
	//AES_CTR_xcrypt(C, nbytes_P, iv, key);
	//***************************************************************
	
	memcpy(C+nbytes_P, T, nbytes_T);
	
	free(B); free(iv); free(T); 
}

int AES_CCM_decrypt(uint8_t* C, int nbytes_C, const uint8_t* nonce, int nbytes_nonce, uint8_t* key, const uint8_t* A, int nbytes_A, int nbytes_T, uint8_t* P)
{
	//Calculate size of plaintext P
	int nbytes_P = nbytes_C-nbytes_T;
	
	//If invalid nbytes return invalid
	if (nbytes_P<=0) { //FAILURE
		P=NULL;
		nbytes_P=0;
		return(0);
	}

	//Calculate iv=CTR0
	uint8_t* iv = calloc(AES_BLOCKLEN, sizeof(uint8_t));
	calculate_iv_AES_CCM(nonce, nbytes_nonce, iv);
	
	//CTR encrypt of T_rec with iv
	uint8_t* T_rec = malloc(nbytes_C*sizeof(uint8_t));

	//***************************************************************
	//TASK10: implement this lines for AESNI
	//memcpy(T_rec, C+nbytes_P, nbytes_T);
	//AES_CTR_xcrypt(T_rec, nbytes_T, iv, key);
	//***************************************************************
	
	//inc32(iv) and CTR encrypt of P
	iv[AES_BLOCKLEN-1]++;
	
	//***************************************************************
	//TASK11: implement these lines for AESNI
	//memcpy(P, C, nbytes_P);
	//AES_CTR_xcrypt(P, nbytes_P, iv, key);
	//***************************************************************
	
	//CALCULATE nbytes_B
	int nbytes_B = estimate_nbytes_B(nbytes_A, nbytes_P);
	uint8_t* B = calloc(nbytes_B, sizeof(uint8_t));
	CCM_formating_B(P, nbytes_P, nonce, nbytes_nonce, A, nbytes_A, nbytes_T, B);
	
	//CALCULATE T_calc
	uint8_t* T_calc=malloc(nbytes_C*sizeof(uint8_t));
	calculate_tag_AES_CCM(B, nbytes_B/AES_BLOCKLEN, key, T_calc, nbytes_T);
	
	//Analyze if received tag and calculated tag are equal. 
	if (0 != memcmp((char*) T_rec, (char*) T_calc, nbytes_T)) //invalid TAG 
	{
		P=NULL;
		nbytes_P=0;
	}
	
	free(B); free(iv); free(T_rec); free(T_calc);
	
	return(nbytes_P);
}
// -------------------------------------


