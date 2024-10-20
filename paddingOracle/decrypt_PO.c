#include "AES_CBC.h"
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>

int main(void)
{
	uint8_t cor;
    	uint32_t clen,plen;

	uint8_t* ciphertext_hex = "60592ff65e192e29a29be678fc8873cd0aabea229e2d4521568b1fa32712a1fd8037b482bbc8f3bc523ad5e2e2fd0868";
	clen=strlen(ciphertext_hex)/2;

	uint8_t* ciphertext = malloc(clen*sizeof(uint8_t));
	parse(clen, ciphertext_hex, ciphertext);
	printf("Ciphertext (hex): "); 
	print_hex(ciphertext,clen);

	plen = clen;
	uint8_t* plaintext = malloc(plen*sizeof(uint8_t));
	uint8_t resultado[16] = {0};
	uint8_t* nombre = malloc(16*sizeof(uint8_t));
	uint8_t* nombrehex = "4a6f6e20457478656261727269610202";
	parse(16, nombrehex, nombre);

	//... 254 10 105
	for (int j = 0; j < 16; j++) {
		
		for (int i = 0; i <= 255; i++) {
			// printf("bucle 1");
			ciphertext[clen-j-17] = i;
			// printf("\nel ciphertext es: \n");
			// print_hex(ciphertext, clen);
			// break;
			plen = decipher_AES_CBC_PO(plaintext, ciphertext, clen);
			if (j == 2){
				printf("\n%d\n",plen);
			}
			if (plen==clen-j-1)
			{
				printf("Plaintext (plen = %d): ", plen);
				print_c(plaintext,plen);
				printf("\n%d\n", i);
				resultado[16-j-1] = i ^ (j+1);		
				// printf("\nel resultado es: %d\n", resultado[16-1]);
				// break;

			}	
			else //invalid pad when plen=0
			{	
				// printf("Padding error, plen = %d.\n", plen);
			}	
		
		}
		// printf("\niteracion: %d\n", j);
		// ciphertext[clen-j-17] = (j+2) ^ resultado[16-j-1]; // mete 15 bytes, en vez de 16
		//printf("\n%d\n", 16-j-1);
		for(int k = 0; k<j+1; k++){
			// printf("\nel resultado es: %d\n", resultado[16-k-1]);
			ciphertext[clen-k-17] = (j+2) ^ resultado[16-k-1]; 
			// print_hex(plaintext, clen);
		}
		// print_hex(plaintext, clen);
		// print_hex(ciphertext, clen);
		// break;
		//printf("bucle 2");
	}


	printf("final1\n\n");
	print_hex(resultado, 16);

	printf("final2\n\n");
	for (int i = 16; i< 32; i++){
		ciphertext[i] = nombre[i-16] ^ resultado[i-16];
	}

	print_hex(ciphertext, clen);
	decipher_AES_CBC_PO(plaintext, ciphertext, clen);

	uint32_t offset=32;
	print_c(plaintext+offset, clen-offset);
	printf("final3");
	// printf("Your name: "); 
	printf("final4");
	//print_c(plaintext, plen);
	//print_c(plaintext+offset, plen-offset);	 //aqui se ralla con el offset parece
	printf("final5");
	free(ciphertext); 
	free(plaintext);
	printf("final6");
	return(0);

}
