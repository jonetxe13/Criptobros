#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <time.h>

#include "des.h"

void sort_blocks(uint8_t *table, int *index, int num_blocks);
int search_in_blocks(uint8_t *table, int num_blocks, uint8_t *x); 
 
int main (void)
{
	//Meet-in-the-middle attack 2DES
	//some of the most significant bytes of key1 and key2 are unkown	
	int bytes_k2=1; 
	int bytes_k1=2;
	uint8_t key1[DES_KEY_SIZE]={0x00,0x00,0x83,0x48,0x42,0x20,0x3f,0x0f}; 
	uint8_t key2[DES_KEY_SIZE]={0x00,0xe5,0x33,0x48,0x36,0x54,0x3f,0x30}; 
	
	//3 plaintext and ciphertext pairs are known (p1,c1), (p2,c2), (p3,c3)
	uint8_t p1[BLOCK_SIZE]="Can you ";
	uint8_t c1[BLOCK_SIZE]={0x5a, 0x72, 0xd1, 0x75, 0x69, 0xfa, 0xe4, 0xba};
	uint8_t p2[BLOCK_SIZE]="find the";
	uint8_t c2[BLOCK_SIZE]={0x1d, 0x9b, 0x47, 0x2a, 0x82, 0xbc, 0xf0, 0x5c};
	uint8_t p3[BLOCK_SIZE]="keys????";
	uint8_t c3[BLOCK_SIZE]={0xbc, 0xe7, 0xe1, 0x41, 0x61, 0x9c, 0xc1, 0xa0};
	//Can you determine p4 from c4?
	uint8_t c4[BLOCK_SIZE]={0x46, 0x00, 0x16, 0xda, 0x57, 0xb2, 0x6a, 0xfd};
	uint8_t p4[BLOCK_SIZE];

	uint64_t iterations_k2 = pow(2, 8*bytes_k2);
	uint64_t iterations_k1 = pow(2, 8*bytes_k1);
	uint64_t i,j,cnt;
	
	uint8_t* table=calloc(iterations_k2,sizeof(uint8_t)*BLOCK_SIZE);
    	int *k_index = calloc(iterations_k2, sizeof(int));
	 
	clock_t start, finish;
	double time_taken;
	start = clock();
	
	//IMPLEMENT MITM ATTACK
	//...
	//...
	// ESTA PARTE LO ENCRIPTA
	int found = 0;
	uint8_t ck[BLOCK_SIZE]; //para cifrados auxiliares
	uint8_t nuevaKey2[BLOCK_SIZE];
	memcpy(nuevaKey2, key2, BLOCK_SIZE);
	for(i = 1; i <= iterations_k2; i++){
	    nuevaKey2[0] = i-1;
	    des(ENCRYPTION, p2, ck, nuevaKey2);
	    memcpy(&table[(i-1)*BLOCK_SIZE], &ck, BLOCK_SIZE);
	    k_index[i-1] = i-1;
	}	

	// sort_blocks(table, k_index, BLOCK_SIZE*8);

	// ESTA PARTE LO DESENCRIPTA
	int indexK1 = 0;
	int indexK2 = 0;
	uint8_t nuevaKey1[BLOCK_SIZE];
	memcpy(nuevaKey1, key1, BLOCK_SIZE);
	for(i = 1; i <= 256 && !found; i++){
	    nuevaKey1[0] = i-1;
	    for(j = 1; j <= 256 && !found; j++){
		nuevaKey1[1] = j-1;
		des(DECRYPTION, c2, ck, nuevaKey1);
		if((indexK2 = search_in_blocks(table, BLOCK_SIZE*8, ck))!=-1){
		    nuevaKey2[0] = k_index[indexK2]; 
		    found = 1;
		}
	    }
	}	

	des(DECRYPTION, c4, ck, nuevaKey1);
	printf("la key1 es: \n");
	print_string_hex(nuevaKey1, 8);
	printf("\n");

	des(DECRYPTION, ck, ck, nuevaKey2);
	printf("la key2 es: \n\n");
	print_string_hex(nuevaKey2, 8);
	printf("\n");
	
	printf("el mensaje sin cifrar es: \n");
	print_string_c(ck, 8);
	printf("\n");

	finish = clock();
	time_taken = (double)(finish - start)/(double)CLOCKS_PER_SEC;
	printf("Time DES: %f seg\n", time_taken);
	
	free(k_index);
	free(table);
	
	return 0;
}

//This functions sorts the table input, the index of the sorted table is stored in variable index
void sort_blocks(uint8_t *table, int *index, int num_blocks) 
{
    int i,j;
    int min_idx;
    uint8_t temp_block[BLOCK_SIZE];
    int temp_idx;
    
    // Initialize index to original indexes
    for (i = 0; i < num_blocks; i++) {
        index[i] = i;
    }

    // Sorting algorithm by selection for blocks
    for (i = 0; i < num_blocks - 1; i++)  {
        min_idx = i;
        for (j = i + 1; j < num_blocks; j++) {
            if (memcmp(&table[j * BLOCK_SIZE], &table[min_idx * BLOCK_SIZE], BLOCK_SIZE) < 0) {
                min_idx = j;
            }
        }

        if (min_idx != i) {
            // Exchange blocks in table
            memcpy(temp_block, &table[i * BLOCK_SIZE], BLOCK_SIZE);
            memcpy(&table[i * BLOCK_SIZE], &table[min_idx * BLOCK_SIZE], BLOCK_SIZE);
            memcpy(&table[min_idx * BLOCK_SIZE], temp_block, BLOCK_SIZE);
            // Exchange indeces in index
            temp_idx = index[i];
            index[i] = index[min_idx];
            index[min_idx] = temp_idx;
        }
    }
}

//This functions searches wether a variable of BLOCK_SIZE is in table input
int search_in_blocks(uint8_t *table, int num_blocks, uint8_t *x) 
{
    int i;
    for (i = 0; i < num_blocks; i++) {
        if (memcmp(&table[i * BLOCK_SIZE], x, BLOCK_SIZE) == 0) {
            return i; // Block found
        }
    }
    return -1; // Block not found
}
