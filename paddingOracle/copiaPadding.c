#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

// Function prototypes (assumed to be defined elsewhere)
void parse(uint32_t len, uint8_t* hex, uint8_t* out);
void print_hex(uint8_t* data, uint32_t len);
void print_c(uint8_t* data, uint32_t len);
uint32_t decipher_AES_CBC_PO(uint8_t* plaintext, uint8_t* ciphertext, uint32_t clen);

int main() {
    uint8_t cor;
    uint32_t clen, plen;

    uint8_t* ciphertext_hex = "60592ff65e192e29a29be678fc8873cd0aabea229e2d4521568b1fa32712a1fd8037b482bbc8f3bc523ad5e2e2fd0868";
    clen = strlen(ciphertext_hex) / 2;

    uint8_t* ciphertext = malloc(clen * sizeof(uint8_t));
    parse(clen, ciphertext_hex, ciphertext);
    printf("Ciphertext (hex): ");
    print_hex(ciphertext, clen);

    // Set plen to the same size as clen for the initial allocation
    plen = clen; // Assuming the plaintext will be the same length as ciphertext
    uint8_t* plaintext = malloc(plen * sizeof(uint8_t));
    uint8_t* resultado = malloc(plen * sizeof(uint8_t));

    // Padding oracle attack loop
for (int j = 0; j < 16; j++) {
    for (int i = 0; i <= 255; i++) {
        // Modify the ciphertext byte for the current position
        ciphertext[clen - j - 1] = i; // Adjusted index for correct byte

        plen = decipher_AES_CBC_PO(plaintext, ciphertext, clen);

        if (plen != 0) { // valid pad when plen != 0
            printf("Plaintext (plen = %d): ", plen);
            print_c(plaintext, plen);
            printf("\n%d\n", i);
            break; // Exit the loop once a valid padding is found
        } else { // invalid pad when plen = 0
            printf("Padding error, plen = %d.\n", plen);
        }
    }
    // Calculate the correct padding value
    resultado[clen - j ] = ciphertext[clen - j ] ^ (j + 1); // XOR with (j + 1)
}

// Print the final result
print_c(resultado, plen);

    uint32_t offset = 32;
    printf("Your name: ");
    print_c(plaintext + offset, plen - offset);

    // Free allocated memory
    free(ciphertext);
    free(plaintext);
    free(resultado);

    return 0;
}


