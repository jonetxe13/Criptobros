#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include "aesni/AESNI_AEAD.c"

#define CRYPTO_KEYBYTES 16
#define CRYPTO_NPUBBYTES 16
#define CRYPTO_ABYTES 16

int main(int argc, char **argv) {
    struct timespec begin, end; // Structures to store the start and end times for timing
    
    // Define a 16-byte key for encryption, initialized with example values
    unsigned char key[CRYPTO_KEYBYTES] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f };
    
    // Define a nonce (initialization vector) of required size for encryption, initialized with example values
    unsigned char nonce[CRYPTO_NPUBBYTES] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f };
    
    int n = atoi(argv[1]);
    char *original_message = "YourmessagehereeYourmessageheree"; 
    int original_length = strlen(original_message); 
    int total_length = original_length * (1 << n); // Total length after n duplications

    unsigned char *plaintext = malloc((total_length + 1) * sizeof(unsigned char));  
    if (plaintext == NULL) {
        fprintf(stderr, "Error allocating memory for plaintext\n");
        return 1;
    }

    // Copy the original message into the buffer
    strcpy((char *)plaintext, original_message);
    int current_length = original_length;

    // Duplicate the message n times
    for (int i = 0; i < n; i++) {
        memcpy(plaintext + current_length, plaintext, current_length);
        current_length *= 2;
    }

    // Add null terminator
    plaintext[total_length] = '\0';

    unsigned long long plaintext_len = total_length;
    
    // Define associated data (optional additional data) for authenticated encryption
    unsigned char associated_data[] = "Optional AD";
    unsigned long long ad_len = strlen((char*) associated_data);
    
    // Allocate memory for the ciphertext with additional bytes for the authentication tag
    unsigned long long ciphertext_len = plaintext_len + CRYPTO_ABYTES;     
    unsigned char* ciphertext = malloc(ciphertext_len * sizeof(unsigned char));
    if (ciphertext == NULL) {
        fprintf(stderr, "Error allocating memory for ciphertext\n");
        free(plaintext);
        return 1;
    }
    
    // Measure encryption time
    clock_gettime(CLOCK_MONOTONIC_RAW, &begin); // Start time for encryption 
    AES_CCM_encrypt(plaintext, plaintext_len, nonce, CRYPTO_NPUBBYTES, key, associated_data, ad_len, CRYPTO_ABYTES, ciphertext); // Encrypt the plaintext 
    clock_gettime(CLOCK_MONOTONIC_RAW, &end); // End time for encryption
    
    // Calculate and print the encryption time in microseconds
    printf("Encryption time = %.3lf us\n", (end.tv_nsec - begin.tv_nsec) / 1000.0 + (end.tv_sec - begin.tv_sec) * 1e6);
    
    // Allocate memory for decrypted text
    unsigned long long decrypted_len = ciphertext_len - CRYPTO_ABYTES; // Will store the length of decrypted text
    unsigned char* decrypted = malloc(decrypted_len * sizeof(unsigned char)); // Allocate memory for decrypted data
    if (decrypted == NULL) {
        fprintf(stderr, "Error allocating memory for decrypted text\n");
        free(ciphertext);
        free(plaintext);
        return 1;
    }
    
    // Measure decryption time 
    clock_gettime(CLOCK_MONOTONIC_RAW, &begin); // Start time for decryption 
    int result = AES_CCM_decrypt(ciphertext, ciphertext_len, nonce, CRYPTO_NPUBBYTES, key, associated_data, ad_len, CRYPTO_ABYTES, decrypted); // Decrypt the ciphertext 
    clock_gettime(CLOCK_MONOTONIC_RAW, &end); // End time for decryption
    
    // Calculate and print the decryption time in microseconds
    printf("Decryption time = %.3lf us\n", (end.tv_nsec - begin.tv_nsec) / 1000.0 + (end.tv_sec - begin.tv_sec) * 1e6);
    
    // Check if decryption was successful (result > 0)
    if (result <= 0) {
        printf("Decryption failed: authentication error!\n"); // Print an error if authentication failed
    }
    
    // Free allocated memory
    free(ciphertext);
    free(decrypted);
    free(plaintext);
    
    return 0;
}
