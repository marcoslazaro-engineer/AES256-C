// Code by Marcos Lazaro
#include <stdio.h>
#include <stdint.h>
#include <string.h>

#define AES_BLOCK_SIZE 16
#define AES_256_KEY_SIZE 32
#define AES_256_ROUNDS 14
#define Nb 4
#define Nk 8
#define Nr 14

typedef uint8_t state_t[4][4];

// S-box 
static const uint8_t sbox[256] = {
//        0       1    2      3    4     5    6      7    8      9     a    b     c       d     e    f
/*0*/    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
/*1*/    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
/*2*/    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
/*3*/    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
/*4*/    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
/*5*/    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
/*6*/    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
/*7*/    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
/*8*/    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
/*9*/    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
/*a*/    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
/*b*/    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
/*c*/    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
/*d*/    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
/*e*/    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
/*f*/    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
};

// Rcon table
static const uint8_t Rcon[15] = {
    0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36,
    0x6C, 0xD8, 0xAB, 0x4D, 0x9A  // Extended to AES-256 (14 rounds)
};

uint8_t xtime(uint8_t x) {
    return (x << 1) ^ (((x >> 7) & 1) * 0x1b);
}

void SubBytes(state_t *state) {
    for (int i = 0; i < 4; ++i) {
        for (int j = 0; j < 4; ++j) {
            (*state)[i][j] = sbox[(*state)[i][j]];
        }
    }
}

void ShiftRows(state_t *state) {
    uint8_t temp;

    // Rotate first row 1 columns to left
    temp = (*state)[1][0];
    (*state)[1][0] = (*state)[1][1];
    (*state)[1][1] = (*state)[1][2];
    (*state)[1][2] = (*state)[1][3];
    (*state)[1][3] = temp;

    // Rotate second row 2 columns to left
    temp = (*state)[2][0];
    (*state)[2][0] = (*state)[2][2];
    (*state)[2][2] = temp;
    temp = (*state)[2][1];
    (*state)[2][1] = (*state)[2][3];
    (*state)[2][3] = temp;

    // Rotate third row 3 columns to left
    temp = (*state)[3][0];
    (*state)[3][0] = (*state)[3][3];
    (*state)[3][3] = (*state)[3][2];
    (*state)[3][2] = (*state)[3][1];
    (*state)[3][1] = temp;
}

void MixColumns(state_t *state) {
    for (int c = 0; c < 4; ++c) {
        uint8_t a0 = (*state)[0][c];
        uint8_t a1 = (*state)[1][c];
        uint8_t a2 = (*state)[2][c];
        uint8_t a3 = (*state)[3][c];

        (*state)[0][c] = xtime(a0) ^ (xtime(a1) ^ a1) ^ a2 ^ a3;
        (*state)[1][c] = a0 ^ xtime(a1) ^ (xtime(a2) ^ a2) ^ a3;
        (*state)[2][c] = a0 ^ a1 ^ xtime(a2) ^ (xtime(a3) ^ a3);
        (*state)[3][c] = (xtime(a0) ^ a0) ^ a1 ^ a2 ^ xtime(a3);
    }
}

void AddRoundKey(uint8_t round, state_t *state, const uint8_t *RoundKey) {
    for (int col = 0; col < 4; ++col) {
        for (int row = 0; row < 4; ++row) {
            (*state)[row][col] ^= RoundKey[round * Nb * 4 + col * Nb + row];
        }
    }
}

void KeyExpansion(const uint8_t *Key, uint8_t *RoundKey) {
    uint8_t temp[4];
    int i = 0;
    
    for (i = 0; i < Nk * 4; i++) {
        RoundKey[i] = Key[i];
    }
    
    i = Nk;
    
    while (i < Nb * (Nr + 1)) {
        for (int k = 0; k < 4; k++) {
            temp[k] = RoundKey[(i - 1) * 4 + k];
        }
        
        if (i % Nk == 0) {
            uint8_t tmp = temp[0];
            temp[0] = temp[1];
            temp[1] = temp[2];
            temp[2] = temp[3];
            temp[3] = tmp;
            
            for (int k = 0; k < 4; k++) {
                temp[k] = sbox[temp[k]];
            }
            
            temp[0] ^= Rcon[i / Nk - 1];
        } else if (Nk > 6 && i % Nk == 4) {
            for (int k = 0; k < 4; k++) {
                temp[k] = sbox[temp[k]];
            }
        }
        
        for (int k = 0; k < 4; k++) {
            RoundKey[i * 4 + k] = RoundKey[(i - Nk) * 4 + k] ^ temp[k];
        }
        
        i++;
    }
}

void AES_256_encrypt(const uint8_t *input, const uint8_t *key, uint8_t *output) {
    state_t state;
    uint8_t RoundKey[AES_BLOCK_SIZE * (Nr + 1)];
    
    KeyExpansion(key, RoundKey);
    
    for (int i = 0; i < 4; ++i) {
        for (int j = 0; j < 4; ++j) {
            state[j][i] = input[i * 4 + j];
        }
    }
    
    AddRoundKey(0, &state, RoundKey);
    
    for (int round = 1; round < Nr; ++round) {
        SubBytes(&state);
        ShiftRows(&state);
        MixColumns(&state);
        AddRoundKey(round, &state, RoundKey);
    }
    
    SubBytes(&state);
    ShiftRows(&state);
    AddRoundKey(Nr, &state, RoundKey);
    
    for (int i = 0; i < 4; ++i) {
        for (int j = 0; j < 4; ++j) {
            output[i * 4 + j] = state[j][i];
        }
    }
}

void print_hex(const uint8_t *data, size_t len) {
    for (size_t i = 0; i < len; i++) {
        printf("%02x", data[i]);
        if ((i + 1) % 4 == 0) printf(" ");
    }
    printf("\n");
}

void get_user_input(uint8_t *input, uint8_t *key) {
    char message[17]; // 16 chars + null
    char password[33]; // 32 chars + null
    
    printf("Introduce the message (max 16 chars): ");
    fgets(message, sizeof(message), stdin);
    message[strcspn(message, "\n")] = '\0';
    
    printf("Introduce the password (max 32 chars): ");
    fgets(password, sizeof(password), stdin);
    password[strcspn(password, "\n")] = '\0';
    
    memset(input, 0, AES_BLOCK_SIZE);
    memcpy(input, message, strlen(message));
    
    memset(key, 0, AES_256_KEY_SIZE);
    memcpy(key, password, strlen(password));
}

int main() {
    uint8_t input[AES_BLOCK_SIZE];
    uint8_t key[AES_256_KEY_SIZE];
    uint8_t output[AES_BLOCK_SIZE];
    
    get_user_input(input, key);
    
    printf("\nOriginal message(hex):\n");
    print_hex(input, AES_BLOCK_SIZE);
    
    printf("\nPassword (hex):\n");
    print_hex(key, AES_256_KEY_SIZE);
    
    AES_256_encrypt(input, key, output);
    
    printf("\nencrypted message(hex):\n");
    print_hex(output, AES_BLOCK_SIZE);
    
    return 0;
}
