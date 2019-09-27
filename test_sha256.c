#include <stdlib.h>
#include <memory.h>
#include "sha256.h"
#include <string.h>
#include <stdio.h>

void BeetoSHA256(uint32_t* a_ptr);
void HexToSHA256(uint32_t* a_ptr, char* s);
void HexToHash(uint32_t* a_ptr, char* s);
void CompareHash(uint32_t* a_ptr, uint32_t* b_ptr);

int main(){
    uint32_t hash[SHA256_DIGEST_SIZE];
    uint32_t beekey[SHA256_DIGEST_SIZE];
    uint32_t beefkey[SHA256_DIGEST_SIZE];
    
    //HexToHash(beefkey, "17e117288642879110850b62f83cb13d07e7961e321c1c762ff5e5ab83029c7c");
    //HexToHash(beekey, "6310D9CBA21701DE7F7F1035C8D7F5DD756CDBF2CD71182CF7724B686F74A3B7");

    HexToSHA256(hash,"BEEF");
    PrintHash(hash);
    //CompareHash(hash,beefkey);

    return 0;
}

void BeetoSHA256(uint32_t* a_ptr){
    
}

void HexToSHA256(uint32_t* a_ptr, char* s){
    sha256_state* state;
    sha256_init(state);
    uint8_t dat[1];
    int count = strlen(s)-1;
    int i = 0;
    while(i <= count){
        if (!isspace(s[i])){
            if ((i & 0x1) == 0){
                dat[0] = hex2bin(s[i]) << 4;
            } else {
                dat[0] |= hex2bin(s[i]);
                sha256_update(state, dat, 1);
            }
        }
        i+=1;
    }
    sha256_final(state,a_ptr);
}

void HexToHash(uint32_t* a_ptr, char* s){
    memset(a_ptr,0,sizeof(uint32_t)*SHA256_DIGEST_SIZE);

    int count = strlen(s)-1;
    unsigned i = 0;

    while (i <= count){
        a_ptr[i>>3] |= ((uint32_t)hex2bin(s[count-i])) << ((i & 0x7) << 2);
        i++;
    }

    PrintHash(a_ptr);
}

void CompareHash(uint32_t* a_ptr, uint32_t* b_ptr){
    for(int i = 0; i < SHA256_DIGEST_SIZE; i+=1 ){
        if ((a_ptr[i] ^ b_ptr[i]) != 0){
            printf("Hash executed incorrectly");
            return;
        }
    }
    printf("Hash Executed Correctly");
}
