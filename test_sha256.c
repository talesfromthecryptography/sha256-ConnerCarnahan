#include <stdlib.h>
#include <memory.h>
#include "sha256.h"

uint8_t* TexttoHash(char* s);

int main(){
    uint8_t hash[32];
    uint8_t key[32] = TexttoHash("6310D9CBA21701DE7F7F1035C8D7F5DD756CDBF2CD71182CF7724B686F74A3B7");


    return 0;
}

uint8_t* TexttoHash(char* s){
    uint8_t loc[32];

}