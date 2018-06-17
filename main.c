/* nano_lib - ESP32 Any functions related to seed/private keys for Nano
 Copyright (C) 2018  Brian Pugh, James Coxon, Michael Smaili
 https://www.joltwallet.com/
 
 This program is free software; you can redistribute it and/or modify
 it under the terms of the GNU General Public License as published by
 the Free Software Foundation; either version 3 of the License, or
 (at your option) any later version.
 This program is distributed in the hope that it will be useful,
 but WITHOUT ANY WARRANTY; without even the implied warranty of
 MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 GNU General Public License for more details.
 You should have received a copy of the GNU General Public License
 along with this program; if not, write to the Free Software Foundation,
 Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301  USA
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "sodium.h"
//#include "sodium/private/common.h"

#include "nano_lib.h"
#include "helpers.h"
#include "inttypes.h"
#include <stdbool.h>
#include <pthread.h>

static uint64_t const publish_test_threshold = 0xff00000000000000;
static uint64_t const publish_full_threshold = 0xffffffc000000000;

nl_err_t nl_parse_server_work_string(hex64_t work_str, uint64_t *work_int){
    /* Converts an ascii hex string to a uint64_t and flips the endianness.
     * This allows work to be used in local computations.
     *
     * Returns 0 on error */
    if( sodium_hex2bin((uint8_t *)work_int, sizeof(uint64_t),
            work_str, sizeof(hex64_t),
            NULL, NULL, NULL) ){
        return E_FAILURE;
    }
    //*work_int = bswap_64(*work_int);
    return E_SUCCESS;
}

void nl_generate_server_work_string(hex64_t work, uint64_t nonce){
    /* Inverse of nl_parse_server_work_string()*/
    //nonce = bswap_64(nonce);
    sodium_bin2hex(work, HEX_64, (uint8_t *)&nonce, sizeof(nonce));
}

static uint64_t pow_output (uint256_t hash, uint64_t nonce){
    /* Computes the resulting hash of using nonce. For Nano's PoW, you want the
     * output hash to be high
     */
    uint64_t res;
    crypto_generichash_blake2b_state state;
    crypto_generichash_blake2b_init(&state, NULL, 0, sizeof(res));
    crypto_generichash_blake2b_update(&state, (uint8_t *)&nonce, sizeof(nonce));
    crypto_generichash_blake2b_update(&state, hash, BIN_256);
    crypto_generichash_blake2b_final(&state, (uint8_t *)&res, sizeof(res));
    return res;
}

bool nl_pow_verify(uint256_t hash, uint64_t nonce){
    /* Usually hash is the previous block hash. For open blocks its the
     * public key.
     *
     * Returns True on success
     */
    return pow_output (hash, nonce) >= publish_full_threshold;
}

uint64_t nl_compute_local_pow(uint256_t hash, uint64_t nonce){
    // Starts guessing nonces starting from the passed in nonce.
    // If you don't care, the passed in nonce can simply be 0
    for(; !nl_pow_verify(hash, nonce); nonce++);
    return nonce;
}

void nl_generate_seed(uint256_t seed_bin){
    // Generates a random 32-long array (256 bits) of random data into seed_bin
    uint32_t rand_buffer;
    
    for(uint8_t i=0; i<8; i++){
        rand_buffer = randombytes_random();
        memcpy(seed_bin + 4*i, &rand_buffer, sizeof(rand_buffer));
    }
    sodium_memzero(&rand_buffer, sizeof(rand_buffer));
}

int stop = 0;
uint64_t work;

void *PoWThread(void *vargp)
{
    uint64_t work;
    nl_err_t res;
    hex64_t work_str;
    uint64_t oldwork1;
    
    uint256_t *previous = (uint256_t *)vargp;
    uint32_t rand_buffer;
    rand_buffer = randombytes_random();
    
    work = nl_compute_local_pow(previous, rand_buffer);
    // Store the value argument passed to this thread
    
    //printf("Thread ID:  Work: 0x%" PRIx64 "\n", work);
    nl_generate_server_work_string(work_str, work);
    //printf("ASCII Work: %s\n", work_str);
    printf("%s\n", work_str);
    
    //nl_parse_server_work_string(work_str, &oldwork1);
    //res = nl_pow_verify(previous, oldwork1);
    //printf("Check: %d\n", res);
    exit(0);
}

int main(int argc, char** argv)
{
    //printf("PoW Generator\n");
    nl_err_t res;
    uint256_t previous;

    int i;
    pthread_t tid;
    
    sodium_hex2bin(previous, sizeof(previous),
                   argv[1],
                   HEX_256, NULL, NULL, NULL);

    for (i = 0; i < 4; i++){
        pthread_create(&tid, NULL, PoWThread, (void *)&previous);
    }
    pthread_exit(NULL);
}
