/*******************************************************************************
*  (c) 2019 Haim Bender, 2020 jjos
*
*
*  Licensed under the Apache License, Version 2.0 (the "License");
*  you may not use this file except in compliance with the License.
*  You may obtain a copy of the License at
*
*      http://www.apache.org/licenses/LICENSE-2.0
*
*  Unless required by applicable law or agreed to in writing, software
*  distributed under the License is distributed on an "AS IS" BASIS,
*  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
*  See the License for the specific language governing permissions and
*  limitations under the License.
********************************************************************************/

#include <stdint.h>
#include <stdbool.h>

#include <os.h>
#include <cx.h>
#include <os_io_seproxyhal.h>

#include "curve25519_i64.h"
#include "returnValues.h"
#include "config.h"

#include "burst.h"



//the global state
states_t state;


//self explanatory
//output must point to buffer of 32 bytes in size
void sha256TwoBuffers(const uint8_t * const bufferTohash1, const uint16_t sizeOfBuffer1, const uint8_t * const bufferTohash2, const uint16_t sizeOfBuffer2, uint8_t * const output) {
    cx_sha256_t shaContext;

    os_memset(output, 0, 32);
    cx_sha256_init(&shaContext); //return value has no info

    cx_hash(&shaContext.header, 0, bufferTohash1, sizeOfBuffer1, output, 32);

    if (0 != bufferTohash2)
        cx_hash(&shaContext.header, 0, bufferTohash2, sizeOfBuffer2, output, 32);
    
    cx_hash(&shaContext.header, CX_LAST, 0, 0, output, 32);
}

//self explanatory
//output must point to buffer of 32 bytes in size
void sha256Buffer(const uint8_t * const bufferTohash, const uint16_t sizeOfBuffer, uint8_t * const output) {
    sha256TwoBuffers(bufferTohash, sizeOfBuffer, 0, 0, output);
}

// Sign implementation for Burst, assumes message data was aleady added by cx_hash
//@param in: sharedKey private key for signing
//@parma in: msgSha256 should point to a 32 byte sha256 of the message we are signing
//@param out: sig should point to 64 bytes allocated to hold the signiture of the message
void signMsg(uint8_t * const sharedKey, const uint8_t * const msgSha256, uint8_t * const sig) {

    uint8_t x[32]; os_memset(x, 0, sizeof(x));
    uint8_t y[32]; os_memset(y, 0, sizeof(y));
    uint8_t h[32]; os_memset(h, 0, sizeof(h));

    // Get x = hash(m, s)
    cx_sha256_init(&state.txnAuth.hashstate);
    cx_hash(&state.txnAuth.hashstate.header, 0, msgSha256, 32, NULL, 0);
    cx_hash(&state.txnAuth.hashstate.header, CX_LAST, sharedKey, 32, x, 32);

    // get y through
    keygen25519(y, NULL, x);

    // h = hash(m, y);
    cx_sha256_init(&state.txnAuth.hashstate);
    cx_hash(&state.txnAuth.hashstate.header, 0, msgSha256, 32, NULL, 0);
    cx_hash(&state.txnAuth.hashstate.header, CX_LAST, y, 32, h, 32);

    // copy h first because sign25519 screws with parameters
    os_memcpy(sig+32, h, 32);
    sign25519(sig, h, x, sharedKey);

    // clear sensitive data
    explicit_bzero(h, sizeof(h));
    explicit_bzero(sharedKey, sizeof(sharedKey));
}


//from curveConversion.C
void morph25519_e2m(uint8_t *montgomery, const uint8_t *y);


//this function derives an burst private key, public key, public key and shared key (for signing)
//For more info on how this derivation works, please read the readme
//@param in: derivationPath - a BIP42 derivation path, must be at least of length MIN_DERIVATION_PATH_LENGTH
//@param optional out: keySeedBfrOut - 32 byte EC-KCDSA keyseed for the derivation path
//@param optional out: publicKeyOut - 32 byte EC-KCDSA public key for the derivation path
//@param optional out: sharedKeyOut
//@param out: exceptionOut - iff the return code is R_EXCEPTION => exceptionOut will be filled with the Nano exception code
//@returns: regular return values
uint8_t burstKeys(const uint8_t index, uint8_t * const privKeyOut, uint8_t * const publicKeyOut,
    uint8_t * const sharedKeyOut, uint16_t * const exceptionOut) {
    
    uint32_t pathPrefix[] = PATH_PREFIX; //defined in Makefile
    uint8_t account = 0;
    uint8_t change = 0;

    uint8_t publicKey[32]; os_memset(publicKey, 0, sizeof(publicKey));
    uint8_t privKey[32]; os_memset(privKey, 0, sizeof(privKey));

    // BURST keypath of 44'/30'/0'/0'/index'
    uint32_t derivationPath[5]; os_memset(derivationPath, 0, sizeof(derivationPath));
    os_memmove(derivationPath, pathPrefix, 2 * sizeof(uint32_t));
    derivationPath[2] = account | 0x80000000;
    derivationPath[3] = change | 0x80000000;
    derivationPath[4] = index | 0x80000000;

    BEGIN_TRY {
            TRY {
                os_perso_derive_node_bip32(CX_CURVE_Ed25519, derivationPath, 5, privKey, NULL);

                if (0 != publicKeyOut || 0 != sharedKeyOut) {
                    keygen25519(publicKey, sharedKeyOut, privKey);
                }

                if (0 != publicKeyOut) {
                    os_memmove(publicKeyOut, publicKey, 32);
                }
                if (0 != privKeyOut) {
                    os_memmove(privKeyOut, privKey, 32);
                }
            }
            CATCH_OTHER(exception) {
                *exceptionOut = exception;
                return R_KEY_DERIVATION_EX;
            }
            FINALLY {
                explicit_bzero(privKey, sizeof(privKey));
                explicit_bzero(publicKey, sizeof(publicKey));
            }
    }
    END_TRY;
    
    return R_SUCCESS;
}

//Creates a shared AES encryption key one the matches the key related to the derivation path, the target public key and the nonce
//@param derivationPath - the derivation path
//@param derivationPathLengthInUints32 - kinda clear what this is
//@param targetPublicKey - the 32 byte public key
uint8_t getSharedEncryptionKey(const uint8_t index, const uint8_t* const targetPublicKey, 
                                const uint8_t * const nonce, uint16_t * const exceptionOut, uint8_t * const aesKeyOut) {
    
    uint8_t keySeed[32]; os_memset(keySeed, 0, sizeof(keySeed));

    uint8_t ret = burstKeys(index, keySeed, 0, 0, exceptionOut);

    if (R_SUCCESS != ret)
        return ret;

    uint8_t sharedKey[32]; os_memset(sharedKey, 0, sizeof(sharedKey));


    curve25519(sharedKey, keySeed, targetPublicKey); //should use only the first 32 bytes of keyseed
    
    for (uint8_t i = 0; i < sizeof(sharedKey); i++)
        sharedKey[i] ^= nonce[i];

    sha256Buffer(sharedKey, sizeof(sharedKey), aesKeyOut);

    return R_SUCCESS;
}

//param: publicKey should point to a 32 byte public key buffer
//returns: a 64bit public key id, used later with reedsolomon to create BURST addresses
uint64_t publicKeyToId(const uint8_t * const publicKey) {
        
    uint8_t tempSha[32];
    sha256Buffer(publicKey, 32, tempSha);

    return ((((uint64_t) tempSha[7]) << 56) |
            (((uint64_t) tempSha[6]) << 48) |
            (((uint64_t) tempSha[5]) << 40) |
            (((uint64_t) tempSha[4]) << 32) |
            (((uint64_t) tempSha[3]) << 24) |
            (((uint64_t) tempSha[2]) << 16) |
            (((uint64_t) tempSha[1]) << 8) |
            (((uint64_t) tempSha[0] )));
}


//app_stack_canary is defined by the link script to be at the start of the user data or end of the stack, something like that
//so if there is a stack overflow then it will be overwriten, this is how check_canary() works.
//make sure HAVE_BOLOS_APP_STACK_CANARY is defined in the makefile, so that the OS code will init it and check against it every io_exchange call
//if the canary is not the same, and if not, it will throw

extern unsigned int app_stack_canary;

bool check_canary() {
    return 0xDEAD0031 == app_stack_canary;
}
