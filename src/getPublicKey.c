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
#include <os_io_seproxyhal.h>
#include "ux.h"

#include "returnValues.h"
#include "config.h"
#include "burst.h"


/*
    This command allows the client to the EC-KCDSA public key, chain code and ED25519 public key for a requested derivation path

    API:

        P1: P1_GET_PUBLIC_KEY:
        dataBuffer: derivation path (uint32) * 3
        returns:    32 byte public key

*/


void getPublicKeyHandlerHelper(const uint8_t p1, const uint8_t p2, const uint8_t * const dataBuffer, const uint8_t dataLength,
     uint8_t * const flags, uint8_t * const tx) {

    UNUSED(p1); UNUSED(flags);

    uint8_t publicKey[32];
    uint16_t exception = 0;

    uint8_t ret = burst_keys(dataBuffer, dataLength, 0, publicKey, 0, &exception);
    // uint8_t ret = burst_keys(dataBuffer, dataLength, publicKey, 0, 0, &exception); // DO NOT COMMIT THIS LINE!!!, used for testing only, to send the privatekey to the client, private key should never be released

    G_io_apdu_buffer[(*tx)++] = ret;

    if (R_SUCCESS == ret) {
        
        memmove(G_io_apdu_buffer + *tx, publicKey, sizeof(publicKey));
        *tx += sizeof(publicKey);

    } else if (R_KEY_DERIVATION_EX == ret) {  
        G_io_apdu_buffer[(*tx)++] = exception >> 8;
        G_io_apdu_buffer[(*tx)++] = exception & 0xFF;
    }
}

void getPublicKeyHandler(const uint8_t p1, const uint8_t p2, const uint8_t * const dataBuffer, const uint8_t dataLength,
     uint8_t * const flags, uint8_t * const tx, const bool isLastCommandDifferent) {

    UNUSED(isLastCommandDifferent); //there is no state to manage, so there's nothing to do with this parameter

    getPublicKeyHandlerHelper(p1, p2, dataBuffer, dataLength, flags, tx);
    
    G_io_apdu_buffer[(*tx)++] = 0x90;
    G_io_apdu_buffer[(*tx)++] = 0x00;
}
