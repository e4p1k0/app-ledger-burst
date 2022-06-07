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

// Flag to also return the public key besides showing the address
#define P1_SHOW_ADDRES_RETURN_KEY 0x01

// The screen content (with the user address)
char screenContent[27];

//done button callback
unsigned int doneButton(const bagl_element_t *e) {    
    UNUSED(e);

    ui_idle();  // redraw ui
    return 0; // DO NOT REDRAW THE BUTTON
}

//Defenition of the UI for this handler
UX_STEP_VALID(saFlowPage1, 
    bnnn_paging,
    doneButton(NULL),
    {
      .title = "Your Address",
      .text = screenContent,
    });
UX_STEP_VALID(saFlowPage2, 
    pb, 
    doneButton(NULL),
    {
      &C_icon_validate_14,
      "Done"
    });
UX_FLOW(saFlow,
  &saFlowPage1,
  &saFlowPage2
);

void showScreen() {
    if(0 == G_ux.stack_count)
        ux_stack_push();

    ux_flow_init(0, saFlow, NULL);
}

//defined in reedSolomon.c
void reedSolomonEncode(const uint64_t inp, char * const output);

void showAddressHandlerHelper(const uint8_t p1, const uint8_t p2, const uint8_t * const dataBuffer, const uint8_t dataLength,
        uint8_t * const flags, uint8_t * const tx) {
    
    UNUSED(p2);

    uint16_t exception = 0;

    uint8_t publicKey[32]; memset(publicKey, 0, sizeof(publicKey));

    uint8_t ret = burst_keys(dataBuffer, dataLength, 0, publicKey, 0, &exception);

    if (R_SUCCESS == ret) {
        memset(screenContent, 0, sizeof(screenContent));
        snprintf(screenContent, sizeof(screenContent), APP_PREFIX);
        reedSolomonEncode(public_key_to_id(publicKey), screenContent + strlen(screenContent));
        showScreen();

        G_io_apdu_buffer[(*tx)++] = R_SUCCESS;

        if((p1&P1_SHOW_ADDRES_RETURN_KEY) == P1_SHOW_ADDRES_RETURN_KEY){
            // Also return the public key if asked
            memmove(G_io_apdu_buffer + *tx, publicKey, sizeof(publicKey));
            *tx += sizeof(publicKey);
        }
    } else {
        G_io_apdu_buffer[0] = ret;
        *tx = 1;
    }
}

void showAddressHandler(const uint8_t p1, const uint8_t p2, const uint8_t * const dataBuffer, const uint8_t dataLength,
       uint8_t * const flags, uint8_t * const tx, const bool isLastCommandDifferent) {

    UNUSED(isLastCommandDifferent);

    showAddressHandlerHelper(p1, p2, dataBuffer, dataLength, flags, tx);
    
    G_io_apdu_buffer[(*tx)++] = 0x90;
    G_io_apdu_buffer[(*tx)++] = 0x00;
}
