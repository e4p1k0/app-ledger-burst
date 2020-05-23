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


#include <string.h>
#include <stdbool.h>

#include <os_io_seproxyhal.h>

#include <cx.h>
#include <os.h>
#include "ux.h"

#include "glyphs.h"
#include "returnValues.h"
#include "config.h"
#include "burst.h"


#define P1_SIGN_INIT      0x01
#define P1_SIGN_CONTINUE  0x02
#define P1_SIGN_FINISH    0x03
#define P1_SIGN_AUTHORIZE 0x10

// This is the code that parses the txn for signing, it parses streamed txn bytes into the state object while hashing the bytes to be signed later,
// displays a dialog of screens which contain the parsed txn bytes from the state, 
//
// authAndSignTxnHandlerHelper is called with some of the txn bytes
// => addToReadBuffer is called adds these bytes to the read buffer
// => parseTxnData tries to pull 176 bytes from the buffer and after that the supported attachments
//      if there is are 176 bytes available:
//          parseTxnData parses the main txn bytes and tries to read possible attachments
//      else
//          R_SEND_MORE_BYTES returned back to the client
//      
// If the parsing goes well without errors screen texts are already configured and shown to the user on the dongle.
// This will block execution and wait for the user to either authorize or reject the request.


//  API:
//
//
//      The mode is encoded in the p1 parameter. The first call must be P1_SIGN_INIT and the last P1_SIGN_FINISH.
//      The caller must also include P1_SIGN_AUTH flag in one call before P1_SIGN_FINISH (e.g. P1_SIGN_INIT|P1_SIGN_AUTH).
//
//      P1: P1_SIGN_INIT: initialize the signing command, with the txn to sign (at least the first 176 bytes)
//      dataBuffer: txn bytes //you can send all of your bytes here if that is possible
//      returns:    1 byte status
//
//      P1: P1_SIGN_CONTINUE:    more txn bytes
//      returns:    1 byte status
//
//      P1: P1_SIGN_FINISH: closes the signing command (no more data, only the path derivation)
//      dataBuffer: path derivation
//      returns:    1 bytes status | 64 byte signiture


// This function cleans the txnAuth part of the state. It is important to call it before starting to load a txn
// also whenever there is an error you should call it so that no one can exploit an error state for some sort of attack.
// The cleaner the state is, the better, allways clean when you can.
void initTxnAuthState() {

    state.txnAuth.numBytesRead = 0;

    state.txnAuth.txnAuthorized = false;
    state.txnAuth.isClean = true;
    
    cx_sha256_init(&state.txnAuth.hashstate);

    explicit_bzero(state.txnAuth.readBuffer, sizeof(state.txnAuth.readBuffer));
    state.txnAuth.readBufferReadOffset = 0;
    state.txnAuth.readBufferEndPos = 0;

    state.txnAuth.txnTypeAndSubType = 0;
    state.txnAuth.recipientId = 0;
    state.txnAuth.amount = 0;

    state.txnAuth.attachmentTempInt32Num1 = 0;
    state.txnAuth.attachmentTempInt32Num2 = 0;
    state.txnAuth.attachmentTempInt64Num1 = 0;
    state.txnAuth.attachmentTempInt64Num2 = 0;
    state.txnAuth.attachmentTempInt64Num3 = 0;

    explicit_bzero(state.txnAuth.feeText, sizeof(state.txnAuth.feeText));
    explicit_bzero(state.txnAuth.txnTypeText, sizeof(state.txnAuth.txnTypeText));
    explicit_bzero(state.txnAuth.optionalWindow1Text, sizeof(state.txnAuth.optionalWindow1Text));
    explicit_bzero(state.txnAuth.optionalWindow2Title, sizeof(state.txnAuth.optionalWindow2Title));
    explicit_bzero(state.txnAuth.optionalWindow2Text, sizeof(state.txnAuth.optionalWindow2Text));
    explicit_bzero(state.txnAuth.appendagesText, sizeof(state.txnAuth.appendagesText));

    ui_idle();
}


// This function formats amounts into string and most importantly add the dot where it's supposed to be.
// The way this is works is that amounts ints and then the dot is added after numDigitsBeforeDecimal digits from right to left
// for example, if the amount is 4200000000 and we have 8 decimals, then the formated amount will be "42"
// for 4210100000 it will be 42.101
// @param outputString - does what it says
// @param maxOutputLength - does what it says
// @param numberToFormat - the input number to format, isn't const cuz we play with it in order to format the number
// @param numDigitsBeforeDecimal - read first paragraph for info
// @returns 0 iff some kind of error happend, else the length of the output string including the null terminator
uint8_t formatAmount(char * const outputString, const uint16_t maxOutputLength, uint64_t numberToFormat, const uint8_t numDigitsBeforeDecimal) {
    
    uint16_t outputIndex = 0;
    bool wasANumberWritten = false;
    bool isDotWritten = false;
    uint8_t numberIndex = 0;


    for (;;) {

        uint8_t modulo = numberToFormat % 10;
        numberToFormat -= modulo;
        numberToFormat /= 10;

        if (numDigitsBeforeDecimal == numberIndex) {
            if (wasANumberWritten && (!isDotWritten) && (0 != numDigitsBeforeDecimal)) {
                isDotWritten = true;
                outputString[outputIndex++] = '.';
            }

            wasANumberWritten = true;
        }

        if (0 != modulo)
            wasANumberWritten = true;

        if (wasANumberWritten || (0 == numDigitsBeforeDecimal))
            outputString[outputIndex++] = '0' + modulo;

        if (outputIndex >= maxOutputLength)
            return 0;

        if ((0 == numberToFormat) && (numDigitsBeforeDecimal <= numberIndex))
            break;

        numberIndex++;

    }


    //reverse the string since we are creating it from left to right, and numbers are right to left
    for (uint16_t i = 0; i < outputIndex - 1 - i; i++) {
        uint8_t temp = outputString[i];
        outputString[i] = outputString[outputIndex - i - 1];
        outputString[outputIndex - i - 1] = temp;
    }

    outputString[outputIndex] = 0;
    return outputIndex + 1;
}

//defined in readSolomon.c
void reedSolomonEncode(const uint64_t inp, const char * output);

//Accept click callback
unsigned int txn_authorized(const bagl_element_t *e) {
    UNUSED(e);
    
    state.txnAuth.txnAuthorized = true;
    G_io_apdu_buffer[0] = R_SUCCESS;
    G_io_apdu_buffer[1] = R_FINISHED;
    G_io_apdu_buffer[2] = 0x90;
    G_io_apdu_buffer[3] = 0x00;
    io_exchange(CHANNEL_APDU | IO_RETURN_AFTER_TX, 4);
    
    ui_signing();  // redraw ui
    return 0; // DO NOT REDRAW THE BUTTON
}

//Canceled click callback
unsigned int txn_canceled(const bagl_element_t *e) {  
    UNUSED(e);

    initTxnAuthState();

    G_io_apdu_buffer[0] = R_SUCCESS;
    G_io_apdu_buffer[1] = R_REJECT;
    G_io_apdu_buffer[2] = 0x90;
    G_io_apdu_buffer[3] = 0x00;
    io_exchange(CHANNEL_APDU | IO_RETURN_AFTER_TX, 4);

    ui_idle(); // redraw ui
    return 0; // DO NOT REDRAW THE BUTTON
}

//Defenition of the UI for the handler
UX_STEP_NOCB(aasFlowAuthorize, 
    pnn, 
    {
      &C_icon_eye,
      "Authorize",
      "transaction",
    });
UX_STEP_NOCB(aasFlowTxType, 
    bnnn_paging, 
    {
      .title = "Transaction Type",
      .text = state.txnAuth.txnTypeText,
    });

UX_STEP_NOCB(aasFlowOptional1,
    bnnn_paging, 
    {
      .title = state.txnAuth.optionalWindow1Title,
      .text = state.txnAuth.optionalWindow1Text,
    });
UX_STEP_NOCB(aasFlowOptional2, 
    bnnn_paging, 
    {
      .title = state.txnAuth.optionalWindow2Title,
      .text = state.txnAuth.optionalWindow2Text,
    });
UX_STEP_NOCB(aasFlowAppendages, 
    bnnn_paging, 
    {
      .title = state.txnAuth.appendagesTitle,
      .text = state.txnAuth.appendagesText,
    });
UX_STEP_NOCB(aasFlowFees, 
    bnnn_paging, 
    {
      .title = "Fees in BURST",
      .text = state.txnAuth.feeText,
    });
UX_STEP_VALID(aasFlowAccept, 
    pb, 
    txn_authorized(NULL),
    {
      &C_icon_validate_14,
      "Authorize",
    });
UX_STEP_VALID(aasFlowReject, 
    pb, 
    txn_canceled(NULL),
    {
      &C_icon_crossmark,
      "Deny",
    });

UX_FLOW(ux_flow_minimal,
  &aasFlowAuthorize,
  &aasFlowTxType,
  &aasFlowFees,
  &aasFlowAccept,
  &aasFlowReject
);

UX_FLOW(ux_flow_appendages,
  &aasFlowAuthorize,
  &aasFlowTxType,
  &aasFlowAppendages,
  &aasFlowFees,
  &aasFlowAccept,
  &aasFlowReject
);

UX_FLOW(ux_flow_1optional,
  &aasFlowAuthorize,
  &aasFlowTxType,
  &aasFlowOptional1,
  &aasFlowFees,
  &aasFlowAccept,
  &aasFlowReject
);

UX_FLOW(ux_flow_optionals,
  &aasFlowAuthorize,
  &aasFlowTxType,
  &aasFlowOptional1,
  &aasFlowOptional2,
  &aasFlowFees,
  &aasFlowAccept,
  &aasFlowReject
);

UX_FLOW(ux_flow_optionals_and_appendages,
  &aasFlowAuthorize,
  &aasFlowTxType,
  &aasFlowOptional1,
  &aasFlowAppendages,
  &aasFlowOptional2,
  &aasFlowFees,
  &aasFlowAccept,
  &aasFlowReject
);

//Just switches between based of the uiFlowBitfeild
static void showScreen() {
    if(0 == G_ux.stack_count)
        ux_stack_push();

    ux_flow_init(0, state.txnAuth.ux_flow, NULL);
}

// Takes bytes away from the buffer, returns 0 if there aren't enough bytes
uint8_t * readFromBuffer(const uint8_t size) {

    if (state.txnAuth.readBufferEndPos - state.txnAuth.readBufferReadOffset < size)
        return 0;

    uint8_t * ret = state.txnAuth.readBuffer + state.txnAuth.readBufferReadOffset;
    state.txnAuth.readBufferReadOffset += size;
    state.txnAuth.numBytesRead += size;

    return ret;
}

// Adds the token ID to Window 1
uint8_t addTokenID() {
    snprintf(state.txnAuth.optionalWindow1Title, sizeof(state.txnAuth.optionalWindow1Title), "%s", "Token ID");
    return formatAmount(state.txnAuth.optionalWindow1Text, sizeof(state.txnAuth.optionalWindow1Text), state.txnAuth.attachmentTempInt64Num1, 0);
}

// Adds to Window 2 the recipient
void addRecipientText() {
    snprintf(state.txnAuth.optionalWindow2Title, sizeof(state.txnAuth.optionalWindow2Title), "Recipient");
    snprintf(state.txnAuth.optionalWindow2Text, sizeof(state.txnAuth.optionalWindow2Text), APP_PREFIX);
    reedSolomonEncode(state.txnAuth.recipientId, state.txnAuth.optionalWindow2Text + strlen(state.txnAuth.optionalWindow2Text));
}

// Reads a uint8_t from buffer
void read_u8(uint8_t *val, uint8_t **ptr){
    os_memmove(val, *ptr, sizeof(uint8_t));
    *ptr += sizeof(uint8_t);
}

// Reads a uint16_t from buffer
void read_u16(uint16_t *val, uint8_t **ptr){
    os_memmove(val, *ptr, sizeof(uint16_t));
    *ptr += sizeof(uint16_t);
}

// Reads a uint64_t from buffer and put the resulting value on val
void read_u64(uint64_t *val, uint8_t **ptr){
    os_memmove(val, *ptr, sizeof(uint64_t));
    *ptr += sizeof(uint64_t);
}

// This is the parse function, it parses the entire txn body and configure ux_flow variables
uint8_t parseTxnData() {
    // Parse the byte array as construted by brs.Transaction.getBytes()
    uint8_t *ptr = NULL;
    uint8_t ret = R_SUCCESS;
    uint8_t len;
    
    if(state.txnAuth.isClean) {
        // No tx type yet, get type and basic information
        state.txnAuth.isClean = false;

        ptr = readFromBuffer(176); // minimal transaction length, first call should have at least this
        if (0 == ptr)
            return R_TXN_SIZE_TOO_SMALL;

        read_u16(&(state.txnAuth.txnTypeAndSubType), &ptr);

        ptr += 4;   // Skip the timestamp
        ptr += 2;   // Skip the deadline
        ptr += 32;  // Skip the sender publickey

        read_u64(&(state.txnAuth.recipientId), &ptr);
        read_u64(&(state.txnAuth.amount), &ptr);

        uint64_t fee = 0;
        read_u64(&fee, &ptr);

        uint8_t ret = formatAmount(state.txnAuth.feeText, sizeof(state.txnAuth.feeText), fee, 8);
        if (0 == ret)
            return R_FORMAT_FEE_ERR;

        ptr += 32;  //Skip the referencedTransactionFullHash TODO: check
        ptr += 64;  //Skip the sig

        ptr += 4;   //Skip the flags
        ptr += 4;   //Skip the block height
        ptr += 8;   //Skip the block Id
    }

    // Read appendages (if some) and configure windows, see brs.Attachment.java
    char *txTypeText = NULL;
    switch (state.txnAuth.txnTypeAndSubType) {
    case 0x1000:
    case 0x1100:
    case 0x1200:
    case 0x1001:
        txTypeText = "Ordinary Payment";
        state.txnAuth.ux_flow = ux_flow_optionals;
        
        if(state.txnAuth.txnTypeAndSubType == 0x1001){
            txTypeText = "Message Payment";
            ret = R_SEND_MORE_BYTES; // potentially need more bytes on another TX
        }
        if(state.txnAuth.txnTypeAndSubType == 0x1100 || state.txnAuth.txnTypeAndSubType == 0x1200){
            txTypeText = "Multiout Payment";
            state.txnAuth.ux_flow = ux_flow_1optional;
            ret = R_SEND_MORE_BYTES; // potentially need more bytes on another TX
        }

        // Window 1 is amount
        snprintf(state.txnAuth.optionalWindow1Title, sizeof(state.txnAuth.optionalWindow1Title), "%s", "BURST Amount");
        if(0 == formatAmount(state.txnAuth.optionalWindow1Text, sizeof(state.txnAuth.optionalWindow1Text), state.txnAuth.amount, 8))
            return R_FORMAT_AMOUNT_ERR;
        // Window 2 is the recipient
        addRecipientText();

        break;
    case 0x1102:
        txTypeText = "Token Transfer";
        state.txnAuth.ux_flow = ux_flow_optionals;
        
        ptr = readFromBuffer(1 + 8*2); // version plus 2 longs
        if (ptr == 0)
            return R_TXN_SIZE_TOO_SMALL;
        ptr += 1; //version
        os_memmove(&(state.txnAuth.attachmentTempInt64Num1), ptr, sizeof(state.txnAuth.attachmentTempInt64Num1)); // assetID
        ptr += sizeof(state.txnAuth.attachmentTempInt64Num1);
        os_memmove(&(state.txnAuth.attachmentTempInt64Num2), ptr, sizeof(state.txnAuth.attachmentTempInt64Num2)); // quantity
        ptr += sizeof(state.txnAuth.attachmentTempInt64Num2);

        if(state.txnAuth.attachmentTempInt64Num1 == TRT_TOKEN){
            // TRT token
            txTypeText = "TRT Transfer";
            snprintf(state.txnAuth.optionalWindow1Title, sizeof(state.txnAuth.optionalWindow1Title), "%s", "TRT Amount");
            if( 0 == formatAmount(state.txnAuth.optionalWindow1Text, sizeof(state.txnAuth.optionalWindow1Text), state.txnAuth.attachmentTempInt64Num2, 4))
                return R_FORMAT_AMOUNT_ERR;
        }
        else {
            // Window 1 is token ID
            if(addTokenID() == 0)
                return R_FORMAT_AMOUNT_ERR;
            // Amount not shown as there is no information about the number of decimal places
        }
        // Window 2 is the recipient
        addRecipientText();

        break;

    case 0x1202:
    case 0x1302:
        // Place token offer
        ptr = readFromBuffer(1 + 8*3); // version plus 3 longs
        if (ptr == 0)
            return R_TXN_SIZE_TOO_SMALL;
        ptr += 1; //version

        os_memmove(&(state.txnAuth.attachmentTempInt64Num1), ptr, sizeof(state.txnAuth.attachmentTempInt64Num1)); // assetID
        ptr += sizeof(state.txnAuth.attachmentTempInt64Num1);
        os_memmove(&(state.txnAuth.attachmentTempInt64Num2), ptr, sizeof(state.txnAuth.attachmentTempInt64Num2)); // quantity
        ptr += sizeof(state.txnAuth.attachmentTempInt64Num2);
        os_memmove(&(state.txnAuth.attachmentTempInt64Num3), ptr, sizeof(state.txnAuth.attachmentTempInt64Num3)); // price
        ptr += sizeof(state.txnAuth.attachmentTempInt64Num3);

        if(state.txnAuth.attachmentTempInt64Num1 == TRT_TOKEN){
            txTypeText = "Place TRT Offer";
            state.txnAuth.ux_flow = ux_flow_optionals;

            snprintf(state.txnAuth.optionalWindow1Title, sizeof(state.txnAuth.optionalWindow1Title), "%s", "TRT Amount");
            if( 0 == formatAmount(state.txnAuth.optionalWindow1Text, sizeof(state.txnAuth.optionalWindow1Text), state.txnAuth.attachmentTempInt64Num2, 4))
                return R_FORMAT_AMOUNT_ERR;
            
            snprintf(state.txnAuth.optionalWindow2Title, sizeof(state.txnAuth.optionalWindow2Title), "%s", "Price in BURST");
            if( 0 == formatAmount(state.txnAuth.optionalWindow2Text, sizeof(state.txnAuth.optionalWindow2Text), state.txnAuth.attachmentTempInt64Num3, 4))
                return R_FORMAT_AMOUNT_ERR;
            
        }
        else {
            txTypeText = "Place Offer";
            state.txnAuth.ux_flow = ux_flow_1optional;

            // Window 1 is token ID
            if(addTokenID() == 0)
                return R_FORMAT_AMOUNT_ERR;
        }

        break;
    
    case 0x1402:
    case 0x1502:
        txTypeText = "Cancel Offer";
        state.txnAuth.ux_flow = ux_flow_1optional;

        ptr = readFromBuffer(1 + 8); // version plus 1 long
        if (ptr == 0)
            return R_TXN_SIZE_TOO_SMALL;
        ptr += 1; //version
        os_memmove(&(state.txnAuth.attachmentTempInt64Num1), ptr, sizeof(state.txnAuth.attachmentTempInt64Num1)); // assetID
        ptr += sizeof(state.txnAuth.attachmentTempInt64Num1);

        // Window 1 is order ID
        snprintf(state.txnAuth.optionalWindow1Title, sizeof(state.txnAuth.optionalWindow1Title), "%s", "Order ID");
        if(0 == formatAmount(state.txnAuth.optionalWindow1Text, sizeof(state.txnAuth.optionalWindow1Text), state.txnAuth.attachmentTempInt64Num1, 0))
            return R_FORMAT_AMOUNT_ERR;

        break;
    case 0x1016:
        txTypeText = "Create Contract";
        state.txnAuth.ux_flow = ux_flow_1optional;
        // Read the contract name
        ptr = readFromBuffer(32); // version, length, and name with up to 30 chars
        if (ptr == 0)
            return R_TXN_SIZE_TOO_SMALL;
        ptr += 1; //version
        read_u8(&len, &ptr);
        snprintf(state.txnAuth.optionalWindow1Title, sizeof(state.txnAuth.optionalWindow1Title), "%s", "Contract name");
        snprintf(state.txnAuth.optionalWindow1Text, MIN(len+1, sizeof(state.txnAuth.optionalWindow1Text)), "%s", ptr);

        // Contract data should always come on P1_SIGN_CONTINUE calls, closed by P1_SIGN_FINISHED
        ret = R_SEND_MORE_BYTES;

        break;
    default:
        return R_UNSUPPORTED_APPENDAGE;
    }

    snprintf(state.txnAuth.txnTypeText, sizeof(state.txnAuth.txnTypeText), "%s", txTypeText);

    return ret;
}

//Parses a txn reference, by just skiping over the bytes :)
uint8_t parseReferencedTxn() {

    if (0 == readFromBuffer(sizeof(uint32_t) + 32))
        return R_SEND_MORE_BYTES;

    return R_SUCCESS;
}

// Adds bytes to the read buffer and to cx_hash
// @param newData: ptr to the data
// @param numBytes: number of bytes in the data
void addToReadBuffer(const uint8_t * const newData, const uint8_t numBytes) {
    cx_hash(&state.txnAuth.hashstate.header, 0, newData, numBytes, 0, 0);

    os_memcpy(state.txnAuth.readBuffer, newData, numBytes);
    state.txnAuth.readBufferReadOffset = 0;
    state.txnAuth.readBufferEndPos = numBytes;
}

//This is the function used to sign the hash of the txn
//@param txnSha256 -                     ptr to 32 byte sha256 of the txn
//@param destBuffer -                    ptr to 64 bytes of memory of where to write the buffer
//@param outException out -              ptr to where to write the exception if it happends
//@returns R_SUCCESS if success else the appropriate error code is returned

uint8_t signTxn(const uint8_t * const dataBuffer, const uint8_t dataLength, uint8_t * const destBuffer, uint16_t * const outException) {

    uint8_t sharedKey[32]; os_memset(sharedKey, 0, sizeof(sharedKey));
    uint8_t ret = 0;

    if (R_SUCCESS != (ret = burst_keys(dataBuffer, dataLength, NULL, NULL, sharedKey, outException))) {
        explicit_bzero(sharedKey, sizeof(sharedKey));
        return ret;
    }

    // Get the message hash
    uint8_t messageSha256[32];
    cx_hash(&state.txnAuth.hashstate.header, CX_LAST, NULL, 0, messageSha256, sizeof(messageSha256));

    sign_msg(sharedKey, messageSha256, destBuffer); //is a void function, no ret value to check against
    //os_memcpy(destBuffer+32, messageSha256, 32);
    
    //clear
    explicit_bzero(messageSha256, sizeof(messageSha256));
    explicit_bzero(sharedKey, sizeof(sharedKey));

    return R_SUCCESS;
}

//This is the main command handler, it checks that params are in the right size,
//and manages calls to initTxnAuthState(), signTxn(), addToReadBuffer()

//Since this is a callback function, and this handler manages state, it's this function's reposibility to call initTxnAuthState
//Every time we get some sort of an error
void authAndSignTxnHandlerHelper(const uint8_t p1, const uint8_t p2, const uint8_t * const dataBuffer, const uint8_t dataLength,
        uint8_t * const flags, uint8_t * const tx, const bool isLastCommandDifferent) {

    uint8_t ret = R_SUCCESS;

    if (P1_SIGN_FINISH == p1) {
        // Sign a transaction initiated before with P1_SIGN_INIT (possibly extended with P1_SIGN_CONTINUE) and authorized with P1_SIGN_AUTHORIZE
        if (isLastCommandDifferent || state.txnAuth.isClean) {
            initTxnAuthState();
            G_io_apdu_buffer[(*tx)++] = R_ERR_NO_INIT_CANT_CONTINUE;
            return;
        }

        if (!state.txnAuth.txnAuthorized) {
            initTxnAuthState();
            G_io_apdu_buffer[(*tx)++] = R_TXN_UNAUTHORIZED;
            return;
        }

        uint16_t exception = 0;

        uint8_t ret = signTxn(dataBuffer, dataLength, G_io_apdu_buffer + 1, &exception);

        // clear the state for a future call
        initTxnAuthState();

        if (R_SUCCESS == ret) {
            G_io_apdu_buffer[(*tx)++] = R_SUCCESS;
            *tx += 64;
        } else {
            G_io_apdu_buffer[(*tx)++] = ret;
        }
        return;
    }

    if ((p1 & P1_SIGN_INIT) == P1_SIGN_INIT) {
        // P1_SIGN_INIT
        initTxnAuthState();

        addToReadBuffer(dataBuffer, dataLength);
        // parse the transaction data, and setup screens
        ret = parseTxnData();
    }
    else if ((p1 & P1_SIGN_CONTINUE) == P1_SIGN_CONTINUE) {
        if (isLastCommandDifferent || state.txnAuth.isClean) {
            initTxnAuthState();
            G_io_apdu_buffer[(*tx)++] = R_ERR_NO_INIT_CANT_CONTINUE;
            return;
        }

        if (state.txnAuth.txnAuthorized) {
            initTxnAuthState();
            G_io_apdu_buffer[(*tx)++] = R_NOT_ALL_BYTES_USED;
            return;
        }

        // Add to hash and wait for more bytes (or the finish command)
        cx_hash(&state.txnAuth.hashstate.header, 0, dataBuffer, dataLength, 0, 0);
        ret = R_SEND_MORE_BYTES;
    }
    else {
        G_io_apdu_buffer[(*tx)++] = R_UNKNOWN_CMD_PARAM_ERR;
        return;
    }

    if ((ret == R_SUCCESS || ret == R_SEND_MORE_BYTES) && (p1 & P1_SIGN_AUTHORIZE) == P1_SIGN_AUTHORIZE) {
        // Will show windows to the user and ask for authorization
        showScreen();
        ret = R_SHOW_DISPLAY;
    }

    if (!((R_SEND_MORE_BYTES == ret) || (R_FINISHED == ret) || (R_SHOW_DISPLAY == ret))) {
        initTxnAuthState();
        G_io_apdu_buffer[(*tx)++] = ret;
        return;
    }

    if (R_SHOW_DISPLAY == ret) {
        *flags |= IO_ASYNCH_REPLY;
    }
    else {
        G_io_apdu_buffer[(*tx)++] = R_SUCCESS;
        G_io_apdu_buffer[(*tx)++] = ret;
    }
}

void authAndSignTxnHandler(const uint8_t p1, const uint8_t p2, const uint8_t * const dataBuffer, const uint8_t dataLength,
        uint8_t * const flags, uint8_t * const tx, const bool isLastCommandDifferent) {

    authAndSignTxnHandlerHelper(p1, p2, dataBuffer, dataLength, flags, tx, isLastCommandDifferent);

    if (0 == ((*flags) & IO_ASYNCH_REPLY)) {
        G_io_apdu_buffer[(*tx)++] = 0x90;
        G_io_apdu_buffer[(*tx)++] = 0x00;
    }
}
