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

#if defined(TARGET_NANOS)
    unsigned int makeTextGoAround_preprocessor(bagl_element_t * const element);
#endif

uint64_t publicKeyToId(const uint8_t * const publicKey);
uint8_t burstKeys(const uint8_t * const dataBuffer, const uint8_t dataLength, uint8_t * const privKeyOut, uint8_t * const publicKeyOut,
    uint8_t * const sharedKeyOut, uint16_t * const exceptionOut);

void signMsg(uint8_t * const sharedKey, const uint8_t * const msgSha256, uint8_t * const sig);

void ui_idle();
void ui_signing();
bool check_canary();

uint8_t getSharedEncryptionKey(const uint8_t * const dataBuffer, const uint8_t dataLength, const uint8_t* const targetPublicKey, 
                                const uint8_t * const nonce, uint16_t * const exceptionOut, uint8_t * const aesKeyOut);


//This is the state object that authAndSignTxn uses
typedef struct {

	bool txnAuthorized;                                    //This most important bool, means the user confirmed the txn content via the dialog and we can sign the current TXN

    uint8_t readBuffer[512];                               //This is where unparsed temp buffer data is kept, since we do streamed parsing we have to have it here
    uint16_t readBufferEndPos;                             //Index of the last byte in readBuffer
    uint16_t readBufferReadOffset;                         //Index of the first byte in readBuffer
    uint16_t numBytesRead;                                 //The total number of bytes parsed up until now

    bool isClean;                                          //If the state was just initilized

    cx_sha256_t hashstate;                                 //The state of the hash for the txn buffer

    uint16_t txnTypeAndSubType;                            //What it says it is

    uint64_t recipientId;                                  //the recipient address ID
    uint64_t amount;                                       //the amount to be sent in the txn, note that every chain parses this number differently, it dives this number by some 10^X
    uint64_t fee;                                          //What it says it is

   	int32_t attachmentTempInt32Num1, attachmentTempInt32Num2;    //Different attachments parse in different ways, they all need space in state, so this is how it's defined
   	int64_t attachmentTempInt64Num1, attachmentTempInt64Num2, attachmentTempInt64Num3; 

    char feeText[21];               //9,223,372,036,854,775,807 is the biggest number you can hold in uint64 + the dot + null terminator means the longest text is 20
    char txnTypeText[60];           //Aproximation of size
    char optionalWindow1Title[20];  //The longest string is price per (some chain name  here)
    char optionalWindow1Text[31];   //same as fee text + name of the chain + space
    char optionalWindow2Title[20];  //The longest string is price per (some chain name  here)
    char optionalWindow2Text[31];   //MAX(Burst arddress = 27, feeText + chainName)
    char appendagesTitle[20];       //0x and then 8 chars
    char appendagesText[31];        //0x and then 8 chars
    const ux_flow_step_t* const * ux_flow;        //The ux flow to be used

} authTxn_t;

//State for the encryptDecrypt handler
typedef struct {
    uint8_t mode;                           //Modes are described in the .C file
    uint8_t cbc[16];                        //Something to do with AES state
    unsigned int ctx[(4 * 4 * 15 + 4) / sizeof(unsigned int)];      //This is the encryption key, unsigned int is the type it uses aes_uint *
} encyptionState_t;

//This is the union states type, the actual object is defined in burst.c
typedef union {
    encyptionState_t encryption;
    authTxn_t txnAuth;
} states_t;

//declared in burst.c
extern states_t state;

// These are the offsets of various parts of a request APDU packet. INS
// identifies the requested command (see above), and P1 and P2 are parameters
// to the command.
#define CLA          0x80
#define OFFSET_CLA   0x00
#define OFFSET_INS   0x01
#define OFFSET_P1    0x02
#define OFFSET_P2    0x03
#define OFFSET_LC    0x04
#define OFFSET_CDATA 0x05
