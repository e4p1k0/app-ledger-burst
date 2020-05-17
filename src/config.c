

//This file holds most of the CONSTANTS used in the APP
//TXN_TYPES is configured in txnTypesList.c, it's there cuz the list is auto-generated from some other java file in order to sync between projects

#include <stdint.h>
#include <stdbool.h>

#include "config.h"

const uint8_t SUPPORTED_TXN_VERSION = 1;

const uint8_t BURST_SPECIAL_IDENTIFIER[] = {0xba, 0xbb, 0xbc};
const uint8_t BURST_SPECIAL_IDENTIFIER_LEN = sizeof(BURST_SPECIAL_IDENTIFIER);

const uint8_t VERSION_FLAGS = 0x00;
