

//This file holds most of the CONSTANTS used in the APP

#include <stdint.h>
#include <stdbool.h>

#include "config.h"

const uint8_t SUPPORTED_TXN_VERSION = 1;

const uint8_t BURST_SPECIAL_IDENTIFIER[] = {0x0a, 0x0b, 0x0c};
const uint8_t BURST_SPECIAL_IDENTIFIER_LEN = sizeof(BURST_SPECIAL_IDENTIFIER);

const uint8_t VERSION_FLAGS = 0x00;
