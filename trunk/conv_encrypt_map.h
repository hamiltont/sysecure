#ifndef CONV_ENCRYPT_MAP_H
#define CONV_ENCRYPT_MAP

// Needed for PurpleConversation
#include <conversation.h>

// Needed for EncryptionInfo
#include "globals.h"

EncryptionInfo *get_encryption_info(PurpleConversation *conv);

void enable_encryption(PurpleConversation *conv);

void disable_encryption(PurpleConversation *conv);

void debug_conv_encrypt_map();

void init_conv_encryption_map();

void uninit_conv_encryption_map();

#endif
