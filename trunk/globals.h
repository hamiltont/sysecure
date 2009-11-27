#ifndef SS_GLOBALS_H
#define SS_GLOBALS_H

/**
 * Used to hold the encryption info for a single conversation 
 */
// TODO - Move all struct stuff into it's own file, and access
// the struct using getter methods to hide the allocation, etc
struct _EncryptionInfo {
  gboolean is_encrypted;
};
typedef struct _EncryptionInfo EncryptionInfo;


EncryptionInfo * init_encryption_info();

void uninit_encryption_info();

#endif
