#ifndef SS_GLOBALS_H
#define SS_GLOBALS_H

#include <glib.h>

#define PLUGIN_ID "sysecure"
#define PLUGIN_AUTHOR "Hamilton Turner <hamiltont@gmail.com>, \
                       Jason Cody <jason.r.cody@vanderbilt.edu>"
#define PLUGIN_SUMMARY "summary"
#define PLUGIN_DESC "desc"
#define PLUGIN_VERSION "0.1"

/**
 * Used to hold the encryption info for a single PurpleConversation 
 */
struct _EncryptionInfo {
  /** Flag for encryption or plain transmission */
  gboolean is_encrypted;
  
  // TODO - Move all struct stuff into it's own file, and access
  // the struct using getter methods to hide the allocation, etc

};
typedef struct _EncryptionInfo EncryptionInfo;


EncryptionInfo * init_encryption_info();

void uninit_encryption_info(EncryptionInfo *e_info);

#endif
