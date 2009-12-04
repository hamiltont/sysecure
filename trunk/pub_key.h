#ifndef PUB_KEY_H
#define PUB_KEY_H

//LIBPURPLE Includes
#include "plugin.h"
#include "debug.h"

//GLIB Includes
#include "glib.h"

//NSS includes:
#include "nss.h"
#include "nspr.h"
#include <ssl.h>
#include <secmod.h>
#include <pk11func.h>
#include <pk11pub.h>
#include <keyhi.h>
#include <nssb64.h>
#include <prtypes.h>

//This file comes directly from the Pidgin_Encryption Plugin
//and includes some useful functions.
#include "nss_oaep.h"

typedef struct {
  char* id_name;
  SECKEYPrivateKey* priv;
  SECKEYPublicKey* pub;
} RSA_Key_Pair;

void find_key_pair (char * key_val, GList** temp_ptr);

void generate_RSA_Key_Pair (RSA_Key_Pair** temp_key);

void init_pub_key (char* name);

gboolean nss_init (void);

void generate_pubkeystring (SECKEYPublicKey* pub, char **temp_string);

void strip_returns (char **init_string);

gboolean pub_key_encrypt (char **enc_msg, char **orig_msg, char *key_val);

gboolean wrap_symkey (PK11SymKey *key, SECItem **key_data, char* name);

gboolean unwrap_symkey (SECItem *wrappedKey, char* name, PK11SymKey **unwrapped_key);

PRBool compare_symkeys (PK11SymKey *key1, PK11SymKey *key2);

#endif //PUB_KEY_H
