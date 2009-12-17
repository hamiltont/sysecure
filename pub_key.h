#ifndef PURPLE_PLUGINS
#  define PURPLE_PLUGINS
#endif

#include <glib.h>

#ifndef G_GNUC_NULL_TERMINATED
#  if __GNUC__ >= 4
#    define G_GNUC_NULL_TERMINATED __attribute__((__sentinel__))
#  else
#    define G_GNUC_NULL_TERMINATED
#  endif /* __GNUC__ >= 4 */
#endif /* G_GNUC_NULL_TERMINATED */

#ifndef PUB_KEY_H
#define PUB_KEY_H

//LIBPURPLE Includes
#include "plugin.h"
#include "debug.h"
#include "request.h"

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
  gboolean trusted;
} RSA_Key_Pair;

gboolean add_public_key (const char *pub_key_content, const char* id);

gboolean find_key_pair (const char * key_val, RSA_Key_Pair** key_pair_ptr);

void init_pub_key (char* name);

gboolean nss_init (void);

void strip_returns (char **init_string);

gboolean pub_key_encrypt (char **enc_msg, char **orig_msg, char *key_val);

gboolean wrap_symkey (PK11SymKey *key, SECItem **key_data, const char* name);

gboolean unwrap_symkey (SECItem *wrappedKey, char* name, PK11SymKey **unwrapped_key);

PRBool compare_symkeys (PK11SymKey *key1, PK11SymKey *key2);

#endif //PUB_KEY_H
