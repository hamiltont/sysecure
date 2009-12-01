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

typedef struct {
  char* id_name;
  SECKEYPrivateKey* priv;
  SECKEYPublicKey* pub;
} RSA_Key_Pair;

void find_pub_key (char * key_val, GList** temp_ptr);

void generate_RSA_Key_Pair (RSA_Key_Pair** temp_key);

void init_pub_key (char* name);

gboolean nss_init (void);

#endif //PUB_KEY_H
