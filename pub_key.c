#ifndef PUB_KEY_C
#define PUB_KEY_C

/*
*References:
*  1) William Tompkins, "Pidgin-Encryption: rsa_nss.c," 
*     (http://pidgin-encrypt.sourceforge.net/install.php)
*
*/

//Internal Includes
#include "pub_key.h"

GList* SYS_key_ring = NULL;

void generate_RSA_Key_Pair (RSA_Key_Pair** temp_key)
{
  PK11SlotInfo *slot = 0;
  PK11RSAGenParams rsaParams;
  rsaParams.keySizeInBits = 1024;
  rsaParams.pe = 65537;
  *temp_key = malloc (sizeof(RSA_Key_Pair));
  slot = PK11_GetInternalKeySlot();

  (*temp_key)->priv = PK11_GenerateKeyPair(slot, CKM_RSA_PKCS_KEY_PAIR_GEN, &rsaParams,
               &((*temp_key)->pub), PR_FALSE, PR_FALSE, 0);

  if ((*temp_key)->priv != NULL)
    purple_debug(PURPLE_DEBUG_INFO, "SySecure", "generate_RSA_Key_Pair: priv Key Exists!");
  else
    purple_debug(PURPLE_DEBUG_INFO, "SySecure", "generate_RSA_Key_Pair: priv Key DOES NOT Exist!");
  return;
}

void init_pub_key (char* name)
{
  RSA_Key_Pair *temp_key;
  if (!SYS_key_ring)
  {
    generate_RSA_Key_Pair(&temp_key);
    temp_key->id_name = malloc(strlen(name)*sizeof(char));
    memset(temp_key->id_name, 0, strlen(name));
    memcpy(temp_key->id_name, name, strlen(name) + 1);
    SYS_key_ring = g_list_append(SYS_key_ring, temp_key);
    purple_debug(PURPLE_DEBUG_INFO, "SySecure", "New key created for: %s.\n",
             temp_key->id_name);
    return;
  }
  temp_key = (RSA_Key_Pair*)SYS_key_ring->data;
  if (temp_key->pub != NULL)
    purple_debug(PURPLE_DEBUG_INFO, "SySecure", "Key exists for : %s.\n", temp_key->id_name);
  else
    purple_debug(PURPLE_DEBUG_INFO, "SySecure", "Key does not exist.");
}

//Reference 1: Used REF 1 as a basis for nss_init()

gboolean nss_init (void) 
{
  //gboolean nss_loaded = FALSE;
  PurplePlugin *plugin = purple_plugins_find_with_name("NSS");
  if (plugin)
  {
    purple_debug(PURPLE_DEBUG_INFO, "SySecure", "NSS is initialized.\n");
    return TRUE;
  }
  else
  {
    purple_debug(PURPLE_DEBUG_ERROR, "SySecure", "NSS is not intitialized.\n");
    return FALSE;
  }
}

#endif //PUB_KEY_C
