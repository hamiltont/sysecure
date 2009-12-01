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

//SYS_key_ring holds all the public keys collected so far
//INCLUDING the user's.
GList* SYS_key_ring = NULL;

//Given a name, this returns a public key
void find_pub_key (char * key_val, GList** temp_ptr)
{
  *temp_ptr = SYS_key_ring;
  RSA_Key_Pair* temp_key;
  gboolean found = FALSE;
  if (!SYS_key_ring)
  {
    *temp_ptr = NULL;
    return;
  }
  while (*temp_ptr != NULL)
  {
    temp_key = (RSA_Key_Pair*)((*temp_ptr)->data);
    purple_debug(PURPLE_DEBUG_INFO, "SySecure", "looking at key with id: %s.\n", temp_key->id_name);
    if (!(strcmp(temp_key->id_name, key_val)))
    {
      purple_debug(PURPLE_DEBUG_INFO, "SySecure", "temp_key->id: %s equals name: %s.\n", temp_key->id_name, key_val);
      found = TRUE;
      return;
      //return (RSA_Key_Pair*)(temp_ptr->data);
    }
    purple_debug(PURPLE_DEBUG_INFO, "SySecure", "temp_key->id: %s does not equal name: %s.\n", temp_key->id_name, key_val);
    
    *temp_ptr = g_list_next(*temp_ptr);
  }
  //If not found, need to clear the pointer.
  if (!found)
  {
    *temp_ptr = NULL;
  }
}

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

void init_pub_key (char* key_val)
{
  RSA_Key_Pair *temp_key;
  GList* temp_ptr;

  //set temp_ptr to the head of the key ring
  temp_ptr = SYS_key_ring;
  
  //if key exists, temp_ptr will point to it
  //otherwise it will be NULL and the key will
  //have to be created.
  find_pub_key(key_val, &temp_ptr);
  if (temp_ptr == NULL)
  {
    purple_debug(PURPLE_DEBUG_INFO, "SySecure", "No key exists for %s...generating new one...\n", key_val);
    generate_RSA_Key_Pair(&temp_key);
    temp_key->id_name = malloc(strlen(key_val)*sizeof(char));
    memset(temp_key->id_name, 0, strlen(key_val));
    memcpy(temp_key->id_name, key_val, strlen(key_val) + 1);
    SYS_key_ring = g_list_append(SYS_key_ring, temp_key);
    purple_debug(PURPLE_DEBUG_INFO, "SySecure", "New key created for: %s.\n",
             temp_key->id_name);
  }
  else
  {
    purple_debug(PURPLE_DEBUG_INFO, "SySecure", "Key exists for %s.\n", key_val);
  }
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
