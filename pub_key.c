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


//Given a name and a reference to a GList pointer,
//sets the pointer to the key-pair identified by 
//key_val in the SYS_key_ring.
gboolean find_key_pair (char * key_val, RSA_Key_Pair** key_pair_ptr)
{
  GList *temp_ptr = SYS_key_ring;
  gboolean found = FALSE;
  if (!SYS_key_ring)
  {
    key_pair_ptr = NULL;
    return FALSE;
  }
  while (temp_ptr != NULL)
  {
    *key_pair_ptr = (RSA_Key_Pair*)(temp_ptr->data);
    purple_debug(PURPLE_DEBUG_INFO, "SySecure", "looking at key with id: %s.\n", (*key_pair_ptr)->id_name);
    if (!(strcmp((*key_pair_ptr)->id_name, key_val)))
    {
      purple_debug(PURPLE_DEBUG_INFO, "SySecure", "temp_key->id: %s equals name: %s.\n", (*key_pair_ptr)->id_name, key_val);
      found = TRUE;
      return;
    }
    purple_debug(PURPLE_DEBUG_INFO, "SySecure", "temp_key->id: %s does not equal name: %s.\n", (*key_pair_ptr)->id_name, key_val);
    
    temp_ptr = g_list_next(temp_ptr);
  }
  //If not found, need to clear the pointer.
  if (!found)
  {
    *key_pair_ptr = NULL;
    return FALSE;
  }
  else
    return TRUE;
}

gboolean add_public_key (char *pub_key_content, char* id)
{
  SECItem *key_data;
  CERTSubjectPublicKeyInfo *key_info = 0;
  SECKEYPublicKey *public_key;
  RSA_Key_Pair *key_pair = malloc(sizeof(RSA_Key_Pair));
  
  //purple_debug(PURPLE_DEBUG_INFO, "SySecure", "Inside add_public_key(%s, %s).", pub_key_content, id);
   //Get the public key from the data stream
   key_data = NSSBase64_DecodeBuffer(0, 0, pub_key_content, strlen(pub_key_content));
   key_info = SECKEY_DecodeDERSubjectPublicKeyInfo(key_data);
   public_key = SECKEY_ExtractPublicKey(key_info);

  //Copy the key and append it to the SYS_key_ring
  purple_debug(PURPLE_DEBUG_INFO, "SySecure", "Importing key for %s\n", id);
  key_pair->id_name = malloc(strlen(id)*sizeof(char));
  key_pair->trusted = TRUE;
  memset(key_pair->id_name, 0, strlen(id));
  memcpy(key_pair->id_name, id, strlen(id) + 1);
  key_pair->pub = public_key;
  SYS_key_ring = g_list_append(SYS_key_ring, key_pair);
  purple_debug(PURPLE_DEBUG_INFO, "SySecure", "New key created for: %s.\n",
            key_pair->id_name);
  
  return TRUE;
}

void generate_RSA_Key_Pair (RSA_Key_Pair** temp_key)
{
  PK11SlotInfo *slot = 0;
  PK11RSAGenParams rsaParams;
  rsaParams.keySizeInBits = 1024;
  rsaParams.pe = 65537L;
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
  char *key_string;
  RSA_Key_Pair *temp_key;
  //GList* temp_ptr;

  //set temp_ptr to the head of the key ring
  //temp_ptr = SYS_key_ring;
  
  //if key exists, temp_ptr will point to it
  //otherwise it will be NULL and the key will
  //have to be created.
  //find_key_pair(key_val, &temp_key);
  if (!find_key_pair(key_val, &temp_key))
  {
    purple_debug(PURPLE_DEBUG_INFO, "SySecure", "No key exists for %s...generating new one...\n", key_val);
    generate_RSA_Key_Pair(&temp_key);
    temp_key->id_name = malloc(strlen(key_val)*sizeof(char));
    temp_key->trusted = TRUE;
    memset(temp_key->id_name, 0, strlen(key_val));
    memcpy(temp_key->id_name, key_val, strlen(key_val) + 1);
    SYS_key_ring = g_list_append(SYS_key_ring, temp_key);
    purple_debug(PURPLE_DEBUG_INFO, "SySecure", "New key created for: %s.\n",
             temp_key->id_name);
  }
  else
  {
    purple_debug(PURPLE_DEBUG_INFO, "SySecure", "Key exists for %s.\n", key_val);
    generate_pubkeystring(temp_key->pub, &key_string);
    if (key_string != NULL)
    {
      purple_debug(PURPLE_DEBUG_INFO, "SySecure", "Key Value is %s\n", key_string);
      strip_returns(&key_string);
      purple_debug(PURPLE_DEBUG_INFO, "SySecure", "Key Value without returns %s\n", key_string);
    }
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

void generate_pubkeystring (SECKEYPublicKey* pub, char **temp_string)
{
  SECItem *key_item;
  if (!pub)
  {
    *temp_string = NULL;
    return;
  }
  key_item = SECKEY_EncodeDERSubjectPublicKeyInfo(pub);
  *temp_string = NSSBase64_EncodeItem(0, 0, 0, key_item);
  //SECItem_FreeItem(key_item, PR_TRUE);
}

void strip_returns (char **init_string)
{
  int char_count = 0;
  int init_length = strlen(*init_string);
  char ret_str[] = "\n\r";
  char* pre_string = malloc(strlen(*init_string)*sizeof(char));
  char* post_string = malloc(strlen(*init_string)*sizeof(char));
  memset(pre_string, 0, strlen(*init_string));
  memset(post_string, 0, strlen(*init_string));
  char_count = strcspn (*init_string, ret_str);
   while (char_count < strlen(*init_string))
   {
     memcpy(pre_string, *init_string, char_count);
     memcpy(post_string, *init_string + char_count + 1, strlen(*init_string) - char_count - 1);
     free(*init_string);
     *init_string = malloc(init_length*sizeof(char));
     memset(*init_string, 0, init_length);
     strcat(pre_string, post_string);
     strcat(*init_string, pre_string);
     char_count = strcspn (*init_string, ret_str);
     memset(pre_string, 0, strlen(pre_string));
     memset(post_string, 0, strlen(post_string));
   }
  free(pre_string);
  free(post_string);
}

gboolean pub_key_encrypt (char **enc_msg, char **orig_msg, char *key_val)
{
  //declare necessary variables
  int modulus_length;
  int unpadded_block_len;
  int num_blocks;
  int msg_block_length;
  int outlen;
  char* decrypted;
  char* padded_block;
  //GList* temp_ptr;
  RSA_Key_Pair *key_struct;
  SECKEYPublicKey *key;
  SECKEYPrivateKey *priv_key;
  SECStatus rv;

  //get the desired public key if this comes back as a NULL
  //then no key exists in the key ring for that key_val.
  //(Case must be handled)
  //find_key_pair(key_val, &key_struct);
  if (!find_key_pair(key_val, &key_struct))
  {
    purple_debug(PURPLE_DEBUG_INFO, "SySecure", "pub_key_encrypt: Key for %s not found\n", key_val);
    return FALSE;
  }

  //Get the key from the GList node
  key = key_struct->pub;
  priv_key = key_struct->priv;

  //Get the modulus length from the key
  modulus_length = SECKEY_PublicKeyStrength(key);
  unpadded_block_len = oaep_max_unpadded_len(modulus_length);

  //Determine the total number of blocks needed
  num_blocks = ((strlen(*orig_msg) - 1)/unpadded_block_len) + 1;

  padded_block = malloc(modulus_length);
  *enc_msg = malloc(modulus_length * num_blocks);
  decrypted = malloc(modulus_length * num_blocks);

  PK11_PubEncryptPKCS1(key, *enc_msg, *orig_msg, strlen(*orig_msg), 0);

  PK11_PrivDecryptPKCS1(priv_key, decrypted, &outlen, modulus_length, *enc_msg, modulus_length);


  purple_debug(PURPLE_DEBUG_INFO, "SySecure", "ENC_MSG: %s, ORIG_MSG: %s, DECRYPT: %s\n", *enc_msg, *orig_msg, decrypted);

  purple_debug(PURPLE_DEBUG_INFO, "SySecure", "Mod_length: %d Unpadded_Blk_Len: %d Num_Block: %d Orig_Msg: %s.\n", modulus_length,
                unpadded_block_len, num_blocks, *orig_msg);
  return TRUE;
}

gboolean wrap_symkey (PK11SymKey *key, SECItem **key_data, char* name)
{
  int rv = 0;
  SECItem *data;
  SECStatus s;
  RSA_Key_Pair *key_pair;
  //find_key_pair(name, &key_pair);
  if (!find_key_pair(name, &key_pair))
  {
    purple_debug(PURPLE_DEBUG_ERROR, "SySecure", "wrap_symkey: Key for %s not found.", name);
    return FALSE;
  }
  data = (SECItem *) malloc(sizeof(SECItem));
  data->len = SECKEY_PublicKeyStrength(key_pair->pub);
  data->data = malloc(data->len * sizeof(char));
  s = PK11_PubWrapSymKey(CKM_RSA_PKCS, key_pair->pub, key, data);
  *key_data = data;
  return TRUE;
}

gboolean unwrap_symkey (SECItem *wrappedKey, char* name, PK11SymKey **unwrapped_key)
{
  //GList *temp_ptr;
  RSA_Key_Pair *key_pair;
  //find_key_pair(name, &key_pair);
  if (!find_key_pair(name, &key_pair))
  {
    purple_debug(PURPLE_DEBUG_ERROR, "SySecure", "unwrap_symkey: Key pair for %s not found.", name);
    return FALSE;
  }
  if (key_pair->priv == NULL)
  {
    purple_debug(PURPLE_DEBUG_ERROR, "SySecure", "unwrap_symkey: Privat Key for %s not found.", name);
    return FALSE;
  }

  *unwrapped_key = PK11_PubUnwrapSymKey(key_pair->priv, wrappedKey, CKM_AES_CBC_PAD, CKA_ENCRYPT, 0);
  return TRUE;
}

PRBool compare_symkeys (PK11SymKey *key1, PK11SymKey *key2)
{
  SECItem *raw_key1 = 0;
  SECItem *raw_key2 = 0;
  raw_key1 = PK11_GetKeyData(key1);
  raw_key2 = PK11_GetKeyData(key2);
  return SECITEM_ItemsAreEqual(raw_key1, raw_key2);
}

#endif //PUB_KEY_C
