/**
 * @file pub_key.c
 * @brief Allows public key encryption, decryption, and key generation. Also 
 *        provides symmetric wrapping.   
 *
 *
 * References:
 *  1) William Tompkins, "Pidgin-Encryption: rsa_nss.c," 
 *     (http://pidgin-encrypt.sourceforge.net/install.php)
 * 
 */

#ifndef PUB_KEY_C
#define PUB_KEY_C

//Internal Includes
#include "pub_key.h"

#include "globals.h"

/**
 * Holds all the key pairs collected so far (including the local user's). 
 * This is a list of RSA_Key_Pair structs
 *
 * @see RSA_Key_Pair
 */
static GList* key_ring = NULL;


/**
 * Finds a RSA_Key_Pair that has the given id. 
 *
 * @param key_val Currently this is the value of the id used in the 
 *                RSA_Key_Pair->id_name, which is set to the username. Note that  
 *                this would not work for two identical usernames on different 
 *                accounts. This is setup this way in case the internal 
 *                structure is changed to a hash. 
 * @param key_pair_ptr An out parameter. Will be set to the appropriate 
 *                     RSA_Key_Pair
 *
 * @returns TRUE if the passed key_val was found and key_pair_ptr was set, 
 *          FALSE otherwise
 */
gboolean 
find_key_pair (const char * key_val, RSA_Key_Pair** key_pair_ptr)
{
  // Declare vars
  GList *temp_ptr;
  
  // Is it even worth our time?
  if (!key_ring)
  {
    key_pair_ptr = NULL;
    return FALSE;
  }
  
  // Init vars
  temp_ptr = key_ring;
  
  // Look for the correct RSA
  while (temp_ptr != NULL)
  {
    *key_pair_ptr = (RSA_Key_Pair*)(temp_ptr->data);
    
    purple_debug(PURPLE_DEBUG_INFO,
                 PLUGIN_ID,
                 "looking at key with id: %s\n",
                 (*key_pair_ptr)->id_name);
                 
    if (strcmp((*key_pair_ptr)->id_name, key_val) == 0)
    {
      purple_debug(PURPLE_DEBUG_INFO,
                   PLUGIN_ID,
                   "temp_key->id: %s equals name: %s.\n",
                   (*key_pair_ptr)->id_name, 
                   key_val);
      return TRUE;
    }
    purple_debug(PURPLE_DEBUG_INFO,
                 PLUGIN_ID,
                 "temp_key->id: %s does not equal name: %s.\n", 
                 (*key_pair_ptr)->id_name, 
                 key_val);
    
    temp_ptr = g_list_next(temp_ptr);
  }
  
  // If not found, clear the pointer to make sure they do not use the wrong one
  *key_pair_ptr = NULL;
  
  return FALSE;
}

/**
 * Accepts the content from a public key announcement message, converts it into
 * a RSA_Key_Pair and stores that (using the passed id as the RSA_Key_Pair id)
 *
 * @param pub_key_content The public key content, as it was sent in the IM. This
 *                        content should be what is enclosed in the tags, and 
 *                        should not include the enclosing tags
 * @param id The id used to identify the created RSA_Key_Pair at a later time. 
 *           For now, this should be the name of the remote user
 *
 * @returns TRUE :) You should be sure to check this to make sure no random
 *          disk errors occurred
 *
 * @todo Figure out this return value, or throw it away
 */
gboolean 
add_public_key (const char *pub_key_content, const char* id)
{
  SECItem *key_data;                // temp item to pass around raw data in NSS
  CERTSubjectPublicKeyInfo *key_info;   // temporary certificate. More on this below
  SECKEYPublicKey *public_key;          // the actual key
  RSA_Key_Pair *key_pair = g_malloc(sizeof(RSA_Key_Pair)); // the struct we are creating
  RSA_Key_Pair *key_check;  // var used only as a parameter placeholder

  if (find_key_pair(id, &key_check))
  {
    purple_debug(PURPLE_DEBUG_INFO,
                 PLUGIN_ID, 
                 "Key exists for %s. Destroying old public key.\n", 
                 id);
                 
    // Destroy old key to make room for the new
    // Note: This is not really safe. We should instead wait till the new key
    //       is ready to be inserted before we delete this one
    key_ring = g_list_remove(key_ring,
                             key_check);
    g_free(key_check);
                             
    /**
      RSA_Key_Pair *debug_key;
      char name[] = "nataliarevenan";
      find_key_pair(name, &debug_key);
      if (SECITEM_ItemsAreEqual(SECKEY_EncodeDERSubjectPublicKeyInfo(key_check->pub), SECKEY_EncodeDERSubjectPublicKeyInfo(debug_key->pub)))
        purple_debug(PURPLE_DEBUG_INFO, "SySecure", "And it was decoded properly %s's key matches %s's key!\n", key_check->id_name, debug_key->id_name);
      else
        purple_debug(PURPLE_DEBUG_ERROR, "SySecure", "It was decoded improperly!.\n");
    */
  }
  
  // Get the public key from the data stream
  key_data = NSSBase64_DecodeBuffer(0, 0, pub_key_content, strlen(pub_key_content));
   
  // NSS assumes that a public key won't be used w/o a certificate to validate
  // the key to ID binding. Because we are creating a key from raw data, NSS
  // wraps it in a temporary certificate, and returns that to us. We promptly
  // throw it away :) 
  key_info = SECKEY_DecodeDERSubjectPublicKeyInfo(key_data);
  public_key = SECKEY_ExtractPublicKey(key_info);

  // Copy the key and append it to the key_ring
  purple_debug(PURPLE_DEBUG_INFO,
               PLUGIN_ID, 
               "Importing key for %s\n", 
               id);
  
  // Create and set id_name
  key_pair->id_name = g_malloc0((strlen(id) + 1) * sizeof(char));
  memcpy(key_pair->id_name, id, strlen(id));
  
  // Auto trust
  key_pair->trusted = TRUE;
  
  // Set the public key (we should only have _our_ private key)
  key_pair->pub = public_key;
  
  // Add the new key
  key_ring = g_list_append(key_ring, key_pair);
  
  purple_debug(PURPLE_DEBUG_INFO,
               PLUGIN_ID, 
               "New key created for: %s.\n",
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

/**
 *
 * @todo make this take the PurpleAccount (rather than some random ass char*).
 *       That way we can easily change the mapping later to _anything_ in the 
 *       account, without having to fix all the external dependencies
 */
void init_pub_key (char* key_val)
{
  char *key_string;
  RSA_Key_Pair *temp_key;
  //GList* temp_ptr;

  //set temp_ptr to the head of the key ring
  //temp_ptr = key_ring;
  
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
    key_ring = g_list_append(key_ring, temp_key);
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

gboolean wrap_symkey (PK11SymKey *key, SECItem **key_data, const char* name)
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

  *unwrapped_key = PK11_PubUnwrapSymKey(key_pair->priv, wrappedKey, CKM_AES_CBC_PAD, CKA_UNWRAP, 16);
  
  if (*unwrapped_key == NULL)
  {
    purple_debug(PURPLE_DEBUG_ERROR,
                 PLUGIN_ID,
                 "Unable to unwrap symmetric key\n");
    return FALSE;
  }
  
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
