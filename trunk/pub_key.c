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
  char* lowercase_key_val;
  int current;
  
  // Is it even worth our time?
  if (!key_ring)
  {
    key_pair_ptr = NULL;
    return FALSE;
  }
  
  // Init vars
  temp_ptr = key_ring;
  lowercase_key_val = g_malloc0((strlen(key_val) + 1) * sizeof(char)); // Plus null terminating char
  
  // Convert key_val to lowercase
  // This avoids some problems, but should probably be changed in the long run
  // Note that libpurple seems to do this internally, so perhaps it is ok? 
  // Answer: There is a purple_normalize() function that works differently for each
  // protocol. We should find and implement this! 
  strcpy(lowercase_key_val, key_val);
  current = 0;
  while (lowercase_key_val[current])
    lowercase_key_val[current] = tolower(lowercase_key_val[current++]);
  
  // Look for the correct RSA
  while (temp_ptr != NULL)
  {
    *key_pair_ptr = (RSA_Key_Pair*)(temp_ptr->data);
    
    purple_debug(PURPLE_DEBUG_INFO,
                 PLUGIN_ID,
                 "looking at key with id: %s\n",
                 (*key_pair_ptr)->id_name);
                 
    if (strcmp((*key_pair_ptr)->id_name, lowercase_key_val) == 0)
    {
      purple_debug(PURPLE_DEBUG_INFO,
                   PLUGIN_ID,
                   "temp_key->id: %s equals name: %s.\n",
                   (*key_pair_ptr)->id_name, 
                   lowercase_key_val);
      
      // Free what we have allocated
      g_free(lowercase_key_val);
      
      return TRUE;
    }
    purple_debug(PURPLE_DEBUG_INFO,
                 PLUGIN_ID,
                 "temp_key->id: %s does not equal name: %s.\n", 
                 (*key_pair_ptr)->id_name, 
                 lowercase_key_val);
    
    temp_ptr = g_list_next(temp_ptr);
  }
  
  // If not found, clear the pointer to make sure they do not use the wrong one
  *key_pair_ptr = NULL;
  
  // Free the memory we used
  g_free(lowercase_key_val);
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
  
  RSA_Key_Pair *temp;
  int current; // Used as a loop counter later

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
    
    if (find_key_pair(id,&temp))
    {
      purple_debug(PURPLE_DEBUG_ERROR,
                   PLUGIN_ID,
                   "Unable to delete old public key (unknown error). Unable to continue\n");
      
      // TODO - change this return value later if we can figure out what the 
      //        ret val of this function is supposed to indicate
      
      // TODO - print out a fat error message
      return TRUE;
    }
                                 
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
  strcat(key_pair->id_name, id);
  
  // Convert id_name to lowercase
  // This avoids some problems, but should probably be changed in the long run
  // Note that libpurple seems to do this internally, so perhaps it is ok?
  // Answer: There is a purple_normalize() function that works differently for each
  // protocol. We should find and implement this! 
  current = 0;
  while (key_pair->id_name[current])
    key_pair->id_name[current] = tolower(key_pair->id_name[current++]);
  
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

/**
 * Generates a new RSA Key Pair. Only used for the local client
 *
 * @param key The out parameter where the generated RSA_Key_Pair will be stored
 * 
 * @returns TRUE if the key was generated and stored in key, FALSE otherwise
 */
static gboolean
generate_RSA_Key_Pair (RSA_Key_Pair** key)
{
  PK11SlotInfo *slot;
  PK11RSAGenParams rsaParams;
  
  // Standard RSA Ky size
  rsaParams.keySizeInBits = 1024;
  
  // Standard RSA public key exponent
  rsaParams.pe = 65537L;

  // Make room for the key
  *key = g_malloc0(sizeof(RSA_Key_Pair));

  // TODO - change to get best slot, not internal slot
  slot = PK11_GetInternalKeySlot();

  // Generate key. Strangely, you pass in the public key pointer to get set, and
  // it returns the private key pointer
  (*key)->priv = PK11_GenerateKeyPair(slot, 
                                      CKM_RSA_PKCS_KEY_PAIR_GEN, 
                                      &rsaParams,
                                      &((*key)->pub),  
                                      PR_FALSE, 
                                      PR_FALSE, 
                                      0);

  if ((*key)->priv == NULL)
  {   
    purple_debug(PURPLE_DEBUG_ERROR,
                 PLUGIN_ID, 
                 "Error when generating private key, unable to continue!\n");
                 
    g_free(*key);
    return FALSE;
  }
  
  return TRUE;
}

/**
 * Makes sure there is a public / private key for the current user. If not, 
 * this generates the key pair. This method should only be passed an id of the 
 * local user. If you are looking for the key pair associated with a remote 
 * person, then you should use find_public_key()
 *
 * @param key_val The same key_val that is used in the find_key_pair function. 
 *                As of writing, this is the id of the person we are looking for
 *
 * @todo make this take the PurpleAccount (rather than some random ass char*).
 *       That way we can easily change the mapping later to _anything_ in the 
 *       account, without having to fix all the external dependencies
 * @todo Should probably ensure that the ID passed in is the ID of the local 
 *       user only, and no other ID. Otherwise, this function would happily 
 *       generate a key pair for a remote screen name ;)
 */
void 
init_pub_key (char* key_val)
{
  char *key_string;  // Used for converting an existing public key into ascii
  RSA_Key_Pair *temp_key;
  gboolean success;       // used to keep track of success in various places

  // Does a key pair exist for us
  if (!find_key_pair(key_val, &temp_key))
  {
    purple_debug(PURPLE_DEBUG_INFO,
                 PLUGIN_ID,
                 "No key exists for %s...generating new one...\n",
                 key_val);
                 
    success = generate_RSA_Key_Pair(&temp_key);
    
    // Make sure we could create the key
    if (success == FALSE)
    {
      purple_debug(PURPLE_DEBUG_ERROR,
                   PLUGIN_ID,
                   "Unable to generate a key pair! Unable to continue initializing public key\n");
      return;
    }
    
    // Set the key values (pub an priv key are set for us)
    temp_key->id_name = g_malloc0((strlen(key_val) + 1) * sizeof(char));
    strcpy(temp_key->id_name, key_val); 
    temp_key->trusted = TRUE;
    
    // Add to our key ring
    key_ring = g_list_append(key_ring, temp_key);
    purple_debug(PURPLE_DEBUG_INFO,
                 PLUGIN_ID, 
                 "New key created for: %s.\n",
                 temp_key->id_name);
                 
    return;
  }
  
  purple_debug(PURPLE_DEBUG_INFO,
               PLUGIN_ID,
               "Public Key exists for %s.\n", 
               key_val);
  
  // Store our public key into a string for debugging            
  generate_pubkeystring(temp_key->pub, &key_string);
  
  purple_debug(PURPLE_DEBUG_INFO,
               PLUGIN_ID, 
               "Key Value is \n%s\n", 
               key_string);
  
}

//Reference 1: Used REF 1 as a basis for nss_init()
/**
 * Checks to see if the NSS Database is running or not. Currently does nothing
 * but return FALSE if it is not running. 
 *
 * @param void WTF??? I have no idea what this is for :)
 *
 * @return TRUE if NSS is primed and ready, FALSE otherwise
 */
gboolean 
nss_init (void) 
{
  PurplePlugin *plugin = purple_plugins_find_with_name("NSS");
  if (plugin)
  {
    purple_debug(PURPLE_DEBUG_INFO,
                 PLUGIN_ID,
                 "NSS is initialized. Continuing...\n");
    return TRUE;
  }
  else
  {
    purple_debug(PURPLE_DEBUG_ERROR,
                 PLUGIN_ID,
                 "NSS is not intitialized. SySecure will likely not load\n");
    return FALSE;
  }
}

/**
 * Given a public key item, turns it into a string that can be printed nicely. 
 * There is likely a NSS call to do something similar, but no one can find it. 
 * This call does not check for a 
 *
 * @param pub The public key to be converted to a printable format. This is 
 *            assumed to be a correct key, alloced and all.
 * @param key_string An out parameter. The armored public key data will be 
 *                   stored here. This will never be NULL after returning, it
 *                   will be set to a blank string if an error occurs.
 */
void 
generate_pubkeystring (SECKEYPublicKey* pub, char **key_string)
{
  SECItem *key_item;
  if (!pub)
  {
    // Only a null term character
    *key_string = g_malloc0(sizeof(char));
    return;
  }
  
  key_item = SECKEY_EncodeDERSubjectPublicKeyInfo(pub);
  *key_string = NSSBase64_EncodeItem(0, 0, 0, key_item);
  
  if (*key_string == NULL)
    *key_string = g_malloc0(sizeof(char));
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

/**
 * Wraps a symmetric key in a public key. Only the person with the appropriate
 * private key can then unwrap the symmetric key. 
 *
 * @param key The symmetric key to be wrapped
 * @param key_data An out parameter. Contains the wrapped key data upon 
 *                 successful completion. This data is _NOT_ ascii armored, and
 *                 should be armored before sending via IM
 * @param name The key_val that is used to find the public key. Currently this 
 *             is the name of the remote person
 *
 * @return TRUE if the public key was found, the symmetric key was wrapped, and
 *         the data was stored to key_data. FALSE otherwise. 
 *
 * @todo Change this to take the Public key, and move the responsibility for 
 *       finding that to the caller, or use some more obvious input than a 
 *       random char* called name
 */
gboolean 
wrap_symkey (PK11SymKey *key, SECItem **key_data, const char* name)
{
  int rv = 0;
  SECItem *data;
  SECStatus s;
  RSA_Key_Pair *key_pair;
  
  // Do we have the key?
  if (find_key_pair(name, &key_pair) == FALSE)
  {
    purple_debug(PURPLE_DEBUG_ERROR, 
                 PLUGIN_ID, 
                 "Unable to find a public key for %s. Unable to continue wrapping the symmetric key.\n", 
                 name);
                 
    return FALSE;
  }
  
  data = (SECItem *) g_malloc0(sizeof(SECItem));
  data->len = SECKEY_PublicKeyStrength(key_pair->pub);
  data->data = malloc(data->len * sizeof(char));
  s = PK11_PubWrapSymKey(CKM_RSA_PKCS, key_pair->pub, key, data);
  *key_data = data;
  return TRUE;
}

/**
 * Unwraps a symmetric key with the local private key 
 *
 * @param wrappedkey The symmetric key to be unwrapped
 * @param unwrapped_key An out parameter. Contains the wrapped key data upon 
 *                      successful completion. This data is _NOT_ ascii armored,
 *                      and should be armored before sending via IM
 * @param name The key_val that is used to find the public key. Currently this 
 *             is the name of the local account that we want to use the priv key
 *
 * @return TRUE if the private key was found, the symmetric key was unwrapped, 
 *         the data was stored to unwrapped_key. FALSE otherwise. 
 *
 * @todo Change this to take the Private key, and move the responsibility for 
 *       finding that to the caller, or use some more obvious input than a 
 *       random char* called name
 */
gboolean 
unwrap_symkey (SECItem *wrappedKey, char* name, PK11SymKey **unwrapped_key)
{
  RSA_Key_Pair *key_pair;
  
  // Do we have the key? 
  if (!find_key_pair(name, &key_pair))
  {
    purple_debug(PURPLE_DEBUG_ERROR,
                 PLUGIN_ID, 
                 "unwrap_symkey: Key pair for %s not found.",
                 name);
    return FALSE;
  }
  
  // Do we have the private key? 
  if (key_pair->priv == NULL)
  {
    purple_debug(PURPLE_DEBUG_ERROR,
                 PLUGIN_ID, 
                 "unwrap_symkey: Private Key for %s not found.", 
                 name);
    return FALSE;
  }

  *unwrapped_key = PK11_PubUnwrapSymKey(key_pair->priv,
                                        wrappedKey, 
                                        CKM_AES_CBC_PAD, 
                                        CKA_UNWRAP, 
                                        16);            // TODO key size should probs not be fixed at 16
  
  if (*unwrapped_key == NULL)
  {
    purple_debug(PURPLE_DEBUG_ERROR,
                 PLUGIN_ID,
                 "Unable to unwrap symmetric key\n");
    return FALSE;
  }
  
  return TRUE;
}

/**
 * Compares two symmetric keys for equality. 
 *
 * @param key1 The first key
 * @param key2 The second
 * 
 * @return TRUE if the data of the two keys are equal, FALSE otherwise
 */
PRBool 
compare_symkeys (PK11SymKey *key1, PK11SymKey *key2)
{
  SECItem *raw_key1 = 0;
  SECItem *raw_key2 = 0;
  raw_key1 = PK11_GetKeyData(key1);
  raw_key2 = PK11_GetKeyData(key2);
  return SECITEM_ItemsAreEqual(raw_key1, raw_key2);
}

#endif //PUB_KEY_C
