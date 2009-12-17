/**
 * @file
 * @brief Responsible for intercepting messages, and encrypting/decrypting if 
 *        the active conversation is supposed to be encrypted. 
 * 
 * Calls on the session_keys file, and the public_keys file to generate keys, 
 * and to actually perform the enc / dec. This file is mainly responsible for 
 * understanding the sysecure message format, and for composing / decomposing 
 * the various parts into a single unified message
 *
 */
 #ifndef MSG_HANDLE_C
#define MSG_HANDLE_C

#include "msg_handle.h"

// Declare message tags
// These are used to wrapper encrypted messages and other sysecure-specific
// information that is being send over the IM channel. 
// @todo - comment these individually. Many of them are not used right now...
static char crypt_tag[] = ";;SYSECURE;;";
static char crypt_close_tag[] = ";;/SYSECURE;;";

static char id_tag[] = ";;ID;;";
static char id_close_tag[] = ";;/ID;;";

static char pub_tag[] = ";;PUB_KEY;;";
static char pub_close_tag[] = ";;/PUB_KEY;;";

static char key_tag[] = ";;S_KEY;;";
static char key_close_tag[] = ";;/S_KEY;;";

static char emsg_tag[] = ";;E_MSG;;";
static char emsg_close_tag[] = ";;/E_MSG;;";

static char msg_tag[] = ";;MSG;;";
static char msg_close_tag[] = ";;/MSG;;";

static char hash_tag[] = ";;HASH;;";
static char hash_close_tag[] = ";;/HASH;;";

/**
 * Convenience method which locates and stores the PurpleConversation with 
 * the given name into the conv parameter. 
 *
 * @param name A null-terminated string representing the conversation name, as
 *             would be returned by purple_conversation_get_name()
 * @param conv An out parameter. If a conversation is found that has the passed
 *             name, then it be stored at *conv. Otherwise, *conv will be NULL
 *
 * @return TRUE if a conversation was found and stored into conv with the 
 *         passed name, FALSE otherwise
 */
static gboolean 
find_conversation_from_name (char *name, PurpleConversation **conv)
{
  // Declare all vars up front
  GList *conv_list = NULL;
  gboolean found = FALSE;
  
  // Init all vars
  conv_list = purple_get_conversations();
  
  // Print out a nice error message if there are no conversations
  // Receiving this message would likely indicate that this method should not 
  // have been called
  if (conv_list == NULL)
  {
    purple_debug_info(PLUGIN_ID,
                      "No conversations from purple_get_conversations(). Unable to find conversation with name '%s'\n",
                      name);
    return FALSE;
  }
  
  // Try to find the conversation
  while(conv_list && !found)
  {
    if (strcmp(purple_conversation_get_name((PurpleConversation*)(conv_list->data)), name) == 0)
      found = TRUE;
    else 
      conv_list = conv_list->next;
  }
  
  // Store the found convo
  if (found)
  {
    *conv = ((PurpleConversation*)(conv_list->data));
    return TRUE;
  }
  
  return FALSE;
}

/**
 * Convenience function that returns whether a conversation with a given name
 * is encrypted. 
 *
 * @param name The name of the conversation, as would be returned by 
 *             purple_congersation_get_name()
 *
 * @return TRUE if that conversation is encrypted, FALSE otherwise
 */
static gboolean 
is_enabled (const char *name)
{
  // Guaranteed to return an alloced / initialized structure
  EncryptionInfo *e_info = get_encryption_info_from_name(name);
  
  return e_info->is_encrypted;
}

/**
 * Convenience function that finds a tag within a given message. Useful for 
 * determining if a message is of a certain type. 
 *
 * @param message The message to check for the tag
 * @param tag The tag to look for. At time of writing, these are available in 
 *            the top of msg_handle.
 *
 * @return A pointer to the location in message that the tag was found, or NULL
 *
 * @todo Is this method used? Can it be removed? Answer: Yes, it is occasionally
 *       used for debugging. Can be removed after version 1.0 release and we are
 *       sure this is stable
 */
char* 
get_tag_location (char *message, char *tag)
{
  char* tag_ptr = NULL;
  tag_ptr = strstr(message, tag);
  return tag_ptr;
}

/**
 * Finds and extracts a component that is stored within the passed message. Uses
 * the tags (currently found at the top of msg_handle) to specify the start and 
 * end strings. 
 *
 * @param message The IM that purple has received. Can contain encrypted text,
 *                session keys, public keys, etc. Anything that has defined 
 *                start and end tags is game. 
 * @param open_tag The start tag for the component to be extracted
 * @param close_tag The closing tag for the component to be extracted
 * @param result An out parameter. Upon exit, result[0] (or *result) will 
 *               contain the component that was inside of the open and close
 *               tags, with the tags stripped. This is allocated internally, 
 *               and g_free() should be called on the return value at some
 *               point. If this function returns FALSE, this value not set
 *               and is equal to NULL
 *
 * @return TRUE if a result was found, and stored to result. FALSE otherwise                 
 *
 */
static gboolean 
get_msg_component (const char *message, char *open_tag, char *close_tag, char **result)
{
  // Declare vars
  char *open_ptr = NULL;
  char *close_ptr = NULL;
  
  // Init vars
  open_ptr = strstr(message, open_tag);
  close_ptr = strstr(message, close_tag);

  if (open_ptr == NULL || close_ptr == NULL)
  {
    purple_debug(PURPLE_DEBUG_ERROR,
                 PLUGIN_ID,
                 "Requested component section not found: %s [] %s\n",
                 open_tag, 
                 close_tag);
    return FALSE;
  }

  // Skip the actual open_tag, we don't care about that!
  open_ptr = open_ptr + strlen(open_tag);
  
  purple_debug(PURPLE_DEBUG_MISC,
               PLUGIN_ID,
               "Found a component in message. First value in component value is '%c', last is '%c'.\n",
               *open_ptr,
               *close_ptr - sizeof(char));
               
  
  // Malloc enough to hold the entire component, plus a null-terminating
  *result = g_malloc0((close_ptr - open_ptr + 1) * sizeof(char));
  
  // Copy the component into the result 
  memcpy(*result, open_ptr, close_ptr - open_ptr);
  
  return TRUE;
}

/**
 * @brief Given a SySecure instant message, this function extracts the components 
 * (the actual message, the wrapped session key, and the hash). The components
 * are used to decrypt the message, which is then returned. 
 *
 *
 * @details This function performs the following operations:
 *          1) Parse the message into component parts. 
 *             (a) The symmetric key component contains the encrypted symmetric key, 
 *                 encrypted with the sender public key to guarantee only the 
 *                 sender can decrypt it. Encrypted(Sender_Public_Key, Session Key)
 *             (b) The message component contains the encrypted message and the 
 *                 encrypted hash. The hash is encrypted with private key, while
 *                 the message is encrypted with the session key. This is a 
 *                 common secure practice, to encrypt the hash with a different
 *                 key. Encrypted(Session_Key,
 *                               MSG || Encrypted(Sender_Private_Key, Hash(MSG))
 *          2) Decrypt the session key
 *             (a) Convert session key from ASCII to raw binary. Libpurple can
 *                 only reliably send ASCII, so the entire sysecureIM has been
 *                 ASCII armored
 *             (b) Unwrap the session key using the senders private key.
 *          3) Convert the message from ASCII, and decrypt the message and hash
 *          4) Generate a hash from the decrypted message
 *          5) Decrypt the hash using the sender public key
 *          6) Compare the received and generated hashes
 *          
 *          If all of these steps succeed, then the message is stored and TRUE
 *          is returned.  
 *
 *
 * @param sysecure_content The sysecure IM content, without the wrapping sysecure
 *                       open and close tags. 
 * @param decrypted_message An out parameter. If this function returns TRUE, 
 *                          then this variable stores a (newly g_malloced())
 *                          string which contains the original message. This 
 *                          should be null terminated
 * @param sender The name of the sender
 * @param receiver The name of the receiver
 *
 * @return TRUE if the session key can be unwrapped, the message decrypted, and 
 *         the hash of the decrypted message matches the hash originally sent. 
 *         return false otherwise
 *
 * @todo This does not actually perform hash checking at this point. This 
 *       should be completed. 
 */
gboolean 
decompose_and_decrypt_message (char* sysecure_content, unsigned char** decrypted_message, char* sender, char* receiver)
{
  char* enc_sess_key;   // The encrypted session key
  SECItem* sess_key_item; // The encrypted session key, after it has been converted from ASCII form to binary
  PK11SymKey* sess_key;   // The fully decrypted session key
  char* enc_message;    // The encrypted message, including the (twice encrypted) hash
  unsigned char* binary_enc_message;  // The encrypted message, after it has been converted from ASCII to binary
  unsigned char* message;   // The fully decrypted message
  gboolean success;   // Used in various locations to ensure the last performed operation was successful
  unsigned int binary_length; // Used to convert the encrypted message from ASCII to binary
  unsigned int message_length; // Used to keep track of the size of the decrypted message
  
  // None of these are used. Should be used for hash
  //char* enc_hash;
  //char* decrypted_hash;
  //char* message_hash;
  
  purple_debug(PURPLE_DEBUG_INFO,
               PLUGIN_ID,
               "Decrypting a IM message. Encrypted content: <S>%s<E> sender: %s.\n",
               sysecure_content, 
               sender);
  
  // Retrieve the encrypted session key component from the sysecure message
  purple_debug(PURPLE_DEBUG_INFO,
               PLUGIN_ID,
               "Trying to get %s component from %s\n",
               key_tag,
               sysecure_content);
  success = get_msg_component(sysecure_content,
                              key_tag, 
                              key_close_tag, 
                              &enc_sess_key); // TODO - make sure to g_free() the ecn_session_key
  if (success == FALSE) 
  {
     purple_debug(PURPLE_DEBUG_ERROR, 
                  PLUGIN_ID,
                  "Unable to extract the encrypted session key from the sysecure IM message. Cannot continue\n");
     return FALSE;
  }
  
  // Extract the encrypted message and hash from the sysecure message
  purple_debug(PURPLE_DEBUG_INFO,
               PLUGIN_ID,
               "Trying to get %s component from %s\n",
               emsg_tag, 
               sysecure_content);
  success = get_msg_component(sysecure_content,
                              emsg_tag, 
                              emsg_close_tag, 
                              &enc_message);  // TODO - make sure to g_free the enc_message
  if (success == FALSE) 
  {
    purple_debug(PURPLE_DEBUG_ERROR,
                 PLUGIN_ID,
                 "Unable to extract the encrypted message and hash from the sysecure IM message. Cannot continue\n");
    
    // Cleanup stuff we have g_malloc() at this point
    // Note - if false was returned, then enc_message was not alloc'ed
    g_free(enc_sess_key);   
    
    return FALSE;
  }
  
  
  // Convert the key back from ASCII, and convert it to a SECItem
  sess_key_item = NSSBase64_DecodeBuffer(NULL,
                                         NULL, 
                                         enc_sess_key, 
                                         strlen(enc_sess_key));
  if (sess_key_item == NULL)
  {
    purple_debug(PURPLE_DEBUG_ERROR,
                 PLUGIN_ID, 
                 "Unable to Base64 decode encrypted session key, and turn it into a SECItem. Unable to continue\n");
    
    // Cleanup what we have g_malloced at this point
    g_free(enc_sess_key);   
    g_free(enc_message);
    
    return FALSE;
  }
  
  
  // Decrypt (unwrap) the session key
  success = unwrap_symkey(sess_key_item,
                          receiver, 
                          &sess_key);  // TODO - this is likely malloc'ed. We 
                                      //        may need to clean it up
  if (success == FALSE)
  {
    purple_debug(PURPLE_DEBUG_ERROR,
                 PLUGIN_ID,
                 "Unwrapping session key failed. Unable to continue\n");
                 
    // Cleanup what we have g_malloced at this point
    g_free(enc_sess_key);   
    g_free(enc_message);
    
    return FALSE;
  }
  
  // =======================================================================
  //
  // At this point, we have completely decrypted the session key. We are now
  // ready to move on to decrypting the message and checking the hash
  //
  // =======================================================================
    
  // Convert the message into binary from ASCII
  binary_length = 0;
  binary_enc_message = ATOB_AsciiToData(enc_message, &binary_length);
  if (binary_enc_message == NULL)
  {
    purple_debug(PURPLE_DEBUG_ERROR,
                 PLUGIN_ID,
                 "Failed to convert binary message into ASCII.\n");
                 
    // Cleanup what we have g_malloced at this point
    g_free(enc_sess_key);   
    g_free(enc_message);
    
    return FALSE;
  }
  
  // Actually decrypt the message, using the session key
  message_length = 0;
  message = decrypt(sess_key,
                    binary_enc_message,
                    binary_length, 
                    &message_length);

  if (message == NULL)
  {
    purple_debug(PURPLE_DEBUG_ERROR, 
                 PLUGIN_ID, 
                 "Failed to decrypt message component. Cannot continue\n");
    
    // Cleanup what we have g_malloced at this point
    g_free(enc_sess_key);   
    g_free(enc_message);
    
    return FALSE;
  }

  // Add terminating character to message
  memset(message, '\0', message_length);
  purple_debug(PURPLE_DEBUG_ERROR, 
                 PLUGIN_ID, 
                 "MESSAGE: %s\n", (char*) message);

  // Cleanup what we have allocated
  g_free(enc_sess_key);   
  g_free(enc_message);
  g_free(binary_enc_message);

  // Actually assign to out param
  *decrypted_message = message;
  
  return TRUE;
}

//SYS_incoming_cb: 
//1) Check to see if conversation exists (if not create it!)
//2) Check for SySecure tag.  If ;;SYSECURE;; tag present then
//   a) If ;;PUBLIC_KEY;; then record public key
//   b) Else then process the message and write it to the 
//      screen (or else an error message if it fails).
/**
 * Handles an incoming IM. There are three options:
 * (1) This is an unencrypted message, just show it
 * (2) This is a public key announcement, just store the key
 * (3) This is an encrypted message. Decrypt and show. 
 * 
 * @param acct The account the message was received on
 * @param sender The username of the sender. Can be modified (remember to free
 *               the original value if you modify!)
 * @param message The original modified. Can be modified by freeing the passed
 *                message and putting a new one in place
 * @param conv The IM conversation. Can be NULL if this is the first incoming
 *             message (aka, no conv actually exists yet)
 * @param flags The message flags
 *
 * @return TRUE to suppress **message from being shown to then receiver, FALSE
 *         otherwise
 */
gboolean 
receiving_im_cb (PurpleAccount *acct, char **sender, char **message,
                 PurpleConversation *conv, PurpleMessageFlags *flags)
{
  // Used to hold the contents of certain parts of messages
  char *sysecure_content;
  char *pub_key_content;
  char *decrypted_message;

  // enc_sender will be used to overwrite **sender
  //if we decrypt a message (in order to distinguish
  //the encrypted messages from the plain text ones).
  char *enc_sender_tag = "(ENC)";
  char *enc_sender;
  
  // Used in many places to indicate current success or failure
  gboolean success; 
  
  // If this is the first message someone has sent us, a 'conversation' has not
  // started. If we were to toss out the first message, it would never start. 
  // For this reason, the conv parameter may actually be null
  // If it is, then we want to create it
  if (conv == NULL)
  {
    purple_debug(PURPLE_DEBUG_INFO,
                 PLUGIN_ID,
                 "First message received from %s. Creating a conversation\n",
                 *sender);
    conv = purple_conversation_new(PURPLE_CONV_TYPE_IM, acct, *sender);
  }
  
  // Check for ;;SYSECURE;; and ;;/SYSECURE;; tags
  success = get_msg_component(*message,
                              crypt_tag, 
                              crypt_close_tag, 
                              &sysecure_content); // TODO - make sure to free sysecure_content
  if (success == FALSE) 
  {
    purple_debug(PURPLE_DEBUG_INFO,
                 PLUGIN_ID,
                 "Non-encrypted message received.\n"); 
	
	  // Just show the message as normal
      purple_conversation_write(conv, NULL,*message, PURPLE_MESSAGE_RECV, time(NULL)); 
	  return TRUE;
  }
  purple_debug(PURPLE_DEBUG_INFO,
               PLUGIN_ID,
               "SySecure message identified.\n"); 
  purple_debug(PURPLE_DEBUG_INFO, 
               PLUGIN_ID,
               "SySecure tag includes: <START>%s<END>\n",
               sysecure_content);
               
  fprintf(stderr, "ss_content: %s\n",sysecure_content);
   
  // ============================================================
  // 
  // Behaviour of next section depends on if the message is a public key
  // announcement, or if the message is a encrypted message
  //
  // ============================================================
  
   
  // Check for public key announcement message
  success = get_msg_component(sysecure_content, 
                              pub_tag, 
                              pub_close_tag, 
                              &pub_key_content); // TODO - figure out why calling g_free() on this seg faults
                              
  fprintf(stderr, "ss_content: %s\n",sysecure_content);
  
  if (success) 
  {
    purple_debug(PURPLE_DEBUG_INFO,
                 PLUGIN_ID,
                 "Public Key received: <START>%s<END>\n",
                 pub_key_content);
    // Attempt to store the public key
    if (add_public_key(pub_key_content, *sender) == FALSE)
    {
      purple_debug(PURPLE_DEBUG_ERROR,
                   PLUGIN_ID,
                   "Failed to store new key for %s.\n",
                   *sender);
      
      // Notify the user
      purple_conversation_write(conv, 
                                NULL, 
	  					                  "SySecure: You received a public key, but could not store it for some reason. Unfortunately, you cannot talk encrypted. This error should not have occurred, so please contact the developers and help them make sure it does not continue occurring. ",
	  					                  PURPLE_MESSAGE_ERROR,
	  					                  time(NULL));  
    }
    // Free everything we have g_malloced before returning
    g_free(sysecure_content);
    //g_free(pub_key_content);
    
    // Don't show the public key announcement message 
    return TRUE;
  } 
  
  // Process SYSECURE message
  success = decompose_and_decrypt_message(sysecure_content,
                                          (unsigned char **)&decrypted_message,
                                          *sender, 
                                          acct->username);

  if (success == FALSE)
  {  
       purple_debug(PURPLE_DEBUG_ERROR,
                    PLUGIN_ID,
                    "Debug error: Could not parse message <START>%s<END>\n",
                    sysecure_content);
                    
     // Notify the user
     purple_conversation_write(conv, 
                               NULL, 
	 					                  "SySecure: You received an encrypted message, but we were unable to understand the message. This should not have happened. Please contact developers to help ensure it does not continue happening!",
	 					                  PURPLE_MESSAGE_ERROR,
  					                  time(NULL));  
     
     // Clean up our memory
     g_free(sysecure_content);
     //g_free(pub_key_content);
     
     // Do not show the encrypted message
     return TRUE;
  }
     
  // Free the encrypted message, and put the decrypted message in it's place
  // TODO - make sure this works!

  enc_sender = g_malloc0((strlen(enc_sender_tag)+strlen(*sender))*sizeof(char));
  strcat(enc_sender, *sender);
  strcat(enc_sender, enc_sender_tag);
  g_free(*sender);
  g_free(*message);

  *message = (char *)decrypted_message;
  *sender = enc_sender;

  // Clean up our memory
  g_free(sysecure_content);
  //g_free(pub_key_content);    
  
  // Do show the message now! We have decrypted and swapped it out
  return FALSE;
}


/**
 * Given open and close tags, and the original message, this function returns
 * the message contained within the tags. 
 * 
 * @param open_tag The tag used to start the sequence
 * @param close_tag The tag used to end the sequence
 * @param message The message to be wrapped within the open and close tags
 * @param result An out parameter. Upon completion, this variable will contain
 *               "open_tagmessageclose_tag". This is freshly allocated inside 
 *               of this function
 */
static void 
add_tags_to_message (char *open_tag, char *close_tag, char *message, char **result)
{
  // Need enough space for the open tag, the message, the close tag, and the 
  // null terminating char
  int message_length = strlen(message) + strlen(open_tag) + strlen(close_tag) + 1;
  
  // Allocate and clear
  *result = g_malloc(message_length * sizeof(char));
  memset(*result, 0, message_length * sizeof(char));
  
  // Put the data
  strcat(*result, open_tag);
  strcat(*result, message);
  strcat(*result, close_tag);
  
  purple_debug(PURPLE_DEBUG_INFO,
               PLUGIN_ID,
               "Added tags to message. Result: %s\n", *result);
}

/**
 * @brief Takes a standard IM message, and converts it to a SySecure message. 
 *
 * @details Builds the outgoing SySecure message. Generates a session key, 
 *          encrypts it with the receiver public key so no one but the receiver
 *          can decrypt, hash the original message, use the sender private key
 *          to encrypt the hash. Concatenate the plain text message and the 
 *          hash, encrypt the concatenated string with the session key. Concat
 *          the encrypted session key and the encrypted message/hash into a new
 *          char*, which is now the ready-to-send message. g_free() the original
 *          message, and assign the sysecure message. While doing these ops, 
 *          this also wraps the various sysecure message components inside of 
 *          tags, so they can be correctly extracted on the receiving end
 *
 * @param message Both an input and an output parameter. Pass in the original 
 *                value of the IM message, referenceable as *message. This 
 *                function will perform the necessary ops to convert this into
 *                a SySecure message. The passed value will eventually be freed, 
 *                and a newly g_alloced() value will be returned in *message
 * @param sender The name of the sender
 * @param reveiver The name of the receiver
 *
 * @todo Add in the hashing function to the encryption
 * @todo It is not a good convention to have an output param also be an input
 *       param, because the function may fail in the middle, resulting in neither
 *       the input data, or the output data existing when it fails. Create 
 *       another signature for this method
 */
static void 
create_outgoing_msg (unsigned char **message, char *sender, const char *receiver)
{
  //declare temporary variables
  char* temp_message;         // holds the wrapped symmetric key and enclosing tags
  char* temp_message2;        // holds the enclosed encrypted message
  char* temp_message3;
  unsigned char* temp_encrypted_message;  // The encrypted session key
  char *encrypted_message;
  unsigned int encrypted_msg_length;
  PK11SymKey *session_key;          // The session key to be used to encrypt this message
  SECItem *wrapped_key;
  char *wrapped_keybuff;
  gboolean success; // used to indicate success at various points

  // Generate the Session Key
  session_key = generate_symmetric_key();
  
  // Wrap the symmetric key in the receiver's public key, so only the receiver
  // can unwrap it
  success = wrap_symkey(session_key, &wrapped_key, receiver);
  
  // Ensure the wrapping was a success 
  if (success == FALSE)
  {
     purple_debug(PURPLE_DEBUG_ERROR,
                  PLUGIN_ID,
                  "Unable to wrap the session key. Unable to continue creating the SySecure IM\n");
     
     // TODO - Notify the user here that their send failed :/
     // TODO - Also, at this point, the unencrypted message would be sent. We should
     //        probably guard against this
     
     return;  
  }
    
  // Convert the SECItem into an ASCII char* that can be safely sent over IM
  wrapped_keybuff = NSSBase64_EncodeItem(0, 0, 0, wrapped_key);
  
  // Ensure the encoding was a success
  if (wrapped_keybuff == NULL)
  {
     purple_debug(PURPLE_DEBUG_ERROR,
                  PLUGIN_ID,
                  "Unable to encode the session key. Unable to continue creating the SySecure IM\n");
     
     // TODO - Notify the user here that their send failed :/
     // TODO - Also, at this point, the unencrypted message would be sent. We should
     //        probably guard against this
     
     return;
  }
  
  // Add tags around the encrypted key, so it can be found and retrieved later
  add_tags_to_message(key_tag, key_close_tag, wrapped_keybuff, &temp_message);

  // Actually encrypt the session key
  temp_encrypted_message = encrypt(session_key, *message, &encrypted_msg_length);

  if (temp_encrypted_message == NULL)
  {
   purple_debug(PURPLE_DEBUG_ERROR,
                PLUGIN_ID,
                "Unable to encrypt the IM. Unable to continue creating the SySecure IM\n");
          
   // TODO - Notify the user here that their send failed :/
   // TODO - Also, at this point, the unencrypted message would be sent. We should
   //        probably guard against this
   
   // Free the memory we were using
   g_free(temp_message);
   
   return; 
  }

  // Convert the encrypted message into an ASCII armored format, so that it is 
  // safe to send over IM
  encrypted_message = BTOA_DataToAscii(temp_encrypted_message, encrypted_msg_length);
  
  // TODO - see if we need this memset. Jason had it commented out
  //memset(encrypted_message + encrypted_msg_length, '\0', 1);
  
  // Enclose the encrypted message in the correct tags,
  add_tags_to_message(emsg_tag, emsg_close_tag, encrypted_message, &temp_message2);
  
  // ==================================================================
  // 
  // At this point temp_message = the enclosed, wrapped session key
  //              temp_message2 = the enclosed, encrypted message
  // Now on to putting those two together into a single char *
  //
  // ==================================================================  
  
  // Create room to store the full SySecure IM content
  // Size of the packaged session key, plus the encrypted message, plus the null
  temp_message3 = g_malloc0((strlen(temp_message)+strlen(temp_message2) + 1)*sizeof(char));
  memset(temp_message3, 0, strlen(temp_message) + strlen(temp_message2) + 1);
  strcat(temp_message3, temp_message);
  strcat(temp_message3, temp_message2);
  
  // Free the old message, so that we can add the encrypted message to that var
  g_free(*message);
 
  // Package the entire sysecure message
  // Note: This is not horribly useful right now, but I guess it could be later?
  // PS - cheaply avoiding compiler error. Should prob change the func. sig :/
  add_tags_to_message(crypt_tag, crypt_close_tag, temp_message3, (char **)message);

  // Free all the temp vars  
  g_free(temp_message);
  g_free(temp_message2);
  g_free(temp_message3);
  g_free(encrypted_message);
  g_free(temp_encrypted_message);
  g_free(wrapped_keybuff);
}

/**
 * If encryption is enabled for the passed receiver, and if we have the correct
 * keys for that person, and we have trusted those keys, the we will encrypt
 * the message and send it to them. 
 * 
 * If the public key does not exist, this method will send a request for the key
 *
 * @param account The IM account this message is being sent on
 * @param reveiver The name of the receipient of this message
 * @param message The original IM message. This variable can be g_free()'d and 
 *                a new message can be placed in it's stead
 *
 *
 * @todo There are a number of places that we need to prevent this message from
 *       being sent. Either change it to a default message, or (better) just
 *       set it to NULL. Not sure if setting to NULL will crash pidgin, so I
 *       dont want to do that _right_ now (in the middle of major changes, I 
 *       enough to think a/b w/o introducing new bugs)
 */
void 
sending_im_cb (PurpleAccount *account, const char *receiver, char **message)
{

  //1) Check if SySecure is enabled...if disabled return TRUE to send message
  //   normally.
  //2) Check to see if a public key exists for the receiver.
  //   if it does, continue.  If not, inform the user that the receiver is not
  //   running SySecure on their system and do not send the message.
  //   NOTE:  init_pub_key() will send a key to active accounts if SySecure is 
  //   enabled.
  //3) Check to see if the key for the receiver is trusted.  If it is not see
  //   bullet 3 (need to only check once!!).
  //4) If we made it through these guards then call create_outgoing_msg to put the
  //   message together.

  // Necessary declarations:
  RSA_Key_Pair *key_pair;
  unsigned char* temp_message;    // Used later to copy the message
  PurpleConversation* conv;   // Used to notify the user of an error by writing
                              // it to their conversation window

  // We only have something to do if encryption is enabled, and there is a 
  // message
  // Note: The message should never be NULL, unless another plugin callback 
  //       actually NULLed it before it got to us. libpurple never sends NULL
  if (is_enabled(receiver) == FALSE ||
      (*message) == NULL)
  {
    purple_debug(PURPLE_DEBUG_INFO, 
                 PLUGIN_ID,
                 "Encryption disabled for conversation with %s\n",
                 receiver);
    return;
  }
  
  // Setup the conv variable, so we can print error messages to the user's
  // conversation window if need be
  conv = purple_find_conversation_with_account( PURPLE_CONV_TYPE_IM,
                                                receiver,
                                                account);	 
  if (conv == NULL)
    conv = purple_conversation_new(PURPLE_CONV_TYPE_IM, 
                                   account, 
                                   receiver);
  
  
  // Initialize pub_key
  init_pub_key(account->username);
  
  // Make sure we have the receivers public key and can actually encrypt the 
  // message
  if (find_key_pair(account->username, &key_pair) == FALSE)
  {
    purple_debug(PURPLE_DEBUG_ERROR, 
                 PLUGIN_ID, 
                 "No public key found for %s. Unable to encrypt IM message\n",
                 receiver);
    
    // Notify the user
    purple_conversation_write(conv, 
                              "SySecure", 
	  					                "You do not have a public key for this person. You are unable to encrypt the messages you send them. Perhaps try IM'ing them in an unsecure fashion and asking for their public key.",
	  					                PURPLE_MESSAGE_ERROR,
	  					                time(NULL)); 
   
   // TODO - set the message to NULL to prevent an unencrypted message from being sent into the network!!
    
	  // Do not show the message in the chat window    
    return;
  }
  
  // Make sure we trust the public key
  // If we dont, we will not encrypt it, and we will also provide a warning
  if (key_pair->trusted == FALSE)
  {
    purple_debug(PURPLE_DEBUG_INFO,
                 PLUGIN_ID,
                 "%s's public key is not trusted. Will not encrypt and send. Also, printing a warning message.\n", 
                 receiver);
    
    purple_conversation_write(conv, 
                              "SySecure", 
	  					                "You do not trust the public key being used by the person you are IMing. An attacker may be able to read messages. SySecure will not send a message to the network if it cannot guarantee that messages safety, therefore we have refused to send this message until you trust the public key. Please turn SySecure off for this IM if you want to talk to this person. ",
	  					                PURPLE_MESSAGE_ERROR,
	  					                time(NULL));
	  
	  // TODO - set the message to NULL to prevent an unencrypted message from being sent into the network!!
    return;   
  }
  
  
  // Copy the passed message into a temporary variable. 
  // We do this just in case creating the create_outgoing_msg() fails at some 
  // point. That method is free to use the pointer you pass it, so we don't
  // want to accidentally corrupt that. 
  // TODO - change this to _not_ copy the memory here once we have changed the 
  //        create_outgoing_msg() params
  temp_message = g_malloc0((strlen(*message) + 1) *sizeof(char));
  memcpy(temp_message, *message, strlen(*message));

  // Actually create the SySecure message from the standard IM messsage. 
  // Store to temp_message
  create_outgoing_msg(&temp_message, account->username, receiver);
  
  if (temp_message == NULL)
  {
    purple_debug(PURPLE_DEBUG_ERROR,
                 PLUGIN_ID,
                 "Error creating output message. Message dropped.\n");
                 
    purple_conversation_write(conv, 
                              "SySecure", 
	  					                "Some error in encrypting the message. Please send debug log to developers, so we can identify the issue! Printing message you tried to send to allow you to copy/paste if you would like",
	  					                PURPLE_MESSAGE_ERROR,
	  					                time(NULL));
	  
	  purple_conversation_write(conv, 
                              "Some plugin", 
	  					                "Some err",
	  					                PURPLE_MESSAGE_ERROR,
	  					                time(NULL));
	  
	  purple_conversation_write(conv, 
                              "SySecure", 
	  					                *message,
	  					                PURPLE_MESSAGE_ERROR,
	  					                time(NULL));
	 
	  // TODO - Do not send unsecure IM into network!
	  
    return;
  }
  
  // Replace the old message with the encrypted message
  g_free(*message);
  *message = g_malloc0((strlen((const char *)temp_message) + 1) *sizeof(char));
  memcpy(*message, temp_message, strlen((const char *)temp_message));
}

/**
 * Handles creating the SySecure message that sends the public key to another 
 * party. This creates the message, sends it off, and returns. 
 *
 * @param conv The conversation we need to send a public key for
 *
 * @return seems to always return true. Not sure what this is supposed to 
 *         indicated
 *
 * @todo Figure out what return value indicates
 */
gboolean 
send_pub_key (PurpleConversation *conv)
{
  RSA_Key_Pair *key_pair;
  SECItem *key_data;
  //SECItem *key_check;
  char* key_buffer;
  char* pub_key_wrap;
  char* pub_key_message;
  PurpleConnection *connect;
  GList *connect_list;
  PurpleConvIm * im_data;
  PurpleMessageFlags flags = PURPLE_MESSAGE_INVISIBLE|PURPLE_MESSAGE_NO_LINKIFY|PURPLE_MESSAGE_RAW|PURPLE_MESSAGE_SEND;

  if (find_key_pair(conv->account->username, &key_pair) == FALSE)
  {
    purple_debug(PURPLE_DEBUG_INFO,
                 PLUGIN_ID, 
                 "No key exists for user %s, unable to send public key\n",
                 conv->account->username);
    return TRUE;
  }
  
   // Seems to turn the public key into a SECItem, so it can be passed around
   key_data = SECKEY_EncodeDERSubjectPublicKeyInfo(key_pair->pub);
   
   // Encode the public key for transmission over IM (ASCII only)
   key_buffer = NSSBase64_EncodeItem(0, 0, 0, key_data);
   
   // Add the tags to wrap the public key, and to wrap the entire message
   add_tags_to_message(pub_tag, pub_close_tag, key_buffer, &pub_key_wrap);
   add_tags_to_message(crypt_tag, crypt_close_tag, pub_key_wrap, &pub_key_message);
   //purple_debug(PURPLE_DEBUG_INFO, "SySecure", "User %s's key ready to send: %s\n", conv->account->username, key_buffer);
   
   //connect_list = purple_connections_get_all();
   //connect = (PurpleConnection*) connect_list->data;
   //serv_send_im(connect, conv->name, pub_key_message, PURPLE_MESSAGE_SEND);
   
   // Get the IM specific data from conversation
   im_data = purple_conversation_get_im_data(conv);
   if (im_data == NULL)
   {
      // This was not an IM conversation
      // TODO - print awesomeish error message
   }
   
   
   // Actually send the IM
   purple_conv_im_send_with_flags	(im_data,
                                   pub_key_message,
                                   flags);	
   
   //DEBUG ONLY
   /*key_check = NSSBase64_DecodeBuffer(0, 0, key_buffer, strlen(key_buffer));
   if(SECITEM_ItemsAreEqual(key_data, key_check))
     purple_debug(PURPLE_DEBUG_INFO, "SySecure", "Pub Key encoded and decoded successfully\n");
   else
     purple_debug(PURPLE_DEBUG_ERROR, "SySecure", "Pub Key encoded and decoded UNSUCCESSFULLY\n");
   */
   return TRUE;
}

//Upon creation of a new conversation, attempt to immediately
//send your public key.
/**
 * Call back for a new conversation being created. Immediately tries to 
 * find (or create) the public key that is used for the account this 
 * conversation is upon, and then sends that public key to the conversation 
 * receipient. 
 *
 * @param conv The conversation that just started
 */
void SYS_create_conversation_cb (PurpleConversation *conv)
{
  purple_debug(PURPLE_DEBUG_INFO,
               PLUGIN_ID, 
               "New conversation created between user %s and buddy %s.\n", 
               conv->account->username, 
               conv->name);
               
               
  init_pub_key(conv->account->username);
  send_pub_key(conv);
}

#endif //MSG_HANDLE_C
