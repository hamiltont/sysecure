#ifndef MSG_HANDLE_C
#define MSG_HANDLE_C

#include "msg_handle.h"

// Declare message tags
// These are used to wrapper encrypted messages and other sysecure-specific
// information that is being send over the IM channel. 
// TODO - comment these individually. Many of them are not used right now...
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

//Given an id, this function finds the conversation
//designated by that name and returns true if 
//SYSECURE is enabled for that conversation and FALSE
//if it is not.
gboolean SYS_enabled_check (char *id)
{
  PurpleConversation *conv;
  EncryptionInfo *e_info;
  if (!find_conversation_from_name(id, &conv))
  {
    purple_debug(PURPLE_DEBUG_ERROR, "SySecure", "CONV with %s not found!", id);
    return FALSE;
  }
  e_info = get_encryption_info(conv);
  if (!(e_info))
      purple_debug(PURPLE_DEBUG_ERROR, "SySecure", "SYS_enabled_check: e_info is NULL!");
  if (!(e_info->is_encrypted))
      purple_debug(PURPLE_DEBUG_ERROR, "SySecure", "SYS_enabled_check: is_encrypted is NULL for conversation with %s!", id);
  return e_info->is_encrypted;
}


//Given a messags and a tag, this returns true if
//the tag is in the message and false if it is not.
//(this is basically a good quick check as to 
//whether or not a message is of a certain type).
char* SYS_tag_check (char *message, char *tag)
{
  char* tag_ptr;
  tag_ptr = strstr(message, tag);
  return tag_ptr;
}

//Given an open tag, close tag, the message, and a string reference
//returns TRUE if both tags are present and result is a newly allocated
//string equal to the information between the tags.
gboolean get_msg_component (char *message, char *open_tag, char *close_tag, char **result)
{
  char *open_ptr = NULL;
  char *close_ptr = NULL;
  char *temp_ptr = NULL;
  open_ptr = strstr(message, open_tag);
  close_ptr = strstr(message, close_tag);

  if (!open_ptr || !close_ptr)
  {
    purple_debug(PURPLE_DEBUG_INFO, "SySecure", "Requested section not found: %s [] %s\n", open_tag, close_tag);
    return FALSE;
  }

  purple_debug(PURPLE_DEBUG_INFO, "SySecure", "DEBUG: open_ptr %c close_ptr %c.\n", *open_ptr, *close_ptr);
  open_ptr = open_ptr + strlen(open_tag);
  *result = malloc((close_ptr - open_ptr + 1) *sizeof(char));
  purple_debug(PURPLE_DEBUG_INFO, "SySecure", "DEBUG: open_ptr %c close_ptr %c.\n", *open_ptr, *close_ptr);
  memcpy(*result, open_ptr, close_ptr - open_ptr);
  memset(*result + (close_ptr - open_ptr), '\0', 1);
  return TRUE;
}

//Given a sysecure message with the ;;SYSECURE;; open and close tags
//stripped, this function processes the message in the following steps:
//1) Parses the message into its parts:
//   a) ;;S_KEY;; Encrypted(Sender_Public_Key, Session_Key)
//   b) ;;E_MSG;; Encrypted(Session_Key, MSG||Encrypted(Sender_Private_Key, Hash(MSG))
//      (1) MSG
//      (2) Encrypted Hash
//2) Decrypts the session key
//   a) Need to convert from ASCII to binary then
//   b) Unwrap it
//3) Decrypts E_MSG
//4) Parses the MSG and the Encrypted Hash
//5) Decrypts the Encrypted Hash using the sender's public key
//6) Takes a hash of the MSG
//7) If the hashes equal, then decrypted_message will point to the 
//   plaintext message and TRUE is returned.
//   Else FALSE is returned.
gboolean process_SYS_message (char* sysecure_content, char** decrypted_message, char* sender, char* receiver)
{
  purple_debug(PURPLE_DEBUG_INFO, "SySecure", "DEBUG. sysecure_content: <S>%s<E> sender: %s.\n", sysecure_content, sender);
  char* enc_sess_key;
  SECItem* sess_key_item;
  PK11SymKey* sess_key;
  char* enc_message;
  unsigned char* binary_enc_message;
  unsigned char* message;
  char* enc_hash;
  char* decrypted_hash;
  char* message_hash;
  //1) a) Get the encrypted session key and encrypted message from sysecure_content
  purple_debug(PURPLE_DEBUG_INFO, "SySecure", "Trying to get %s component from %s\n", key_tag, sysecure_content);
  if (!(get_msg_component(sysecure_content, key_tag, key_close_tag, &enc_sess_key)))
  {
     purple_debug(PURPLE_DEBUG_ERROR, "SySecure", "Process message.  Failed to get enc_sess_key.\n");
       return FALSE;
  }
  
  //1) b) Get the encrypted message
  purple_debug(PURPLE_DEBUG_INFO, "SySecure", "Trying to get %s component from %s\n", emsg_tag, sysecure_content);
  if (!(get_msg_component(sysecure_content, emsg_tag, emsg_close_tag, &enc_message)))
  {
    purple_debug(PURPLE_DEBUG_ERROR, "SySecure", "Process message.  Failed to get enc_message.\n");
       return FALSE;
  }
  //2) Decrypt the session key
  sess_key_item = NSSBase64_DecodeBuffer(NULL, NULL, enc_sess_key, strlen(enc_sess_key));
  if (sess_key_item)
    purple_debug(PURPLE_DEBUG_INFO, "SySecure", "Session key item decoded!");

  if (unwrap_symkey(sess_key_item, receiver, &sess_key))
    purple_debug(PURPLE_DEBUG_INFO, "SySecure", "Session key recovered!");
  else
    purple_debug(PURPLE_DEBUG_INFO, "SySecure", "Session key recovery FAILED!");

  //3) Decrypt E_MSG

  int binary_length;
  binary_enc_message = ATOB_AsciiToData(enc_message, &binary_length);
  if (!binary_enc_message)
  {
    purple_debug(PURPLE_DEBUG_INFO, "SySecure", "Failed to convert binary to ASCII.\n");
    return FALSE;
  }
  int message_length;
  message = decrypt(sess_key, binary_enc_message, binary_length, &message_length);
  if (!message)
  {
    purple_debug(PURPLE_DEBUG_INFO, "SySecure", "Failed to decrypt message.\n");
    return FALSE;
  }
  char *temp_message = malloc ((message_length + 1)*sizeof(char));
  memset(temp_message, 0, message_length + 1);
  strncat(temp_message, message, message_length);
  temp_message[message_length + 1] = '\0';
  purple_debug(PURPLE_DEBUG_INFO, "SySecure", "DECRYPTED MESSAGE: %s", message);
//decrypt(PK11SymKey *key, unsigned char * cipher, unsigned int cipher_length, 
        //unsigned int * result_length)
  //encrypted_message = BTOA_DataToAscii(temp_encrypted_message, encrypted_msg_length);
  //temp_encrypted_message = encrypt(session_key, *message, &encrypted_msg_length);

  //temp_encrypted_message is binary...the function below will convert it to sendable
  //ASCII code.
  //encrypted_message = BTOA_DataToAscii(temp_encrypted_message, encrypted_msg_length);

  purple_debug(PURPLE_DEBUG_INFO, "SySecure", "Received encrypted session key <START>%s<END>\n", enc_sess_key);
  purple_debug(PURPLE_DEBUG_INFO, "SySecure", "Received encrypted message <START>%s<END>\n", enc_message);
  purple_debug(PURPLE_DEBUG_INFO, "SySecure", "strlen(enc_sess_key): %d strlen(enc_message): %d\n", strlen(enc_sess_key), strlen(enc_message));
  *decrypted_message = malloc(strlen(enc_sess_key)*sizeof(char));
  memset(*decrypted_message, 0, strlen(enc_sess_key));
  strcat(*decrypted_message, enc_sess_key);
  return TRUE;
}

//SYS_incoming_cb: 
//1) Check to see if conversation exists (if not create it!)
//2) Check for SySecure tag.  If ;;SYSECURE;; tag present then
//   a) If ;;PUBLIC_KEY;; then record public key
//   b) Else then process the message and write it to the 
//      screen (or else an error message if it fails).
gboolean SYS_incoming_cb (PurpleAccount *acct, char **who, char **message,
                                    PurpleConversation *conv, int *flags)
{
  char *sysecure_content;
  char *pub_key_content;
  char *message_content;
  char *decrypted_message;
  //1) Check to see if conversation exists
  //   NOTE:  Need to add the CREATION of the 
  //   conversation if one doesn't exist
  if (!find_conversation_from_name(*who, &conv))
  {
    purple_debug(PURPLE_DEBUG_INFO, "SySecure", "SYS_incoming_cb: No conversation for %s.  Creating one.\n", *who);
      conv = purple_conversation_new(PURPLE_CONV_TYPE_IM, acct, *who);
  }

  //2) Check for ;;SYSECURE;; and ;;/SYSECURE;; tags
  if (get_msg_component(*message, crypt_tag, crypt_close_tag, &sysecure_content))
  {
    purple_debug(PURPLE_DEBUG_INFO, "SySecure", "SySecure message identified.\n"); 
    purple_debug(PURPLE_DEBUG_INFO, "SySecure", "SYSECURE tag includes: <START>%s<END>\n", sysecure_content);
   //a) Check for public key message
    if (get_msg_component(sysecure_content, pub_tag, pub_close_tag, &pub_key_content))
    {
      purple_debug(PURPLE_DEBUG_INFO, "SySecure", "Public Key received: <START>%s<END>\n", pub_key_content);
      if (!add_public_key(pub_key_content, *who))
      {
        purple_debug(PURPLE_DEBUG_ERROR, "SySecure", "Failed to store new key for %s.\n", *who);
        return TRUE;
      }
      else 
       return TRUE;
    }
    else 
    //b) Process SYSECURE message
    {
     if (!process_SYS_message(sysecure_content, &decrypted_message, *who, acct->username))
     {
       purple_debug(PURPLE_DEBUG_ERROR, "SySecure", "Protocol error.  Could not parse message <START>%s<END>\n",sysecure_content);
       return TRUE;
     }
      purple_conversation_write(conv, NULL, 
	  					decrypted_message, PURPLE_MESSAGE_RECV, time(NULL));
      return TRUE;
    }
  }
  else
  {
    purple_debug(PURPLE_DEBUG_INFO, "SySecure", "Non-encrypted message received.\n"); 

    purple_conversation_write(conv, NULL, 
	  					*message, PURPLE_MESSAGE_RECV, time(NULL));
  }
  return TRUE;
  
}

void add_tags_to_message (char *open_tag, char *close_tag, char *message, char **result)
{
  int message_length = strlen(message) + strlen(open_tag) + strlen(close_tag);
  char* temp_message = malloc(message_length*sizeof(char));
  memset(temp_message, 0, message_length);
  strcat(temp_message, open_tag);
  strcat(temp_message, message);
  strcat(temp_message, close_tag);
  *result = malloc(message_length*sizeof(char));
  memset(*result, 0, message_length);
  memcpy(*result, temp_message, message_length + 1);
  purple_debug(PURPLE_DEBUG_INFO, "SySecure", "add_tags_to_message: RESULT: %s\n", *result);
  g_free(temp_message);
  
}


//Create_outgoing_msg:  This function builds the outgoing message
//adding the following:
//1) Session Key, Encrypted using the receiver's public key
//2) E(K_Session, Message||E(Priv_Sender, Hash(Message))
//  -Note that within the encryption this is split into 
//   ;;MSG;; and ;;E_HASH;;
//3) The sender's public key.

void create_outgoing_msg (RSA_Key_Pair *key_pair, char **message, char *sender, char *receiver)
{
  //declare temporary variables
  char* temp_message;
  char* temp_message2;
  char* temp_message3;
  char* temp_message4;
  unsigned char* temp_encrypted_message;
  char *encrypted_message;
  unsigned int encrypted_msg_length;
  PK11SymKey *session_key;
  SECItem *wrapped_key;
  char *wrapped_keybuff;

  //1) Add the Session Key, encrypted
  session_key = generate_symmetric_key();
  wrap_symkey(session_key, &wrapped_key, receiver);
  wrapped_keybuff = NSSBase64_EncodeItem(0, 0, 0, wrapped_key);
  //add ;;S_KEY;; tag to the beginning and end of the encrypted KS
  add_tags_to_message(key_tag, key_close_tag, wrapped_keybuff, &temp_message);

  //purple_debug(PURPLE_DEBUG_INFO, "SySecure", "create_outgoing_msg: temp_message: %s\n", temp_message);

  //2) Add the encrypted message
  //   Note:  Need to add the hashing function here!
  temp_encrypted_message = encrypt(session_key, *message, &encrypted_msg_length);

  //temp_encrypted_message is binary...the function below will convert it to sendable
  //ASCII code.
  encrypted_message = BTOA_DataToAscii(temp_encrypted_message, encrypted_msg_length);
  //memset(encrypted_message + encrypted_msg_length, '\0', 1);
  add_tags_to_message(emsg_tag, emsg_close_tag, encrypted_message, &temp_message2);
  
  //At this point temp_message = ;;S_KEY;;<WRAPPED SESSION KEY>;;/S_KEY;;
  //              temp_message2 = ;;E_MSG;;<E(SESSION_KEY, MSG)>;;/E_MSG;;
  temp_message3 = malloc((strlen(temp_message)+strlen(temp_message2))*sizeof(char));
  memset(temp_message3, 0, strlen(temp_message) + strlen(temp_message2));
  strcat(temp_message3, temp_message);
  strcat(temp_message3, temp_message2);
  add_tags_to_message(crypt_tag, crypt_close_tag, temp_message3, &temp_message4);

  //Set temp_message to a concatenation of temp_message and temp_message2
  free(temp_message);
  temp_message = malloc (strlen(temp_message4)*sizeof(char));
  memset(temp_message, 0, strlen(temp_message4));
  memcpy(temp_message, temp_message4, strlen(temp_message4) + 1);
  //Now overwrite message so that it reflects all the updates from above.
  free(*message);
  *message = malloc(strlen(temp_message)*sizeof(char));
  memset(*message, 0, strlen(temp_message));
  memcpy(*message, temp_message, strlen(temp_message) + 1);

/*  //DEBUGGING ONLY
  char* debug;
  purple_debug(PURPLE_DEBUG_INFO, "SySecure", "DEBUGGING: temp_message3 <START>%s<END> sender %s\n", temp_message3, sender);
  process_SYS_message (temp_message3, &debug, sender);
  //END DEBUGGING*/

  free(temp_message);
  free(temp_message2);
  free(temp_message3);
  free(temp_message4);
  free(encrypted_message);
  free(wrapped_keybuff);
}

//SYS_outgoing_cb: prepares for an outgoing message.  Notice that
//this method checks first for the enabling of SySecure and then
//checks for the presence of a public key for the intended receiver.
//If the public key does not exist, then this method will send a request for the key.
gboolean SYS_outgoing_cb (PurpleAccount *account, const char *receiver, char **message)
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

  //Necessary declarations:
  RSA_Key_Pair *key_pair;
  char* temp_message = malloc(strlen(*message)*sizeof(char));
  memset(temp_message, 0, strlen(*message));
  memcpy(temp_message, *message, strlen(*message) + 1);
  

  //Initialize pub_key
  init_pub_key(account->username);

  //1) SySecure enabled or message NULL?
  if (!SYS_enabled_check(receiver) || !(*message))
  {
    purple_debug(PURPLE_DEBUG_INFO, "SySecure", "SYS_disabled for conversation with %s.\n", receiver);
    return TRUE;
  }
  //2) Do we have the receiver's public key?
  //if (!(find_key_pair(receiver, &key_pair)))
  // FOR DEBUGGING ONLY!!!!!
  if (!(find_key_pair(account->username, &key_pair)))
  {
    purple_debug(PURPLE_DEBUG_INFO, "SySecure", "%s's public key unknown.\n", receiver);
    return FALSE;
  }
  //3) Is the key we have trusted?
  if (!(key_pair->trusted))
  {
    purple_debug(PURPLE_DEBUG_INFO, "SySecure", "%s's public key unknown.\n", receiver);
    return FALSE;
  }
  //4) SySecure is enabled and we have a trusted key for the receiver.
  purple_debug(PURPLE_DEBUG_INFO, "SySecure", "%s's public key is known and trusted and SySecure is enabled.\n", receiver);
  create_outgoing_msg(key_pair, &temp_message, account->username, receiver);
  
  if (temp_message == 0)
  {
    purple_debug(PURPLE_DEBUG_ERROR, "SySecure", "Error creating message.  Message dropped.\n");
    return FALSE;
  }
  free(*message);
  *message = malloc(strlen(temp_message)*sizeof(char));
  memset(*message, 0, strlen(temp_message));
  memcpy(*message, temp_message, strlen(temp_message) + 1);
  purple_debug(PURPLE_DEBUG_INFO, "SySecure", "TEMP_MSG: %s MESSAGE: %s\n", temp_message, *message);
  
  return TRUE;
}

gboolean send_pub_key (PurpleConversation *conv)
{
  RSA_Key_Pair *key_pair;
  SECItem *key_data;
  //SECItem *key_check;
  char* key_buffer;
  char* pub_key_wrap;
  char* pub_key_message;
  PurpleConnection *connect;
  GList *connect_list;

  if (!find_key_pair(conv->account->username, &key_pair))
  {
    purple_debug(PURPLE_DEBUG_INFO, "SySecure", "No key exists for user %s.\n", conv->account->username);
    return TRUE;
  }
   key_data = SECKEY_EncodeDERSubjectPublicKeyInfo(key_pair->pub);
   key_buffer = NSSBase64_EncodeItem(0, 0, 0, key_data);
   add_tags_to_message(pub_tag, pub_close_tag, key_buffer, &pub_key_wrap);
   add_tags_to_message(crypt_tag, crypt_close_tag, pub_key_wrap, &pub_key_message);
   //purple_debug(PURPLE_DEBUG_INFO, "SySecure", "User %s's key ready to send: %s\n", conv->account->username, key_buffer);

   connect_list = purple_connections_get_all();
   connect = (PurpleConnection*) connect_list->data;
   serv_send_im(connect, conv->name, pub_key_message, PURPLE_MESSAGE_SEND);
   

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
void SYS_create_conversation_cb (PurpleConversation *conv)
{
  purple_debug(PURPLE_DEBUG_INFO, "SySecure", 
               "New conversation created between user %s and buddy %s.\n", 
                                         conv->account->username, conv->name);
  init_pub_key(conv->account->username);
  send_pub_key(conv);
}

#endif //MSG_HANDLE_C
