#ifndef MSG_HANDLE_C
#define MSG_HANDLE_C

#include "msg_handle.h"

gboolean SYS_enabled_check (char *id)
{
  GList *conv_list = NULL;
  GList *temp_ptr = NULL;
  EncryptionInfo *e_info;
  gboolean found = FALSE;
  conv_list = purple_get_conversations();
  temp_ptr = conv_list;
  if (conv_list == NULL)
  {
    purple_debug(PURPLE_DEBUG_INFO, "SySecure", "NO CONVERSATIONS from purple_get_conversations()!\n");
    return FALSE;
  }
  while(temp_ptr && found == FALSE)
  {
    if ((purple_conversation_get_name((PurpleConversation*)(temp_ptr->data))) == id)
    {
      found = TRUE;
    }
    if (!found)
      temp_ptr = temp_ptr->next;
  }
  if (!temp_ptr)
    return FALSE;
  else
  {
    e_info = get_encryption_info((PurpleConversation*)(temp_ptr->data));
    if (!(e_info))
      purple_debug(PURPLE_DEBUG_ERROR, "SySecure", "SYS_enabled_check: e_info is NULL!");
    else 
    {
      if (e_info->is_encrypted)
        purple_debug(PURPLE_DEBUG_INFO, "SySecure", "SYS_enabled_check: e_info->is_encrypted is TRUE!");
      else
        purple_debug(PURPLE_DEBUG_INFO, "SySecure", "SYS_enabled_check: e_info->is_encrypted is FALSE!");
    }
    return e_info->is_encrypted;
  }
}

char* SYS_tag_check (char *message, char *tag)
{
  char* tag_ptr;
  tag_ptr = strstr(message, tag);
  return tag_ptr;
}

gboolean SYS_incoming_cb (PurpleAccount *acct, char **who, char **message,
                                    PurpleConversation *conv, int *flags)
{
  EncryptionInfo* e_info = NULL;
  //Note:  libpurple converts special characters when it receives them.
  //Below is the same <SYSECURE> tag from above encoded.  On receipt of a message
  //the check below will check for the <SYSECURE> tag.
  char crypt_tag[] = "&lt;SYSECURE&gt;";
  GList* conv_list = NULL;
  GList* temp_ptr = NULL;
  
  init_pub_key(acct->username);

  conv_list = purple_get_conversations();
  temp_ptr = conv_list;
  if (conv_list == NULL)
  {
    purple_debug(PURPLE_DEBUG_INFO, "SySecure", "NO CONVERSATIONS from purple_get_conversations()!\n");
    return TRUE;
  }

   while (g_list_next(temp_ptr))
   {
     if (purple_conversation_get_name(temp_ptr->data) == *who)
     { 
       conv = temp_ptr->data;
     }
     temp_ptr = temp_ptr->next;
   }
  
  if (conv == NULL)
  {
    purple_debug(PURPLE_DEBUG_INFO, "SySecure", "conversation not found.\n");
  }
  else
  {
    purple_debug(PURPLE_DEBUG_INFO, "SySecure", "Conversation with %s in progress.\n", purple_conversation_get_name(conv));
  }
  
  if (*message != NULL)
  {
    purple_debug(PURPLE_DEBUG_INFO, "Sysecure", "Message Received: %s.\n",
               *message);
    e_info = get_encryption_info(conv);
    if (SYS_tag_check(*message, crypt_tag) && e_info->is_encrypted)
    {
      purple_debug(PURPLE_DEBUG_INFO, "SySecure", "Encrypted message received. %s\n", *message);
      //add decrypt code here.
    }
    else if (SYS_tag_check(*message, crypt_tag))
    {
      purple_debug(PURPLE_DEBUG_INFO, "SySecure", "Encrypted message received, but Encryption disabled! %s\n", *message);
      //add notification here and the user ability to turn on encryption to read the message.
    }
    else
    {
      purple_conversation_write(conv, NULL, 
	  					*message, PURPLE_MESSAGE_RECV, time(NULL));
    }
    
  }
  else 
  {
    purple_debug(PURPLE_DEBUG_INFO, "SySecure", "NULL Message Received!\n");
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
  //Declare message tags
  char crypt_tag[] = ";;SYSECURE;;";
  char crypt_close_tag[] = ";;/SYSECURE;;";
  char id_tag[] = ";;ID;;";
  char id_close_tag[] = ";;/ID;;";
  char key_tag[] = ";;S_KEY;;";
  char key_close_tag[] = ";;/S_KEY;;";
  char emsg_tag[] = ";;E_MSG;;";
  char emsg_close_tag[] = ";;/E_MSG;;";
  char msg_tag[] = ";;MSG;;";
  char msg_close_tag[] = ";;/MSG;;";
  char hash_tag[] = ";;HASH;;";
  char hash_close_tag[] = ";;/HASH;;";

  //declare temporary variables
  char* temp_message;
  char* temp_message2;
  char* temp_message3;
  unsigned char* temp_encrypted_message;
  char *encrypted_message;
  unsigned int encrypted_msg_length;
  PK11SymKey *session_key;
  SECItem *wrapped_key;
  char *wrapped_keybuff;

  //1) Add the Session Key, encrypted
  session_key = generate_symmetric_key();
  //NOTE:  I am wrapping this in the sender's public key for debugging purposes ONLY.
  wrap_symkey(session_key, &wrapped_key, sender);
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
  memset(encrypted_message + encrypted_msg_length, '\0', 1);
  add_tags_to_message(emsg_tag, emsg_close_tag, encrypted_message, &temp_message2);
  
  //At this point temp_message = ;;S_KEY;;<WRAPPED SESSION KEY>;;/S_KEY;;
  //              temp_message2 = ;;E_MSG;;<E(SESSION_KEY, MSG)>;;/E_MSG;;
  temp_message3 = malloc((strlen(temp_message)+strlen(temp_message2))*sizeof(char));
  memset(temp_message3, 0, strlen(temp_message) + strlen(temp_message2));
  strcat(temp_message3, temp_message);
  strcat(temp_message3, temp_message2);

  //Set temp_message to a concatenation of temp_message and temp_message2
  free(temp_message);
  temp_message = malloc (strlen(temp_message3)*sizeof(char));
  memset(temp_message, 0, strlen(temp_message3));
  memcpy(temp_message, temp_message3, strlen(temp_message3) + 1);
  //Now overwrite message so that it reflects all the updates from above.
  free(*message);
  *message = malloc(strlen(temp_message)*sizeof(char));
  memset(*message, 0, strlen(temp_message));
  memcpy(*message, temp_message, strlen(temp_message) + 1);

  free(temp_message);
  free(temp_message2);
  free(temp_message3);
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

/*
  char* temp_string = malloc(strlen(*message)*sizeof(char));
  char* enc_msg;
  PK11SymKey *key;
  PK11SymKey *test_key;
  int key_length;
  SECItem* key_data;
  char* key_buff;
  PRBool compare_check = FALSE;

  //First check for a NULL message
  if (!*message)
    return TRUE;

  if (!SYS_enabled_check(receiver))
  {
    purple_debug(PURPLE_DEBUG_INFO, "SySecure", "SYS_disabled for conversation with %s.\n", receiver);
    return TRUE;
  }

  purple_debug(PURPLE_DEBUG_INFO, "SySecure", "SYS_disabled for conversation with %s.\n", receiver);
  

  init_pub_key(account->username);

  //If SySecure is Enabled then build a new message
  memset(temp_string, 0, strlen(*message));
  memcpy(temp_string, *message, strlen(*message) + 1);

  //Create the outgoing message
  create_outgoing_msg(&temp_string);

  //Overwrite original message
  free(*message);
  *message = malloc(strlen(temp_string)*sizeof(char));
  memset(*message, 0, strlen(temp_string));
  memcpy(*message, temp_string, strlen(temp_string) + 1);

  key = generate_symmetric_key();
  key_length = PK11_GetKeyLength(key);
  wrap_symkey(key, &key_data, account->username);
  unwrap_symkey(key_data, account->username, &test_key);
  
  compare_check = compare_symkeys (key, test_key);
  if (compare_check)
    purple_debug(PURPLE_DEBUG_INFO, "SySecure", "Key generated and wrapped and unwrapped successfully.\n");
  else
   purple_debug(PURPLE_DEBUG_INFO, "SySecure", "Key generated but failed wrap/unwrap comparison.\n");
  //key_data = PK11_GetKeyData(key);
  key_buff = NSSBase64_EncodeItem(0, 0, 0, key_data);
  purple_debug(PURPLE_DEBUG_INFO, "SySecure", "Key generated and wrapped.  Length: %d Key_buff: %s\n", key_length, key_buff);

  //pub_key_encrypt(&enc_msg, &(*message), account->username);
  
  purple_debug(PURPLE_DEBUG_INFO, "SySecure", "TEMP_Message Sent: %s.\n",
               temp_string);
  purple_debug(PURPLE_DEBUG_INFO, "SySecure", "Message Sent: %s.\n",
               *message);
  return TRUE;
*/
}

#endif //MSG_HANDLE_C
