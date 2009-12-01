#ifndef MSG_HANDLE_C
#define MSG_HANDLE_C

#include "msg_handle.h"

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
    if ((SYS_tag_check(*message, crypt_tag)) && (e_info->is_encrypted))
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


gboolean SYS_outgoing_cb (PurpleAccount *acct, char **who, char **message,
                                    PurpleConversation *conv, int *flags)
{
  //Insert the following check for "Use_SySecure" boolean here:
  //if (!Use_SySecure)
  //  return TRUE;
  //Note:  Returning "TRUE" will let the message be sent, as 
  //normal, unmolested.

  //Otherwise, we need compile the message.
  //1) Add <SYSECURE> tag.
  //2) Add ID for sender.
  //3) Add key (initially we'll transmit in the 
  //   clear--for testing only).<--will be encrypted with receiver's public key
  //4) Add message (initially in the clear --+
  //   for testing only).                    |--will be encrypted with session key
  //5) Add hash (initially in the clear)   --+
  
  char crypt_tag[] = "<SYSECURE>";
  char id_tag[] = "<ID>";
  char id_close_tag[] = "</ID>";
  char key_tag[] = "<KEY>";
  char key_close_tag[] = "</KEY>";

  char temp_string[strlen(crypt_tag) + strlen(message)];
  char temp_message[strlen(crypt_tag) + strlen(*message)];

  purple_debug(PURPLE_DEBUG_INFO, "SySecure", "Message Sent: %s.\n",
               *message);
  memset(temp_message, 0, strlen(crypt_tag) + strlen(*message));
  memcpy(temp_message, crypt_tag, strlen(crypt_tag));

  if (*message != NULL)
  { 
    memcpy(temp_message + strlen(crypt_tag), *message, strlen(*message) + 1);
    free(*message);
    *message = malloc(sizeof(char[strlen(temp_message)]));
    memset(*message, 0, strlen(temp_message));
    memcpy(*message, temp_message, strlen(temp_message) + 1);
    purple_debug(PURPLE_DEBUG_INFO, "SySecure", "Message Sent: %s.\n",
               temp_message);
  }
  else 
  {
    purple_debug(PURPLE_DEBUG_INFO, "SySecure", "NULL Message Sent!\n");
  }
  return TRUE;
}

#endif //MSG_HANDLE_C
