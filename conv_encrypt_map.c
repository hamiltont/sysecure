/**
 * @file
 * @brief This file presents an interface to allow a mapping between a unique
 *        libpurple conversation object and a sysecure encryption details 
 *        object. 
 * 
 * This file presents an interface to a managed hash map. If an 
 * EncryptionInfo object does not exist for a queried conversation, a new
 * object will be created and returned. When the uninit method of this class 
 * is called, it cleans up the memory used, and has a change to store some 
 * information permanently (although right now it does not). 
 */

// Needed for a lot
#include <glib.h>

// libpurple debugging
#include <debug.h>

// Needed for PurpleConversation
#include "conversation.h"

// Needed for EncryptionInfo
#include "globals.h"

#include "conv_encrypt_map.h"

/**
 * Used to store the EncryptionInfo information associated with each
 * conversation.
 */
static GHashTable *conv_EI = NULL;

/**
 * Retrieves the EncryptionInfo for a specific conversation. If the passed
 * conversation has no EncryptionInfo, a default EncryptionInfo is created and
 * returned
 */
EncryptionInfo *
get_encryption_info(PurpleConversation *conv)
{
  EncryptionInfo *e_info;
  
  // Check to see if the EI exists yet
  e_info = (EncryptionInfo *)g_hash_table_lookup(conv_EI,
                                                 conv);
  
  // Create it if it does not
  if (e_info == NULL)
    e_info = init_encryption_info();
    
  return e_info;  
}

/**
 * Enables encryption for the passed conversation
 */
void 
enable_encryption(PurpleConversation *conv)
{
  EncryptionInfo *e_info = get_encryption_info(conv);
  
  e_info->is_encrypted = TRUE;
  
  purple_debug_info(PLUGIN_ID, 
		                "Enabled encryption on conversation '%p' with name '%s'\n",
		                 conv,
		                 purple_conversation_get_name(conv));
}

void 
debug_conv_encrypt_map()
{
  EncryptionInfo *enc;
  PurpleConversation *conv;
  GHashTableIter iter;
  gpointer key, value;

  g_hash_table_iter_init (&iter, conv_EI);
  while (g_hash_table_iter_next (&iter, &key, &value)) 
    {
      conv = key;
      enc = value;
      if (enc->is_encrypted)
	      purple_debug_info(PLUGIN_ID,
			                    "Conversation '%p' with name '%s' is encrypted\n",
			                    conv,
			                    purple_conversation_get_name(conv));
      else
	      purple_debug_info(PLUGIN_ID,
			                    "Conversation '%p' with name '%s' is not encrypted\n",
			                    conv,
			                    purple_conversation_get_name(conv));
    }
}

/**
 * Initializes the mapping structure
 */
void 
init_conv_encryption_map() {
  conv_EI = g_hash_table_new(NULL, NULL);
}


/**
 * Cleans up the mapping structure
 */
void 
uninit_conv_encryption_map() {

}
