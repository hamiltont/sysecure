#ifndef CONV_ENCRYPT_MAP_C
#define CONV_ENCRYPT_MAP_C

#ifndef G_GNUC_NULL_TERMINATED
# if __GNUC__ >= 4
#  define G_GNUC_NULL_TERMINATED __attribute__((__sentinel__))
# else
#  define G_GNUC_NULL_TERMINATED
# endif
#endif
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
    {
      purple_debug_info(PLUGIN_ID,
                        "Conversation '%p' with title '%s' has no EncryptionInfo\n",
                        conv,
                        purple_conversation_get_name(conv));
      
      // Create and insert into hash table
      e_info = init_encryption_info();
      g_hash_table_insert(conv_EI,
                          conv,
                          e_info);
                          
      purple_debug_info(PLUGIN_ID,
                        "Created and returned EncryptionInfo '%p'\n",
                        e_info);
    }

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

/**
 * Disables encryption for the passed conversation
 */
void 
disable_encryption(PurpleConversation *conv)
{
  EncryptionInfo *e_info = get_encryption_info(conv);
  
  e_info->is_encrypted = FALSE;
  
  purple_debug_info(PLUGIN_ID, 
		                "Disabled encryption on conversation '%p' with name '%s'\n",
		                 conv,
		                 purple_conversation_get_name(conv));
}

void encrypt_check (gpointer key, gpointer value, gpointer userdata)
{
  EncryptionInfo *enc;
  PurpleConversation *conv;
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

/**
 * For each entry in the data structure, this prints out the information for 
 * conversation and for the Encryption Info
 */
void 
debug_conv_encrypt_map()
{
  EncryptionInfo *enc;
  PurpleConversation *conv;
/*  
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

*/

}

/**
 * Initializes the mapping structure
 */
void 
init_conv_encryption_map() {
  conv_EI = g_hash_table_new(NULL, NULL);
}


/**
 * Cleans up the mapping structure by freeing all memory
 */
void 
uninit_conv_encryption_map() {

  EncryptionInfo *enc;
  PurpleConversation *conv;
/*  GHashTableIter iter;
  gpointer key, value;

  purple_debug_info(PLUGIN_ID,
                    "Starting to clean up conversation-encryptionInfo mapping\n");
  g_hash_table_iter_init (&iter, conv_EI);
  while (g_hash_table_iter_next (&iter, &key, &value)) 
    {
      conv = key;
      enc = value;
      uninit_encryption_info(enc);
      purple_debug_info(PLUGIN_ID,
                        "Freed EncryptionInfo '%p' from conversation '%p' with name '%s'\n",
                        enc,
                        conv,
                        purple_conversation_get_name(conv));
    }
  purple_debug_info(PLUGIN_ID,
                    "Done cleaning up conversation-encryptionInfo mapping\n");
  
  // TODO - do I need to free memory here?
*/
}
#endif
