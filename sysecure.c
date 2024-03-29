/**
 * @file
 * @brief Starting location for the project. Handles initializing the plugin
 * 
 * Registers the appropriate libpurple and GTK+ (Pidgin) callback functions to 
 * have SySecure actually do something. 
 *
 */
#ifdef HAVE_CONFIG_H
# include <config.h>
#endif

/* This will prevent compiler errors in some instances and is better explained in the
 * how-to documents on the wiki */
#ifndef G_GNUC_NULL_TERMINATED
# if __GNUC__ >= 4
#  define G_GNUC_NULL_TERMINATED __attribute__((__sentinel__))
# else
#  define G_GNUC_NULL_TERMINATED
# endif
#endif

// Needed at the top of all libpurple plugins
#ifndef PURPLE_PLUGINS
# define PURPLE_PLUGINS
#endif

#include <plugin.h>
#include <version.h>
#include <gtkplugin.h>
#include <version.h>
#include <debug.h>

#include "conv_encrypt_map.h"
#include "gtk_ui.h"
#include "msg_handle.h"
#include "pub_key.h"

#include "sysecure.h"

/**
 * Called when SySecure is first loaded. Registers signal callbacks, 
 * and adds SySecure menu to open conversations
 *
 * @return TRUE if plugin should continue loading, FALSE otherwise
 */
static gboolean plugin_load(PurplePlugin *plugin)
{
  purple_debug(PURPLE_DEBUG_INFO,
               PLUGIN_ID,
               "Compiled with Purple '%d.%d.%d'.\n",
               PURPLE_MAJOR_VERSION, 
               PURPLE_MINOR_VERSION, 
               PURPLE_MICRO_VERSION);

  if (!nss_init())
  {
    purple_debug(PURPLE_DEBUG_INFO,
                 PLUGIN_ID,
                 "NSS is not enabled. SySecure unable to operate.\n");
    
    // TODO - pop up a notify box for the user
    
    return FALSE;
  }
  
  // TODO: If we plan to use a UI other than GTK+, we should register for the
  //       signals for that UI here. 
  
  void * conv_handle;
  //Get Conversation Handle and initialize our plugin handle
  conv_handle = purple_conversations_get_handle();

  // Initialize the mapping between conversations to their encryption info
  init_conv_encryption_map();

  // Initialize the UI for GTK+
  init_gtk_ui(plugin);

  purple_signal_connect(conv_handle, "receiving-im-msg", plugin,
                        PURPLE_CALLBACK(receiving_im_cb), NULL);
  purple_signal_connect(conv_handle, "sending-im-msg", plugin,
                        PURPLE_CALLBACK(sending_im_cb), NULL);
  purple_signal_connect(conv_handle, "conversation-created", plugin,
                        PURPLE_CALLBACK(SYS_create_conversation_cb), NULL);
  
  /* Now just return TRUE to tell libpurple to finish loading. */
  return TRUE;
}

/**
 * Called when SySecure is unloaded. Unregisters signals and removes
 * SySecure menu from conversations.
 */
static gboolean
plugin_unload(PurplePlugin *plugin)
{
  // disconnect signals on unload
  purple_signals_disconnect_by_handle(plugin);

  // unload the GTK+ UI
  uninit_gtk_ui(plugin);
  
  // unload the encryption mapping
  uninit_conv_encryption_map();
  
  purple_debug(PURPLE_DEBUG_INFO,
               PLUGIN_ID,
               "Unloaded Successfully.\n");
  
  // Return TRUE to allow the plugin to continue unloading
  // NOTE: If "FALSE" is returned, the plugin will not be unloaded, Pidgin will
  // display an error.  The plugin WILL be unloaded anyway when Pidgin is closed.
  return TRUE;
}

static PurplePluginInfo info = {
	PURPLE_PLUGIN_MAGIC,        /* magic number */
	PURPLE_MAJOR_VERSION,       /* purple major */
	PURPLE_MINOR_VERSION,       /* purple minor */
	PURPLE_PLUGIN_STANDARD,     /* plugin type */
	PIDGIN_PLUGIN_TYPE,         /* UI requirement */
	0,                          /* flags */
	NULL,                       /* dependencies */
	PURPLE_PRIORITY_DEFAULT,    /* priority */

	PLUGIN_ID,                  /* id */
	"SySecure",                 /* name */
	PLUGIN_VERSION,             /* version */
	PLUGIN_SUMMARY,             /* summary */
  PLUGIN_DESC,                /* description */
	PLUGIN_AUTHOR,              /* author */
	"http://pidgin.im",         /* homepage */

	plugin_load,                /* load */
	plugin_unload,              /* unload */
	NULL,                       /* destroy */

	NULL,                       /* ui info */
	NULL,                       /* extra info */
	NULL,                       /* prefs info */
	NULL,                       /* actions */
	NULL,                       /* reserved */
	NULL,                       /* reserved */
	NULL,                       /* reserved */
	NULL                        /* reserved */
};

static void
init_plugin(PurplePlugin *plugin)
{
}

PURPLE_INIT_PLUGIN(addencryption, init_plugin, info)

