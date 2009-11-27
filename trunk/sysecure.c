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

#include "sysecure.h"

#include "conv_encrypt_map.h"
#include "gtk_ui.h"

/**
 * Called when SySecure is first loaded. Registers signal callbacks, 
 * and adds SySecure menu to open conversations
 */
static gboolean plugin_load(PurplePlugin *plugin)
{
  // TODO: If we plan to use a UI other than GTK+, we should register for the
  //       signals for that UI here. 

  // Initialize the mapping between conversations to their encryption info
  init_conv_encryption_map();

  // Initialize the UI for GTK+
  init_gtk_ui(plugin);
  
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
  // unload the GTK+ UI
  //uninit_gtk_ui(plugin);
  
  // I assume this means continue unloading?
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
	PLUGIN_VERSION,            /* version */
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

