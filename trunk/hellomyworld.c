#define PURPLE_PLUGINS

#include <glib.h> 

#include "notify.h" 
#include "plugin.h" 
#include "version.h"

/* We need a plugin handle. This is assigned in load */
PurplePlugin *helloworld_plugin = NULL;

static gboolean 
plugin_load(PurplePlugin *plugin) {
    purple_notify_message(plugin, PURPLE_NOTIFY_MSG_INFO, "Hello World!",
	"This is the Hello World! plugin :)", 
	NULL, NULL, NULL);
    
    /* Assign so we have a valid handle later */
    helloworld_plugin = plugin;
    return TRUE;
}

static void 
plugin_action_test_cb(PurplePluginAction *action)
{
  purple_notify_message(helloworld_plugin, PURPLE_NOTIFY_MSG_INFO, "Plugin Actions Test", "This is a plugins action test :)", NULL, NULL, NULL);

}

static GList*
plugin_actions(PurplePlugin *plugin, gpointer context) 
{
  GList* list = NULL;
  PurplePluginAction* action = NULL;

  action = purple_plugin_action_new("Plugin Action Test", plugin_action_test_cb);

  list = g_list_append(list, action);

  return list;
}

static PurplePluginInfo info = {
    PURPLE_PLUGIN_MAGIC,
    PURPLE_MAJOR_VERSION,
    PURPLE_MINOR_VERSION,
    PURPLE_PLUGIN_STANDARD,
    NULL,
    0,
    NULL,
    PURPLE_PRIORITY_DEFAULT,

    "core-hello_world",
    "Hello World!",
    "1.1",

    "Hello World Plugin",
    "Hello World Plugin",
    "My Name <email@helloworld.tld>",
    "http://helloworld.tld",
    
    plugin_load,
    NULL,
    NULL,
                                   
    NULL,
    NULL,
    NULL,
    plugin_actions,
   
    NULL,
    NULL,
    NULL,
    NULL
};
    
static void 
init_plugin(PurplePlugin *plugin)
{
}

PURPLE_INIT_PLUGIN(hello_world, init_plugin, info)
