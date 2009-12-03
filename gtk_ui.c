#ifndef G_GNUC_NULL_TERMINATED
# if __GNUC__ >= 4
#  define G_GNUC_NULL_TERMINATED __attribute__((__sentinel__))
# else
#  define G_GNUC_NULL_TERMINATED
# endif
#endif
/**
 * @file
 * @brief Sets up and manages interfacing SySecure with GTK+. This includes
 *        adding security options to the chat conversation window(s) and 
 *        handling callbacks from those options.
 * 
 * TODO
 * Figure out how to link against internal.h so (_("Some String")) works
 * Add Disable Encryption options
 * Add some sort of indicator for [un]encrypted messages
 */ 

#include <glib.h>
#include <string.h>

// libpurple includes
#include <debug.h>
#include <plugin.h>
#include <version.h>

// pidgin (GTK) includes
#include <gtkconv.h>
#include <gtkconvwin.h>
#include <gtkplugin.h>

// Allows our button callbacks to actually perform some actions ;)
#include "conv_encrypt_map.h"

// Used to debug the session stuff
#include "session_keys.h"

#include "gtk_ui.h"

static GtkWidget * encryption_menuitem,
                 * decryption_menuitem;

/**
 * Callback for the 'Enable Encryption' menu item
 * @param widget The widget that caused this callback. In this case, 
 *               the Menuitem
 * @param gtk_conv The GTK+ (Pidgin) conversation showing when this 
 *                 menu item was clicked. 
 */
static void 
enable_encryption_cb(GtkWidget *widget, PidginConversation *gtk_conv)
{
  // Used to hold the 'active' pidgin conversation
  // We have no guarantee that the conversation passed to us is the 
  // conversation currently showing on the screen (AKA the one we would 
  // like to turn encryption on for). When someone is using tabbed IMs, the 
  // PidginConversation returned to us is the first conversation that opened 
  // that window (because the menubar aka our menuitem exists for _that_ 
  // conversation). In order to figure out what conversation is actually showing
  // we use this method
  PidginConversation *active_conv = pidgin_conv_window_get_active_gtkconv(gtk_conv->win);

  enable_encryption(active_conv->active_conv);
  
  gtk_widget_set_sensitive(encryption_menuitem,
                           FALSE);
  gtk_widget_set_sensitive(decryption_menuitem,
                           TRUE);

}

/**
 * Callback for the 'Disable Encryption' menu item
 * @param widget The widget that caused this callback. In this case, 
 *               the Menuitem
 * @param gtk_conv The GTK+ (Pidgin) conversation showing when this 
 *                 menu item was clicked. 
 */
static void 
disable_encryption_cb(GtkWidget *widget, PidginConversation *gtk_conv)
{
  // Used to hold the 'active' pidgin conversation
  // We have no guarantee that the conversation passed to us is the 
  // conversation currently showing on the screen (AKA the one we would 
  // like to turn encryption on for). When someone is using tabbed IMs, the 
  // PidginConversation returned to us is the first conversation that opened 
  // that window (because the menubar aka our menuitem exists for _that_ 
  // conversation). In order to figure out what conversation is actually showing
  // we use this method
  PidginConversation *active_conv = pidgin_conv_window_get_active_gtkconv(gtk_conv->win);

  disable_encryption(active_conv->active_conv);
  
  gtk_widget_set_sensitive(encryption_menuitem,
                           TRUE);
  gtk_widget_set_sensitive(decryption_menuitem,
                           FALSE);

}

// Doesnt do much now but print the encrypted chats onto the debug window
// TODO - documentation
static void 
show_chats_cb(GtkWidget *widget, gboolean data)
{
  debug_conv_encrypt_map();
}

/**
 * Callback for the active conversation switching. Updates the menu items 
 * appropriately.
 */
static void 
conversation_switched_cb(PurpleConversation *conv)
{
  if (get_encryption_info(conv)->is_encrypted == TRUE) 
  {
    gtk_widget_set_sensitive(encryption_menuitem,
                             FALSE);
    gtk_widget_set_sensitive(decryption_menuitem,
                             TRUE);                         
  }
  else
  {
    gtk_widget_set_sensitive(encryption_menuitem,
                             TRUE);
    gtk_widget_set_sensitive(decryption_menuitem,
                             FALSE);
  }
}

// Doesnt do much 
// TODO - documentation or remove
static void 
debug_session_cb(GtkWidget *widget, gboolean data)
{
  //debug_symmetric_key(generate_symmetric_key());
  
  unsigned char strdata[1024];
  strcpy(strdata, "Encrypt some text!");
  
  encrypt(generate_symmetric_key(), &strdata);
  
  purple_debug_info(PLUGIN_ID, "Want to encrypt %s", &strdata);

}

/**
 * Adds the SySecure menu to a GTK+ (Pidgin) conversation window. 
 * Checks to be sure the menu is not already present. 
 * Used as the callback function for whenever the 'conversation-displayed'
 * is fired. This is a GTK+ callback, so we know this is a PidginConversation.
 *
 * @param gtk_conv A conversation using the GTK+ UI, aka the call 
 *                 PIDGIN_IS_PIDGIN_CONVERSATION(gtk_conv) should 
 *                 always be TRUE
 */
static void
conversation_displayed_cb(PidginConversation *gtk_conv)
{
  // Items we will be creating
  GtkWidget *submenu, *submenuitem, *submenuitem2, *ss_menuitem;
  
  // Items we will be loading
  GtkWidget *menubar;
  PidginWindow *win;
  win = pidgin_conv_get_window(gtk_conv);
  menubar = win->menu.menubar;
  
  // Check that we have not added the menu already
  ss_menuitem = g_object_get_data(G_OBJECT(menubar), 
				  "encrypt_menu");
  if (ss_menuitem != NULL)
    {
      purple_debug_warning(PLUGIN_ID,  
 			   "Tried to add the SySecure Menu to chat '%s' (window '%p'), but it already existed.\n", 
			   purple_conversation_get_name(gtk_conv->active_conv), 
			   gtk_conv->win); 
      return;
    }

  //===== Create the submenu ===========
  // First, create and connect the encryption button
  submenu = gtk_menu_new();
  encryption_menuitem = gtk_menu_item_new_with_label ("Enable Encryption");
  gtk_menu_shell_append(GTK_MENU_SHELL(submenu), 
			encryption_menuitem);
  gtk_widget_show(encryption_menuitem);
  g_signal_connect(G_OBJECT(encryption_menuitem), 
		   "activate", 
		   G_CALLBACK(enable_encryption_cb), 
		   gtk_conv);	   
	
	// Then the decryption button
	decryption_menuitem = gtk_menu_item_new_with_label ("Disable Encryption");
  gtk_menu_shell_append(GTK_MENU_SHELL(submenu), 
			decryption_menuitem);
  gtk_widget_show(decryption_menuitem);
  g_signal_connect(G_OBJECT(decryption_menuitem), 
		   "activate", 
		   G_CALLBACK(disable_encryption_cb), 
		   gtk_conv);

	// Then the Show Chats button
  submenuitem = gtk_menu_item_new_with_label ("Show Chats");
  gtk_menu_shell_append(GTK_MENU_SHELL(submenu), 
			submenuitem);
  gtk_widget_show(submenuitem);
  g_signal_connect(G_OBJECT(submenuitem), 
		   "activate", 
		   G_CALLBACK(show_chats_cb), 
		   NULL);
		   
  // Then the Debug Session Key button
  submenuitem2 = gtk_menu_item_new_with_label ("Debug Session Key");
  gtk_menu_shell_append(GTK_MENU_SHELL(submenu), 
			submenuitem2);
  gtk_widget_show(submenuitem2);
  g_signal_connect(G_OBJECT(submenuitem2), 
		   "activate", 
		   G_CALLBACK(debug_session_cb), 
		   NULL);

  // Add the SySecure menu item to the window menubar, and 
  // attach the submenu to the menu item
  ss_menuitem = gtk_menu_item_new_with_label ("SySecure");
  gtk_menu_shell_append(GTK_MENU_SHELL(menubar),
			ss_menuitem);
  gtk_menu_item_set_submenu(GTK_MENU_ITEM(ss_menuitem),
			    submenu);
  gtk_widget_show(ss_menuitem);
  

  // Get the menubar to remember that we have added 
  // our menu to it by saving a pointer to the menuitem
  g_object_set_data(G_OBJECT(menubar),
		    "encrypt_menu",
		    ss_menuitem);


  purple_debug_info(PLUGIN_ID, 
		    "Added the SySecure Menu to chat '%s', window '%p'\n", 
		    purple_conversation_get_name(gtk_conv->active_conv),
		    gtk_conv->win);
		    
  // Setup the menu options appropriately
  if (get_encryption_info(gtk_conv->active_conv)->is_encrypted == TRUE) 
  {
    gtk_widget_set_sensitive(encryption_menuitem,
                             FALSE);
    gtk_widget_set_sensitive(decryption_menuitem,
                             TRUE);                         
  }
  else
  {
    gtk_widget_set_sensitive(encryption_menuitem,
                             TRUE);
    gtk_widget_set_sensitive(decryption_menuitem,
                             FALSE);
  }
}

/**
 * Removes the SySecure menu from a GTK+ (Pidgin) conversation window. 
 * Checks to be sure the menu is present before removing. We get the 
 * conversation, and not the PidginWindow itself so we can debug
 * nicely.
 *
 * @param gtk_conv A conversation using the GTK+ UI, aka the call 
 *                 PIDGIN_IS_PIDGIN_CONVERSATION(gtk_conv) should 
 *                 always be TRUE
 */
static void
remove_ss_menu_gtk(PidginConversation *gtk_conv)
{ 
  // Handle to the SySecure menu
  GtkWidget *ss_menuitem;
 
  // Handle to the window of the PidginConversation
  PidginWindow *win;

  // Handle to the menubar within the PidginWindow
  GtkWidget *menubar;

  win = pidgin_conv_get_window(gtk_conv);
  menubar = win->menu.menubar;
  
  // Check that we have added the menu already
  ss_menuitem = g_object_get_data(G_OBJECT(menubar), 
				  "encrypt_menu");
  if (ss_menuitem == NULL)
    {
      purple_debug_warning(PLUGIN_ID, 
			   "Tried to remove the SySecure Menu from chat '%s' (window '%p'), but it did not exist.\n", 
			   purple_conversation_get_name(gtk_conv->active_conv),
			   gtk_conv->win);
      return;
    }

  gtk_container_remove(GTK_CONTAINER(menubar),
		       ss_menuitem);

  // Get the menubar to remember that we have added 
  // our menu to it by saving a pointer to the menuitem
  g_object_set_data(G_OBJECT(menubar),
		    "encrypt_menu",
		    NULL);

  purple_debug_info(PLUGIN_ID, 
		    "Removed the SySecure Menu from chat '%s'\n", 
		    purple_conversation_get_name(gtk_conv->active_conv));
}


/**
 * Adds the SySecure options to all open GTK user conversations, and connects
 * a callback for new GTK conversation windows being opened
 *
 * @param plugin The SySecure plugin. This is needed to be able to connect 
 *               signal callbacks. 
 */
void
init_gtk_ui(PurplePlugin *plugin) 
{

  // We need to add the SySecure menu to all currently
  // open conversation windows
  GList *conversations = purple_get_conversations();
 
  // We want to register for the 'conversation-displayed' signal, so 
  // we can add the button to the created GTK+ conv window
  void *gtk_conversation_handle = pidgin_conversations_get_handle();

  // Call us back when a new conv window is created
  // 'conversation-displayed' is a GTK callback, so this will only
  // be fired if Pidgin is being used
  purple_signal_connect(gtk_conversation_handle, 
			"conversation-displayed", 
			plugin, 
			PURPLE_CALLBACK(conversation_displayed_cb), 
			NULL);
  purple_debug_info(PLUGIN_ID,
		    "Connected conversation-display signal\n");
		    
		      // Inject our menu into all open gtk windows
  purple_debug_info(PLUGIN_ID,
		    "Beginning to inject menu into open windows\n");
  while (conversations) {
    PurpleConversation *current_conv = 
      (PurpleConversation *)conversations->data;

    // Only inject if this is a gtk window
    if (PIDGIN_IS_PIDGIN_CONVERSATION(current_conv))
      conversation_displayed_cb(PIDGIN_CONVERSATION(current_conv));

    conversations = conversations->next;
  }

  purple_debug_info(PLUGIN_ID,
		    "Done injecting button into open windows\n");
		    
  // Call us back when the active conv window is switched
  // 'conversation-switched' is a GTK callback, so this will only
  // be fired if Pidgin is being used
  purple_signal_connect(gtk_conversation_handle, 
			"conversation-switched", 
			plugin, 
			PURPLE_CALLBACK(conversation_switched_cb), 
			NULL);
  purple_debug_info(PLUGIN_ID,
		    "Connected conversation-switched signal\n");
}

/**
 * Removes the SySecure options to all open GTK user conversations, and 
 * disconnects callbacks for new GTK conversation windows being opened
 *
 * @param plugin The SySecure plugin. This is needed to be able to disconnect 
 *               signal callbacks. 
 */
void 
uninit_gtk_ui(PurplePlugin *plugin) 
{
  GList *convs = purple_get_conversations();

  // We want to register for the 'conversation-displayed' signal, so 
  // we can add the button to the created conv window
  void *gtk_conversation_handle = pidgin_conversations_get_handle();

  // Clean up our connected signals
  purple_signal_disconnect(gtk_conversation_handle, 
			   "conversation-displayed", 
			   plugin, 
			   PURPLE_CALLBACK(conversation_displayed_cb));
  purple_debug_info(PLUGIN_ID,
		    "Disconnected conversation-display signal\n");  

  // Clean up our connected signals
  purple_signal_disconnect(gtk_conversation_handle, 
			"conversation-switched", 
			plugin, 
			PURPLE_CALLBACK(conversation_switched_cb));
	purple_debug_info(PLUGIN_ID,
		    "Disconnected conversation-switched signal\n");  

  while (convs) {
    PurpleConversation *conv = (PurpleConversation *)convs->data;

    // Remove SySecure menu
    if (PIDGIN_IS_PIDGIN_CONVERSATION(conv))
      remove_ss_menu_gtk(PIDGIN_CONVERSATION(conv));

    convs = convs->next;
  }
}

