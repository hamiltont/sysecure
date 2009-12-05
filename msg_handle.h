/*                      SySecure Encryption Protocol                        */
/*                    Copyright (C) 2009 Jason R. Cody                    */

/* This plugin is free software, distributed under the GNU General Public */
/* License.                                                               */
/* Please see the file "COPYING" distributed with this source code        */
/* for more details                                                       */
/*                                                                        */
/*                                                                        */
/*    This software is distributed in the hope that it will be useful,    */
/*   but WITHOUT ANY WARRANTY; without even the implied warranty of       */
/*   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU    */
/*   General Public License for more details.                             */

//---------------------------------------------------------------------------//
//Title: message_handle.h                                                    //
//Purpose:  The purpose of this file is to provide an interface to intercept //
//  and handle incoming and outgoing messages (check for encryption and take //
//  appropriate actions).                                                    //
//---------------------------------------------------------------------------//
//References:                                                                //
//  1) William Tompkins, "GAIM Encryption Plugin," (available at             //
//     http://pidgin-encrypt.sourceforge.net/, last accessed on 23NOV09)     //
//     NOTE:  Based our encryption files on this plugn.  This plugin uses    //
//     STRICTLY RSA encryption with public announcement.  We will be         //
//     using PKI to distribute symmetric session keys that will be encrypted //
//     and attached to the outgoing message (similar to the PGP protocol).   //
//---------------------------------------------------------------------------//

#ifndef MSG_HANDLE_H
#define MSG_HANDLE_H

#ifndef G_GNUC_NULL_TERMINATED
# if __GNUC__ >= 4
#  define G_GNUC_NULL_TERMINATED __attribute__((__sentinel__))
# else
#  define G_GNUC_NULL_TERMINATED
# endif
#endif

// Needed for a lot
#include <glib.h>

//Pidgin-LibPurple includes:
#include "server.h"
#include "request.h"
#include "cmds.h"
#include "notify.h"
#include "plugin.h"
#include "version.h"
#include "debug.h"
#include "conversation.h"

//Standard C includes:
#include "stdio.h"
#include "time.h"
#include "stdlib.h"
#include "string.h"

// NSS includes
#include "nss.h"
#include "pk11pub.h"
#include "pk11func.h"
#include "nssb64.h"
#include "base64.h"

//SYSECURE includes:
#include "conv_encrypt_map.h"
#include "pub_key.h"
#include "session_keys.h"

gboolean SYS_enabled_check (char *id);

char* SYS_tag_check (char *message, char *tag);

gboolean SYS_incoming_cb (PurpleAccount *acct, char **who, char **message,
                                    PurpleConversation *conv, int *flags);

gboolean SYS_outgoing_cb (PurpleAccount *account, const char *receiver, char **message);


#endif //MSG_HANDLE_H
