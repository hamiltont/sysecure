/*                      SySecure Encryption Protocol                        */
/*                    Copyright (C) 2009 Hamilton Turner                    */

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


#ifndef SESSION_KEY_H
#define SESSION_KEY_H

#ifndef G_GNUC_NULL_TERMINATED
# if __GNUC__ >= 4
#  define G_GNUC_NULL_TERMINATED __attribute__((__sentinel__))
# else
#  define G_GNUC_NULL_TERMINATED
# endif
#endif

#include "pk11pub.h"

PK11SymKey * generate_symmetric_key();

void debug_symmetric_key(PK11SymKey * key);

#endif //SESSION_KEY_H
