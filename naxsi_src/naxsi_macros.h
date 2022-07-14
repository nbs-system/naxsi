// SPDX-FileCopyrightText: 2019, Giovanni Dante Grazioli <gda@nbs-system.com>
// SPDX-License-Identifier: GPL-3.0-or-later

#ifndef __NAXSI_MACROS_H__
#define __NAXSI_MACROS_H__

#define is_whitespace(c) ((c) == ' ' || (c) == '\t' || (c) == '\n' || (c) == '\r')
#define is_printable(c)  ((c) >= ' ' && (c) <= '~')
#define is_numeric(c)    ((c) >= '0' && (c) <= '9')
#define const_len(s)     (sizeof(s) - sizeof(s[0]))

#define return_value_if(cond, val)                                                                 \
  if ((cond))                                                                                      \
  return (val)
#define return_void_if(cond)                                                                       \
  if ((cond))                                                                                      \
  return
#define break_if(cond)                                                                             \
  if ((cond))                                                                                      \
  break

#endif /* __NAXSI_MACROS_H__ */
