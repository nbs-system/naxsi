// SPDX-FileCopyrightText: 1999 Markus Kuhn <mgk25@cl.cam.ac.uk>
// SPDX-License-Identifier: LGPL-3.0-only

#include <naxsi.h>

/* @file naxsi_utf8.c
 *
 * Checks if the string is containing invalid utf8 codes.
 *
 * Original code from https://www.cl.cam.ac.uk/~mgk25/ucs/utf8_check.c
 */

unsigned char*
ngx_utf8_check(ngx_str_t* str)
{
  unsigned int   offset = 0;
  unsigned char* s;

  s = str->data;

  while (offset < str->len && *s) {
    if (*s < 0x80) {
      /* 0xxxxxxx */
      s++;
      offset++;
    } else if ((s[0] & 0xe0) == 0xc0) {
      if (offset + 1 >= str->len) {
        // not enough bytes
        return s;
      }
      /* 110XXXXx 10xxxxxx */
      if ((s[1] & 0xc0) != 0x80 || (s[0] & 0xfe) == 0xc0) { /* overlong? */
        return s;
      } else {
        s += 2;
        offset += 2;
      }
    } else if ((s[0] & 0xf0) == 0xe0) {
      if (offset + 2 >= str->len) {
        // not enough bytes
        return s;
      }
      /* 1110XXXX 10Xxxxxx 10xxxxxx */
      if ((s[1] & 0xc0) != 0x80 || (s[2] & 0xc0) != 0x80 ||
          (s[0] == 0xe0 && (s[1] & 0xe0) == 0x80) ||                 /* overlong? */
          (s[0] == 0xed && (s[1] & 0xe0) == 0xa0) ||                 /* surrogate? */
          (s[0] == 0xef && s[1] == 0xbf && (s[2] & 0xfe) == 0xbe)) { /* U+FFFE or U+FFFF? */
        return s;
      } else {
        s += 3;
        offset += 3;
      }
    } else if ((s[0] & 0xf8) == 0xf0) {
      if (offset + 3 >= str->len) {
        // not enough bytes
        return s;
      }
      /* 11110XXX 10XXxxxx 10xxxxxx 10xxxxxx */
      if ((s[1] & 0xc0) != 0x80 || (s[2] & 0xc0) != 0x80 || (s[3] & 0xc0) != 0x80 ||
          (s[0] == 0xf0 && (s[1] & 0xf0) == 0x80) ||      /* overlong? */
          (s[0] == 0xf4 && s[1] > 0x8f) || s[0] > 0xf4) { /* > U+10FFFF? */
        return s;
      } else {
        s += 4;
        offset += 4;
      }
    } else {
      return s;
    }
  }
  return NULL;
}