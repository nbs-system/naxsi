/*
** x=ww;y=zz
*/
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

enum state {
  ERROR=0,
  B_KEY,
  KEY,
  A_KEY,
  SEP,
  B_VAL,
  VAL,
  A_VAL,
  COMPLETE
};

/*
** check allowed nb of space/tabs in B_KEY/A_KEY/B_VAL
** check max key/val lens
*/
void p_cookies(char *cookie) {
  char	state = B_KEY;
  char	*curr = cookie;
  char  *ks,*ke,*vs,*ve;
  int	kl,vl;
  
  while (*curr && state != ERROR) {
    printf("[%d]", state);
    switch (state) {
      
    case B_KEY: /* after ; or before anything : skip on spaces */
      ks = ke = vs = ve = NULL;
      vl = kl = 0;
      if (*curr == ' ' || *curr == '\t')
	curr++;
      else {
	state = KEY;
	ks = curr;
      }
      break;
      
    case KEY: /* in key name and before = : eat untill = */
      if (*curr == '=')
	state = A_KEY;
      else {
	ke = curr;
	curr++;
      }
      break;
      
    case A_KEY: /* After the key, before = : skip on spaces, stop on = */
      if (*curr == ' ' || *curr == '\t')
	curr++;
      else if (*curr == '=')
	state = SEP;
      else
	state = ERROR;
      break;
      
    case SEP: /* = */
      if (*curr == '=') {
	curr++;
	state = B_VAL;
      }
      else
	state = ERROR;
      break;
      
    case B_VAL: /* after =, before value */
      if (*curr == ' ' || *curr == '\t')
	curr++;
      else {
	vs = curr;
	state = VAL;
      }
      break;
      
    case VAL: /* in the actual value, followed by ; or EOL */
      if (*curr == ';')
	state = COMPLETE;
      else if (*(curr+1) == '\0') {
	state = COMPLETE;
	ve = curr;
      }
      else {
	ve = curr;
	curr++;
      }
      break;
      
    case COMPLETE: /* We have a full cookie, process :) */
      kl = ke-ks+1;
      vl = ve-vs+1;
      printf("now, do things\n");
      printf("len(s) key %d or val %d\n", kl, vl);
      if (!ks || !ke || !vs || !ve || kl < 1 || vl < 1) {
	printf("empty key %d or val %d\n", kl, vl);
	state = ERROR;
	break;
      }
      
      /* process the *** out of the data */
      char *k = malloc(kl+1);
      memcpy(k, ks, kl);
      char *v = malloc(vl+1);
      memcpy(v, vs, vl);
      printf("vals '%s' '%s'\n", k, v);
      ks = ke = vs = ve = NULL;
      state = B_KEY;
      curr++;
      break;
    }
  }
  if (state != B_KEY) {
    printf("misformed cookie, do stuff !!\n");
  }
}


int main(int ac, char **av) {
  char in[1024];
  memset(in, 0, 1024);
  read(0, in, 1024);
  p_cookies(in);
}
