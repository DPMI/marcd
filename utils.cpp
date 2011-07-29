#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "utils.h"
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <linux/if_ether.h>

int inet_atoP(char *dest,char *org){
  char tmp[3];
  tmp[2]='\0';
  int j,k;
  j=k=0;
  int t;
  for(j=0;j<ETH_ALEN;j++){
    strncpy(tmp,org+k,2);
    t=(int)strtoul(tmp,NULL,16);
    *(dest+j)=t;
    k=k+2;
  }
  return 1;
}

char* inet_ntoa_r(struct in_addr in, char* dst){
  strcpy(dst, inet_ntoa(in));
  return dst;
}
