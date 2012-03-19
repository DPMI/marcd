#ifndef MARCD_UTILS_H
#define MARCD_UTILS_H

/* Convert a string ip with dotted decimal to a hexc.. */
int inet_atoP(char *dest,char *org);

char* inet_ntoa_r(struct in_addr in, char* dst);

#endif /* MARCD_UTILS_H */
