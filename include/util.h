#ifndef UTIL_H
#define UTIL_H

#ifdef DEBUG
#define out_debug(fmt, args...) fprintf(stderr, fmt, ##args)
#else
#define out_debug(fmt, args...)
#endif

typedef unsigned char       BYTE;   // 1byte
typedef unsigned short      WORD;   // 2bytes
typedef unsigned long       DWORD;  // 4bytes
typedef unsigned long long  ULONGLONG;   //8bytes










#endif