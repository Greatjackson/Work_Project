#ifndef MD5_SUM_H
#define MD5_SUM_H

typedef unsigned int u32;
typedef struct
{
    u32 A, B, C, D;   /* chaining variables */
    u32  nblocks;
    unsigned char buf[64];
    int  count;
} MD5_CONTEXT;

extern int get_md5_resust(const char *file_path, MD5_CONTEXT *md5_rst);

#endif
