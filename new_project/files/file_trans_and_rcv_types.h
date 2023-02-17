#ifndef FILE_TRANS_AND_RCV_TYPES_H
#define FILE_TRANS_AND_RCV_TYPES_H
#include <stdio.h>
#include "crc.h"

//#define ARRAY_SIZE(x)   (sizeof((x)) / sizeof((x)[0]))
#define STROE_AFTER_RCV_DONE   1
#define STROE_WHILE_RCV        2
#define PAYLOAD_LEN 1400

//typedef off_t file_size_type;
typedef unsigned int file_size_type;

typedef enum
{
    STATUS_OK = 1, STATUS_RANDOM_NUM_CHECK_ERR, STATUS_CRC_CHECK_ERR, STATUS_MD5_CHECK_ERR,
} ack_type;

#define MD5_RST_LEN 16
typedef struct
{
    unsigned int pack_head;
    file_size_type filesize;
    long long int challenge_id;
    char file_name[32];//只支持当前路径下的文件，注意
    unsigned char md5_rst[MD5_RST_LEN];
    unsigned char reserve[12];
    CHECK_TYPE check_rst;
} file_info;

typedef struct
{
    unsigned int pack_head;
    unsigned int packid;
    long long int challenge_id;
    unsigned int real_payload_len;
    unsigned char pay_load[PAYLOAD_LEN];
    CHECK_TYPE check_rst;
} trans_load;

typedef union
{
    file_info src_file_info;
    trans_load pay_load;
} rcv_load;

typedef struct
{
    unsigned int pack_head;
    unsigned int packid;
    long long int challenge_id;
    ack_type reply;
    CHECK_TYPE check_rst;
} trans_reply;

#endif
