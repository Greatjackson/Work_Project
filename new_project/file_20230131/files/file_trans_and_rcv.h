#ifndef FILE_TRANS_AND_RCV_H
#define FILE_TRANS_AND_RCV_H
#include <stdio.h>
#include "file_trans_and_rcv_types.h"

extern int file_send(const char *file_path, int to_fd, unsigned int delay_us, file_size_type *snd_len);
extern int file_rcv(file_info *rcv_file_info, file_size_type *rcv_len, int store_policy, int fd_data_src);

#endif
