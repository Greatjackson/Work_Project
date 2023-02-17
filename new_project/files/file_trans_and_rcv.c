#define _LARGEFILE_SOURCE
#define _LARGEFILE64_SOURCE
#define _FILE_OFFSET_BITS 64
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <math.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <poll.h>
#include <stdlib.h>
#include <pthread.h>
#include <arpa/inet.h>
#include <sys/time.h>
#include <termios.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <arpa/inet.h>

#include "ucas_log.h"
#include "file_trans_and_rcv_types.h"
#include "md5sum.h"

#define LOG_TAG "file_trans_and_rcv.c :"

#define FPGA_CHECK_FAILED 0xaf
#define FPGA_CHECK_OK 0xa1

#define UPDATE_BEGIN        0xfe
#define SND_FIRMWARE_DATA   0xfd
#define SND_FIRMWARE_DONE   0xfc

//#define PRINT_DEBUG
#define ENABLE_PACK_CRC_CHECK

static int open_or_create_file(const char *file_path, int clean_file)
{
    int fd = -1, ret_val = -1;
    fd = open(file_path, O_RDWR | O_CREAT | O_LARGEFILE, 0777);
    if (fd < 0)
    {
        LOGE(LOG_TAG"open failed for file:%s,errno = %d\r\n", file_path, errno);
        return -errno;
    }

    if (clean_file)
    {
        ret_val = ftruncate(fd, 0);
        if (ret_val < 0)
        {
            LOGE(LOG_TAG"ftruncate failed for file:%s,errno = %d\r\n", file_path, errno);
            return -errno;
        }
    }

    return fd;
}

static file_size_type get_file_size(int fd)
{
    file_size_type size = 0, current = 0;
    current = lseek(fd, 0, SEEK_CUR);
    RETURN_ERR(LOG_TAG, "lseek", current < 0);

    size = lseek(fd, 0, SEEK_END);
    RETURN_ERR(LOG_TAG, "lseek", size < 0);

    current = lseek(fd, current, SEEK_SET);
    RETURN_ERR(LOG_TAG, "lseek", current < 0);

    return size;
}

static int give_up_rcv(void *buff, size_t len)
{
    file_info *file_info_ptr = (file_info *)(buff);
    if (file_info_ptr->pack_head == UPDATE_BEGIN)
        return 1;
    else
        return 0;
}

static int sec_read(int fd, void *buffer, size_t len, int (*give_up_cond)(void *buff, size_t len), int retry_enable)
{
    int ret_val = -1, read_len = 0, retry_count = 0;
sec_read_retry:
    ret_val = read(fd, buffer + read_len, len - read_len);
    if (ret_val < 0)
    {
        LOGE("get net_data faild,errno = %d\r\n", errno);
        return -errno;
    }

    if (retry_enable)
    {
        if (give_up_cond && give_up_cond(buffer + read_len, ret_val))
        return ret_val;

        read_len += ret_val;
        if (read_len < len)
        {
            if (retry_count++ < 10) goto sec_read_retry;
        }
    }

    return read_len;
}

/*
file_info: 文件信息，记录文件大小名称，md5等等
rcv_len: 单次传输过程累计接收的长度，每次重启传输该值会被清零
store_policy:存储策略，store_policy为STROE_WHILE_RCV, 边接收边存储，STROE_AFTER_RCV_DONE，
    接收完以后再存储，设置存储策略是因为在某些性能比较低的cpu上，比如z7的arm，STROE_WHILE_RCV
    会导致包接收明显变慢

    STROE_WHILE_RCV策略下，软件会申请 数据包 大小1024对齐的空间，每次接收到的数据会立刻
    存储到fd_store对应的文件，直到数据接收完

    STROE_AFTER_RCV_DONE策略下，软件会先申请100M内存(远程更新时候目前最大文件size小于这个值)，
    用于存放接收到的数据，接收完数据后将数据一次性写入
fd_data_src: 数据来源的描述符，可以是网络，串口，spi，管道，i2c等等
*/
int file_rcv(file_info *rcv_file_info, file_size_type *rcv_len, int store_policy, int fd_data_src)
{
    int file_size = 0, ret_val = -1, fd_store = -1, i = 0, cur_rcv_len = 0;
    long long int challenge_id = 0;
    unsigned int pack_id = 0;
    unsigned int crc_rst = 0;
    file_size_type rcv_count = 0;
    unsigned char *file_container_ptr = NULL;
    rcv_load  rcv_pay_load;
    file_info *file_info_ptr = (file_info *)(&rcv_pay_load);
    file_info file_info_tmp;
    trans_load *trans_load_ptr = (trans_load *)(&rcv_pay_load);
    trans_reply *trans_rpl = (trans_reply *)(&rcv_pay_load);
    MD5_CONTEXT md5_rst;

    if (!rcv_file_info)
    {
        LOGE("rcv_file_info should not be null\r\n");
        return -EINVAL;
    }
    if (!rcv_len)
    {
        LOGE("rcv_len should not be null\r\n");
        return -EINVAL;
    }

    *rcv_len = 0;
    if (store_policy == STROE_AFTER_RCV_DONE)
    {
        file_container_ptr = (unsigned char *)malloc(100 * 1024 * 1024);
        RETURN_ERR(LOG_TAG, "malloc", file_container_ptr == NULL);
    }

    while (1)
    {
        ret_val = sec_read(fd_data_src, &rcv_pay_load, sizeof(rcv_pay_load), give_up_rcv, 1);
        CHECK_ERR(LOG_TAG, "sec_read", ret_val < 0, file_rcv_err_out);
        if (ret_val == 0)
        {
            LOG("for net tunnle,client may closed!\r\n");
            return 0;
        }
        cur_rcv_len = ret_val;
#ifdef PRINT_DEBUG
        LOGD("cur_rcv_len = %d\r\n", cur_rcv_len);
        for (i = 0; i < cur_rcv_len; i++)
        {
            if (i % 8 == 0 && i != 0)
                LOG("\r\n");
            LOG("%02x ", ((unsigned char *)(&rcv_pay_load))[i]);
        }
        LOG("\r\n");
#endif
        if ((file_info_ptr->pack_head == SND_FIRMWARE_DATA) || (file_info_ptr->pack_head == SND_FIRMWARE_DONE))
        {
#ifdef ENABLE_PACK_CRC_CHECK
            crc_rst = crc_32((const unsigned char *)(trans_load_ptr), (size_t)&trans_load_ptr->check_rst - (size_t)&trans_load_ptr->pack_head);

            if (trans_load_ptr->check_rst != crc_rst)
            {
#ifdef PRINT_DEBUG
                LOGD("cur_rcv_len = %d\r\n", cur_rcv_len);
                for (i = 0; i < cur_rcv_len; i++)
                {
                    if (i % 8 == 0 && i != 0)
                        LOG("\r\n");
                    LOG("%02x ", ((unsigned char *)(&rcv_pay_load))[i]);
                }
                LOG("\r\n");
#endif
                LOGE("SND_FIRMWARE_DATA SND_FIRMWARE_DONE rcv crc check error,needs 0x%x,get 0x%x,pack_id = %d\r\n!\r\n", crc_rst, trans_load_ptr->check_rst, pack_id);
                trans_rpl->packid = pack_id;
                trans_rpl->challenge_id = challenge_id;
                trans_rpl->reply = STATUS_CRC_CHECK_ERR;
                crc_rst = crc_32((const unsigned char *)trans_rpl, (size_t)&trans_rpl->check_rst - (size_t)&trans_rpl->pack_head);
                trans_rpl->check_rst = crc_rst;

                ret_val = write(fd_data_src, trans_rpl, sizeof(trans_reply));
                RETURN_ERR(LOG_TAG, "write", ret_val < 0);
#ifdef PRINT_DEBUG
                LOGE("reply:\r\n");
                LOGD("cur_rcv_len = %d\r\n", cur_rcv_len);
                for (i = 0; i < sizeof(trans_reply); i++)
                {
                    if (i % 8 == 0 && i != 0)
                        LOG("\r\n");
                    LOG("%02x ", ((unsigned char *)(&trans_rpl))[i]);
                }
                LOG("\r\n");
#endif
                ret_val = -1;
                goto file_rcv_err_out;
            }
#endif
            if (trans_load_ptr->challenge_id != challenge_id)
            {
#ifdef PRINT_DEBUG
                LOGD("cur_rcv_len = %d\r\n", cur_rcv_len);
                for (i = 0; i < cur_rcv_len; i++)
                {
                    if (i % 8 == 0 && i != 0)
                        LOG("\r\n");
                    LOG("%02x ", ((unsigned char *)(&rcv_pay_load))[i]);
                }
                LOG("\r\n");
#endif
                LOGE("SND_FIRMWARE_DATA SND_FIRMWARE_DONE rcv challenge_id check error,pack_id = %d\r\n", pack_id);
                trans_rpl->packid = pack_id;
                trans_rpl->challenge_id = challenge_id;
                trans_rpl->reply = STATUS_RANDOM_NUM_CHECK_ERR;
#ifdef ENABLE_PACK_CRC_CHECK
                crc_rst = crc_32((const unsigned char *)trans_rpl, (size_t)&trans_rpl->check_rst - (size_t)&trans_rpl->pack_head);
                trans_rpl->check_rst = crc_rst;
#endif
                ret_val = write(fd_data_src, trans_rpl, sizeof(trans_reply));
                RETURN_ERR(LOG_TAG, "write", ret_val < 0);

#ifdef PRINT_DEBUG
                LOGE("reply:\r\n");
                LOGD("cur_rcv_len = %d\r\n", cur_rcv_len);
                for (i = 0; i < sizeof(trans_reply); i++)
                {
                    if (i % 8 == 0 && i != 0)
                        LOG("\r\n");
                    LOG("%02x ", ((unsigned char *)(&trans_rpl))[i]);
                }
                LOG("\r\n");
#endif
                ret_val = -1;
                goto file_rcv_err_out;
            }

            if (file_info_ptr->pack_head == SND_FIRMWARE_DONE)
            {
                if (fd_store)
                {
                    close(fd_store);
                    fd_store = -1;
                }
                goto rcv_done_jump_out;
            }

            if (store_policy == STROE_AFTER_RCV_DONE)
            {
                memcpy(file_container_ptr + rcv_count, trans_load_ptr->pay_load, trans_load_ptr->real_payload_len);
                rcv_count += trans_load_ptr->real_payload_len;
                *rcv_len = rcv_count;
                if (rcv_count >= file_info_tmp.filesize)
                {
                    LOG("rcv file done,write to file!\r\n");
                    ret_val = write(fd_store, file_container_ptr, rcv_count);
                    CHECK_ERR(LOG_TAG, "write", ret_val < 0, file_rcv_err_out);
                    rcv_count = 0;
                }
            }
            else if (store_policy == STROE_WHILE_RCV)
            {
                ret_val = write(fd_store, trans_load_ptr->pay_load, trans_load_ptr->real_payload_len);
                CHECK_ERR(LOG_TAG, "write", ret_val < 0, file_rcv_err_out);
                rcv_count += trans_load_ptr->real_payload_len;
                *rcv_len = rcv_count;
                if (rcv_count >= file_info_tmp.filesize)
                {
                    LOG("rcv file done!\r\n");
                    rcv_count = 0;
                }
            }
            else
            {
                LOGE("wrong store_policy!\r\n");
                return -1;
            }
        }
        else if (file_info_ptr->pack_head == UPDATE_BEGIN)
        {
#ifdef ENABLE_PACK_CRC_CHECK
            crc_rst = crc_32((const unsigned char *)(file_info_ptr), (size_t)&file_info_ptr->check_rst - (size_t)&file_info_ptr->pack_head);
            if (file_info_ptr->check_rst != crc_rst)
            {
#ifdef PRINT_DEBUG
                LOGD("cur_rcv_len = %d\r\n", cur_rcv_len);
                for (i = 0; i < cur_rcv_len; i++)
                {
                    if (i % 8 == 0 && i != 0)
                        LOG("\r\n");
                    LOG("%02x ", ((unsigned char *)(&rcv_pay_load))[i]);
                }
                LOG("\r\n");
#endif
                LOGE("UPDATE_BEGIN rcv crc check error,needs 0x%x,get 0x%x,pack_id = %d\r\n", crc_rst, file_info_ptr->check_rst, pack_id);
                trans_rpl->packid = pack_id;
                trans_rpl->challenge_id = challenge_id;
                trans_rpl->reply = STATUS_CRC_CHECK_ERR;
                crc_rst = crc_32((const unsigned char *)trans_rpl, (size_t)&trans_rpl->check_rst - (size_t)&trans_rpl->pack_head);
                trans_rpl->check_rst = crc_rst;

                ret_val = write(fd_data_src, trans_rpl, sizeof(trans_reply));
                RETURN_ERR(LOG_TAG, "write", ret_val < 0);
#ifdef PRINT_DEBUG
                LOGE("reply:\r\n");
                for (i = 0; i < sizeof(trans_reply); i++)
                {
                    if (i % 8 == 0 && i != 0)
                        LOG("\r\n");
                    LOG("%02x ", ((unsigned char *)(&trans_rpl))[i]);
                }
                LOG("\r\n");
#endif
                ret_val = -1;
                goto file_rcv_err_out;
            }
#endif
            challenge_id = file_info_ptr->challenge_id;
            memcpy(&file_info_tmp, &rcv_pay_load, sizeof(file_info));
            rcv_count = 0;
            *rcv_len = 0;
            if (fd_store) close(fd_store);
            fd_store = open_or_create_file(file_info_tmp.file_name, 1);
            CHECK_ERR(LOG_TAG, "open_or_create_file", fd_store < 0, file_rcv_err_out);
        }
        else
        {
            LOGE("wrong pack head,exit!\r\n");
            break;
        }
rcv_done_jump_out:
        trans_rpl->packid = pack_id;
        trans_rpl->challenge_id = challenge_id;
        trans_rpl->reply = STATUS_OK;
#ifdef ENABLE_PACK_CRC_CHECK
        crc_rst = crc_32((const unsigned char *)trans_rpl, (size_t)&trans_rpl->check_rst - (size_t)&trans_rpl->pack_head);
        trans_rpl->check_rst = crc_rst;
#endif
        ret_val = write(fd_data_src, trans_rpl, sizeof(trans_reply));
        RETURN_ERR(LOG_TAG, "open_or_create_file", ret_val < 0);
        pack_id++;

        if (file_info_ptr->pack_head == SND_FIRMWARE_DONE)
        {
            LOGD("rcv SND_FIRMWARE_DONE flag,exit!\r\n");
            break;
        }
    }

    memcpy(rcv_file_info, &file_info_tmp, sizeof(file_info));

    LOG("rcv file MD5 result:");
    get_md5_resust(file_info_tmp.file_name, &md5_rst);
    ret_val = memcmp(file_info_tmp.md5_rst, md5_rst.buf, MD5_RST_LEN);
    if (ret_val != 0)
    {
        LOGE("md5 check failed!\r\n");
        memset(rcv_file_info, '\0', sizeof(file_info));
        *rcv_len = 0;
        ret_val = -1;
    }

    trans_rpl->packid = pack_id;
    trans_rpl->challenge_id = challenge_id;
    trans_rpl->reply = (ret_val == 0) ? STATUS_OK : STATUS_MD5_CHECK_ERR;
#ifdef ENABLE_PACK_CRC_CHECK
    crc_rst = crc_32((const unsigned char *)trans_rpl, (size_t)&trans_rpl->check_rst - (size_t)&trans_rpl->pack_head);
    trans_rpl->check_rst = crc_rst;
#endif
    ret_val = write(fd_data_src, trans_rpl, sizeof(trans_reply));
    RETURN_ERR(LOG_TAG, "write", ret_val < 0);

file_rcv_err_out:
    if (file_container_ptr)
    {
        free(file_container_ptr);
        file_container_ptr = NULL;
    }
    if (fd_store)
    {
        close(fd_store);
        fd_store = -1;
    }
    return ret_val;
}
/*
file_path: 发送文件路径
to_fd:  发送通道的数据描述，发送通道可以是网络，串口，spi，管道，i2c等等
delay_us: 每次发送间隔，控速用
*/
int file_send(const char *file_path, int to_fd, unsigned int delay_us, file_size_type *snd_len)
{
    int fd = -1, file_size = 0, ret_val = -1, i = 0, file_send_done = 0, cur_rcv_len = 0;
    file_size_type filesize = 0;
    unsigned int  crc_rst = 0;
    long long int challenge_id = 0;
    unsigned int pack_id = 0;
    file_info src_file_info;
    trans_load  trans_pay_load;
    trans_reply trans_rpl;
    MD5_CONTEXT md5_rst;

    if (!file_path)
    {
        LOGE("file_path should not be null\r\n");
        return -EINVAL;
    }
    if (!snd_len)
    {
        LOGE("snd_len should not be null\r\n");
        return -EINVAL;
    }

    memset(&src_file_info, '\0', sizeof(src_file_info));
    memset(&trans_pay_load, '\0', sizeof(trans_pay_load));
    memset(&trans_rpl, '\0', sizeof(trans_rpl));

    //send file info
    src_file_info.pack_head = UPDATE_BEGIN;
    fd = open_or_create_file(file_path, 0);
    RETURN_ERR(LOG_TAG, "open_or_create_file", fd < 0);
    filesize = get_file_size(fd);
    src_file_info.filesize = filesize;

    challenge_id = random();
    src_file_info.challenge_id = challenge_id;

    for (i = 0; i < sizeof(src_file_info.file_name) && (file_path[i] != '\0'); i++)
        src_file_info.file_name[i] = file_path[i];
    LOG("src file name %s\r\n", file_path);

    LOG("snd file MD5 result:");
    get_md5_resust(file_path, &md5_rst);
    memcpy(src_file_info.md5_rst, md5_rst.buf, MD5_RST_LEN);
#ifdef ENABLE_PACK_CRC_CHECK
    src_file_info.check_rst = crc_32((const unsigned char *)(&src_file_info), (size_t)&src_file_info.check_rst - (size_t)&src_file_info.pack_head);
#endif
    ret_val = write(to_fd, &src_file_info, sizeof(src_file_info));
    RETURN_ERR(LOG_TAG, "open_or_create_file", ret_val < 0);

    ret_val = sec_read(to_fd, &trans_rpl, sizeof(trans_reply), NULL, 1);
    CHECK_ERR(LOG_TAG, "sec_read", ret_val < 0, file_send_err_out);
    cur_rcv_len = ret_val;
#ifdef ENABLE_PACK_CRC_CHECK
    crc_rst = crc_32((const unsigned char *)(&trans_rpl), (size_t)&trans_rpl.check_rst - (size_t)&trans_rpl.pack_head);
    if (trans_rpl.check_rst != crc_rst)
    {
#ifdef PRINT_DEBUG
        LOGD("cur_rcv_len = %d\r\n", cur_rcv_len);
        for (i = 0; i < cur_rcv_len; i++)
        {
            if (i % 8 == 0 && i != 0)
                LOG("\r\n");
            LOG("%02x ", ((unsigned char *)(&trans_rpl))[i]);
        }
        LOG("\r\n");
#endif
        LOGE("UPDATE_BEGIN reply crc check error,needs 0x%x,get 0x%x,pack_id = %d\r\n", crc_rst, trans_rpl.check_rst, pack_id);
        ret_val = -1;
        goto file_send_err_out;
    }
#endif
    switch (trans_rpl.reply)
    {
        case STATUS_OK:
            break;//snd pack ok
        case STATUS_RANDOM_NUM_CHECK_ERR:
            LOGE("wrong challenge id in snd pack,pack_id = %d\r\n", pack_id);
            file_send_done = 1;
            break;
#ifdef ENABLE_PACK_CRC_CHECK
        case STATUS_CRC_CHECK_ERR:
            LOGE("crc check error in snd pack,pack_id = %d\r\n", pack_id);
            file_send_done = 1;
            break;
#endif
        default:
            LOGE("illegal reply status value!pack_id = %d\r\n", pack_id);
            file_send_done = 1;
            break;
    }

    if (file_send_done) goto file_send_err_out;

    //send file containt
    while (!file_send_done)
    {
        trans_pay_load.pack_head = SND_FIRMWARE_DATA;
        trans_pay_load.packid = pack_id++;
        trans_pay_load.challenge_id = challenge_id;
        ret_val = sec_read(fd, trans_pay_load.pay_load, sizeof(trans_pay_load.pay_load), NULL, 1);
        CHECK_ERR(LOG_TAG, "sec_read", ret_val < 0, file_send_err_out);
        *snd_len += ret_val;

        //snd file done
        if (ret_val == 0)
        {
            trans_pay_load.pack_head = SND_FIRMWARE_DONE;
            //LOG("file send done,last cycle!\r\n");
            file_send_done = 1;
        }
        trans_pay_load.real_payload_len = ret_val;
#ifdef ENABLE_PACK_CRC_CHECK
        trans_pay_load.check_rst = crc_32((const unsigned char *)(&trans_pay_load), (size_t)&trans_pay_load.check_rst - (size_t)&trans_pay_load.pack_head);
#endif
        ret_val = write(to_fd, &trans_pay_load, sizeof(trans_pay_load));
        CHECK_ERR(LOG_TAG, "write", ret_val < 0, file_send_err_out);

        ret_val = sec_read(to_fd, &trans_rpl, sizeof(trans_reply), NULL, 1);
        CHECK_ERR(LOG_TAG, "sec_read", ret_val < 0, file_send_err_out);
        cur_rcv_len = ret_val;

#ifdef ENABLE_PACK_CRC_CHECK
        crc_rst = crc_32((const unsigned char *)(&trans_rpl), (size_t)&trans_rpl.check_rst - (size_t)&trans_rpl.pack_head);
        if (trans_rpl.check_rst != crc_rst)
        {
#ifdef PRINT_DEBUG
            LOGD("cur_rcv_len = %d\r\n", cur_rcv_len);
            for (i = 0; i < cur_rcv_len; i++)
            {
                if (i % 8 == 0 && i != 0)
                    LOG("\r\n");
                LOG("%02x ", ((unsigned char *)(&trans_rpl))[i]);
            }
            LOG("\r\n");
#endif
            LOGE("SND_FIRMWARE_DATA reply crc check error,needs 0x%x,get 0x%x,pack_id = %d\r\n", crc_rst, trans_rpl.check_rst, pack_id);
            ret_val = -1;
            goto file_send_err_out;
        }
#endif
        if (trans_rpl.challenge_id != challenge_id)
        {
#ifdef PRINT_DEBUG
            LOGD("cur_rcv_len = %d\r\n", cur_rcv_len);
            for (i = 0; i < cur_rcv_len; i++)
            {
                if (i % 8 == 0 && i != 0)
                    LOG("\r\n");
                LOG("%02x ", ((unsigned char *)(&trans_rpl))[i]);
            }
            LOG("\r\n");
#endif
            LOGE("illegal reply pack,wrong challenge id,needs 0x%llx,get 0x%llx pack_id = %d\r\n", challenge_id, trans_rpl.challenge_id, pack_id);
            ret_val = -1;
            goto file_send_err_out;
        }

        switch (trans_rpl.reply)
        {
            case STATUS_OK:
                break;//snd pack ok
            case STATUS_RANDOM_NUM_CHECK_ERR:
                LOGE("wrong challenge id in snd pack,pack_id = %d\r\n", pack_id);
                file_send_done = 1;
                break;
#ifdef ENABLE_PACK_CRC_CHECK
            case STATUS_CRC_CHECK_ERR:
                LOGE("crc check error in snd pack,pack_id = %d\r\n", pack_id);
                file_send_done = 1;
                break;
#endif
            default:
                LOGE("rcv file containt,illegal reply status value!pack_id = %d\r\n", pack_id);
                file_send_done = 1;
                break;
        }

        if (delay_us)
        {
            usleep(delay_us);
        }
        //getchar();//for debug
    }
    //wait for md5 check result
    //LOG("wait for md5 check result...\r\n");
    ret_val = sec_read(to_fd, &trans_rpl, sizeof(trans_reply), NULL, 1);
    CHECK_ERR(LOG_TAG, "sec_read", ret_val < 0, file_send_err_out);
#ifdef ENABLE_PACK_CRC_CHECK
    crc_rst = crc_32((const unsigned char *)(&trans_rpl), (size_t)&trans_rpl.check_rst - (size_t)&trans_rpl.pack_head);
    if (trans_rpl.check_rst != crc_rst)
    {
        LOGE("wait for md5 check result reply crc check error,needs 0x%x,get 0x%x!\r\n", crc_rst, trans_rpl.check_rst);
        ret_val = -1;
        goto file_send_err_out;
    }
#endif
    if (trans_rpl.challenge_id != challenge_id)
    {
        LOGE("illegal reply pack,wrong challenge id!\r\n");
        ret_val = -1;
        goto file_send_err_out;
    }

    if (trans_rpl.reply == STATUS_OK)
    {
        ;//LOG("rcv md5 ok reply\r\n");
    }
    else if (trans_rpl.reply == STATUS_MD5_CHECK_ERR)
    {
        LOG("rcv md5 failed reply\r\n");
        ret_val = -1;
    }

file_send_err_out:
    if (fd >= 0)
    {
        close(fd);
        fd = -1;
    }

    return ret_val;
}
