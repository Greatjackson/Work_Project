#include <sys/socket.h>
#include <errno.h>
#include <sys/msg.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <assert.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/sem.h>
#include <unistd.h>
#include <sys/ipc.h>
#include <sys/sysinfo.h>

#include "ucas_log.h"
#include "pthread_own.h"

#define LOG_TAG "pthread_own.c "
#define M_SIZE (1024 * 1024)

int get_sysinfo(void)
{
    struct sysinfo info;
    int ret_val = -1, online_cpu_cores = 0;

    ret_val = sysinfo(&info);
    if (ret_val < 0)
    {
        LOGE(LOG_TAG"sysinfo failed,errno = %d\r\n", errno);
        ret_val = -errno;
    }

    online_cpu_cores = sysconf(_SC_NPROCESSORS_ONLN);
    LOG("system cpu num is %ld\n", sysconf(_SC_NPROCESSORS_CONF));
    LOG("system enable cpu(online cpu) num is %d\n", online_cpu_cores);

    LOG("ret_val         : %d\n", ret_val);
    LOG("uptime          : %ld\n", info.uptime);
    LOG("1 min load average : %.2f%%\n", info.loads[0] / 65536.0 / online_cpu_cores); // info.loads[0] / 65536.0 / cores_of_cpu  we can get the percentage of cpu load
    LOG("5 min load average : %.2f%%\n", info.loads[1] / 65536.0 / online_cpu_cores);
    LOG("15 min load average: %.2f%%\n", info.loads[2] / 65536.0 / online_cpu_cores);
    LOG("totalram           : %lu\n", info.totalram / M_SIZE);
    LOG("freeram            : %lu\n", info.freeram / M_SIZE);
    LOG("procs              : %u\n", info.procs);
    return 0;
}

int pthread_create_and_setaffinity(pthread_t *thread, const pthread_attr_t *attr,
                                   void *(*start_routine)(void *), void *arg, int affinity_core_num)
//affinity_core_num 0--> do not set affinity,(>0)--> set affinity affinity_core_num-1
{
    int ret_val = -1, online_cpu_cores = 0;
    static int first_round = 0;
    cpu_set_t cpu_info;

    if (!first_round)
    {
        get_sysinfo();
        first_round = 1;
    }

    ret_val = pthread_create(thread, attr, start_routine, arg);
    if (ret_val != 0)
    {
        LOGE(LOG_TAG"pthread_create faild,errno = %d!\r\n", errno);
        return -errno;
    }

    if (affinity_core_num >= 0)
    {
        online_cpu_cores = sysconf(_SC_NPROCESSORS_ONLN);
        if (affinity_core_num >= online_cpu_cores)
        {
            LOG("affinity_core_num %d,", affinity_core_num);
            affinity_core_num = affinity_core_num % online_cpu_cores;
            LOG("online cpu cores:%d,set affinity_core_num to %d\r\n", online_cpu_cores, affinity_core_num);
        }

        CPU_ZERO(&cpu_info);
        CPU_SET(affinity_core_num, &cpu_info);
        if (0 != pthread_setaffinity_np(*thread, sizeof(cpu_set_t), &cpu_info))
        {
            LOGE(LOG_TAG"pthread_setaffinity_np thread set affinity failed,errno = %d\r\n", errno);
            return -errno;
        }
    }
    return 0;
}

