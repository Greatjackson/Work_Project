#ifndef PTHREAD_OWN_H
#define PTHREAD_OWN_H

#define __USE_GNU
#define _GNU_SOURCE
#include <pthread.h>
#include <sched.h>

extern int pthread_create_and_setaffinity(pthread_t *thread, const pthread_attr_t *attr, void *(*start_routine)(void *), void *arg, int affinity_core_num);

#endif
