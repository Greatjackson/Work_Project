#include <stdio.h>
#include "ucas_log.h"
#include "version.h"
#define LOG_TAG "version.c:  "

void show_version(void)
{
    LOGI("mode        :%s\r\n", MODE);
    LOGI("platform    :%s\r\n", PLATFORM);
    LOGI("redirect    :%s\r\n", REDIRECT);
    LOGI("build time  :%s\r\n", BUILD_TIME);
    LOGI("who build   :%s\r\n", WHO_BUILD);
    LOGI("branch name :%s\r\n", BRANCH_NAME);
    LOGI("commit id   :%s\r\n", COMMIT_ID);
}