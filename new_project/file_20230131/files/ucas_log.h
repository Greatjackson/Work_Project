#ifndef _LOG_H_
#define _LOG_H_
#include <syslog.h>
#include <errno.h>
#include <stdio.h>

#define DEBUG
#define TO_TERMINAL

#ifdef DEBUG
#define LOG_LEVEL_CLSUN   4
#endif

#ifdef RELEASE
#define LOG_LEVEL_CLSUN   3
#endif

/*设置输出前景色*/
#define UCAS_FONT_BLA  LOG("\033[30m"); //黑色
#define UCAS_FONT_RED  LOG("\033[31m"); //红色
#define UCAS_FONT_GRE  LOG("\033[32m"); //绿色
#define UCAS_FONT_YEL  LOG("\033[33m"); //黄色
#define UCAS_FONT_BLU  LOG("\033[34m"); //蓝色
#define UCAS_FONT_PUR  LOG("\033[35m"); //紫色
#define UCAS_FONT_CYA  LOG("\033[36m"); //青色
#define UCAS_FONT_WHI  LOG("\033[37m"); //白色
/*设置输出背景色*/
#define UCAS_BACK_BLA  LOG("\033[40m"); //黑色
#define UCAS_BACK_RED  LOG("\033[41m"); //红色
#define UCAS_BACK_GRE  LOG("\033[42m"); //绿色
#define UCAS_BACK_YEL  LOG("\033[43m"); //黄色
#define UCAS_BACK_BLU  LOG("\033[44m"); //蓝色
#define UCAS_BACK_PUR  LOG("\033[45m"); //紫色
#define UCAS_BACK_CYA  LOG("\033[46m"); //青色
#define UCAS_BACK_WHI  LOG("\033[47m"); //白色
/*输出属性设置*/
#define UCAS_ATTR_DEFAULT  LOG("\033[0m");  //重新设置属性到缺省设置
#define UCAS_ATTR_BOL  LOG("\033[1m");  //设置粗体
#define UCAS_ATTR_LIG  LOG("\033[2m");  //设置一半亮度(模拟彩色显示器的颜色)
#define UCAS_ATTR_LIN  LOG("\033[4m");  //设置下划线(模拟彩色显示器的颜色)
#define UCAS_ATTR_GLI  LOG("\033[5m");  //设置闪烁
#define UCAS_ATTR_REV  LOG("\033[7m");  //设置反向图象
#define UCAS_ATTR_THI  LOG("\033[22m"); //设置一般密度
#define UCAS_ATTR_ULIN  LOG("\033[24m");//关闭下划线
#define UCAS_ATTR_UGLI  LOG("\033[25m");//关闭闪烁
#define UCAS_ATTR_UREV  LOG("\033[27m");//关闭反向图象

#ifndef TO_TERMINAL
#if (LOG_LEVEL_CLSUN > 3)
#define LOGD(format, ...)   do{syslog(LOG_DEBUG,"LOG_DEBUG-->"format, ##__VA_ARGS__);}while(0)
#else
#define LOGD(format, ...)
#endif

#if (LOG_LEVEL_CLSUN > 2)
#define LOGI(format, ...)   do{syslog(LOG_INFO, "LOG_INFO -->"format, ##__VA_ARGS__);}while(0)
#else
#define LOGI(format, ...)
#endif

#if (LOG_LEVEL_CLSUN > 1)
#define LOGE(format, ...)   do{syslog(LOG_ERR,  "LOG_ERR  -->"format, ##__VA_ARGS__);}while(0)
#define CHECK_ERR(_TAG_,func_name,cond,label)                                                    \
                                            do{                                                              \
                                                if (cond)                                                \
                                                {                                                            \
                                                    UCAS_FONT_RED;                                          \
                                                    LOGE(_TAG_"%s failed,line %d,errno = %d\r\n",func_name,__LINE__,errno);   \
                                                    UCAS_ATTR_DEFAULT;                                       \
                                                    goto label;                                              \
                                                }                                                            \
                                            }while(0)
#define RETURN_ERR(_TAG_,func_name,cond) do{                                                              \
                                                           if (cond)                                                \
                                                           {                                                            \
                                                               UCAS_FONT_RED;                                          \
                                                               LOGE(_TAG_"%s failed,line %d,errno = %d\r\n",func_name,__LINE__,errno);   \
                                                               UCAS_ATTR_DEFAULT;                                       \
                                                               return -errno;                        \
                                                           }                                                            \
                                                       }while(0)

#define ERR_LOG(_TAG_,func_name,cond)       do{                                                              \
                                                            if (cond)                                                \
                                                            {                                                            \
                                                                UCAS_FONT_RED;                                          \
                                                                LOGE(_TAG_"%s failed,line %d,errno = %d\r\n",func_name,__LINE__,errno);   \
                                                                UCAS_ATTR_DEFAULT;                                       \
                                                            }                                                            \
                                                        }while(0)
#else
#define LOGE(format, ...)
#define CHECK_ERR(_TAG_,func_name,cond,label)
#define RETURN_ERR(_TAG_,func_name,cond)
#define ERR_LOG(_TAG_,func_name,cond)
#endif

#if (LOG_LEVEL_CLSUN > 0)
#define LOG(format, ...)    do{syslog(LOG_ERR,  format, ##__VA_ARGS__);}while(0)
#else
#define LOG(format, ...)
#endif

#endif

#ifdef TO_TERMINAL
#if (LOG_LEVEL_CLSUN > 3)
#define LOGD(format, ...)   do{printf("LOG_DEBUG-->"format, ##__VA_ARGS__);}while(0)
#else
#define LOGD(format, ...)
#endif

#if (LOG_LEVEL_CLSUN > 2)
#define LOGI(format, ...)   do{printf("LOG_INFO -->"format, ##__VA_ARGS__);}while(0)
#else
#define LOGI(format, ...)
#endif

#if (LOG_LEVEL_CLSUN > 1)
#define LOGE(format, ...)   do{printf("LOG_ERR  -->"format, ##__VA_ARGS__);}while(0)
#define CHECK_ERR(_TAG_,func_name,cond,label)                                                    \
                                            do{                                                              \
                                                if (cond)                                                \
                                                {                                                            \
                                                    UCAS_FONT_RED;                                          \
                                                    LOGE(_TAG_"%s failed,line %d,errno = %d\r\n",func_name,__LINE__,errno);   \
                                                    UCAS_ATTR_DEFAULT;                                       \
                                                    goto label;                                              \
                                                }                                                            \
                                            }while(0)
#define RETURN_ERR(_TAG_,func_name,cond) do{                                                                   \
                                                            if (cond)                                                \
                                                            {                                                            \
                                                                UCAS_FONT_RED;                                          \
                                                                LOGE(_TAG_"%s failed,line %d,errno = %d\r\n",func_name,__LINE__,errno);   \
                                                                UCAS_ATTR_DEFAULT;                                       \
                                                                return -errno;                        \
                                                            }                                                            \
                                                        }while(0)
#define ERR_LOG(_TAG_,func_name,cond)       do{                                                              \
                                                            if (cond)                                                \
                                                            {                                                            \
                                                                UCAS_FONT_RED;                                          \
                                                                LOGE(_TAG_"%s failed,line %d,errno = %d\r\n",func_name,__LINE__,errno);   \
                                                                UCAS_ATTR_DEFAULT;                                       \
                                                            }                                                            \
                                            }while(0)
#else
#define LOGE(format, ...)
#define CHECK_ERR(_TAG_,func_name,cond,label)
#define RETURN_ERR(_TAG_,func_name,cond)
#define ERR_LOG(_TAG_,func_name,cond)
#endif

#if (LOG_LEVEL_CLSUN > 0)
#define LOG(format, ...)   do{printf(format, ##__VA_ARGS__);}while(0)
#else
#define LOG(format, ...)
#endif
#endif

#define UCAS_DEBUG_LOG LOGD("tag--> file:%s func: %s,line %d\r\n",__FILE__,__func__,__LINE__)

#endif
