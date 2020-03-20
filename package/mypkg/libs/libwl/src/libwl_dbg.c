/*
 * Copyright (C) 2011-2014  chenzejun <jack_chen_mail@163.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License version 2.1
 * as published by the Free Software Foundation
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <asm/types.h>

#include <sys/socket.h>  
#include <linux/netlink.h>
#include <syslog.h>
//#include "ccan/list/list.h"
#include <time.h>  
#include <signal.h>  
#include <unistd.h>
#include <sched.h>
#include <dirent.h>
#include <net/if_arp.h>
#include <netinet/in.h>
#include <linux/sockios.h>
#include <sys/stat.h>  
#include <sys/time.h>
#include <sys/socket.h>    
#include <sys/epoll.h>   
#include <sys/file.h>
#include <fcntl.h>  
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdarg.h>
#include <pthread.h>
#include <net/if.h>
#include <sys/ioctl.h>  
#include <sys/un.h>
#include <uci.h>  
#include <libubox/uloop.h>
#include <libubox/utils.h>
#include <libubox/usock.h>
#include <sys/inotify.h>
#include "libwl_api_pub.h"
#include "libwl_api.h"
#include "libwl_mscan_pub.h"
#include "libwl_dbg_pub.h"
#include "libwl_dbg.h"
#include "libwl_alist_pub.h"
#include "libwl_alist.h"


/*
history:

20170331:chenzejun create file


*/




PF_LIBWL_PRINT pf_debug_function = printf;


#if FUNCTION_DESC("debug function")

/**
*@Description: degug flag
*@debug_flag: 1: print info to terminal
*@debug_flag: 2: print info to log file
*/

static struct LIBWL_GLOBAL_DEBUG g_debug_config =
{
        .debug_flag = 1,
        .dbg_switch = {0},
        .log_printf_mutex = PTHREAD_MUTEX_INITIALIZER,
        .log_file_mutex = PTHREAD_MUTEX_INITIALIZER,
        .logfilename = "/tmp/log/libwl.log",
        .logstr = {0},
};


/**
*@Description: mutex lock
*@lock: pthread_mutex_t: pointer to pthread_mutex_t
*@Return: void: void
*@author: chenzejun 20160123
*/
static inline void libwl_log_lock(pthread_mutex_t *lock) 
{
        pthread_mutex_lock(lock);
}
/**
*@Description: mutex unlock
*@lock: pthread_mutex_t: pointer to pthread_mutex_t
*@Return: void: void
*@author: chenzejun 20160123
*/
static inline void libwl_log_unlock(pthread_mutex_t *lock)
{
        pthread_mutex_unlock(lock);
}

/**
*@Description: write log
*@Input: logname: log name
*@Input: pszFmt: the string of input
*@Return: void: void
*@author: chenzejun 20160123
*/
static void libwl_log_write_file(const char *logname, const char *logstr)
{
        time_t timep;
        struct tm *p;
        FILE * file_fd; 
        char name_bak[BUF_LEN_256];

        if (logname == NULL || logstr == NULL)  return;
        
        file_fd = fopen(logname, "a+");
        if (file_fd == NULL)  return;

        // time stamp
        time(&timep);
        p = localtime(&timep); //get local time
        if (p == NULL)  return;

        fprintf(file_fd, "[%04d-%02d-%02d %02d:%02d:%02d] %s", 
                p->tm_year+1900, p->tm_mon+1, p->tm_mday, p->tm_hour, p->tm_min, p->tm_sec, 
                logstr);
        
        if (ftell(file_fd) > MAX_LOGSIZE)
        {
                fclose(file_fd);
                snprintf(name_bak, sizeof(name_bak), "%s.old", logname);
                if (rename(logname, name_bak))
                {
                        remove(name_bak);
                        rename(logname, name_bak);
                }
        }
        else
        {
                fclose(file_fd);
        }
        return;
}


/**
*@Description: write log
*@Input: pszFmt: void
*@Return: void: void
*@author: chenzejun 20160123
*/
int libwl_log_printf(const char *format, ...)
{
        va_list argp;

        if (g_debug_config.logfilename[0] == 0)
        {
                return -1;
        }

        libwl_log_lock(&g_debug_config.log_printf_mutex);
        va_start(argp, format);
        vsnprintf(g_debug_config.logstr, LOG_BUFFER_1024, format, argp); 
        va_end(argp);

        libwl_log_write_file(g_debug_config.logfilename, g_debug_config.logstr);
        libwl_log_unlock(&g_debug_config.log_printf_mutex);
        return 0;
}




/**
*@Description: write log
*@Input: name: the log name
*@Input: format: the format string
*@Return: void: void
*@author: chenzejun 20160123
*/
int libwl_log(const char *name, const char *format, ...)
{
        va_list argp;

        libwl_log_lock(&g_debug_config.log_file_mutex);
        va_start(argp, format);
        vsnprintf(g_debug_config.logstr, LOG_BUFFER_1024, format, argp); 
        va_end(argp);

        libwl_log_write_file(name, g_debug_config.logstr);
        libwl_log_unlock(&g_debug_config.log_file_mutex);
        return 0;
}
/**
*@Description: display the data of buffer
*@Input: str: str
*@Input: pbuf: the pointer of buffer
*@Input: size: buffer length
*@Return: 0: ok;   -1: fail
*@author: chenzejun 20160123
*/
static void libwl_log_hexdump(const char *str, const unsigned char *pbuf, const int size)  
{  
        int i = 0;  
        int len = 0;
        char *p_log = g_debug_config.logstr;

        if (g_debug_config.debug_flag == 1)
        {
                libwl_printf_hexdump(str, pbuf, size);
                return;
        }
                
        if(str != NULL)
        {  
                len += snprintf((p_log + len), LOG_BUFFER_1024 - len, "%s", str); 
        }  

        if(pbuf != NULL && size > 0)
        {  
                for(i=0; i<size; i++)
                {
                        len += snprintf((p_log + len), LOG_BUFFER_1024 - len, "%02x", pbuf[i]); 
                }
        } 

        libwl_log_printf("%s\n", g_debug_config.logstr); 
        return;
}  



/**
*@Description: display the data of buffer
*@Input: str: str
*@Input: pbuf: the pointer of buffer
*@Input: size: buffer length
*@Return: 0: ok;   -1: fail
*@author: chenzejun 20160123
*/
 static inline void libwl_printf_hexdump(const char *str, const unsigned char *pbuf, unsigned int len) 
{
        if(str != NULL)
        {
                printf("%s:", str);  
        }

        while(len--)
        {        
                printf("%02x", *pbuf++);
        }
        printf("\n");
}



/**
*@Description: print current time
*@Input: void
*@Return: void
*@author: chenzejun 20160123
*/
void libwl_printf_currtime(void)  
{
        char data_time_str[64] = {0}; 
        time_t now;  
        time(&now);

        strftime(data_time_str, 64, "%Y %b %d %X", localtime(&now));  
        printf("Info: current time %s\n", data_time_str);  
        return;  
} 



/**
*@Description: write log to file
*@Input: void
*@Return: void
*@author: chenzejun 20160123
if cannot open file fn, return -1, or return written size when sccessed
*/
int libwl_safe_write2file(const char *fn, const char *buf, size_t buflen)
{
        int fd;
        int written_size = 0;

        fd = open(fn, O_WRONLY|O_CREAT);
        if ( fd == -1 )
        {
                return -1;
        }

        flock(fd, LOCK_EX);
        written_size = write(fd, buf, buflen);
        close(fd);
        flock(fd, LOCK_UN);
        return (int) written_size;
}


/**
*@Description: print current time
*@Input: void
*@Return: 0: ok;   -1: fail
*@author: chenzejun 20160123
*/
int libwl_printf2serial(const char *format, ...)
{
        char log[LOG_BUFFER_2048 + BUF_LEN_16] = {0};
        va_list args;
        int len = 0;
        
        va_start(args, format);
        len = vsnprintf(log, LOG_BUFFER_2048, format, args);
        va_end(args);

        if (len >= LOG_BUFFER_2048)  len = LOG_BUFFER_2048;
        if (len < 0)       return -1;

        //libwl_safe_write2file("/dev/tty", log, LOG_BUFFER_4096);
        libwl_safe_write2file("/dev/ttyS0", log, len);
        return 0;
}




/**
*@Description: wrie file
*@Input: void
*@Return: 0: ok;   -1: fail
*@author: chenzejun 20160123
*/
int libwl_write_file(const char *name, const char *format, ...)
{
        char log[LOG_BUFFER_2048 + BUF_LEN_16] = {0};
        va_list args;
        int len = 0;
        
        va_start(args, format);
        len = vsnprintf(log, LOG_BUFFER_2048, format, args);
        va_end(args);
        
        if (len >= LOG_BUFFER_2048)  len = LOG_BUFFER_2048;
        if (len < 0)       return -1;

        //libwl_safe_write2file("/dev/tty", log, LOG_BUFFER_4096);
        return libwl_safe_write2file(name, log, len);
}


/**
 *@Description: libwl command init
 *@Input: void: void
 *@Return: 0: ok;   -1: fail
 *@author: chenzejun 20160323
 */
int libwl_debug_get_switch(int category)
{
        if (category < sizeof(g_debug_config.dbg_switch))
        {
                return g_debug_config.dbg_switch[category];
        }

        return 0;
}



/**
*@Description: close all debug switch
*@Input: void
*@Return: void
*@author: chenzejun 20160123
*/
static void libwl_debug_switch_close(void)  
{
        memset(g_debug_config.dbg_switch, 0, sizeof(g_debug_config.dbg_switch));
        return;  
} 

#endif




#if FUNCTION_DESC("shell popen")
int ancestor_pid = -1;
static pthread_mutex_t cmd_mutex = PTHREAD_MUTEX_INITIALIZER;

// get_cmd_timeout read the timeout env from mqtt_config file
// return: 0: faild, >0 get the timeout secounds
// ExecuateShellCMD argument len is the length of r_buffer
// return :
// 		1: error 0: succeed
int libwl_execuate_shell_command(const char *shellCMD, char *r_buffer, int len) 
{
        fd_set readfd;
        time_t startTime = time(NULL);
        struct timeval tv;
        int sele_ret = 0;
        int ret = 0;
        char tmp[1024]={0};
        FILE *fstream = NULL;
        int fd_popen = -1;
        int script_tmout = 240;
        int blk_count = 0;
        
        if (shellCMD == NULL || r_buffer == NULL)
        {
                return 1;
        }
        
        pthread_mutex_lock(&cmd_mutex);
        fstream = popen(shellCMD, "r");
        if (NULL == fstream) 
        {
                perror("ExecuateShellCMD popen");
                LIBWL_DBG_PRINTF(LIBWL_ERROR, "CMD:EXEC:[%s] popen init faild\n", shellCMD);
                pthread_mutex_unlock(&cmd_mutex);
                return 1;
        }

        // get file desc
        fd_popen = fileno(fstream);

        // close exe
        ret  = fcntl(fd_popen , F_SETFD, FD_CLOEXEC);
        if (ret == -1) 
        {
                LIBWL_DBG_PRINTF(LIBWL_ERROR, "com: fcntl to FD_CLOEXEC faild");
                pclose(fstream);
                pthread_mutex_unlock(&cmd_mutex);
                return 1;
        }


        /** Select Timeout **/
        tv.tv_sec = 240;
        tv.tv_usec = 0;

        while(1)
        {
                FD_ZERO(&readfd);
                FD_SET(fd_popen , &readfd);


                sele_ret = select(fd_popen +1, &readfd, NULL, NULL, &tv);
                if (sele_ret < 0) {
                        LIBWL_DBG_PRINTF(LIBWL_ERROR, "com: [%s] select failed!\n", shellCMD);
                        ret = 1;
                        break;
                } 
                else if (sele_ret == 0) {
                        LIBWL_DBG_PRINTF(LIBWL_ERROR, "com: [%s] select Time out!\n", shellCMD);
                        ret =2;
                        break;
                } 

                
                // read command exec result to r_buffer
                if(FD_ISSET(fd_popen , &readfd)) 
                {
                        memset(r_buffer, 0 , len);
                       
                        /* set to file begin */
                        fseek(fstream, 0, SEEK_SET);
                        blk_count = fread(r_buffer, len, 1, fstream);
                        if(blk_count == 1 || feof(fstream))
                        {
                                // read ok
                                //LIBWL_DBG_PRINTF(GSET_ERROR, "blk_count: %d.\n", blk_count);
                                r_buffer[len -  1] = 0;   //'\0'
                                //LIBWL_DBG_PRINTF(GSET_ERROR, "blk_count: %d\n", blk_count);
                                ret = 0;
                                break;
                        }
                        else
                        {
                                ret = ferror(fstream);
                                break;
                        }
                } 
                else 
                {
                        ret = 4;
                        break;
                }

                // timeout
                if ((startTime + script_tmout) < time(NULL)) {
                        LIBWL_DBG_PRINTF(LIBWL_ERROR, "com: script Time out!: %s.\n", shellCMD);
                        ret = 5;
                        break;
                }
       

        }

        pclose(fstream);
        LIBWL_DBG_PRINTF(LIBWL_INFO, "CMD:[%s] result = %d\n", shellCMD, ret);
        pthread_mutex_unlock(&cmd_mutex);
        return ret;
}

#endif


#if FUNCTION_DESC("command function")

static char cmd_buffer[LOG_BUFFER_2048 + BUF_LEN_128] = {0};
static int  cmd_client_kill = 1;  
static int  cmd_client_fd = -1;

static struct sockaddr_un server_address =
{
        .sun_family = AF_UNIX,
        .sun_path = "/var/run/libwl.cmd.serv",
};  
static struct sockaddr_un client_address =
{
        .sun_family = AF_UNIX,
        .sun_path = "/var/run/libwl.cmd.client",
}; 



/**
 *@Description: create socket
 *@Input: 
        address: socket address
 *@len: 
        address: socket address length
 *@Return: 0: ok;   -1: fail
 *@author: chenzejun 20160323
 */
int libwl_cmd_create_socket(const struct sockaddr_un *address)
{
        int sock_fd = -1;  
        int result;  
        int opt = SO_REUSEADDR;
        int len = 0;

        if (address == NULL)    return -1;  

        sock_fd = socket (AF_UNIX, SOCK_DGRAM, 0);  
        if (sock_fd < 0)
        {
                LIBWL_DBG_PRINTF(LIBWL_ERROR, "socket error, %s, errno:%s\n",  __FUNCTION__, strerror(errno));  
                return -1;    
        }

        setsockopt(sock_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));


        /* delete old path */
        unlink (address->sun_path); 


        /* bind socket */
        len = strlen(address->sun_path) + sizeof(address->sun_family);
        result = bind(sock_fd, (struct sockaddr*)address, len);  
        if(result < 0)
        {  
                LIBWL_DBG_PRINTF(LIBWL_ERROR, "bind error, %s, errno:%s\n",  __FUNCTION__, strerror(errno));  
                close(sock_fd);  
                return -1;    
        } 
        
        //LIBWL_DBG_PRINTF(LIBWL_CMD_TRACE, "server is waiting for client connect..., fd:%d\n", sock_fd);  
        return sock_fd;
}


 




/**
*@Description: send msg to service by socket
*@Input: 
        format: the string to format
*@Return: 0: ok;   -1: fail
*@author: chenzejun 20160123
*/
int libwl_cmd_service_send_msg(const char *format, ...)
{
        char log[LOG_BUFFER_1024 + 32] = {0};
        int client_len = 0;
        int  log_len;  
        va_list args;
        int bytes;

        if (cmd_client_fd < 0)
        {
                return -1;
        }
       
        va_start(args, format);
        log_len = vsnprintf(log, LOG_BUFFER_1024, format, args);
        va_end(args);
        
        if (log_len >= LOG_BUFFER_1024)  log_len = LOG_BUFFER_1024;

        client_len = strlen(client_address.sun_path) + sizeof(client_address.sun_family);
        bytes = sendto(cmd_client_fd, log, log_len, 0, (struct sockaddr*)&client_address, client_len);
        if (bytes < 0)
        {
                if(errno == EAGAIN)
                {
                        // buffer is impossable full, continue,   Resource temporarily unavailable
                        system("sync");
                        //sync();
                        //sched_yield();
                        bytes = sendto(cmd_client_fd, log, log_len, 0, (struct sockaddr*)&client_address, client_len);
                        if (bytes > 0)   return bytes;
                }
        
                printf("cmd socket send fail, client socket close\n");
                /* close debug switch */
                pf_debug_function = printf;
                libwl_debug_switch_close();
                return -1;
        }

        printf("cmd socket send %d, %d\n", log_len, bytes);

        return bytes;
}



/**
 *@Description: the callback function of uloop
 *@Input: u: the file description of uloop
 *@Input: ev: the event of uloop
 *@Return: void
 *@author: chenzejun 20160323
 */
void libwl_cmd_service_callback(int sock_fd, LIBWL_CMD_LIST ast_list[], int size)
{
        AP_TLV_DATA *pst_tlv = (AP_TLV_DATA *)cmd_buffer;
        int client_len = 0;
        int bytes;
        int slen;
        int i;
        int rt0_count = 0;

        if (ast_list == NULL || size == 0)
        {
                return;
        }
        
        //LIBWL_DBG_PRINTF(LIBWL_CMD_TRACE, "handle server ...fd:%d, %d\n", sock_fd, cmd_client_fd);  
        client_len = strlen(client_address.sun_path) + sizeof(client_address.sun_family);

        /* found new client, process */
        while(1)  
        {

                /* recv data, non block */
                bytes = recvfrom(sock_fd, cmd_buffer, LOG_BUFFER_2048, MSG_DONTWAIT, (struct sockaddr*)&client_address, &client_len);
                if(bytes < 0)
                {
                        if(errno != EAGAIN)  
                        {
                                LIBWL_DBG_PRINTF(LIBWL_CMD_TRACE, "recvmsg end fd:%d, errno:%d, ret:%d\n", sock_fd, errno, bytes); 
                        }

                        break;
                }
                else if(bytes == 0){
                        //if peer socket ctrl+c; it return 0; when socktype = SOCK_DGRAM;
                        // count 5 to exit;
                        //protect
                        if (rt0_count > 5){
                                break;
                        }
                        
                        rt0_count++; 
                        LIBWL_DBG_PRINTF(LIBWL_CMD_TRACE, "next receive, count:%d, %d\n", rt0_count, errno);  
                        continue;
                }

                LIBWL_DBG_PRINTF(LIBWL_CMD_TRACE, "handle receive client:%d bytes:%d, type:%d\n", sock_fd, bytes, pst_tlv->us_tlv_type);

                if (pst_tlv->us_tlv_type == LIBWL_CLIENT_DEBUG)
                {
                        memcpy(g_debug_config.dbg_switch, pst_tlv + 1, sizeof(g_debug_config.dbg_switch));
                        
                        pf_debug_function = libwl_cmd_service_send_msg;
                        libwl_cmd_service_send_msg("receive debug command\n");
                }
                else if (pst_tlv->us_tlv_type == LIBWL_CLIENT_SHOW)
                {
                        /* show command execute only once, then close socket */
                        for (i = 0; i < size; i++)
                        {
                                slen = strlen(ast_list[i].cmd_name);
                                if (!strncmp((char *)(pst_tlv + 1), ast_list[i].cmd_name, slen) &&
                                   (*((char *)(pst_tlv + 1) + slen) == ' ' || *((char *)(pst_tlv + 1) + slen) == '\0'))
                                {
                                        bytes = ast_list[i].pf_function(cmd_buffer, LOG_BUFFER_2048);
                                        if (bytes > 0)
                                        {
                                                sendto(sock_fd, cmd_buffer, bytes, 0, (struct sockaddr*)&client_address, client_len);
                                        }

                                        break;
                                }
                        }

                        // not found command
                        if (i == size)
                        {
                                cmd_buffer[BUF_LEN_1024 - 1] = 0;
                                bytes = snprintf(&cmd_buffer[BUF_LEN_1024], LOG_BUFFER_2048, "command not support:%s\n", (char *)(pst_tlv + 1));
                                if (bytes > 0)
                                {
                                        sendto(sock_fd, &cmd_buffer[BUF_LEN_1024], (bytes + 1), 0, (struct sockaddr*)&client_address, client_len);
                                }
                        }                
                }

              
                LIBWL_DBG_PRINTF(LIBWL_CMD_TRACE, "receive command, get bytes:%d\n", bytes);  
        }

        //LIBWL_DBG_PRINTF(LIBWL_CMD_TRACE, "libwl_cmd_service_callback, exit\n");  
        return;
}





/**
 *@Description: libwl service create socket
 *@Input: void: void
 *@Return: 0: ok;   -1: fail
 *@author: chenzejun 20160323
 */
int libwl_cmd_service_create(char *name)
{
        int sock_fd = -1;
        
        //it need init clien and service
        client_address.sun_family = AF_UNIX;
        snprintf(client_address.sun_path, sizeof(client_address.sun_path), "/var/run/%s.cmd.client", name);
        server_address.sun_family = AF_UNIX;
        snprintf(server_address.sun_path, sizeof(server_address.sun_path), "/var/run/%s.cmd.serv", name);

        /* command service*/
        sock_fd = libwl_cmd_create_socket(&server_address);


        /* log */
        snprintf(g_debug_config.logfilename, sizeof(g_debug_config.logfilename), "/var/log/%s.log", name);

        cmd_client_fd = sock_fd;

        LIBWL_DBG_PRINTF(LIBWL_INFO, "libwl service create fd:%d\n", sock_fd);  
        return cmd_client_fd;
}






/**
 *@Description: libwl command init
 *@Input: void: void
 *@Return: 0: ok;   -1: fail
 *@author: chenzejun 20160323
 */
int libwl_cmd_service_destroy(void)
{
        unlink (server_address.sun_path); 

        if (cmd_client_fd > 0)
        {
                close(cmd_client_fd);
                cmd_client_fd = -1;
        }
        return 0;
}







/**
 *@Description: libwl client create socket
 *@Input: name: name
 *@Return: 0: ok;   -1: fail
 *@author: chenzejun 20160323
 */
int libwl_cmd_client_create(char *name)
{
        int sock_fd = -1;

        //it need init clien and service
        client_address.sun_family = AF_UNIX;
        snprintf(client_address.sun_path, sizeof(client_address.sun_path), "/var/run/%s.cmd.client", name);
        server_address.sun_family = AF_UNIX;
        snprintf(server_address.sun_path, sizeof(server_address.sun_path), "/var/run/%s.cmd.serv", name);

        /* command service*/
        sock_fd = libwl_cmd_create_socket(&client_address);


        LIBWL_DBG_PRINTF(LIBWL_INFO, "[#]cmd client start work...\n", sock_fd);  
        return sock_fd;
}



/**
 *@Description: the process for show in client
 *@Input: sock_fd: socket fd
 *@Input: p_cmd: command
 *@Return: 0: ok;   -1: fail
 *@author: chenzejun 20160323
 */
int libwl_cmd_client_show(int sock_fd, char *arg1, char *arg2, char *arg3)
{
        AP_TLV_DATA *pst_tlv = (AP_TLV_DATA *)cmd_buffer;
        int addr_len;
        int bytes;  
        int retval;   
        fd_set read_fds;
        struct timeval tv_out = {5, 0};

        if (sock_fd < 0 || arg1 == NULL)   return -1;

        //tlv
        pst_tlv = (AP_TLV_DATA *)cmd_buffer;
        pst_tlv->us_tlv_type = LIBWL_CLIENT_SHOW;
        pst_tlv->us_tlv_len = sizeof(AP_TLV_DATA);
        if (arg2 && arg3)
        {
                pst_tlv->us_tlv_len += snprintf((char *)(pst_tlv + 1), LOG_BUFFER_2048, "%s %s %s", arg1, arg2, arg3);
        }
        else if (arg2)
        {
                pst_tlv->us_tlv_len += snprintf((char *)(pst_tlv + 1), LOG_BUFFER_2048, "%s %s", arg1, arg2);
        }
        else
        {
                pst_tlv->us_tlv_len += snprintf((char *)(pst_tlv + 1), LOG_BUFFER_2048, "%s", arg1);
        }
        
        cmd_buffer[pst_tlv->us_tlv_len + 1] = 0;
        pst_tlv->us_tlv_len++;    //'\0'

        //printf("client command:%s, len:%d\n", (pst_tlv + 1), pst_tlv->us_tlv_len); 

        /* send switch information */
        addr_len = strlen(server_address.sun_path) + sizeof(server_address.sun_family);
        sendto(sock_fd, cmd_buffer, pst_tlv->us_tlv_len, 0, (struct sockaddr*)&server_address, addr_len);

        while(1)  
        {
                FD_ZERO(&read_fds);
                FD_SET(sock_fd, &read_fds);
                retval = select(sock_fd + 1, &read_fds, NULL, NULL, &tv_out);
                if (retval > 0)
                {
                        if(FD_ISSET(sock_fd, &read_fds)) 
                        {
                                bytes = recvfrom(sock_fd, cmd_buffer, LOG_BUFFER_2048, 0, NULL, NULL);
                                if(bytes > 0)
                                {
                                        printf ("%.*s", bytes, cmd_buffer);
                                        break;
                                }
                        }
                }
                else if (retval == 0)
                {
                        //timeout
                        printf("timeout exit!\n");
                        break;
                }
        }

        close(sock_fd);
        return 0;
}






/**
 *@Description: the process for debug in client
 *@Input: sock_fd: socket fd
 *@Return: 0: ok;   -1: fail
 *@author: chenzejun 20160323
 */
int libwl_cmd_client_debug(int sock_fd)
{
        AP_TLV_DATA *pst_tlv = NULL;
        int addr_len;
        int bytes; 
        int retval;   
        fd_set read_fds;
        struct timeval tv_out = {1800, 0};    //timeout 1800s


        if (sock_fd < 0)   return -1;

        pst_tlv = (AP_TLV_DATA *)cmd_buffer;
        pst_tlv->us_tlv_type = LIBWL_CLIENT_DEBUG;
        pst_tlv->us_tlv_len = sizeof(g_debug_config.dbg_switch) + sizeof(AP_TLV_DATA);
        memcpy((pst_tlv + 1), g_debug_config.dbg_switch, sizeof(g_debug_config.dbg_switch));


        /* send switch information */
        addr_len = strlen(server_address.sun_path) + sizeof(server_address.sun_family);
        sendto(sock_fd, cmd_buffer, pst_tlv->us_tlv_len, 0, (struct sockaddr*)&server_address, addr_len);

        while(cmd_client_kill)  
        {
                FD_ZERO(&read_fds);
                FD_SET(sock_fd, &read_fds);
                retval = select(sock_fd + 1, &read_fds, NULL, NULL, &tv_out);
                if (retval > 0)
                {
                        if(FD_ISSET(sock_fd, &read_fds)) 
                        {
                                bytes = recvfrom(sock_fd, cmd_buffer, LOG_BUFFER_2048, 0, NULL, NULL);
                                if(bytes > 0)
                                {
                                        printf ("%.*s", bytes, cmd_buffer);
                                }
                        }
                }
                else if (retval == 0)
                {
                        //timeout
                        printf("client auto exit -------------\n");
                        break;
                }
        }


        close(sock_fd);
        return 0;
}



/**
 *@Description: libwl command exit by timer
 *@Input: void: void
 *@Return: 0: ok;   -1: fail
 *@author: chenzejun 20160323
 */
void libwl_cmd_client_timeout(int sig)
{
        cmd_client_kill = 0;
        printf("client auto exit -------------\n");
        return;
}




/**
 *@Description: set output mode is screen
 *@Input: void: void
 *@Return: 0: ok;   -1: fail
 *@author: chenzejun 20160323
 */
void libwl_cmd_output_printf(int num)
{
        pf_debug_function = printf;

        if (num < 0)    return;
        
        if (num < ARRAY_SIZE(g_debug_config.dbg_switch))
        {
                g_debug_config.dbg_switch[num] = true;
        }
        else if (num == 999)
        {
                memset(g_debug_config.dbg_switch, true, sizeof(g_debug_config.dbg_switch));
        }
        return;
}




/**
 *@Description: set output mode is log
 *@Input: void: void
 *@Return: 0: ok;   -1: fail
 *@author: chenzejun 20160323
 */
void libwl_cmd_output_log(int num)
{
        pf_debug_function = libwl_log_printf;

        if (num < 0)    return;
        
        if (num < ARRAY_SIZE(g_debug_config.dbg_switch))
        {
                g_debug_config.dbg_switch[num] = true;
        }
        else if (num == 999)
        {
                memset(g_debug_config.dbg_switch, true, sizeof(g_debug_config.dbg_switch));
        }
        return;
}


#endif



#if FUNCTION_DESC("lock file function")
static int g_inst_lock_fd = -1;


/**
*@Description: libwl_try_create_dir
*@Input: path_name: path name
*@Return: 0 ok;  1- fail
*@author: chenzejun 20160123
*/
static int libwl_try_create_dir(char *path_name)  
{
        DIR *mydir = NULL;  
        char my_path[BUF_LEN_512 + 1] = {0};
        char * p= NULL;
        int retval;

        if (path_name == NULL)  return -1;

        p = strrchr(path_name, '/');
        if (p == NULL || p < path_name)
        {
                LIBWL_DBG_PRINTF(LIBWL_ERROR, "strrchr error, %s\n",  __FUNCTION__);
                return -1;
        }

        snprintf(my_path, BUF_LEN_512, "%.*s", (p - path_name), path_name);
        mydir = opendir(my_path);
        if(mydir == NULL)
        {  
                retval = mkdir(my_path, S_IRWXU | S_IRWXG | S_IRWXO);
                if (retval != 0)  
                {  
                        LIBWL_DBG_PRINTF(LIBWL_ERROR, "mkdir error, %s\n",  __FUNCTION__);
                        return -1;  
                }  
                //printf("%s created sucess!\n", my_path);  
                return 0;  
        }  
        
        //printf("%s exist!\n", my_path);  
        return 0;  
}  
  


/**
*@Description: clean lock fd
*@Input: void: voidname
*@Return: 0 ok;  1- fail
*@author: chenzejun 20160123
*/
static void libwl_lockfile_cleanup(void)
{
        if (g_inst_lock_fd != -1) 
        {
                //printf("close lock fd\n");
                close(g_inst_lock_fd);
                g_inst_lock_fd = -1;
        }
        return;
}


/**
*@Description: check if lbalance instance is running
*@Input: void: instance void
*@Return: 0 ok;  1- fail
*@author: chenzejun 20160123
*/
bool libwl_inst_is_running(char *lock_file)
{
        libwl_try_create_dir(lock_file);

        g_inst_lock_fd = open(lock_file, O_CREAT|O_RDWR, 0644);
        if (-1 == g_inst_lock_fd)
        {
                fprintf(stderr, "Fail to open lock file(%s). Error: %s\n",
                        lock_file, strerror(errno));
                return false;
        }

        if (0 == flock(g_inst_lock_fd, LOCK_EX | LOCK_NB))
        {
                atexit(libwl_lockfile_cleanup);
                return true;
        }

        close(g_inst_lock_fd);
        g_inst_lock_fd = -1; 
        return false;
} 



#endif




