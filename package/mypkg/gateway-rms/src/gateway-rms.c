/*
 * Copyright (C) 2011-2019  chenzejun <jack_chen_mail@163.com>
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
#include <sys/time.h>
#include <sys/socket.h>    
#include <sys/epoll.h>  
#include <sys/file.h>
#include <sys/stat.h>  
#include <fcntl.h>  
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdarg.h>
#include <pthread.h>
#include <net/if.h>
#include <sys/ioctl.h>  
#include <sys/un.h>
#include <libubox/uloop.h>
#include <libubox/utils.h>
#include <libubox/usock.h>

#include "libwl/libwl_api_pub.h"
#include "libwl/libwl_dbg_pub.h"
#include "libwl/libwl_alist_pub.h"

#include "gateway-rms.h"
#include "cJSON.h"

//#include   <linux/net.h>

//#include <execinfo.h>

/*
history:

by 2016.1.6:
modify plc-gateway output by josn


by 2016.1.18:
support -d -v
//plc-gateway -d    debug switch
//plc-gateway -v    version

by 2016.1.21:
//plc-gateway -p   ipaddr   support get ip addr by -p

by 2016.1.21:
1.0.3
fix the issue of getting br-lan mac is error

1.0.3


*/

/*

comande exmple:

dest/source/type/name


yun--->gateway:
F85E3C011FB0/yunAC/CMD_EXE/firmware


gateway--->yun:
yunWTBL/donghai/post/plc

*/


//static char plc-gateway_version[]="1.1.8";




static struct GATEWAY_GLOBAL_CONFIG g_config =
{
        .my_name = "gateway-rms",
        .version[0] = 0,
        .buildtime[0] = 0,
        .wan_name[0] = 0,
        .route_mac[0] = 0,
        .route_ip[0] = 0,
        .dev_type[0] = 0,
        .channelpath[0] = 0,

        .srvaddr_name = "/var/run/mqtt-client.localserv",
        .lockfile_name = "",
        


        .uloop_fd_cmd.fd = -1,
        .uloop_fd_cmd.cb = gateway_cmd_socket_handle,
};





#if FUNCTION_DESC("command function")

static struct LIBWL_CMD_LIST_ST  g_function_list[] = 
{
        {"config", gateway_show_config},
        {"debug", gateway_show_debug_switch},
};


/**
 *@Description: the callback function of uloop
 *@Input: u: the file description of uloop
 *@Input: ev: the event of uloop
 *@Return: void
 *@author: chenzejun 20190323
 */
static void gateway_cmd_socket_handle(struct uloop_fd *u, unsigned int ev)
{
        libwl_cmd_service_callback(u->fd, g_function_list, ARRAY_SIZE(g_function_list));
        return;
}





/**
 *@Description: mscan command init
 *@Input: void: void
 *@Return: 0: ok;   -1: fail
 *@author: chenzejun 20190323
 */
static int gateway_cmd_init(void)
{
 
        /* command service*/
        g_config.uloop_fd_cmd.cb = gateway_cmd_socket_handle;
        g_config.uloop_fd_cmd.fd = libwl_cmd_service_create(g_config.my_name);
        if (g_config.uloop_fd_cmd.fd > 0)
        {
                uloop_fd_add(&g_config.uloop_fd_cmd,  ULOOP_READ | ULOOP_EDGE_TRIGGER);
                GATEWAY_DBG_PRINTF(GATEWAY_INFO, "[gateway] add cmd fd:%d\n", g_config.uloop_fd_cmd.fd );  

        }
        
        return 0;
}



/**
 *@Description: mscan command destroy
 *@Input: void: void
 *@Return: 0: ok;   -1: fail
 *@author: chenzejun 20190323
 */
static int gateway_cmd_destroy(void)
{
        return libwl_cmd_service_destroy();
}

#endif



#if FUNCTION_DESC("remote command function")

static pthread_mutex_t cmd_mutex = PTHREAD_MUTEX_INITIALIZER;
char g_operate_result[2048] = {0};
char g_operate_cmd[512] = {0};



// get_cmd_timeout read the timeout env from mqtt_config file
// return: 0: faild, >0 get the timeout secounds
// ExecuateShellCMD argument len is the length of r_buffer
// return :
// 		1: error 0: succeed
int gateway_execuate_shell_command(const char *shellCMD, char *r_buffer, int len) 
{
        fd_set readfd;
        time_t startTime = time(NULL);
        struct timeval tv;
        int sele_ret = 0;
        int ret = 0;
        char tmp[1024]={0};
        FILE *fstream = NULL;
        int fd_popen = -1;
        unsigned int script_tmout = 240;
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
                GATEWAY_DBG_PRINTF(GATEWAY_GATEWAY, "CMD:EXEC:[%s] popen init faild\n", shellCMD);
                pthread_mutex_unlock(&cmd_mutex);
                return 1;
        }

        // get file desc
        fd_popen = fileno(fstream);

        // close exe
        ret  = fcntl(fd_popen , F_SETFD, FD_CLOEXEC);
        if (ret == -1) 
        {
                GATEWAY_DBG_PRINTF(GATEWAY_ERROR, "com: fcntl to FD_CLOEXEC faild");
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
                        GATEWAY_DBG_PRINTF(GATEWAY_ERROR, "com: [%s] select failed!\n", shellCMD);
                        ret = 1;
                        break;
                } 
                else if (sele_ret == 0) {
                        GATEWAY_DBG_PRINTF(GATEWAY_ERROR, "com: [%s] select Time out!\n", shellCMD);
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
                                //GATEWAY_DBG_PRINTF(GATEWAY_ERROR, "blk_count: %d.\n", blk_count);
                                r_buffer[len -  1] = 0;   //'\0'
                                GATEWAY_DBG_PRINTF(GATEWAY_ERROR, "blk_count: %d\n", blk_count);
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
                        GATEWAY_DBG_PRINTF(GATEWAY_ERROR, "com: script Time out!: %s.\n", shellCMD);
                        ret = 5;
                        break;
                }
       

        }

        pclose(fstream);
        GATEWAY_DBG_PRINTF(GATEWAY_GATEWAY, "CMD:[%s] result = %d\n", shellCMD, ret);
        pthread_mutex_unlock(&cmd_mutex);
        return ret;
}





/**
 *@Description: the callback function of uloop
 *@Input: u: the file description of uloop
 *@Input: ev: the event of uloop
 *@Return: void
 *@author: chenzejun 20190323
 */
static int gateway_exe_firmware(cJSON *json_item, cJSON *pst_json)
{
        cJSON *json_md5 = NULL;
        cJSON *json_sfile = NULL;
        cJSON *json_id = NULL;
        cJSON *json_devtype = NULL;
        cJSON *json_dver = NULL;
        char * p_firmware_name = NULL;
        char * tmpfile = "/tmp/upgrd.sh";
        int resv_len = 0;
        int use_len = 0;


        if (pst_json == NULL || json_item == NULL)
        {
                return -1;
        }

        GATEWAY_DBG_PRINTF(GATEWAY_GATEWAY, "[gateway] gateway_exe_firmware, in...\n");  

        
        json_sfile = cJSON_GetObjectItem( pst_json, "sfile" );  //获取键值内容
        if (json_sfile == NULL)         return -1;

        json_id = cJSON_GetObjectItem( pst_json, "id" );  //获取键值内容
        if (json_id == NULL)         return -1;
        
        json_dver = cJSON_GetObjectItem( pst_json, "dest_version" );  //获取键值内容
        if (json_dver == NULL)         return -1;
                
        json_md5 = cJSON_GetObjectItem( pst_json, "md5" );  //获取键值内容
        if (json_md5 == NULL)         return -1;
                
        json_devtype = cJSON_GetObjectItem( pst_json, "dev_type" );  //获取键值内容
        if (json_devtype == NULL)         return -1;

        // dev_type check invalid
        if (0 != strcmp(json_devtype->valuestring, g_config.dev_type))
        {
                GATEWAY_DBG_PRINTF(GATEWAY_GATEWAY, "[gateway] dev_type not match, dev_type:%s\n", json_devtype->valuestring);
                return -2;
        }

        // dev_type check invalid, sub string
        if (NULL == strstr(json_sfile->valuestring, g_config.dev_type))
        {
                GATEWAY_DBG_PRINTF(GATEWAY_GATEWAY, "[gateway] dev_type not match, json_sfile:%s\n", json_sfile->valuestring);
                return -3;
        }

       
        GATEWAY_DBG_PRINTF(GATEWAY_GATEWAY, "[gateway] json_devtype:%s\n", json_devtype->valuestring); 


        // last position for lookup
        p_firmware_name = strrchr(json_sfile->valuestring, '/');
        if (p_firmware_name == NULL)
        {
                GATEWAY_DBG_PRINTF(GATEWAY_GATEWAY, "[gateway] p_pos fail, sfile:%s\n", json_sfile->valuestring);
                return -4;
        }

        p_firmware_name++;
        
        //delete file
        tmpfile = "/tmp/upgrd.sh";
        system("rm -rf  /tmp/upgrd.sh");



        resv_len = sizeof(g_operate_cmd);
        use_len = 0;
        use_len += snprintf(&g_operate_cmd[use_len], (resv_len - use_len), "#!/bin/sh\n");
        use_len += snprintf(&g_operate_cmd[use_len], (resv_len - use_len), "echo \"%s\">/tmp/md5sums\n", json_md5->valuestring);
        use_len += snprintf(&g_operate_cmd[use_len], (resv_len - use_len), "wget -O /tmp/%s %s\n", p_firmware_name, json_sfile->valuestring);
        use_len += snprintf(&g_operate_cmd[use_len], (resv_len - use_len), "cd /tmp\n");
        use_len += snprintf(&g_operate_cmd[use_len], (resv_len - use_len), "tt=$(md5sum -c md5sums 2> /dev/null | grep OK)\n");
        //use_len += snprintf(&g_operate_cmd[use_len], (resv_len - use_len), "echo $tt\n");
        use_len += snprintf(&g_operate_cmd[use_len], (resv_len - use_len), "if [ -z $tt ]; then echo \"FAIL:md5sum\"; exit 0; fi\n");
        use_len += snprintf(&g_operate_cmd[use_len], (resv_len - use_len), "sysupgrade -q /tmp/%s\n", p_firmware_name);
        use_len += snprintf(&g_operate_cmd[use_len], (resv_len - use_len), "echo \"OK:sysupgrade\"; exit 0\n");

        // generate shell script file
        libwl_write_file(tmpfile, g_operate_cmd);

        // exec script
        snprintf(g_operate_cmd, sizeof(g_operate_cmd), "/bin/sh %s", tmpfile);

        // this function is block
        gateway_execuate_shell_command(g_operate_cmd, g_operate_result, sizeof(g_operate_result));
        
        GATEWAY_DBG_PRINTF(GATEWAY_GATEWAY, "[gateway] g_operate_result:%s\n", g_operate_result); 

        gateway_reply_2_mqttclient(json_item->valuestring, json_id->valuestring, 0, g_operate_result);


        GATEWAY_DBG_PRINTF(GATEWAY_GATEWAY, "[gateway] gateway_exe_firmware, exit\n");  
        return 0;
}






/**
 *@Description: the callback function of uloop
 *@Input: u: the file description of uloop
 *@Input: ev: the event of uloop
 *@Return: void
 *@author: chenzejun 20190323
 */
static int gateway_exe_install_ipk(cJSON *json_item, cJSON *pst_json)
{
        cJSON *json_str_name = NULL;
        cJSON *json_sfile = NULL;
        cJSON *json_id = NULL;
        cJSON *json_devtype = NULL;
        cJSON *json_dver = NULL;
        char * p_ipk_name = NULL;
        char * tmpfile = "/tmp/appsgrd.sh";
        int resv_len = 0;
        int use_len = 0;


        if (pst_json == NULL || json_item == NULL)
        {
                return -1;
        }

        GATEWAY_DBG_PRINTF(GATEWAY_GATEWAY, "[gateway] gateway_exe_install_ipk, in...\n");  

        
        json_sfile = cJSON_GetObjectItem( pst_json, "sfile" );  //获取键值内容
        if (json_sfile == NULL)         return -1;

        json_id = cJSON_GetObjectItem( pst_json, "id" );  //获取键值内容
        if (json_id == NULL)         return -1;
        
        json_dver = cJSON_GetObjectItem( pst_json, "pkg_version" );  //获取键值内容
        if (json_dver == NULL)         return -1;

        json_str_name = cJSON_GetObjectItem( pst_json, "pkg_str_name" );  //获取键值内容
        if (json_str_name == NULL)         return -1;

#if 0
                
        json_md5 = cJSON_GetObjectItem( pst_json, "md5" );  //获取键值内容
        if (json_md5 == NULL)         return -1;
                
        json_devtype = cJSON_GetObjectItem( pst_json, "dev_type" );  //获取键值内容
        if (json_devtype == NULL)         return -1;



        // dev_type check invalid
        if (0 != strcmp(json_devtype->valuestring, g_config.dev_type))
        {
                GATEWAY_DBG_PRINTF(GATEWAY_GATEWAY, "[gateway] dev_type not match, dev_type:%s\n", json_devtype->valuestring);
                return -2;
        }

        // dev_type check invalid, sub string
        if (NULL == strstr(json_sfile->valuestring, g_config.dev_type))
        {
                GATEWAY_DBG_PRINTF(GATEWAY_GATEWAY, "[gateway] dev_type not match, json_sfile:%s\n", json_sfile->valuestring);
                return -3;
        }
       
        GATEWAY_DBG_PRINTF(GATEWAY_GATEWAY, "[gateway] json_devtype:%s\n", json_devtype->valuestring); 

#endif

        // last position for lookup
        p_ipk_name = strrchr(json_sfile->valuestring, '/');
        if (p_ipk_name == NULL)
        {
                GATEWAY_DBG_PRINTF(GATEWAY_GATEWAY, "[gateway] p_pos fail, sfile:%s\n", json_sfile->valuestring);
                return -4;
        }

        p_ipk_name++;
        
        //delete file
        tmpfile = "/tmp/appsgrd.sh";
        system("rm -rf  /tmp/appsgrd.sh");



        resv_len = sizeof(g_operate_cmd);
        use_len = 0;
        use_len += snprintf(&g_operate_cmd[use_len], (resv_len - use_len), "#!/bin/sh\n");
        use_len += snprintf(&g_operate_cmd[use_len], (resv_len - use_len), "cd /tmp\n");
        use_len += snprintf(&g_operate_cmd[use_len], (resv_len - use_len), "wget -O /tmp/%s %s\n", p_ipk_name, json_sfile->valuestring);
        //use_len += snprintf(&g_operate_cmd[use_len], (resv_len - use_len), "echo $tt\n");
        use_len += snprintf(&g_operate_cmd[use_len], (resv_len - use_len), "if [ ! -e %s ]; then echo \"FAIL:download\"; exit 0; fi\n", p_ipk_name);
        use_len += snprintf(&g_operate_cmd[use_len], (resv_len - use_len), "opkg remove %s\n",json_str_name->valuestring);
        use_len += snprintf(&g_operate_cmd[use_len], (resv_len - use_len), "opkg install %s\n", p_ipk_name);
        use_len += snprintf(&g_operate_cmd[use_len], (resv_len - use_len), "echo \"OK:install\"; exit 0\n");

        // generate shell script file
        libwl_write_file(tmpfile, g_operate_cmd);

        // exec script
        snprintf(g_operate_cmd, sizeof(g_operate_cmd), "/bin/sh %s", tmpfile);

        // this function is block
        gateway_execuate_shell_command(g_operate_cmd, g_operate_result, sizeof(g_operate_result));
        
        GATEWAY_DBG_PRINTF(GATEWAY_GATEWAY, "[gateway] g_operate_result:%s\n", g_operate_result); 

        gateway_reply_2_mqttclient(json_item->valuestring, json_id->valuestring, 0, g_operate_result);


        GATEWAY_DBG_PRINTF(GATEWAY_GATEWAY, "[gateway] gateway_exe_install_ipk, exit\n");  
        return 0;
}










/**
 *@Description: the callback function of uloop
 *@Input: u: the file description of uloop
 *@Input: ev: the event of uloop
 *@Return: void
 *@author: chenzejun 20190323
 */
static int gateway_exe_script(cJSON *json_item, cJSON *pst_json)
{
        cJSON *json_md5 = NULL;
        cJSON *json_sfile = NULL;
        cJSON *json_id = NULL;
        cJSON *json_devtype = NULL;
        cJSON *json_dver = NULL;
        char * p_script_name = NULL;
        char * tmpfile = "/tmp/scriptgrd.sh";
        int resv_len = 0;
        int use_len = 0;


        if (pst_json == NULL || json_item == NULL)
        {
                return -1;
        }

        GATEWAY_DBG_PRINTF(GATEWAY_GATEWAY, "[gateway] gateway_exe_install_ipk, in...\n");  

        
        json_sfile = cJSON_GetObjectItem( pst_json, "sfile" );  //获取键值内容
        if (json_sfile == NULL)         return -1;

        json_id = cJSON_GetObjectItem( pst_json, "id" );  //获取键值内容
        if (json_id == NULL)         return -1;

#if 0
        json_dver = cJSON_GetObjectItem( pst_json, "dest_version" );  //获取键值内容
        if (json_dver == NULL)         return -1;
                
        json_md5 = cJSON_GetObjectItem( pst_json, "md5" );  //获取键值内容
        if (json_md5 == NULL)         return -1;
                
        json_devtype = cJSON_GetObjectItem( pst_json, "dev_type" );  //获取键值内容
        if (json_devtype == NULL)         return -1;



        // dev_type check invalid
        if (0 != strcmp(json_devtype->valuestring, g_config.dev_type))
        {
                GATEWAY_DBG_PRINTF(GATEWAY_GATEWAY, "[gateway] dev_type not match, dev_type:%s\n", json_devtype->valuestring);
                return -2;
        }

        // dev_type check invalid, sub string
        if (NULL == strstr(json_sfile->valuestring, g_config.dev_type))
        {
                GATEWAY_DBG_PRINTF(GATEWAY_GATEWAY, "[gateway] dev_type not match, json_sfile:%s\n", json_sfile->valuestring);
                return -3;
        }
       
        GATEWAY_DBG_PRINTF(GATEWAY_GATEWAY, "[gateway] json_devtype:%s\n", json_devtype->valuestring); 

#endif

        // last position for lookup
        p_script_name = strrchr(json_sfile->valuestring, '/');
        if (p_script_name == NULL)
        {
                GATEWAY_DBG_PRINTF(GATEWAY_GATEWAY, "[gateway] p_pos fail, sfile:%s\n", json_sfile->valuestring);
                return -4;
        }

        p_script_name++;
        
        //delete file
        tmpfile = "/tmp/scriptgrd.sh";
        system("rm -rf  /tmp/scriptgrd.sh");



        resv_len = sizeof(g_operate_cmd);
        use_len = 0;
        use_len += snprintf(&g_operate_cmd[use_len], (resv_len - use_len), "#!/bin/sh\n");
        use_len += snprintf(&g_operate_cmd[use_len], (resv_len - use_len), "cd /tmp\n");
        use_len += snprintf(&g_operate_cmd[use_len], (resv_len - use_len), "wget -O /tmp/%s %s\n", p_script_name, json_sfile->valuestring);
        //use_len += snprintf(&g_operate_cmd[use_len], (resv_len - use_len), "echo $tt\n");
        use_len += snprintf(&g_operate_cmd[use_len], (resv_len - use_len), "/bin/sh %s", p_script_name);
        use_len += snprintf(&g_operate_cmd[use_len], (resv_len - use_len), "echo \"OK:sysupgrade\"; exit 0\n");

        // generate shell script file
        libwl_write_file(tmpfile, g_operate_cmd);

        // exec script
        snprintf(g_operate_cmd, sizeof(g_operate_cmd), "/bin/sh %s", tmpfile);

        // this function is block
        gateway_execuate_shell_command(g_operate_cmd, g_operate_result, sizeof(g_operate_result));
        
        GATEWAY_DBG_PRINTF(GATEWAY_GATEWAY, "[gateway] g_operate_result:%s\n", g_operate_result); 

        gateway_reply_2_mqttclient(json_item->valuestring, json_id->valuestring, 0, g_operate_result);


        GATEWAY_DBG_PRINTF(GATEWAY_GATEWAY, "[gateway] gateway_exe_install_ipk, exit\n");  
        return 0;
}





/**
 *@Description: the callback function of uloop
 *@Input: u: the file description of uloop
 *@Input: ev: the event of uloop
 *@Return: void
 *@author: chenzejun 20190323
 */
static int gateway_exe_reboot(cJSON *json_item, cJSON *pst_json)
{
        cJSON *json_id = NULL;


        if (pst_json == NULL || json_item == NULL)
        {
                return -1;
        }

        GATEWAY_DBG_PRINTF(GATEWAY_GATEWAY, "[gateway] gateway_exe_reboot, in...\n");  



        json_id = cJSON_GetObjectItem( pst_json, "id" );  //获取键值内容
        if (json_id == NULL)         return -1;
        

        // this function is block
        gateway_execuate_shell_command("reboot", g_operate_result, sizeof(g_operate_result));
        
        GATEWAY_DBG_PRINTF(GATEWAY_GATEWAY, "[gateway] g_operate_result:%s\n", g_operate_result); 

        gateway_reply_2_mqttclient(json_item->valuestring, json_id->valuestring, 0, g_operate_result);


        GATEWAY_DBG_PRINTF(GATEWAY_GATEWAY, "[gateway] gateway_exe_reboot, exit\n");  
        return 0;
}








/**
 *@Description: the callback function of uloop
 *@Input: u: the file description of uloop
 *@Input: ev: the event of uloop
 *@Return: void
 *@author: chenzejun 20190323
 */
static int gateway_exe_start_ssh(cJSON *json_item, cJSON *pst_json)
{
        cJSON *json_id = NULL;


        if (pst_json == NULL || json_item == NULL)
        {
                return -1;
        }

        GATEWAY_DBG_PRINTF(GATEWAY_GATEWAY, "[gateway] gateway_exe_start_ssh, in...\n");  



        json_id = cJSON_GetObjectItem( pst_json, "id" );  //获取键值内容
        if (json_id == NULL)         return -1;
        

        // this function is block
        gateway_execuate_shell_command("/etc/init.d/frpc start", g_operate_result, sizeof(g_operate_result));
        
        GATEWAY_DBG_PRINTF(GATEWAY_GATEWAY, "[gateway] g_operate_result:%s\n", g_operate_result); 

        gateway_reply_2_mqttclient(json_item->valuestring, json_id->valuestring, 0, "call shell ok");


        GATEWAY_DBG_PRINTF(GATEWAY_GATEWAY, "[gateway] gateway_exe_start_ssh, exit\n");  
        return 0;
}










/**
 *@Description: the callback function of uloop
 *@Input: u: the file description of uloop
 *@Input: ev: the event of uloop
 *@Return: void
 *@author: chenzejun 20190323
 */
static int gateway_exe_stop_ssh(cJSON *json_item, cJSON *pst_json)
{
        cJSON *json_id = NULL;


        if (pst_json == NULL || json_item == NULL)
        {
                return -1;
        }

        GATEWAY_DBG_PRINTF(GATEWAY_GATEWAY, "[gateway] gateway_exe_stop_ssh, in...\n");  



        json_id = cJSON_GetObjectItem( pst_json, "id" );  //获取键值内容
        if (json_id == NULL)         return -1;
        

        // this function is block
        gateway_execuate_shell_command("/etc/init.d/frpc stop", g_operate_result, sizeof(g_operate_result));
        
        GATEWAY_DBG_PRINTF(GATEWAY_GATEWAY, "[gateway] g_operate_result:%s\n", g_operate_result); 

        gateway_reply_2_mqttclient(json_item->valuestring, json_id->valuestring, 0, "call shell ok");


        GATEWAY_DBG_PRINTF(GATEWAY_GATEWAY, "[gateway] gateway_exe_stop_ssh, exit\n");  
        return 0;
}



#endif




#if FUNCTION_DESC("local client function")

static char msg_buffer[LOG_BUFFER_2048 + BUF_LEN_128] = {0};
static char *gateway_publish_msg = NULL;














/**
*@Description: send msg to kernel
*@Input: epollfd: epoll fd
*@Input: sock_fd: socket fd
*@Return:  0: ok
           <0: fail
*@author: chenzejun 20190323
*/
static int gateway_reply_2_mqttclient(char *cmd_item, char *uuId, int retno, char *retmsg)
{
        struct cmsghdr *pst_head = (struct cmsghdr *)gateway_publish_msg;
        CLIENT_TLV_DATA *pst_tlv_data = (CLIENT_TLV_DATA *)(pst_head + 1);
        int msg_len = 0;
        int topic_len = 0;
        int bytes = 0;
        char *pc_msg = NULL;
        time_t now;
        unsigned long unixtime; 


        if (cmd_item == NULL || uuId == NULL)
        {
                return -1;
        }

        GATEWAY_DBG_PRINTF(GATEWAY_GATEWAY, "[gateway] gateway_reply_2_mqttclient, in\n");  

        //msg header
        pst_head->cmsg_len = 0;
        pst_head->cmsg_type = MOSQ_CLIENT_PUB;
        pst_head->cmsg_len += sizeof(struct cmsghdr);


        // tlv:  topic
        pst_tlv_data = (CLIENT_TLV_DATA *)(pst_head + 1);
        pst_tlv_data->us_tlv_type =TLV_TYPE_TOPIC;
        pc_msg = (char *)(pst_tlv_data + 1);
        topic_len = snprintf(pc_msg, LOG_BUFFER_4096, "yunAC/%s/%s", g_config.route_mac, cmd_item);
        pst_tlv_data->us_tlv_len = sizeof(CLIENT_TLV_DATA) + topic_len + 1;  
        pst_head->cmsg_len += pst_tlv_data->us_tlv_len;


        //GATEWAY_DBG_PRINTF(GATEWAY_GATEWAY, "[gateway] topic:%s\n", pc_msg);  

        // tlv:  message
        pst_tlv_data =  (CLIENT_TLV_DATA *)((char *)pst_tlv_data + pst_tlv_data->us_tlv_len);
        pst_tlv_data->us_tlv_type =TLV_TYPE_PAYLOAD;
        pc_msg = (char *)(pst_tlv_data + 1);


        // 1.0 fill msg
        unixtime = time(&now);
     		
        //GATEWAY_DBG_PRINTF(GATEWAY_GATEWAY, "[gateway] sendto 22, uuId:%s\n", uuId); 
        //GATEWAY_DBG_PRINTF(GATEWAY_GATEWAY, "[gateway] sendto 22, errno:%d\n", retno); 
        //GATEWAY_DBG_PRINTF(GATEWAY_GATEWAY, "[gateway] sendto 22, errmsg:%s\n", retmsg); 
        //GATEWAY_DBG_PRINTF(GATEWAY_GATEWAY, "[gateway] sendto 22, g_config.route_m:%s\n", g_config.route_mac); 
        //GATEWAY_DBG_PRINTF(GATEWAY_GATEWAY, "[gateway] sendto 22, unixtime:%lu\n", unixtime); 
        // 3.0 fill tail msg
        msg_len = snprintf(pc_msg, LOG_BUFFER_4096,
                "{\"id\":\"%s\",\"retcode\":\"%d\",\"retmsg\":\"%s\",\"mac\":\"%s\",\"unixtime\":\"%lu\"}", 
                uuId, retno, retmsg,  g_config.route_mac, unixtime);  
        // snprintf is return source string length
        if (msg_len >= LOG_BUFFER_4096){
                msg_len = LOG_BUFFER_4096;
        }
        else{
                msg_len++;
        }

        // length
        pst_tlv_data->us_tlv_len = sizeof(CLIENT_TLV_DATA) + msg_len;  
        pst_head->cmsg_len += pst_tlv_data->us_tlv_len;

        GATEWAY_DBG_PRINTF(GATEWAY_GATEWAY, "[gateway] sendto to server...\n");  


        bytes = sendto(g_config.uloop_fd_client.fd, gateway_publish_msg, pst_head->cmsg_len, 0, (struct sockaddr*)&g_config.mqttclient_sockaddr, g_config.mqttclient_addr_len);
        GATEWAY_DBG_PRINTF(GATEWAY_GATEWAY, "[gateway] sendto serv message[%d]: %s\n", msg_len, pc_msg); 

        return 0;
}




/**
*@Description: send msg to kernel
*@Input: epollfd: epoll fd
*@Input: sock_fd: socket fd
*@Return:  0: ok
           <0: fail
*@author: chenzejun 20190323
*/
static void gateway_sendmsg_2_mqttclient()
{
        struct cmsghdr *pst_head = (struct cmsghdr *)gateway_publish_msg;
        CLIENT_TLV_DATA *pst_tlv_data = (CLIENT_TLV_DATA *)(pst_head + 1);
        int i_ret = 0;
        time_t now;
        unsigned long unixtime; 
        char data_time_str[BUF_LEN_64] = {0}; 
        int publish_msg_len = 0;
        struct tm *p_tm;
        struct tm  tm;
        static int t_count = 0;
        unsigned int resv_len = 0;
        int bytes = 0;
        int i = 0;
        char *pc_msg = NULL;



        t_count++;
        if (t_count < 6)	return;
        t_count = 0;

        //this is zone set, it's fixed localtime don't update when zone change.
        //2016.8.11, use tzset(), localtime Is still wrong.
        //tzset();  

        //time stamp
        unixtime = time(&now);
        p_tm = localtime(&now);
         strftime(data_time_str, sizeof(data_time_str), "%Y-%m-%d %H:%M:%S", p_tm); 
        g_config.sequence_number++;



        //msg header
        pst_head->cmsg_len = 0;
        pst_head->cmsg_type = MOSQ_CLIENT_PUB;
        pst_head->cmsg_len += sizeof(struct cmsghdr);


        // tlv:  topic
        pst_tlv_data = (CLIENT_TLV_DATA *)(pst_head + 1);
        pst_tlv_data->us_tlv_type =TLV_TYPE_TOPIC;
        pst_tlv_data->us_tlv_len = sizeof(CLIENT_TLV_DATA) + sizeof("yunJDWX/jdwx_exec/post/plc");  
        pc_msg = (char *)(pst_tlv_data + 1);
        snprintf(pc_msg, BUF_LEN_512, "yunJDWX/jdwx_exec/post/plc");
        pst_head->cmsg_len += pst_tlv_data->us_tlv_len;

        // tlv:  message
        pst_tlv_data =  (CLIENT_TLV_DATA *)((char *)pst_tlv_data + pst_tlv_data->us_tlv_len);
        pst_tlv_data->us_tlv_type =TLV_TYPE_PAYLOAD;
        pc_msg = (char *)(pst_tlv_data + 1);



        // 1.0 fill msg
        publish_msg_len = snprintf(pc_msg, LOG_BUFFER_4096,
                "{\"devList\":[{\"devId\":%d,\"devName\":\"plc\",\"varList\":[", 
                2);   


        // 2.0 fill var body
        for(i = 0; i < 60; i++) 
        {
                resv_len = LOG_BUFFER_4096 - publish_msg_len;
                if (resv_len < 100)   //left length is too short
                {
                        break;
                }
                
                publish_msg_len += snprintf(&pc_msg[publish_msg_len], resv_len, "{\"varName\":\"testVar%d\",\"varValue\":\"%.3f\",\"varId\":%u},", 
                        i,
                        (tm.tm_min/3+0.11)*(0.117 + i),
                        i);
        }

		
        // 3.0 fill tail msg
        resv_len = LOG_BUFFER_4096 - publish_msg_len;
        publish_msg_len += snprintf(&pc_msg[publish_msg_len-1], resv_len,
                "]}],\"cmdId\":%d,\"gwSn\":\"JDWX%s\",\"time\":\"%s\",\"unixtime\":\"%lu\",\"seqnum\":\"%u\"}", 
                103,
                g_config.route_mac,
                data_time_str,
                unixtime,
                g_config.sequence_number);       

        publish_msg_len--;   ///  pc_msg[publish_msg_len-1],
        GATEWAY_DBG_PRINTF(GATEWAY_GATEWAY, "pc_msg[%d], %d, %d, %d\n", 
                publish_msg_len, pc_msg[publish_msg_len-1], pc_msg[publish_msg_len], pc_msg[publish_msg_len+1]); 
        
        // snprintf is return source string length
        if (publish_msg_len >= LOG_BUFFER_4096){
                publish_msg_len = LOG_BUFFER_4096;
        }
        else{
                publish_msg_len++;  //\0
        }


        // length
        pst_tlv_data->us_tlv_len = sizeof(CLIENT_TLV_DATA) + publish_msg_len;  
        pst_head->cmsg_len += pst_tlv_data->us_tlv_len;



        bytes = sendto(g_config.uloop_fd_client.fd, gateway_publish_msg, pst_head->cmsg_len, 0, (struct sockaddr*)&g_config.mqttclient_sockaddr, g_config.mqttclient_addr_len);
        GATEWAY_DBG_PRINTF(GATEWAY_GATEWAY, "sendto serv message[%d]: %s\n", publish_msg_len, pc_msg); 

        return;
}




/**
 *@Description: the callback function of uloop
 *@Input: u: the file description of uloop
 *@Input: ev: the event of uloop
 *@Return: void
 *@author: chenzejun 20190323
 */
static int gateway_parse_msg(char *pc_msg, int msg_len)
{
        cJSON *pst_json = NULL;
        cJSON *json_item = NULL;
        cJSON *json_sfile = NULL;
        char * p_pos = NULL;
        char * cmd_type= "NA";
        char * cmd_name ="NA";


        if (pc_msg == NULL)
        {
                return -1;
        }
        
        pst_json = cJSON_Parse(pc_msg);
        json_item = cJSON_GetObjectItem(pst_json , "item" );  //获取键值内容
        if (json_item == NULL)
        {
                return -1;
        }

        
        GATEWAY_DBG_PRINTF(GATEWAY_GATEWAY, "[gateway] parse json, json_item:%s\n", json_item->valuestring); 


        p_pos = strstr(json_item->valuestring, "CMD_EXE");
        if (NULL != p_pos)
        {
                cmd_type = "CMD_EXE";
                cmd_name = p_pos + sizeof("CMD_EXE");
        }
        else
        {
                cmd_type = "NA";
                cmd_name = "NA";
                GATEWAY_DBG_PRINTF(GATEWAY_GATEWAY, "[gateway] command not know, json_item:%s, exit\n", json_item->valuestring);  
                return -1;
        }


        GATEWAY_DBG_PRINTF(GATEWAY_GATEWAY, "[gateway] cmd_type:%s, cmd_name:%s\n", cmd_type, cmd_name); 


        if (0 == strcmp(cmd_name, "firmware"))
        {
                gateway_exe_firmware(json_item, pst_json);
        }
        else if (0 == strcmp(cmd_name, "script"))
        {
                gateway_exe_script(json_item, pst_json);
        }
        else if (0 == strcmp(cmd_name, "apps"))
        {
                gateway_exe_install_ipk(json_item, pst_json);
        }
        else if (0 == strcmp(cmd_name, "reboot"))
        {
                gateway_exe_reboot(json_item, pst_json);
        }
        else if (0 == strcmp(cmd_name, "startssh"))
        {
                gateway_exe_start_ssh(json_item, pst_json);
        }
        else if (0 == strcmp(cmd_name, "stopssh"))
        {
                gateway_exe_stop_ssh(json_item, pst_json);
        }
        else
        {
                GATEWAY_DBG_PRINTF(GATEWAY_GATEWAY, "[gateway] command not match, cmd_name:%s, exit\n", cmd_name);  
                return -1;
        }



        GATEWAY_DBG_PRINTF(GATEWAY_GATEWAY, "[gateway] parse json, exit\n");  
        return 0;
}




/**
 *@Description: the callback function of uloop
 *@Input: u: the file description of uloop
 *@Input: ev: the event of uloop
 *@Return: void
 *@author: chenzejun 20190323
 */
static void gateway_recvfrom_handle(struct uloop_fd *u, unsigned int ev)
{
        CLIENT_TLV_DATA *pst_tlv = (CLIENT_TLV_DATA *)msg_buffer;
        int bytes;
        int sock_fd = -1;
        int rt0_count = 0;

        if (u == NULL)
        {
                return;
        }
        
        sock_fd = u->fd;
        GATEWAY_DBG_PRINTF(GATEWAY_GATEWAY, "[gateway] gateway_recvfrom_handle..., fd:%d\n", sock_fd);  

        /* found new client, process */
        while(1)  
        {

                /* recv data, non block */
                memset(msg_buffer, 0, sizeof(msg_buffer));
                bytes = recv(sock_fd, msg_buffer, LOG_BUFFER_2048, MSG_DONTWAIT);
                if(bytes < 0)
                {
                        if(errno != EAGAIN)  
                        {
                                GATEWAY_DBG_PRINTF(GATEWAY_GATEWAY, "recvmsg end fd:%d, errno:%d, ret:%d\n", sock_fd, errno, bytes); 
                        }

                        break;
                }
                else if(bytes == 0){
                        //if peer socket ctrl+c; it return 0;
                        // count 5 to exit;
                        //当客户端Socket关闭时，服务端的Socket会接收到0字节的通知。
                        if (rt0_count > 5){
                                g_config.uloop_fd_client.fd = -1;
                                break;
                        }
                        
                        rt0_count++; 
                        GATEWAY_DBG_PRINTF(GATEWAY_GATEWAY, "[gateway] next receive, count:%d, %d\n", rt0_count, errno);  
                        continue;
                }

                GATEWAY_DBG_PRINTF(GATEWAY_GATEWAY, "[gateway] receive msg, get bytes:%d, %d\n", bytes, errno);  
                GATEWAY_DBG_PRINTF(GATEWAY_GATEWAY, "[gateway] receive msg, msg:%s\n", msg_buffer); 
                gateway_parse_msg(msg_buffer, bytes);
        }

        GATEWAY_DBG_PRINTF(GATEWAY_GATEWAY, "[gateway] gateway_recvfrom_handle, exit\n");  
        return;
}




/**
*@Description: try to start socket of 5g
*@Input: void: void
*@Return: void
*@author: chenzejun 20190323
*/
static void gateway_gateway_try_connect_service(void)
{
         struct sockaddr_un client_address  = {0};



        if (g_config.uloop_fd_client.fd <= 0)
        {
                //it need init clien and service
                client_address.sun_family = AF_UNIX;
                snprintf(client_address.sun_path, sizeof(client_address.sun_path), "/var/run/%s.client", g_config.my_name);

        
                /* command service*/
                g_config.uloop_fd_client.cb = gateway_recvfrom_handle;
                g_config.uloop_fd_client.fd = libwl_cmd_create_socket(&client_address);
                if (g_config.uloop_fd_client.fd > 0)
                {
                        uloop_fd_add(&g_config.uloop_fd_client,  ULOOP_READ | ULOOP_EDGE_TRIGGER);
                        GATEWAY_DBG_PRINTF(GATEWAY_GATEWAY, "[gateway] connect ok, uloop_fd_client fd:%d\n", g_config.uloop_fd_client.fd );  

                }

                GATEWAY_DBG_PRINTF(GATEWAY_GATEWAY, "[gateway] try connect service fd:%d\n", g_config.uloop_fd_client.fd );  

        }
        

        GATEWAY_DBG_PRINTF(GATEWAY_GATEWAY, "[gateway] try connect service\n");  
        return;
}



/**
 *@Description: monoff command init
 *@Input: void: void
 *@Return: 0: ok;   -1: fail
 *@author: chenzejun 20190323
 */
static int gateway_gateway_init(void)
{

        gateway_publish_msg = malloc(LOG_BUFFER_4096 + BUF_LEN_512);
        if(NULL == gateway_publish_msg)
        {  
                GATEWAY_DBG_PRINTF(GATEWAY_ERROR, "malloc gateway_publish_msg failed\n");
                return -1;
        }


        /* init sun_path */
        g_config.mqttclient_sockaddr.sun_family = AF_UNIX;
        snprintf(g_config.mqttclient_sockaddr.sun_path, sizeof(g_config.mqttclient_sockaddr.sun_path), "%s", g_config.srvaddr_name);
        g_config.mqttclient_addr_len = strlen(g_config.mqttclient_sockaddr.sun_path) + sizeof(g_config.mqttclient_sockaddr.sun_family);


        gateway_gateway_try_connect_service();
        
        return 0;
}



/**
 *@Description: monoff command destroy
 *@Input: void: void
 *@Return: 0: ok;   -1: fail
 *@author: chenzejun 20190323
 */
static int gateway_gateway_destroy(void)
{
        if (g_config.uloop_fd_client.fd > 0)
        {
                close(g_config.uloop_fd_client.fd);
                g_config.uloop_fd_client.fd = -1;
        }

        if (gateway_publish_msg)
        {
                free(gateway_publish_msg);
                gateway_publish_msg = NULL;
        }

        return 0;
}

#endif








#if FUNCTION_DESC("timer function")

static struct uloop_timeout gateway_10s_timer = 
{
        .cb = gateway_uloop_10s_timer,
};



/**
*@Description: timer function
*@Input: timeout: timeout
*@Return: 0: ok;   -1: fail
*@author: chenzejun 20190323
*/
static void gateway_uloop_10s_timer(struct uloop_timeout *timeout)
{
        GATEWAY_DBG_PRINTF(GATEWAY_TIMER, "[in] uloop 10s timer.... \n"); 

        uloop_timeout_set(timeout, 10000);

        gateway_gateway_try_connect_service();

        gateway_sendmsg_2_mqttclient();

        GATEWAY_DBG_PRINTF(GATEWAY_TIMER, "[out] uloop 10s timer.... \n"); 

        return;
}


#endif


#if FUNCTION_DESC("option function")



/**
 *@Description: show mac scan config
 *@Input: void
 *@Return: 0: ok;   -1: fail
 *@author: chenzejun 20190323
 */
static int gateway_show_config(char *buffer, int buff_size)
{
        int  buf_len = 0;  

        if (buffer == NULL)    return 0;
        
        buf_len += snprintf(&buffer[buf_len], (buff_size - buf_len), "%-30s: %s\n", "version", g_config.version);
        buf_len += snprintf(&buffer[buf_len], (buff_size - buf_len), "%-30s: %s\n", "buildtime", g_config.buildtime);
        buf_len += snprintf(&buffer[buf_len], (buff_size - buf_len), "%-30s: %s\n", "my_name", g_config.my_name);
        buf_len += snprintf(&buffer[buf_len], (buff_size - buf_len), "%-30s: %s\n", "srvaddr_name", g_config.srvaddr_name);
        buf_len += snprintf(&buffer[buf_len], (buff_size - buf_len), "%-30s: %s\n", "lockfile_name", g_config.lockfile_name);
        buf_len += snprintf(&buffer[buf_len], (buff_size - buf_len), "%-30s: %s\n", "route_mac", g_config.route_mac);
        buf_len += snprintf(&buffer[buf_len], (buff_size - buf_len), "%-30s: %s\n", "wan_name", g_config.wan_name);
        buf_len += snprintf(&buffer[buf_len], (buff_size - buf_len), "%-30s: %s\n", "dev_type", g_config.dev_type);


        // buf_len is string length, buf_len++ will include \0 char to send.
        return ++buf_len;
}





/**
 *@Description: show debug switich
 *@Input: buffer
 *@Input: buff_size
 *@Return: 0: ok;   -1: fail
 *@author: chenzejun 20170323
 */
static int gateway_show_debug_switch(char *buffer, int buff_size)
{
        int  buf_len = 0;  

        if (buffer == NULL)    return 0;

        buf_len += snprintf(&buffer[buf_len], (buff_size - buf_len), "%-30s: %d\n", MACROSTR_VALUE(LIBWL_INFO));
        buf_len += snprintf(&buffer[buf_len], (buff_size - buf_len), "%-30s: %d\n", MACROSTR_VALUE(LIBWL_ERROR));
        buf_len += snprintf(&buffer[buf_len], (buff_size - buf_len), "%-30s: %d\n", MACROSTR_VALUE(LIBWL_LOG_TRACE));
        buf_len += snprintf(&buffer[buf_len], (buff_size - buf_len), "%-30s: %d\n", MACROSTR_VALUE(GATEWAY_GATEWAY));
        buf_len += snprintf(&buffer[buf_len], (buff_size - buf_len), "%-30s: %d\n", MACROSTR_VALUE(LIBWL_API_TRACE));
        buf_len += snprintf(&buffer[buf_len], (buff_size - buf_len), "%-30s: %d\n", MACROSTR_VALUE(GATEWAY_INFO));
        buf_len += snprintf(&buffer[buf_len], (buff_size - buf_len), "%-30s: %d\n", MACROSTR_VALUE(GATEWAY_ERROR));
        buf_len += snprintf(&buffer[buf_len], (buff_size - buf_len), "%-30s: %d\n", MACROSTR_VALUE(GATEWAY_DBG));
        buf_len += snprintf(&buffer[buf_len], (buff_size - buf_len), "%-30s: %d\n", MACROSTR_VALUE(GATEWAY_TIMER));
        buf_len += snprintf(&buffer[buf_len], (buff_size - buf_len), "%-30s: %d\n", MACROSTR_VALUE(GATEWAY_SCAN_INFO));
        buf_len += snprintf(&buffer[buf_len], (buff_size - buf_len), "%-30s: %d\n", MACROSTR_VALUE(GATEWAY_CONN_INFO));
        buf_len += snprintf(&buffer[buf_len], (buff_size - buf_len), "%-30s: %d\n", MACROSTR_VALUE(GATEWAY_MQTT_CALLBACK_LOG));
        buf_len += snprintf(&buffer[buf_len], (buff_size - buf_len), "%-30s: %d\n", MACROSTR_VALUE(GATEWAY_UBUS_INFO));
        buf_len += snprintf(&buffer[buf_len], (buff_size - buf_len), "%-30s: %d\n", MACROSTR_VALUE(GATEWAY_UCI_INFO));
        buf_len += snprintf(&buffer[buf_len], (buff_size - buf_len), "%-30s: %d\n", MACROSTR_VALUE(GATEWAY_CMD_INFO));
        buf_len += snprintf(&buffer[buf_len], (buff_size - buf_len), "%-30s: %d\n", MACROSTR_VALUE(GATEWAY_CMD_TRACE));

        // buf_len is string length, buf_len++ will include \0 char to send.
        return ++buf_len;
}


/**
*@Description: get the information of router by wan
*@Input: void: void
*@return: 0 ok;  1- fail
*@author: chenzejun 20160123
*/
void gateway_get_wan_info()
{
        FILE  *stream;

        char   buf[BUF_LEN_256];
        memset( buf, 0, BUF_LEN_256 );
        /* get AP  wan's ip & mac */


        // uci get network.wan.ifname----->eth2.2
        // ifconfig eth2.2 | awk NR==1'{print $5}'------>D4:EE:07:25:0C:7F   NR==1  
        // ifconfig eth2.2 | awk NR==1'{print $5}'|awk -F: '{print $1$2$3$4$5$6}'-------->D4EE07250C7F
        //ifconfig eth2.2 |grep 'inet addr' | awk -F: '{print $2}'|awk '{print $1}'&&ifconfig eth2.2 | awk NR==1'{print $5}'|awk -F: '{print $1$2$3$4$5$6}'
        //output information:
        //121.194.169.217
        // D4EE07250C7F
                
        //stream = popen("ifconfig `uci get network.lan.ifname`|awk NR==1'{print $5}'|awk -F: '{print $1$2$3$4$5$6}'","r");
        stream = popen("ifconfig | grep br-lan | awk NR==1'{print $5}'|awk -F: '{print $1$2$3$4$5$6}'","r");
        if(stream != NULL)
        {
                fread( buf, sizeof(char), BUF_LEN_256, stream);
                /*while (fgets(buf, BUF_LEN_256, stream) != NULL) */
                {
                        snprintf(g_config.route_mac, sizeof(g_config.route_mac), "%s", strtok(buf, "\n"));
                }

                if (strlen(g_config.route_mac) >= 12) 
                {
                        printf("route_mac=%s\n", g_config.route_mac);
                }
        }
        pclose( stream );
}

/**
*@Description: print usage
*@Input: void: void
*@return: 0 ok;  1- fail
*@author: chenzejun 20160123
*/
static void gateway_print_usage(void)
{
	printf("gateway-rms version %s (build date %s)\n", g_config.version, g_config.buildtime);
	printf("Usage: gateway-rms [-d] [-l] [-h]\n");
	printf("               [test]\n");
	printf("       gateway-rms --help\n\n");

	
	printf(" -d : debug switch, output to screen.\n");
	printf(" -l : debug switch, output to log.\n");
	printf(" -v : display the version\n");

	printf(" --conn-num : config the number of the connected mac list, between 100 and 5000\n");
	printf(" --scan-num : config the number of the scaned mac list, between 100 and 5000\n");
	printf(" test : send test package to the remote service.\n");
}

/**
*@Description: Process a tokenised single line from a file or set of real argc/argv
*@Input: void: void
*@return: 0 ok;  1- fail
*@author: chenzejun 20160123
*/
int gateway_option_proc(int argc, char *argv[])
{
        int i;
        int test_count = 0;
        int num;
        int remote_flag = 0;
        int sockfd = -1;

        for (i=1; i<argc; i++)
        {
                if(!strcmp(argv[i], "-h") || !strcmp(argv[i], "--help"))
                {
                        gateway_print_usage();
                        exit(0);
                }
                else if(!strcmp(argv[i], "-v"))
                {
                        printf("[GATEWAY-RMS] Welcome to gateway-rms, Revision:%s (build date:%s)\n"
                                "(C) 2004-19 jindawanxiang.com\n",
                                g_config.version, g_config.buildtime);
                        exit(0);
                }
                else if(!strcmp(argv[i], "-d"))
                {
                        GATEWAY_OPTION_CHECK_RET(i, argc);
                
                        num = atoi(argv[i+1]);
                        libwl_cmd_output_printf(num);
                        i++;
                }
                else if(!strcmp(argv[i], "-l"))
                {
                        GATEWAY_OPTION_CHECK_RET(i, argc);
                        
                        num = atoi(argv[i+1]);
                        libwl_cmd_output_log(num);
                        i++;
                }
                else if(!strcmp(argv[i], "remote-show"))
                {
                        GATEWAY_OPTION_CHECK_RET(i, argc);
                        sockfd = libwl_cmd_client_create(g_config.my_name);
                        if (sockfd > 0)   
                        {
                                libwl_cmd_client_show(sockfd, 
                                        GET_VALID_ARG(i+1, argc, argv), 
                                        GET_VALID_ARG(i+2, argc, argv), 
                                        GET_VALID_ARG(i+3, argc, argv));
                        }                        exit(0);
                }
                else if(!strcmp(argv[i], "remote-debug"))
                {
                        GATEWAY_OPTION_CHECK_RET(i, argc);
                        remote_flag = 1;
                }
        }

        /* client */
        if (remote_flag == 1)
        {
                signal(SIGUSR1, SIG_IGN);
                signal(SIGUSR2, SIG_IGN);
                
                //start timer, exit after 0.5 hour
                signal(SIGALRM, libwl_cmd_client_timeout);
                alarm(1800); 
        
                sockfd = libwl_cmd_client_create(g_config.my_name);
                if (sockfd > 0)   libwl_cmd_client_debug(sockfd);
                exit(0);
        }

        return 0;

unknown_option:

        exit(0);
        return 0;
}



/**
*@Description: mac scan function init
*@Input: void: void
*@return: 0 ok;  1- fail
*@author: chenzejun 20160123
*/
static int gateway_init(void)
{
        int i_ret = 0;


        //gateway_get_wan_info();
        libwl_get_router_hwaddr_short("br-lan", g_config.route_mac, sizeof(g_config.route_mac));
        libwl_get_board_name(g_config.dev_type, sizeof(g_config.dev_type));

        uloop_init();




        //cmd init
        i_ret = gateway_cmd_init();
        if (i_ret != 0)
        {
                return -1;
        }


        //gateway init
        i_ret = gateway_gateway_init();
        if (i_ret != 0)
        {
                return -1;
        }


        return 0;

}

/**
*@Description: mac scan function destroy
*@Input: void: void
*@return: 0 ok;  1- fail
*@author: chenzejun 20160123
*/
static int gateway_destroy(void)
{
        gateway_cmd_destroy();
        gateway_gateway_destroy();
        
        return 0;
}

#endif


int main(int argc, char **argv)
{
        int i_ret = 0;

        /* init version */
        #ifdef PKG_RELEASE
        snprintf(g_config.version, BUF_LEN_64, PKG_RELEASE);
        #endif
        #ifdef TIMESTAMP
        snprintf(g_config.buildtime, BUF_LEN_64, TIMESTAMP);
        #endif

        /* option process */
        gateway_option_proc(argc, argv);


        snprintf(g_config.lockfile_name, sizeof(g_config.lockfile_name), "/var/lock/%s.lock", g_config.my_name);
        if (!libwl_inst_is_running(g_config.lockfile_name))
        {
                printf("Not support multiple instances, exit!\n");
                exit(0);
        }

        //sleep  one rand time, avoid to start at same time.
        srand((int)time(0));
        sleep(rand()%10);

        libwl_printf_currtime();

        // init
        i_ret = gateway_init();
        if (i_ret != 0)
        {
                goto OUT;
        }
        
        uloop_timeout_set(&gateway_10s_timer, 10000);


        //run
        uloop_run();

OUT:

        GATEWAY_DBG_PRINTF(GATEWAY_INFO, "main exit\n");   
        gateway_destroy();
        return 0;
}


