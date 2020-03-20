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

#include "gateway-gset.h"
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


//static char plc-gset_version[]="1.1.8";




static struct GSET_GLOBAL_CONFIG g_config =
{
        .my_name = "gateway-gset",
        .version[0] = 0,
        .buildtime[0] = 0,
        .wan_name[0] = 0,
        .route_mac[0] = 0,
        .route_ip[0] = 0,
        .dev_type[0] = 0,

        .srvaddr_name = "/var/run/mqtt-client.localserv",
        .lockfile_name = "",
        


        .uloop_fd_cmd.fd = -1,
        .uloop_fd_cmd.cb = gset_cmd_socket_handle,
};





#if FUNCTION_DESC("command function")

static struct LIBWL_CMD_LIST_ST  g_function_list[] = 
{
        {"config", gset_show_config},
        {"debug", gset_show_debug_switch},
};


/**
 *@Description: the callback function of uloop
 *@Input: u: the file description of uloop
 *@Input: ev: the event of uloop
 *@Return: void
 *@author: chenzejun 20190323
 */
static void gset_cmd_socket_handle(struct uloop_fd *u, unsigned int ev)
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
static int gset_cmd_init(void)
{
 
        /* command service*/
        g_config.uloop_fd_cmd.cb = gset_cmd_socket_handle;
        g_config.uloop_fd_cmd.fd = libwl_cmd_service_create(g_config.my_name);
        if (g_config.uloop_fd_cmd.fd > 0)
        {
                uloop_fd_add(&g_config.uloop_fd_cmd,  ULOOP_READ | ULOOP_EDGE_TRIGGER);
                GSET_DBG_PRINTF(GSET_INFO, "[gset] add cmd fd:%d\n", g_config.uloop_fd_cmd.fd );  

        }
        
        return 0;
}



/**
 *@Description: mscan command destroy
 *@Input: void: void
 *@Return: 0: ok;   -1: fail
 *@author: chenzejun 20190323
 */
static int gset_cmd_destroy(void)
{
        return libwl_cmd_service_destroy();
}

#endif



#if FUNCTION_DESC("remote command function")

GSET_SHELL_CMD_TBL shell_cmd_tbl[] =
{
	{"hostname", 			"uci get system.@system[0].hostname 2>/tmp/uci_err.log", 0},
	{"boardname", 			"cat /tmp/sysinfo/board_name", 0},
	{"boardtype", 			"cat /tmp/sysinfo/board_type", 0},
	{"fwversion", 			"uci get firmwareinfo.info.firmware_version 2>/tmp/uci_err.log", 0},
	{"rsyslogversion", 		"cat /usr/lib/opkg/info/rsyslog.control | grep Version | awk '{print $2}' 2>/dev/null", 0},
//	{"macscanversion", 		"cat /usr/lib/opkg/info/macscan.control | grep Version | awk '{print $2}'",			0},
//	{"wdpiversion",			"cat /usr/lib/opkg/info/kmod-wdpi_kernel.control | grep Version | awk '{print $2}'",0},
//	{"wifidogversion",		"cat /usr/lib/opkg/info/apfree_wifidog.control | grep Version | awk '{print $2}'", 	0},
//	{"mosquittoversion",	"cat /usr/lib/opkg/info/mosquitto.control | grep Version | awk '{print $2}'",	 	0},
	{"mqtt-clientversion",	"cat /usr/lib/opkg/info/mqtt-client.control | grep Version | awk '{print $2}'", 0},
	{"luciversion",			"cat /usr/lib/opkg/info/luci.control | grep Version | awk '{print $2}'", 0},
	{"mode",				"uci get network.lan.proto 2>/tmp/uci_err.log", 0},
	{"ssid", 				"uci get wireless.@wifi-iface[%c].ssid 2>/tmp/uci_err.log", 0},
	{"encryption", 			"uci get wireless.@wifi-iface[%c].encryption 2>/tmp/uci_err.log", 0},
	{"key", 				"uci get wireless.@wifi-iface[%c].key 2>/tmp/uci_err.log",	0},
	// liudf changed 20160215
	// add kt_wireless_op shell to be compatible with different device type
	{"channel_2.4", 		"/usr/sbin/kt_wireless_op.lua chan get 2", 0},
	{"channel_5", 			"/usr/sbin/kt_wireless_op.lua chan get 5", 0},
	{"rsyslogserverIP", 	"uci get rsyslog.@rsyslog[0].server_hostname 2>/tmp/uci_err.log", 0},
//	{"wifidogserverIP",		"uci show wifidog.@wifidog[0].auth_server_hostname | cut -d'=' -f 2", 1},
	{"mosquittoserverIP",	"uci get mosquitto.@bridge[0].address 2>/tmp/uci_err.log", 0},
	{"channel_path",	"uci get firmwareinfo.info.channel_path 2>/tmp/uci_err.log", 0},
	{NULL, NULL},
};

static pthread_mutex_t cmd_mutex = PTHREAD_MUTEX_INITIALIZER;
char g_operate_result[4096] = {0};
char g_operate_cmd[512] = {0};














/**
 *@Description: the callback function of uloop
 *@Input: u: the file description of uloop
 *@Input: ev: the event of uloop
 *@Return: void
 *@author: chenzejun 20190323
 */
static int gset_shell_cmd(cJSON *json_item, cJSON *pst_json)
{
        cJSON *json_cmd = NULL;
        cJSON *json_id = NULL;


        if (pst_json == NULL || json_item == NULL)
        {
                return -1;
        }

        GSET_DBG_PRINTF(GSET_GATEWAY, "[gset] gset_exe_shell, in...\n");  

        
        json_cmd = cJSON_GetObjectItem( pst_json, "cmd" );  //获取键值内容
        if (json_cmd == NULL)         return -1;

        json_id = cJSON_GetObjectItem( pst_json, "id" );  //获取键值内容
        if (json_id == NULL)         return -1;
        


        // exec script
        snprintf(g_operate_cmd, sizeof(g_operate_cmd), "%s", json_cmd->valuestring);

        // this function is block
        libwl_execuate_shell_command(g_operate_cmd, g_operate_result, sizeof(g_operate_result));
        
        GSET_DBG_PRINTF(GSET_GATEWAY, "[gset] shell result:\n%s", g_operate_result); 
        GSET_DBG_PRINTF(GSET_GATEWAY, "\n"); 

        gset_reply_2_mqttclient(json_item->valuestring, json_id->valuestring, 0, g_operate_result);


        GSET_DBG_PRINTF(GSET_GATEWAY, "[gset] gset_exe_shell, exit\n");  
        return 0;
}



/**
 *@Description: the callback function of uloop
 *@Input: u: the file description of uloop
 *@Input: ev: the event of uloop
 *@Return: void
 *@author: chenzejun 20190323
 */
static int gset_get_shell(cJSON *json_item, cJSON *pst_json)
{
        
        GSET_DBG_PRINTF(GSET_GATEWAY, "[gset] gset_get_shell, exit\n");  
        return 0;
}






/**
 *@Description: the callback function of uloop
 *@Input: u: the file description of uloop
 *@Input: ev: the event of uloop
 *@Return: void
 *@author: chenzejun 20190323
 */
static int gset_get_sysinfo(cJSON *json_item, cJSON *pst_json)
{





        GSET_DBG_PRINTF(GSET_GATEWAY, "[gset] gset_get_sysinfo, exit\n");  
        return 0;
}








/**
 *@Description: the callback function of uloop
 *@Input: u: the file description of uloop
 *@Input: ev: the event of uloop
 *@Return: void
 *@author: chenzejun 20190323
 */
static int gset_get_version(cJSON *json_item, cJSON *pst_json)
{





        GSET_DBG_PRINTF(GSET_GATEWAY, "[gset] gset_get_version, exit\n");  
        return 0;
}



#endif




#if FUNCTION_DESC("local client function")

static char msg_buffer[LOG_BUFFER_4096 + BUF_LEN_512] = {0};
static char *gset_publish_msg = NULL;














/**
*@Description: send msg to kernel
*@Input: epollfd: epoll fd
*@Input: sock_fd: socket fd
*@Return:  0: ok
           <0: fail
*@author: chenzejun 20190323
*/
static int gset_reply_2_mqttclient(char *cmd_item, char *uuId, int retno, char *retmsg)
{
        struct cmsghdr *pst_head = (struct cmsghdr *)gset_publish_msg;
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

        GSET_DBG_PRINTF(GSET_GATEWAY, "[gset] gset_reply_2_mqttclient, in\n");  

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


        //GSET_DBG_PRINTF(GSET_GATEWAY, "[gset] topic:%s\n", pc_msg);  

        // tlv:  message
        pst_tlv_data =  (CLIENT_TLV_DATA *)((char *)pst_tlv_data + pst_tlv_data->us_tlv_len);
        pst_tlv_data->us_tlv_type =TLV_TYPE_PAYLOAD;
        pc_msg = (char *)(pst_tlv_data + 1);


        // 1.0 fill msg
        unixtime = time(&now);
     		
        //GSET_DBG_PRINTF(GSET_GATEWAY, "[gset] sendto 22, uuId:%s\n", uuId); 
        //GSET_DBG_PRINTF(GSET_GATEWAY, "[gset] sendto 22, errno:%d\n", retno); 
        //GSET_DBG_PRINTF(GSET_GATEWAY, "[gset] sendto 22, errmsg:%s\n", retmsg); 
        //GSET_DBG_PRINTF(GSET_GATEWAY, "[gset] sendto 22, g_config.route_m:%s\n", g_config.route_mac); 
        //GSET_DBG_PRINTF(GSET_GATEWAY, "[gset] sendto 22, unixtime:%lu\n", unixtime); 
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

        GSET_DBG_PRINTF(GSET_GATEWAY, "[gset] sendto to server...\n");  


        bytes = sendto(g_config.uloop_fd_client.fd, gset_publish_msg, pst_head->cmsg_len, 0, (struct sockaddr*)&g_config.mqttclient_sockaddr, g_config.mqttclient_addr_len);
        GSET_DBG_PRINTF(GSET_GATEWAY, "[gset] sendto serv message[%d]: %s\n", msg_len, pc_msg); 

        return 0;
}




/**
 *@Description: the callback function of uloop
 *@Input: u: the file description of uloop
 *@Input: ev: the event of uloop
 *@Return: void
 *@author: chenzejun 20190323
 */
static int gset_parse_msg(char *pc_msg, int msg_len)
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

        
        GSET_DBG_PRINTF(GSET_GATEWAY, "[gset] parse json, json_item:%s\n", json_item->valuestring); 


        p_pos = strstr(json_item->valuestring, "CMD_GET");
        if (NULL != p_pos)
        {
                cmd_type = "CMD_GET";
                cmd_name = p_pos + sizeof("CMD_GET");
                GSET_DBG_PRINTF(GSET_GATEWAY, "[gset] cmd_type:%s, cmd_name:%s\n", cmd_type, cmd_name); 

                if (0 == strcmp(cmd_name, "sysinfo"))
                {
                        gset_get_sysinfo(json_item, pst_json);
                }
                else if (0 == strcmp(cmd_name, "version"))
                {
                        gset_get_version(json_item, pst_json);
                }
                else
                {
                        GSET_DBG_PRINTF(GSET_GATEWAY, "[gset] command not match, cmd_name:%s, exit\n", cmd_name);  
                        return -1;
                }

                GSET_DBG_PRINTF(GSET_GATEWAY, "[gset] parse json, exit\n"); 
                return 0;
                
        }

        // CMD_SET
        p_pos = strstr(json_item->valuestring, "CMD_SET");
        if (NULL != p_pos)
        {
                cmd_type = "CMD_SET";
                cmd_name = p_pos + sizeof("CMD_SET");
                GSET_DBG_PRINTF(GSET_GATEWAY, "[gset] cmd_type:%s, cmd_name:%s\n", cmd_type, cmd_name); 




                GSET_DBG_PRINTF(GSET_GATEWAY, "[gset] parse json, exit\n"); 
                return 0;
        }

        // CMD_SHELL
        p_pos = strstr(json_item->valuestring, "CMD_SHELL");
        if (NULL != p_pos)
        {
                cmd_type = "CMD_SHELL";
                cmd_name = p_pos + sizeof("CMD_SHELL");
                GSET_DBG_PRINTF(GSET_GATEWAY, "[gset] cmd_type:%s, cmd_name:%s\n", cmd_type, cmd_name); 


                if (0 == strcmp(cmd_name, "linux"))
                {
                        gset_shell_cmd(json_item, pst_json);
                }
                
                GSET_DBG_PRINTF(GSET_GATEWAY, "[gset] parse json, exit\n"); 
                return 0;
        }



        GSET_DBG_PRINTF(GSET_GATEWAY, "[gset] parse json fail, unknow cmd, exit\n");  
        return -1;
}




/**
 *@Description: the callback function of uloop
 *@Input: u: the file description of uloop
 *@Input: ev: the event of uloop
 *@Return: void
 *@author: chenzejun 20190323
 */
static void gset_recvfrom_handle(struct uloop_fd *u, unsigned int ev)
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
        GSET_DBG_PRINTF(GSET_GATEWAY, "[gset] gset_recvfrom_handle..., fd:%d\n", sock_fd);  

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
                                GSET_DBG_PRINTF(GSET_GATEWAY, "recvmsg end fd:%d, errno:%d, ret:%d\n", sock_fd, errno, bytes); 
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
                        GSET_DBG_PRINTF(GSET_GATEWAY, "[gset] next receive, count:%d, %d\n", rt0_count, errno);  
                        continue;
                }

                GSET_DBG_PRINTF(GSET_GATEWAY, "[gset] receive msg, get bytes:%d, %d\n", bytes, errno);  
                GSET_DBG_PRINTF(GSET_GATEWAY, "[gset] receive msg, msg:%s\n", msg_buffer); 
                gset_parse_msg(msg_buffer, bytes);
        }

        GSET_DBG_PRINTF(GSET_GATEWAY, "[gset] gset_recvfrom_handle, exit\n");  
        return;
}




/**
*@Description: try to start socket of 5g
*@Input: void: void
*@Return: void
*@author: chenzejun 20190323
*/
static void gset_gset_try_connect_service(void)
{
         struct sockaddr_un client_address  = {0};



        if (g_config.uloop_fd_client.fd <= 0)
        {
                //it need init clien and service
                client_address.sun_family = AF_UNIX;
                snprintf(client_address.sun_path, sizeof(client_address.sun_path), "/var/run/%s.client", g_config.my_name);

        
                /* command service*/
                g_config.uloop_fd_client.cb = gset_recvfrom_handle;
                g_config.uloop_fd_client.fd = libwl_cmd_create_socket(&client_address);
                if (g_config.uloop_fd_client.fd > 0)
                {
                        uloop_fd_add(&g_config.uloop_fd_client,  ULOOP_READ | ULOOP_EDGE_TRIGGER);
                        GSET_DBG_PRINTF(GSET_GATEWAY, "[gset] connect ok, uloop_fd_client fd:%d\n", g_config.uloop_fd_client.fd );  

                }

                GSET_DBG_PRINTF(GSET_GATEWAY, "[gset] try connect service fd:%d\n", g_config.uloop_fd_client.fd );  

        }
        

        GSET_DBG_PRINTF(GSET_GATEWAY, "[gset] try connect service\n");  
        return;
}



/**
 *@Description: monoff command init
 *@Input: void: void
 *@Return: 0: ok;   -1: fail
 *@author: chenzejun 20190323
 */
static int gset_gset_init(void)
{

        gset_publish_msg = malloc(LOG_BUFFER_4096 + BUF_LEN_512);
        if(NULL == gset_publish_msg)
        {  
                GSET_DBG_PRINTF(GSET_ERROR, "malloc gset_publish_msg failed\n");
                return -1;
        }


        /* init sun_path */
        g_config.mqttclient_sockaddr.sun_family = AF_UNIX;
        snprintf(g_config.mqttclient_sockaddr.sun_path, sizeof(g_config.mqttclient_sockaddr.sun_path), "%s", g_config.srvaddr_name);
        g_config.mqttclient_addr_len = strlen(g_config.mqttclient_sockaddr.sun_path) + sizeof(g_config.mqttclient_sockaddr.sun_family);


        gset_gset_try_connect_service();
        
        return 0;
}



/**
 *@Description: monoff command destroy
 *@Input: void: void
 *@Return: 0: ok;   -1: fail
 *@author: chenzejun 20190323
 */
static int gset_gset_destroy(void)
{
        if (g_config.uloop_fd_client.fd > 0)
        {
                close(g_config.uloop_fd_client.fd);
                g_config.uloop_fd_client.fd = -1;
        }

        if (gset_publish_msg)
        {
                free(gset_publish_msg);
                gset_publish_msg = NULL;
        }

        return 0;
}

#endif








#if FUNCTION_DESC("timer function")

static struct uloop_timeout gset_10s_timer = 
{
        .cb = gset_uloop_10s_timer,
};



/**
*@Description: timer function
*@Input: timeout: timeout
*@Return: 0: ok;   -1: fail
*@author: chenzejun 20190323
*/
static void gset_uloop_10s_timer(struct uloop_timeout *timeout)
{
        GSET_DBG_PRINTF(GSET_TIMER, "[in] uloop 10s timer.... \n"); 

        uloop_timeout_set(timeout, 10000);

        gset_gset_try_connect_service();


        GSET_DBG_PRINTF(GSET_TIMER, "[out] uloop 10s timer.... \n"); 

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
static int gset_show_config(char *buffer, int buff_size)
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
static int gset_show_debug_switch(char *buffer, int buff_size)
{
        int  buf_len = 0;  

        if (buffer == NULL)    return 0;

        buf_len += snprintf(&buffer[buf_len], (buff_size - buf_len), "%-30s: %d\n", MACROSTR_VALUE(LIBWL_INFO));
        buf_len += snprintf(&buffer[buf_len], (buff_size - buf_len), "%-30s: %d\n", MACROSTR_VALUE(LIBWL_ERROR));
        buf_len += snprintf(&buffer[buf_len], (buff_size - buf_len), "%-30s: %d\n", MACROSTR_VALUE(LIBWL_LOG_TRACE));
        buf_len += snprintf(&buffer[buf_len], (buff_size - buf_len), "%-30s: %d\n", MACROSTR_VALUE(GSET_GATEWAY));
        buf_len += snprintf(&buffer[buf_len], (buff_size - buf_len), "%-30s: %d\n", MACROSTR_VALUE(LIBWL_API_TRACE));
        buf_len += snprintf(&buffer[buf_len], (buff_size - buf_len), "%-30s: %d\n", MACROSTR_VALUE(GSET_INFO));
        buf_len += snprintf(&buffer[buf_len], (buff_size - buf_len), "%-30s: %d\n", MACROSTR_VALUE(GSET_ERROR));
        buf_len += snprintf(&buffer[buf_len], (buff_size - buf_len), "%-30s: %d\n", MACROSTR_VALUE(GSET_DBG));
        buf_len += snprintf(&buffer[buf_len], (buff_size - buf_len), "%-30s: %d\n", MACROSTR_VALUE(GSET_TIMER));
        buf_len += snprintf(&buffer[buf_len], (buff_size - buf_len), "%-30s: %d\n", MACROSTR_VALUE(GSET_SCAN_INFO));
        buf_len += snprintf(&buffer[buf_len], (buff_size - buf_len), "%-30s: %d\n", MACROSTR_VALUE(GSET_CONN_INFO));
        buf_len += snprintf(&buffer[buf_len], (buff_size - buf_len), "%-30s: %d\n", MACROSTR_VALUE(GSET_MQTT_CALLBACK_LOG));
        buf_len += snprintf(&buffer[buf_len], (buff_size - buf_len), "%-30s: %d\n", MACROSTR_VALUE(GSET_UBUS_INFO));
        buf_len += snprintf(&buffer[buf_len], (buff_size - buf_len), "%-30s: %d\n", MACROSTR_VALUE(GSET_UCI_INFO));
        buf_len += snprintf(&buffer[buf_len], (buff_size - buf_len), "%-30s: %d\n", MACROSTR_VALUE(GSET_CMD_INFO));
        buf_len += snprintf(&buffer[buf_len], (buff_size - buf_len), "%-30s: %d\n", MACROSTR_VALUE(GSET_CMD_TRACE));

        // buf_len is string length, buf_len++ will include \0 char to send.
        return ++buf_len;
}


/**
*@Description: get the information of router by wan
*@Input: void: void
*@return: 0 ok;  1- fail
*@author: chenzejun 20160123
*/
void gset_get_wan_info()
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
static void gset_print_usage(void)
{
	printf("gateway-gset version %s (build date %s)\n", g_config.version, g_config.buildtime);
	printf("Usage: gateway-gset [-d] [-l] [-h]\n");
	printf("               [test]\n");
	printf("       gateway-gset --help\n\n");

	
	printf(" -d : debug switch, output to screen.\n");
	printf(" -l : debug switch, output to log.\n");
	printf(" -v : display the version\n");
}

/**
*@Description: Process a tokenised single line from a file or set of real argc/argv
*@Input: void: void
*@return: 0 ok;  1- fail
*@author: chenzejun 20160123
*/
int gset_option_proc(int argc, char *argv[])
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
                        gset_print_usage();
                        exit(0);
                }
                else if(!strcmp(argv[i], "-v"))
                {
                        printf("[GATEWAY-GSET] Welcome to gateway-gset, Revision:%s (build date:%s)\n"
                                "(C) 2004-19 jindawanxiang.com\n",
                                g_config.version, g_config.buildtime);
                        exit(0);
                }
                else if(!strcmp(argv[i], "-d"))
                {
                        GSET_OPTION_CHECK_RET(i, argc);
                
                        num = atoi(argv[i+1]);
                        libwl_cmd_output_printf(num);
                        i++;
                }
                else if(!strcmp(argv[i], "-l"))
                {
                        GSET_OPTION_CHECK_RET(i, argc);
                        
                        num = atoi(argv[i+1]);
                        libwl_cmd_output_log(num);
                        i++;
                }
                else if(!strcmp(argv[i], "remote-show"))
                {
                        GSET_OPTION_CHECK_RET(i, argc);
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
                        GSET_OPTION_CHECK_RET(i, argc);
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
static int gset_init(void)
{
        int i_ret = 0;


        //gset_get_wan_info();
        libwl_get_router_hwaddr_short("br-lan", g_config.route_mac, sizeof(g_config.route_mac));
        libwl_get_board_name(g_config.dev_type, sizeof(g_config.dev_type));

        uloop_init();




        //cmd init
        i_ret = gset_cmd_init();
        if (i_ret != 0)
        {
                return -1;
        }


        //gset init
        i_ret = gset_gset_init();
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
static int gset_destroy(void)
{
        gset_cmd_destroy();
        gset_gset_destroy();
        
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
        gset_option_proc(argc, argv);


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
        i_ret = gset_init();
        if (i_ret != 0)
        {
                goto OUT;
        }
        
        uloop_timeout_set(&gset_10s_timer, 10000);


        //run
        uloop_run();

OUT:

        GSET_DBG_PRINTF(GSET_INFO, "main exit\n");   
        gset_destroy();
        return 0;
}


