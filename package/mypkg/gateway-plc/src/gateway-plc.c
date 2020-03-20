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

#include "libwl/libwl_mscan_pub.h"
#include "libwl/libwl_api_pub.h"
#include "libwl/libwl_dbg_pub.h"
#include "libwl/libwl_alist_pub.h"

#include "gateway-plc.h"
//#include   <linux/net.h>

//#include <execinfo.h>

/*
history:

by 2016.1.6:
modify gateway-plc output by josn


by 2016.1.18:
support -d -v
//gateway-plc -d    debug switch
//gateway-plc -v    version

by 2016.1.21:
//gateway-plc -p   ipaddr   support get ip addr by -p

by 2016.1.21:
1.0.3
fix the issue of getting br-lan mac is error

1.0.3


*/




//static char gateway-plc_version[]="1.1.8";




static struct PLC_GLOBAL_CONFIG g_config =
{
        .my_name = "gateway-plc",
        .version[0] = 0,
        .buildtime[0] = 0,
        .wan_name[0] = 0,
        .route_mac[0] = 0,
        .route_ip[0] = 0,
        .channelpath[0] = 0,

        .srvaddr_name = "/var/run/mqtt-client.localserv",
        .lockfile_name = "",
        


        .uloop_fd_cmd.fd = -1,
        .uloop_fd_cmd.cb = plc_cmd_socket_handle,
};





#if FUNCTION_DESC("command function")

static struct LIBWL_CMD_LIST_ST  g_function_list[] = 
{
        {"config", plc_show_config},
        {"debug", plc_show_debug_switch},
};


/**
 *@Description: the callback function of uloop
 *@Input: u: the file description of uloop
 *@Input: ev: the event of uloop
 *@Return: void
 *@author: chenzejun 20160323
 */
static void plc_cmd_socket_handle(struct uloop_fd *u, unsigned int ev)
{
        libwl_cmd_service_callback(u->fd, g_function_list, ARRAY_SIZE(g_function_list));
        return;
}





/**
 *@Description: mscan command init
 *@Input: void: void
 *@Return: 0: ok;   -1: fail
 *@author: chenzejun 20160323
 */
static int plc_cmd_init(void)
{
 
        /* command service*/        
        g_config.uloop_fd_cmd.cb = plc_cmd_socket_handle;
        g_config.uloop_fd_cmd.fd = libwl_cmd_service_create(g_config.my_name);
        if (g_config.uloop_fd_cmd.fd > 0)
        {
                uloop_fd_add(&g_config.uloop_fd_cmd,  ULOOP_READ | ULOOP_EDGE_TRIGGER);
                PLC_DBG_PRINTF(PLC_INFO, "gateway-plc add cmd fd:%d\n", g_config.uloop_fd_cmd.fd );  

        }
        
        return 0;
}



/**
 *@Description: mscan command destroy
 *@Input: void: void
 *@Return: 0: ok;   -1: fail
 *@author: chenzejun 20160323
 */
static int plc_cmd_destroy(void)
{
        return libwl_cmd_service_destroy();
}

#endif





#if FUNCTION_DESC("local client function")

static char msg_buffer[LOG_BUFFER_2048 + BUF_LEN_128] = {0};
static char *plc_publish_msg = NULL;






/**
 *@Description: the callback function of uloop
 *@Input: u: the file description of uloop
 *@Input: ev: the event of uloop
 *@Return: void
 *@author: chenzejun 20160323
 */
static void plc_sendto_service(char *topic, char * p_msg,  int msg_len)
{
        int i_ret = 0;
        time_t now;
        unsigned long unixtime; 
        char data_time_str[BUF_LEN_64] = {0}; 
        unsigned int publish_msg_len = 0;
        struct tm *p_tm;
        struct tm  tm;
        static int t_count = 0;
        unsigned int resv_len = 0;
        int bytes = 0;
        int i = 0;
        struct sockaddr_un mqttclient_sockaddr = {0 };
        int mqttclient_addr_len = 0;


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


        // 1.0 fill msg
        publish_msg_len = snprintf(plc_publish_msg, LOG_BUFFER_4096,
                "{\"devList\":[{\"devId\":%d,\"devName\":\"plc\",\"varList\":[", 
                2);   


        // 2.0 fill var body
        for(i = 0; i < 6; i++) 
        {
                resv_len = LOG_BUFFER_4096 - publish_msg_len;
                if (resv_len < 100)   //left length is too short
                {
                        break;
                }
                
                publish_msg_len += snprintf(&plc_publish_msg[publish_msg_len], resv_len, "{\"varName\":\"testVar%d\",\"varValue\":\"%.3f\",\"varId\":%u},", 
                        i,
                        (tm.tm_min+0.21)*(0.317 + i),
                        i);
        }

		
        // 3.0 fill tail msg
        resv_len = LOG_BUFFER_4096 - publish_msg_len;
        publish_msg_len += snprintf(&plc_publish_msg[publish_msg_len-1], resv_len,
                "]}],\"cmdId\":%d,\"gwSn\":\"JDWX%s\",\"time\":\"%s\",\"unixtime\":\"%lu\",\"seqnum\":\"%u\"}", 
                103,
                g_config.route_mac,
                data_time_str,
                unixtime,
                g_config.sequence_number);       




        bytes = sendto(g_config.uloop_fd_client.fd, plc_publish_msg, publish_msg_len, 0, (struct sockaddr*)&g_config.mqttclient_sockaddr, g_config.mqttclient_addr_len);
        PLC_DBG_PRINTF(PLC_GATEWAY, "publish message[%d]: %s\n", i_ret, plc_publish_msg); 


        return;
}






/**
*@Description: send msg to kernel
*@Input: epollfd: epoll fd
*@Input: sock_fd: socket fd
*@Return:  0: ok
           <0: fail
*@author: chenzejun 20160323
*/
static void plc_sendmsg_2_mqttclient()
{
        struct cmsghdr *pst_head = (struct cmsghdr *)plc_publish_msg;
        CLIENT_TLV_DATA *pst_tlv_data = (CLIENT_TLV_DATA *)(pst_head + 1);
        int i_ret = 0;
        time_t now;
        unsigned long unixtime; 
        char data_time_str[BUF_LEN_64] = {0}; 
        unsigned int publish_msg_len = 0;
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
        pst_tlv_data->us_tlv_len = sizeof(CLIENT_TLV_DATA) + sizeof("yunJDWX/jdwx_test/post/plc");  
        pc_msg = (char *)(pst_tlv_data + 1);
        strcpy(pc_msg, "yunJDWX/jdwx_test/post/plc");
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
        for(i = 0; i < 6; i++) 
        {
                resv_len = LOG_BUFFER_4096 - publish_msg_len;
                if (resv_len < 100)   //left length is too short
                {
                        break;
                }
                
                publish_msg_len += snprintf(&pc_msg[publish_msg_len], resv_len, "{\"varName\":\"testVar%d\",\"varValue\":\"%.3f\",\"varId\":%u},", 
                        i,
                        (tm.tm_min+0.21)*(0.317 + i),
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


        // length
        pst_tlv_data->us_tlv_len = sizeof(CLIENT_TLV_DATA) + publish_msg_len;  
        pst_head->cmsg_len += pst_tlv_data->us_tlv_len;



        bytes = sendto(g_config.uloop_fd_client.fd, plc_publish_msg, pst_head->cmsg_len, 0, (struct sockaddr*)&g_config.mqttclient_sockaddr, g_config.mqttclient_addr_len);
        PLC_DBG_PRINTF(PLC_GATEWAY, "sendto serv message[%d]: %s\n", publish_msg_len, pc_msg); 

        return;
}




/**
 *@Description: the callback function of uloop
 *@Input: u: the file description of uloop
 *@Input: ev: the event of uloop
 *@Return: void
 *@author: chenzejun 20160323
 */
static void plc_sendto_service_test()
{
        int i_ret = 0;
        time_t now;
        unsigned long unixtime; 
        char data_time_str[BUF_LEN_64] = {0}; 
        unsigned int publish_msg_len = 0;
        struct tm *p_tm;
        struct tm  tm;
        static int t_count = 0;
        unsigned int resv_len = 0;
        int bytes = 0;
        int i = 0;


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


        // 1.0 fill msg
        publish_msg_len = snprintf(plc_publish_msg, LOG_BUFFER_4096,
                "{\"devList\":[{\"devId\":%d,\"devName\":\"plc\",\"varList\":[", 
                2);   


        // 2.0 fill var body
        for(i = 0; i < 6; i++) 
        {
                resv_len = LOG_BUFFER_4096 - publish_msg_len;
                if (resv_len < 100)   //left length is too short
                {
                        break;
                }
                
                publish_msg_len += snprintf(&plc_publish_msg[publish_msg_len], resv_len, "{\"varName\":\"testVar%d\",\"varValue\":\"%.3f\",\"varId\":%u},", 
                        i,
                        (tm.tm_min+0.21)*(0.317 + i),
                        i);
        }

		
        // 3.0 fill tail msg
        resv_len = LOG_BUFFER_4096 - publish_msg_len;
        publish_msg_len += snprintf(&plc_publish_msg[publish_msg_len-1], resv_len,
                "]}],\"cmdId\":%d,\"gwSn\":\"JDWX%s\",\"time\":\"%s\",\"unixtime\":\"%lu\",\"seqnum\":\"%u\"}", 
                103,
                g_config.route_mac,
                data_time_str,
                unixtime,
                g_config.sequence_number);       






        bytes = sendto(g_config.uloop_fd_client.fd, plc_publish_msg, publish_msg_len, 0, (struct sockaddr*)&g_config.mqttclient_sockaddr, g_config.mqttclient_addr_len);           
        PLC_DBG_PRINTF(PLC_GATEWAY, "publish message[%d]: %s\n", i_ret, plc_publish_msg); 
        //if (g_mosq_config.publish_record_log)   libwl_log("/var/log/monoff.log", "publish [%d]: %s\n", i_ret, plc_publish_msg);


        return;
}


/**
 *@Description: the callback function of uloop
 *@Input: u: the file description of uloop
 *@Input: ev: the event of uloop
 *@Return: void
 *@author: chenzejun 20160323
 */
static void plc_gateway_handle(struct uloop_fd *u, unsigned int ev)
{
        AP_TLV_DATA *pst_tlv = (AP_TLV_DATA *)msg_buffer;
        int bytes;
        int sock_fd = -1;
        int rt0_count = 0;

        if (u == NULL)
        {
                return;
        }
        
        sock_fd = u->fd;
        LIBWL_DBG_PRINTF(LIBWL_CMD_TRACE, "plc_gateway_handle..., fd:%d\n", sock_fd);  

        /* found new client, process */
        while(1)  
        {

                /* recv data, non block */
                bytes = recv(sock_fd, msg_buffer, LOG_BUFFER_2048, MSG_DONTWAIT);
                if(bytes < 0)
                {
                        if(errno != EAGAIN)  
                        {
                                LIBWL_DBG_PRINTF(LIBWL_CMD_TRACE, "recvmsg end fd:%d, errno:%d, ret:%d\n", sock_fd, errno, bytes); 
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
                        LIBWL_DBG_PRINTF(LIBWL_CMD_TRACE, "next receive, count:%d, %d\n", rt0_count, errno);  
                        continue;
                }

                
                LIBWL_DBG_PRINTF(LIBWL_CMD_TRACE, "receive msg, get bytes:%d, %d\n", bytes, errno);  
        }

        LIBWL_DBG_PRINTF(LIBWL_CMD_TRACE, "plc_gateway_handle, exit\n");  
        return;
}




/**
*@Description: try to start socket of 5g
*@Input: void: void
*@Return: void
*@author: chenzejun 20160323
*/
static void plc_gateway_try_connect_service(void)
{
         struct sockaddr_un client_address  = {0};

         

        if (g_config.uloop_fd_client.fd <= 0)
        {
                //it need init clien and service
                client_address.sun_family = AF_UNIX;
                snprintf(client_address.sun_path, sizeof(client_address.sun_path), "/var/run/%s.client", g_config.my_name);
        
                /* command service*/
                g_config.uloop_fd_client.cb = plc_gateway_handle;
                g_config.uloop_fd_client.fd = libwl_cmd_create_socket(&client_address);
                if (g_config.uloop_fd_client.fd > 0)
                {
                        uloop_fd_add(&g_config.uloop_fd_client,  ULOOP_READ | ULOOP_EDGE_TRIGGER);
                        PLC_DBG_PRINTF(PLC_GATEWAY, "[gateway-plc] connect ok, uloop_fd_client fd:%d\n", g_config.uloop_fd_client.fd );  

                }

                PLC_DBG_PRINTF(PLC_GATEWAY, "[gateway-plc] try connect service fd:%d\n", g_config.uloop_fd_client.fd );  

        }
        

        PLC_DBG_PRINTF(PLC_GATEWAY, "[gateway-plc] try connect service\n");  
        return;
}



/**
 *@Description: monoff command init
 *@Input: void: void
 *@Return: 0: ok;   -1: fail
 *@author: chenzejun 20160323
 */
static int plc_gateway_init(void)
{

        plc_publish_msg = malloc(LOG_BUFFER_4096 + BUF_LEN_512);
        if(NULL == plc_publish_msg)
        {  
                PLC_DBG_PRINTF(PLC_ERROR, "malloc plc_publish_msg failed\n");
                return -1;
        }


        /* init sun_path */
        g_config.mqttclient_sockaddr.sun_family = AF_UNIX;
        snprintf(g_config.mqttclient_sockaddr.sun_path, sizeof(g_config.mqttclient_sockaddr.sun_path), "%s", g_config.srvaddr_name);
        g_config.mqttclient_addr_len = strlen(g_config.mqttclient_sockaddr.sun_path) + sizeof(g_config.mqttclient_sockaddr.sun_family);


        plc_gateway_try_connect_service();
        
        return 0;
}



/**
 *@Description: monoff command destroy
 *@Input: void: void
 *@Return: 0: ok;   -1: fail
 *@author: chenzejun 20160323
 */
static int plc_gateway_destroy(void)
{
        if (g_config.uloop_fd_client.fd > 0)
        {
                close(g_config.uloop_fd_client.fd);
                g_config.uloop_fd_client.fd = -1;
        }

        if (plc_publish_msg)
        {
                free(plc_publish_msg);
                plc_publish_msg = NULL;
        }

        return 0;
}

#endif








#if FUNCTION_DESC("timer function")

static struct uloop_timeout plc_10s_timer = 
{
        .cb = plc_uloop_10s_timer,
};



/**
*@Description: timer function
*@Input: timeout: timeout
*@Return: 0: ok;   -1: fail
*@author: chenzejun 20160323
*/
static void plc_uloop_10s_timer(struct uloop_timeout *timeout)
{
        PLC_DBG_PRINTF(PLC_TIMER, "[in] uloop 10s timer.... \n"); 

        uloop_timeout_set(timeout, 10000);

        plc_gateway_try_connect_service();

        plc_sendmsg_2_mqttclient();

        PLC_DBG_PRINTF(PLC_TIMER, "[out] uloop 10s timer.... \n"); 

        return;
}


#endif


#if FUNCTION_DESC("option function")



/**
 *@Description: show mac scan config
 *@Input: void
 *@Return: 0: ok;   -1: fail
 *@author: chenzejun 20160323
 */
static int plc_show_config(char *buffer, int buff_size)
{
        int  buf_len = 0;  

        if (buffer == NULL)    return 0;
        
        buf_len += snprintf(&buffer[buf_len], (buff_size - buf_len), "%-30s: %s\n", "version", g_config.version);
        buf_len += snprintf(&buffer[buf_len], (buff_size - buf_len), "%-30s: %s\n", "my_name", g_config.my_name);
        buf_len += snprintf(&buffer[buf_len], (buff_size - buf_len), "%-30s: %s\n", "srvaddr_name", g_config.srvaddr_name);
        buf_len += snprintf(&buffer[buf_len], (buff_size - buf_len), "%-30s: %s\n", "lockfile_name", g_config.lockfile_name);
        buf_len += snprintf(&buffer[buf_len], (buff_size - buf_len), "%-30s: %s\n", "route_mac", g_config.route_mac);


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
static int plc_show_debug_switch(char *buffer, int buff_size)
{
        int  buf_len = 0;  

        if (buffer == NULL)    return 0;

        buf_len += snprintf(&buffer[buf_len], (buff_size - buf_len), "%-30s: %d\n", MACROSTR_VALUE(LIBWL_INFO));
        buf_len += snprintf(&buffer[buf_len], (buff_size - buf_len), "%-30s: %d\n", MACROSTR_VALUE(LIBWL_ERROR));
        buf_len += snprintf(&buffer[buf_len], (buff_size - buf_len), "%-30s: %d\n", MACROSTR_VALUE(LIBWL_LOG_TRACE));
        buf_len += snprintf(&buffer[buf_len], (buff_size - buf_len), "%-30s: %d\n", MACROSTR_VALUE(LIBWL_CMD_TRACE));
        buf_len += snprintf(&buffer[buf_len], (buff_size - buf_len), "%-30s: %d\n", MACROSTR_VALUE(LIBWL_API_TRACE));
        buf_len += snprintf(&buffer[buf_len], (buff_size - buf_len), "%-30s: %d\n", MACROSTR_VALUE(PLC_INFO));
        buf_len += snprintf(&buffer[buf_len], (buff_size - buf_len), "%-30s: %d\n", MACROSTR_VALUE(PLC_ERROR));
        buf_len += snprintf(&buffer[buf_len], (buff_size - buf_len), "%-30s: %d\n", MACROSTR_VALUE(PLC_DBG));
        buf_len += snprintf(&buffer[buf_len], (buff_size - buf_len), "%-30s: %d\n", MACROSTR_VALUE(PLC_TIMER));
        buf_len += snprintf(&buffer[buf_len], (buff_size - buf_len), "%-30s: %d\n", MACROSTR_VALUE(PLC_SCAN_INFO));
        buf_len += snprintf(&buffer[buf_len], (buff_size - buf_len), "%-30s: %d\n", MACROSTR_VALUE(PLC_CONN_INFO));
        buf_len += snprintf(&buffer[buf_len], (buff_size - buf_len), "%-30s: %d\n", MACROSTR_VALUE(PLC_MQTT_CALLBACK_LOG));
        buf_len += snprintf(&buffer[buf_len], (buff_size - buf_len), "%-30s: %d\n", MACROSTR_VALUE(PLC_UBUS_INFO));
        buf_len += snprintf(&buffer[buf_len], (buff_size - buf_len), "%-30s: %d\n", MACROSTR_VALUE(PLC_UCI_INFO));
        buf_len += snprintf(&buffer[buf_len], (buff_size - buf_len), "%-30s: %d\n", MACROSTR_VALUE(PLC_CMD_INFO));
        buf_len += snprintf(&buffer[buf_len], (buff_size - buf_len), "%-30s: %d\n", MACROSTR_VALUE(PLC_CMD_TRACE));

        // buf_len is string length, buf_len++ will include \0 char to send.
        return ++buf_len;
}


/**
*@Description: get the information of router by wan
*@Input: void: void
*@return: 0 ok;  1- fail
*@author: chenzejun 20160123
*/
void plc_get_wan_info()
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
static void plc_print_usage(void)
{
	printf("gateway-plc version %s (build date %s)\n", g_config.version, g_config.buildtime);
	printf("Usage: gateway-plc [-d] [-l] [-h] [--conn-num num] [--scan-num num]\n");
	printf("               [test]\n");
	printf("       gateway-plc --help\n\n");

	
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
int plc_option_proc(int argc, char *argv[])
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
                        plc_print_usage();
                        exit(0);
                }
                else if(!strcmp(argv[i], "-v"))
                {
                        printf("[GATEWAY-PLC] Welcome to gateway-plc, Revision:%s (build date:%s)\n"
                                "(C) 2004-19 jindawanxiang.com\n",
                                g_config.version, g_config.buildtime);
                        exit(0);
                }
                else if(!strcmp(argv[i], "-d"))
                {
                        PLC_OPTION_CHECK_RET(i, argc);
                
                        num = atoi(argv[i+1]);
                        libwl_cmd_output_printf(num);
                        i++;
                }
                else if(!strcmp(argv[i], "-l"))
                {
                        PLC_OPTION_CHECK_RET(i, argc);
                        
                        num = atoi(argv[i+1]);
                        libwl_cmd_output_log(num);
                        i++;
                }
                else if(!strcmp(argv[i], "remote-show"))
                {
                        PLC_OPTION_CHECK_RET(i, argc);
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
                        PLC_OPTION_CHECK_RET(i, argc);
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
static int plc_init(void)
{
        int i_ret = 0;


        //plc_get_wan_info();
        libwl_get_router_hwaddr_short("br-lan", g_config.route_mac, sizeof(g_config.route_mac));


        uloop_init();




        //cmd init
        i_ret = plc_cmd_init();
        if (i_ret != 0)
        {
                return -1;
        }


        //gateway init
        i_ret = plc_gateway_init();
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
static int plc_destroy(void)
{
        plc_cmd_destroy();
        plc_gateway_destroy();
        
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
        plc_option_proc(argc, argv);


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
        i_ret = plc_init();
        if (i_ret != 0)
        {
                goto OUT;
        }
        
        uloop_timeout_set(&plc_10s_timer, 10000);


        //run
        uloop_run();

OUT:

        PLC_DBG_PRINTF(PLC_INFO, "main exit\n");   
        plc_destroy();
        return 0;
}


