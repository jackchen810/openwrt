/*
 * Copyright (C) 2011-2014 Felix Fietkau <nbd@openwrt.org>
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
#include <mosquitto.h>
#include <pthread.h>
#include <net/if.h>
#include <sys/ioctl.h>  
#include <sys/un.h>
#include <uci.h>  
#include <libubox/uloop.h>
#include <libubox/utils.h>
#include <libubox/usock.h>
#include <sys/inotify.h>

#include "libwl/libwl_mscan_pub.h"
#include "libwl/libwl_api_pub.h"
#include "libwl/libwl_dbg_pub.h"
#include "libwl/libwl_alist_pub.h"

#include "mac_onoffline.h"


/*
history:

 receive comand type:
 1)
/YunAC/CMD_SET/(type)
/YunAC/CMD_GET/
/YunAC/CMD_EXE/

*/






static struct MONOFF_GLOBAL_CONFIG g_config =
{
        .my_name = "mac-onoffline",
        .version[0] = 0,
        .buildtime[0] = 0,
        .wan_name[0] = 0,
        .route_mac[0] = 0,
        .route_ip[0] = 0,
        .channelpath[0] = 0,
        .localsrv_name[0] = 0,

        .age_time = 0xfff0,


        .uloop_fd_cmd.fd = -1,
        .uloop_fd_cmd.cb = monoff_cmd_socket_handle,
        
};







#if FUNCTION_DESC("command function")

static struct LIBWL_CMD_LIST_ST  g_function_list[] = 
{
        {"config", monoff_show_config},
        {"debug", monoff_show_debug_switch},
};



/**
 *@Description: the callback function of uloop
 *@Input: u: the file description of uloop
 *@Input: ev: the event of uloop
 *@Return: void
 *@author: chenzejun 20160323
 */
static void monoff_cmd_socket_handle(struct uloop_fd *u, unsigned int ev)
{
        libwl_cmd_service_callback(u->fd, g_function_list, ARRAY_SIZE(g_function_list));
        return;
}



/**
 *@Description: monoff command init
 *@Input: void: void
 *@Return: 0: ok;   -1: fail
 *@author: chenzejun 20160323
 */
static int monoff_cmd_init(void)
{
        /* command service*/
        g_config.uloop_fd_cmd.cb = monoff_cmd_socket_handle;
        g_config.uloop_fd_cmd.fd = libwl_cmd_service_create(g_config.my_name);
        if (g_config.uloop_fd_cmd.fd > 0)
        {
                uloop_fd_add(&g_config.uloop_fd_cmd,  ULOOP_READ | ULOOP_EDGE_TRIGGER);
                MONOFF_DBG_PRINTF(MONOFF_INFO, "monoff add cmd fd:%d\n", g_config.uloop_fd_cmd.fd );  

        }
        
        return 0;
}



/**
 *@Description: monoff command destroy
 *@Input: void: void
 *@Return: 0: ok;   -1: fail
 *@author: chenzejun 20160323
 */
static int monoff_cmd_destroy(void)
{
        return libwl_cmd_service_destroy();
}

#endif





#if FUNCTION_DESC("uci function")

static struct uci_context  *uci_contex = NULL;



/*
*@Description: get config by timer
*@Input: void: void
*@Return: void: void
*@author: chenzejun 20160123
*/
static void monoff_time_get_config(void)  
{  
        static int time_count = 5;

        time_count++;
        if (time_count%6 == 0)
        {
                //libwl_uci_get_option_fast(uci_contex, "firmwareinfo", "version", "info", "channel_path", g_config.channelpath, sizeof(g_config.channelpath));

                /* get wan name */
                libwl_uci_get_option_fast(uci_contex, "network", "interface", "wan", "ifname", g_config.wan_name, sizeof(g_config.wan_name));

                /* get ip type */
                libwl_uci_get_option_fast(uci_contex, "network", "interface", "wan", "proto", g_config.wan_ip_type, sizeof(g_config.wan_ip_type));

                /* if the proto is pppoe, ip interface is pppoe-wan */
                if (0 == strcmp(g_config.wan_ip_type, "pppoe"))
                {
                        libwl_get_router_ip("pppoe-wan", g_config.route_ip, sizeof(g_config.route_ip));
                }
                else
                {
                        libwl_get_router_ip(g_config.wan_name, g_config.route_ip, sizeof(g_config.route_ip));
                }
                MONOFF_DBG_PRINTF(MONOFF_UCI_INFO, "router_ip:%s\n", g_config.route_ip);

                time_count = 0;
        }
 
        return;
}  

/*
*@Description: uci load config
*@Input: void: void
*@Return: 0: ok;   -1: fail
*@author: chenzejun 20160123
*/
static int monoff_uci_load_config(void)  
{  
        uci_contex = uci_alloc_context();
        if (uci_contex == NULL)
        {
                return -1;
        }

        //get the config
        (void)monoff_time_get_config();
      
        return 0;
}  


/*
*@Description: uci unload config
*@Input: void: void
*@Return: 0: ok;   -1: fail
*@author: chenzejun 20160123
*/
static int monoff_uci_unload_config(void)  
{  
        
        if (uci_contex)
        {
                uci_free_context(uci_contex);
                uci_contex = NULL;
        }
      
        return 0;
}  



#endif






#if FUNCTION_DESC("list api function")

static ALIST_HEAD connect_info =
{
        .cfg_num = 8,
        .node_count = 0,
        .tail_id = INVALID_ID,
};


/*
*@Description: add node to connect info
*@Input: pst_connect: pointer to scan info node
*@Return: 0: ok;   -1: fail
*@author: chenzejun 20160123
*/
static int monoff_connect_add(CLIENT_CONN_NODE_INFO  *pst_node)
{
        return libwl_alist_add(&connect_info, &pst_node->sock_fd, sizeof(int), pst_node, sizeof(CLIENT_CONN_NODE_INFO));
}
/*
*@Description: delet node by key
*@Input:pc_key: pointer to macaddr
*@return: find id
*@author: chenzejun 20160123
*/
static int monoff_connect_del(unsigned char  ac_key[])
{
        return libwl_alist_del(&connect_info, (void *)ac_key, sizeof(int));
}



/**
*@Description: replace the oldest data
*@Input:
        pst_add: the data need to add 
*@Output:
        pst_del: the data need to delete 
*@return: void
*@author: chenzejun 20160123
*/
static int monoff_connect_replace_oldest(CLIENT_CONN_NODE_INFO  *pst_add, CLIENT_CONN_NODE_INFO  *pst_del)
{
        return libwl_alist_replace(&connect_info, pst_del, pst_add);
}




/**
*@Description: monoff client function init
*@Input: void: void
*@return: 0 ok;  1- fail
*@author: chenzejun 20160123
*/
static int monoff_connect_init(void)
{
        /* init connect information */
        connect_info.node_count = 0;
        connect_info.tail_id = INVALID_ID;


        //connect info
        connect_info.pst_node =  malloc(connect_info.cfg_num * sizeof(CLIENT_CONN_NODE_INFO));
        if (NULL == connect_info.pst_node)
        {
                MONOFF_DBG_PRINTF(MONOFF_ERROR, "malloc connect_info failed\n");
                return -1;
        }
        
        memset(connect_info.pst_node, 0, connect_info.cfg_num * sizeof(CLIENT_CONN_NODE_INFO));



        printf("macscn startup, cfg_num:%d\n",  connect_info.cfg_num);


        return 0;
}


/**
*@Description: monoff client function destroy
*@Input: void: void
*@return: 0 ok;  1- fail
*@author: chenzejun 20160123
*/
static int monoff_connect_destroy(void)
{
        if (connect_info.pst_node)  free(connect_info.pst_node);
        connect_info.pst_node = NULL;

        return 0;
}



#endif




#if FUNCTION_DESC("local service and client function")

static char client_buffer[LOG_BUFFER_2048 + BUF_LEN_128] = {0};




/**
 *@Description: the callback function of uloop
 *@Input: u: the file description of uloop
 *@Input: ev: the event of uloop
 *@Return: void
 *@author: chenzejun 20160323
 */
static void monoff_local_recvfrom_client_handle(struct uloop_fd *u, unsigned int ev)
{


        MONOFF_DBG_PRINTF(MONOFF_LOCAL_SERVICE, "[monoff] recvfrom handle client\n");  
        return;
}






/**
 *@Description: the callback function of uloop
 *@Input: u: the file description of uloop
 *@Input: ev: the event of uloop
 *@Return: void
 *@author: chenzejun 20160323
 */
static void monoff_local_sendto_client(char *topic, char * p_msg,  int msg_len)
{
        CLIENT_CONN_NODE_INFO *pst_connect = NULL;
        int i = 0;
        int bytes;
        int sock_fd = -1;

        // if 
        //scan connect info, send msg to service
        libwl_alist_for_entry(pst_connect, i,  &connect_info) 
        {
                if (pst_connect == NULL)  break;

                if (NULL == strstr(topic, pst_connect->look_topic)){
                        //not found, not match
                        continue;

                }

                sock_fd = pst_connect->uloop_fd.fd;
                bytes = sendto(sock_fd, p_msg, msg_len, 0, (struct sockaddr*)&pst_connect->st_client_addr, pst_connect->client_addr_len);
                if (bytes < 0)
                {
                        if(errno == EAGAIN)
                        {
                                // buffer is impossable full, continue,   Resource temporarily unavailable
                                system("sync");
                                //sync();
                                //sched_yield();
                                bytes = sendto(sock_fd, p_msg, msg_len, 0, (struct sockaddr*)&pst_connect->st_client_addr, pst_connect->client_addr_len);
                        }

                }
                
                MONOFF_DBG_PRINTF(MONOFF_LOCAL_SERVICE, "sendto client, fd:%d\n", sock_fd);  

        }

        

        MONOFF_DBG_PRINTF(MONOFF_LOCAL_SERVICE, "handle local client  exit\n");  
        return;
}




/**
 *@Description: create socket
 *@Input: 
        address: socket address
 *@len: 
        address: socket address length
 *@Return: 0: ok;   -1: fail
 *@author: chenzejun 20160323
 */
int monoff_local_service_create(const char *name)
{
        int sock_fd = -1;  
        int result;  
        int opt = SO_REUSEADDR;
        int len = 0;
        struct sockaddr_un service_address = {0 };


        
        if (name == NULL)    return -1;  
        
        
        MONOFF_DBG_PRINTF(MONOFF_LOCAL_SERVICE, "local server start create...\n");  
        sock_fd = socket (AF_UNIX, SOCK_STREAM, 0);  
        if (sock_fd < 0)
        {
                MONOFF_DBG_PRINTF(LIBWL_ERROR, "socket error, %s, errno:%s\n",  __FUNCTION__, strerror(errno));  
                return -1;    
        }

        setsockopt(sock_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));


        /* init sun_path */
        service_address.sun_family = AF_UNIX;
        snprintf(service_address.sun_path, sizeof(service_address.sun_path), "/var/run/%s.local", name);


        /* delete old path */
        unlink (service_address.sun_path); 


        MONOFF_DBG_PRINTF(MONOFF_LOCAL_SERVICE, "local server start bind...\n");  

        /* bind socket */
        len = strlen(service_address.sun_path) + sizeof(service_address.sun_family);
        result = bind(sock_fd, (struct sockaddr*)&service_address, len);  
        if(result < 0)
        {  
                MONOFF_DBG_PRINTF(MONOFF_LOCAL_SERVICE, "bind error, %s, errno:%s\n",  __FUNCTION__, strerror(errno));  
                close(sock_fd);  
                return -1;    
        } 


        MONOFF_DBG_PRINTF(MONOFF_LOCAL_SERVICE, "local server start listen...\n");  

        result = listen(sock_fd, LISTEN_MAX_SOCKET_NUM);	// 等待队列为
        if(result < 0)
        {  
                MONOFF_DBG_PRINTF(MONOFF_LOCAL_SERVICE, "listen error, %s, errno:%s\n",  __FUNCTION__, strerror(errno));  
                close(sock_fd);  
                return -1;    
        } 
        
        MONOFF_DBG_PRINTF(MONOFF_LOCAL_SERVICE, "local server is listen..., fd:%d\n", sock_fd);  
        return sock_fd;
}


/**
 *@Description: the callback function of uloop
 *@Input: u: the file description of uloop
 *@Input: ev: the event of uloop
 *@Return: void
 *@author: chenzejun 20160323
 */
static void monoff_local_service_handle(struct uloop_fd *u, unsigned int ev)
{
        CLIENT_CONN_NODE_INFO st_connect = {0};
        char * pc_ch = NULL;
        char * pc_str = NULL;
        int i = 0;

        
        MONOFF_DBG_PRINTF(MONOFF_LOCAL_SERVICE, "[monoff] handle local server ...\n");  

        /* found new client, process */
        st_connect.sock_fd = accept(u->fd, (struct sockaddr*)&st_connect.st_client_addr, &st_connect.client_addr_len);       
        if(st_connect.sock_fd < 0)
        {
                MONOFF_DBG_PRINTF(MONOFF_LOCAL_SERVICE, "accept error, connfd :%d\n", st_connect.sock_fd);  
                return;
        }

        MONOFF_DBG_PRINTF(MONOFF_LOCAL_SERVICE, "[monoff] service accept...\n");  

        /* recv client connect */
        monoff_connect_add(&st_connect);


        pc_str = st_connect.st_client_addr.sun_path;
        MONOFF_DBG_PRINTF(MONOFF_LOCAL_SERVICE, "[monoff] service accept, sun_path:%s, exit\n", pc_str);  

        for(i = 0; pc_str!=NULL ; i++){

                if (i > st_connect.client_addr_len)     break;
                if (pc_str[i] == '\0')  break;
                if (pc_str[i] == '#')  break;

                st_connect.look_topic[i] = pc_str[i];
        }
        

        
        /* add to uloop service*/
        /*  Illegal instruction
        st_connect.uloop_fd.cb = monoff_local_recvfrom_client_handle;
        st_connect.uloop_fd.fd =  st_connect.sock_fd;

        uloop_fd_add(&st_connect.uloop_fd,  ULOOP_READ | ULOOP_EDGE_TRIGGER);
        */

        MONOFF_DBG_PRINTF(MONOFF_LOCAL_SERVICE, "monoff_local_service_handle callback, fd:%d,  exit\n", st_connect.sock_fd);  
        return;
}


/**
 *@Description: monoff command init
 *@Input: void: void
 *@Return: 0: ok;   -1: fail
 *@author: chenzejun 20160323
 */
static int monoff_local_service_init(void)
{
        /* command service*/
        g_config.uloop_fd_local_service.cb = monoff_local_service_handle;
        g_config.uloop_fd_local_service.fd = monoff_local_service_create(g_config.my_name);
        if (g_config.uloop_fd_local_service.fd > 0)
        {
                uloop_fd_add(&g_config.uloop_fd_local_service,  ULOOP_READ | ULOOP_EDGE_TRIGGER);
                MONOFF_DBG_PRINTF(MONOFF_LOCAL_SERVICE, "[monoff] add local_service fd:%d\n", g_config.uloop_fd_local_service.fd );  

        }
        
        return 0;
}



/**
 *@Description: monoff command destroy
 *@Input: void: void
 *@Return: 0: ok;   -1: fail
 *@author: chenzejun 20160323
 */
static int monoff_local_service_destroy(void)
{
        if (g_config.uloop_fd_local_service.fd > 0)
        {
                close(g_config.uloop_fd_local_service.fd);
                g_config.uloop_fd_local_service.fd = -1;
        }

        return 0;
}

#endif







#if FUNCTION_DESC("mqtt client function")
static MOSQ_CLINENT_CONFIG g_mosq_config =
{
        .notice_switch = false,
        .mosq_id =  "jdwx_router",  
        .topic = "yunJDWX/jdwx_test/post/plc",
        .host = "emqtt.jdwanxiang.com",
        .port = 1883,
        .username = "jdwx",
        .password = "jdwx",
        .keepalive = 100,
        .mosquitto_test = false,
        .publish_record_log = false,
        .sequence_number = 0,
};

static struct mosquitto *p_mosq_client = NULL;
static char *monoff_publish_msg = NULL;





/**
*@Description: Set the logging callback.  This should be used if you want event logging information from the client library.
        mosq	the mosquitto instance making the callback.
        obj	the user data provided in mosquitto_new
        level	the log message level from the values: MOSQ_LOG_INFO MOSQ_LOG_NOTICE MOSQ_LOG_WARNING MOSQ_LOG_ERR MOSQ_LOG_DEBUG
        str	the message string.
*@Return:  0: ok
           <0: fail
*@author: chenzejun 20160323
*/
static void monoff_mqttclient_log_callback(struct mosquitto *mosq, void *obj, int level, const char *str)
{
        MONOFF_DBG_PRINTF(MONOFF_MQTT_CALLBACK_LOG, "log callback, log:%s\n", str);
}

/**
*@Description: Set the connect callback.  This is called when the broker sends a CONNACK message in response to a connection.
        mosq	the mosquitto instance making the callback.
        obj	the user data provided in mosquitto_new
        rc	integer value indicating the reason for the disconnect.  A value of 0 means the client has called mosquitto_disconnect.  Any other value indicates that the disconnect is unexpected.
*@Return:  0: ok
           <0: fail
*@author: chenzejun 20160323
*/
static void monoff_mqttclient_connect_callback(struct mosquitto *mosq, void *obj, int result)
{
        MONOFF_DBG_PRINTF(MONOFF_MQTT_INFO, "connect_callback, result: %d\n", result);

        return;
}

/**
*@Description: Set the disconnect callback.  This is called when the broker has received the DISCONNECT command and has disconnected the client.
        mosq	the mosquitto instance making the callback.
        obj	the user data provided in mosquitto_new
        rc	integer value indicating the reason for the disconnect.  A value of 0 means the client has called mosquitto_disconnect.  Any other value indicates that the disconnect is unexpected.
*@Return:  0: ok
           <0: fail
*@author: chenzejun 20160323
*/
static void monoff_mqttclient_disconnect_callback(struct mosquitto *mosq, void *obj, int result)
{
        MONOFF_DBG_PRINTF(MONOFF_MQTT_INFO, "disconnect_callback, result:%d\n", result);
        MONOFF_MCLIENT_SET_CONN_STATUS(false);
        if (p_mosq_client)  
        {
                mosquitto_destroy(p_mosq_client);
                p_mosq_client = NULL;
                
                (void)mosquitto_lib_cleanup();
        }

        return;
}



/**
*@Description: Set the message callback.  This is called when a message is received from the broker.
        mosq	the mosquitto instance making the callback.
        obj	the user data provided in mosquitto_new
        mid	the message id of the subscribe message.
        qos_count	the number of granted subscriptions (size of granted_qos).
        granted_qos	an array of integers indicating the granted QoS for each of the subscriptions.
*@Return:  0: ok
           <0: fail
*@author: chenzejun 20160323
*/
static void monoff_mqttclient_message_callback(struct mosquitto *mosq, void *obj, const struct mosquitto_message *message)
{
        MONOFF_DBG_PRINTF(MONOFF_MQTT_INFO, "message (topic: %s): %s", message->topic, message->payload);

        monoff_local_sendto_client(message->topic, message->payload, message->payloadlen);
}


/**
*@Description: Set the subscribe callback.  This is called when the broker responds to a subscription request.
        mosq	the mosquitto instance making the callback.
        obj	the user data provided in mosquitto_new
        mid	the message id of the subscribe message.
        qos_count	the number of granted subscriptions (size of granted_qos).
        granted_qos	an array of integers indicating the granted QoS for each of the subscriptions.
*@Return:  0: ok
           <0: fail
*@author: chenzejun 20160323
*/
static void monoff_mqttclient_subscribe_callback(struct mosquitto *mosq, void *obj, int mid, int qos_count, const int *granted_qos)
{

        MONOFF_DBG_PRINTF(MONOFF_MQTT_INFO, "Subscribed (mid: %d): %d", mid, granted_qos[0]);

        return;
}

/**
*@Description: mqtt client pusblish
*@Input: pst_connect: the pointer to connection information
*@Input: pc_event: the pointer to event, support up or down.
*@Return:  0: ok
           <0: fail
*@author: chenzejun 20160323
*/
static int monoff_mqttclient_publish(char *pc_event)
{
        int i_ret = 0;
        time_t now;
        unsigned long unixtime; 
        char data_time_str[BUF_LEN_64] = {0}; 
        unsigned int publish_msg_len = 0;
        struct tm *p_tm;
        struct tm  tm;

        //this is zone set, it's fixed localtime don't update when zone change.
        //2016.8.11, use tzset(), localtime Is still wrong.
        //tzset();  

        //time stamp
        unixtime = time(&now);
        //p_tm = localtime(&now);
        p_tm = gmtime(&now);

        memcpy(&tm, p_tm, sizeof(tm));
        if (tm.tm_hour < 16)
        {
                tm.tm_hour = tm.tm_hour + 8;
        }
        else
        {
                tm.tm_hour = tm.tm_hour - 16;
        }

        //strftime(data_time_str, sizeof(data_time_str), "%Y %b %d %X", p_tm);  
        strftime(data_time_str, sizeof(data_time_str), "%Y %b %d %X", &tm);  

        g_mosq_config.sequence_number++;
        publish_msg_len = snprintf(monoff_publish_msg, LOG_BUFFER_4096, 
                "{\"date\":\"%s\",\"routerip\":\"%s\",\"routermac\":\"%s\",\"channelpath\":\"%s\",\"program\":\"jdwx-router\",\"unixtime\":\"%lu\"}", 
                data_time_str,
                g_config.route_ip,
                g_config.route_mac,
                g_config.channelpath,
                unixtime);              

        publish_msg_len = publish_msg_len > LOG_BUFFER_4096 ? LOG_BUFFER_4096 : publish_msg_len;
                
        i_ret = mosquitto_publish(p_mosq_client, NULL, g_mosq_config.topic, publish_msg_len, ( const void *)monoff_publish_msg, 2, false);

             
        MONOFF_DBG_PRINTF(MONOFF_MQTT_INFO, "publish message[%d]: %s\n", i_ret, monoff_publish_msg); 
        if (g_mosq_config.publish_record_log)   libwl_log("/var/log/monoff.log", "publish [%d]: %s\n", i_ret, monoff_publish_msg);


        return 0;
}


/**
*@Description: mqtt client pusblist test
*@Input: void: void
*@Return:  0: ok
           <0: fail
*@author: chenzejun 20160323
*/
int monoff_mqttclient_publish_test(void)
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
        int i = 0;


        t_count++;
        if (t_count < 6)	return 0;
        t_count = 0;

        //this is zone set, it's fixed localtime don't update when zone change.
        //2016.8.11, use tzset(), localtime Is still wrong.
        //tzset();  

        //time stamp
        unixtime = time(&now);
        p_tm = localtime(&now);
         strftime(data_time_str, sizeof(data_time_str), "%Y-%m-%d %H:%M:%S", p_tm); 
        /*
        p_tm = gmtime(&now);
        memcpy(&tm, p_tm, sizeof(tm));
        if (tm.tm_hour < 16)
        {                
                tm.tm_hour = tm.tm_hour + 8;
        }
        else
        { 
                tm.tm_hour = tm.tm_hour - 16;
        }
        strftime(data_time_str, sizeof(data_time_str), "%Y-%m-%d %H:%M:%S", &tm); 
        */



        g_mosq_config.sequence_number++;

        // 1.0 fill msg
        //publish_msg_len = snprintf(monoff_publish_msg, LOG_BUFFER_4096,
        //        "{\"devList\":[{\"devId\":%d,\"devName\":\"plc\",\"varList\":[{\"varName\":\"jdwxtest\",\"varValue\":\"0.123\",\"varId\":2}]}],\"cmdId\":103,\"gwSn\":\"WG282LL0718110200211\",\"gwName\":\"WG282LL0718110200211\"}", 
        //        100);              



        // 1.0 fill msg
        publish_msg_len = snprintf(monoff_publish_msg, LOG_BUFFER_4096,
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
                
                publish_msg_len += snprintf(&monoff_publish_msg[publish_msg_len], resv_len, "{\"varName\":\"testVar%d\",\"varValue\":\"%.3f\",\"varId\":%u},", 
                        i,
                        (tm.tm_min+0.21)*(0.317 + i),
                        i);
        }

		
        // 3.0 fill tail msg
        resv_len = LOG_BUFFER_4096 - publish_msg_len;
        publish_msg_len += snprintf(&monoff_publish_msg[publish_msg_len-1], resv_len,
                "]}],\"cmdId\":%d,\"gwSn\":\"JDWX%s\",\"time\":\"%s\",\"unixtime\":\"%lu\",\"seqnum\":\"%u\"}", 
                103,
                g_config.route_mac,
                data_time_str,
                unixtime,
                g_mosq_config.sequence_number);       





        publish_msg_len = publish_msg_len > LOG_BUFFER_4096 ? LOG_BUFFER_4096 : publish_msg_len;
                
        i_ret = mosquitto_publish(p_mosq_client, NULL, g_mosq_config.topic, publish_msg_len-1, ( const void *)monoff_publish_msg, 2, false);

             
        MONOFF_DBG_PRINTF(MONOFF_MQTT_INFO, "publish message[%d]: %s\n", i_ret, monoff_publish_msg); 
        if (g_mosq_config.publish_record_log)   libwl_log("/var/log/monoff.log", "publish [%d]: %s\n", i_ret, monoff_publish_msg);


        return 0;
}



/**
*@Description: try to connect to mosquitto
*@Input: void: void
*@Return: void
*@author: chenzejun 20160323
*/
static void monoff_mqttclient_try_connect(void)
{
        int i_ret = 0;


        if (p_mosq_client == NULL)
        {
                MONOFF_DBG_PRINTF(MONOFF_MQTT_INFO, "try to mosquitto_lib_init ...........\n");  

                i_ret= mosquitto_lib_init();
                if (i_ret != MOSQ_ERR_SUCCESS)
                {  
                        MONOFF_DBG_PRINTF(MONOFF_MQTT_ERROR, "mosquitto_lib_init failedr, ret = %d\n", i_ret);   
                        return;
                }

                p_mosq_client = mosquitto_new(g_mosq_config.mosq_id, true, &g_mosq_config);
                if(NULL == p_mosq_client)
                {
                        MONOFF_DBG_PRINTF(MONOFF_MQTT_ERROR, "mosquitto_new error, ret = %d\n", i_ret);   
                        return;
                }

                /* callback function load */
                mosquitto_log_callback_set(p_mosq_client, monoff_mqttclient_log_callback);
                mosquitto_subscribe_callback_set(p_mosq_client, monoff_mqttclient_subscribe_callback);
                mosquitto_connect_callback_set(p_mosq_client, monoff_mqttclient_connect_callback);
                mosquitto_message_callback_set(p_mosq_client, monoff_mqttclient_message_callback);
                mosquitto_disconnect_callback_set(p_mosq_client, monoff_mqttclient_disconnect_callback);

	  //set username and passsword
	  mosquitto_username_pw_set(p_mosq_client, g_mosq_config.username, g_mosq_config.password);
        }



        if (false == MONOFF_MCLIENT_GET_CONN_STATUS())
        {
                MONOFF_DBG_PRINTF(MONOFF_MQTT_INFO, "try to connect mosquitto ...........\n");  
                i_ret = mosquitto_connect(p_mosq_client, g_mosq_config.host, g_mosq_config.port, g_mosq_config.keepalive);
                if (i_ret == MOSQ_ERR_SUCCESS)
                {
                        MONOFF_MCLIENT_SET_CONN_STATUS(true);

                        MONOFF_DBG_PRINTF(MONOFF_MQTT_INFO, "reconnect mosquitto success\n");  
                }
        }

        return;
}


/**
*@Description: create mqtt client and connect
*@Input: void: void
*@Return:  0: ok
           <0: fail
*@author: chenzejun 20160711
*/
static int monoff_mqttclient_init(void)
{
        int i_ret = 0;

        monoff_publish_msg = malloc(LOG_BUFFER_4096 + BUF_LEN_512);
        if(NULL == monoff_publish_msg)
        {  
                MONOFF_DBG_PRINTF(MONOFF_MQTT_ERROR, "malloc monoff_publish_msg failed\n");
                return -1;
        }
       
        
        /* monoff init topic */
        snprintf(g_mosq_config.mosq_id, BUF_LEN_64, "%s", g_config.route_mac);
        MONOFF_DBG_PRINTF(MONOFF_MQTT_INFO, "topic is %s\n", g_mosq_config.topic);



        /* try to connect, if connect failed, then connect by timer */
        monoff_mqttclient_try_connect();


        return 0;
}


/**
*@Description: destroy mqtt client thread
*@Input: void: pointer to void
*@Return:  0: ok
           <0: fail
*@author: chenzejun 20160711
*/
static int monoff_mqttclient_destroy(void)
{
        MONOFF_DBG_PRINTF(MONOFF_INFO, "mqtt client destroy...\n"); 

        if (p_mosq_client)  
        {
                mosquitto_destroy(p_mosq_client);
                p_mosq_client = NULL;
        }

        (void)mosquitto_lib_cleanup();

        if (monoff_publish_msg)
        {
                free(monoff_publish_msg);
                monoff_publish_msg = NULL;
        }

        return 0;
}




#endif



#if FUNCTION_DESC("local service and client function")

static char msg_buffer[LOG_BUFFER_2048 + BUF_LEN_128] = {0};




/**
 *@Description: the callback function of uloop
 *@Input: u: the file description of uloop
 *@Input: ev: the event of uloop
 *@Return: void
 *@author: chenzejun 20160323
 */
static void monoff_localserv_recvfrom_client_handle(struct uloop_fd *u, unsigned int ev)
{


        MONOFF_DBG_PRINTF(MONOFF_LOCAL_SERVICE, "[monoff] recvfrom handle client\n");  
        return;
}






/**
 *@Description: the callback function of uloop
 *@Input: u: the file description of uloop
 *@Input: ev: the event of uloop
 *@Return: void
 *@author: chenzejun 20160323
 */
static void monoff_localserv_sendto_client(char *topic, char * p_msg,  int msg_len)
{
        CLIENT_CONN_NODE_INFO *pst_connect = NULL;
        int i = 0;
        int bytes;
        int sock_fd = -1;

        // if 
        //scan connect info, send msg to service
        libwl_alist_for_entry(pst_connect, i,  &connect_info) 
        {
                if (pst_connect == NULL)  break;

                if (NULL == strstr(topic, pst_connect->look_topic)){
                        //not found, not match
                        continue;

                }

                sock_fd = pst_connect->uloop_fd.fd;
                bytes = sendto(sock_fd, p_msg, msg_len, 0, (struct sockaddr*)&pst_connect->st_client_addr, pst_connect->client_addr_len);
                if (bytes < 0)
                {
                        if(errno == EAGAIN)
                        {
                                // buffer is impossable full, continue,   Resource temporarily unavailable
                                system("sync");
                                //sync();
                                //sched_yield();
                                bytes = sendto(sock_fd, p_msg, msg_len, 0, (struct sockaddr*)&pst_connect->st_client_addr, pst_connect->client_addr_len);
                        }

                }
                
                MONOFF_DBG_PRINTF(MONOFF_LOCAL_SERVICE, "sendto client, fd:%d\n", sock_fd);  

        }

        

        MONOFF_DBG_PRINTF(MONOFF_LOCAL_SERVICE, "handle local client  exit\n");  
        return;
}




/**
 *@Description: create socket
 *@Input: 
        address: socket address
 *@len: 
        address: socket address length
 *@Return: 0: ok;   -1: fail
 *@author: chenzejun 20160323
 */
int monoff_localserv_create(const char *name)
{
        int sock_fd = -1;  
        int result;  
        int opt = SO_REUSEADDR;
        int len = 0;
        struct sockaddr_un service_address = {0 };


        
        if (name == NULL)    return -1;  
        
        
        MONOFF_DBG_PRINTF(MONOFF_LOCAL_SERVICE, "local server start create...\n");  
        sock_fd = socket (AF_UNIX, SOCK_STREAM, 0);  
        if (sock_fd < 0)
        {
                MONOFF_DBG_PRINTF(LIBWL_ERROR, "socket error, %s, errno:%s\n",  __FUNCTION__, strerror(errno));  
                return -1;    
        }

        setsockopt(sock_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));


        /* init sun_path */
        service_address.sun_family = AF_UNIX;
        snprintf(service_address.sun_path, sizeof(service_address.sun_path), "/var/run/%s.local", name);


        /* delete old path */
        unlink (service_address.sun_path); 


        MONOFF_DBG_PRINTF(MONOFF_LOCAL_SERVICE, "local server start bind...\n");  

        /* bind socket */
        len = strlen(service_address.sun_path) + sizeof(service_address.sun_family);
        result = bind(sock_fd, (struct sockaddr*)&service_address, len);  
        if(result < 0)
        {  
                MONOFF_DBG_PRINTF(MONOFF_LOCAL_SERVICE, "bind error, %s, errno:%s\n",  __FUNCTION__, strerror(errno));  
                close(sock_fd);  
                return -1;    
        } 


        MONOFF_DBG_PRINTF(MONOFF_LOCAL_SERVICE, "local server start listen...\n");  

        result = listen(sock_fd, LISTEN_MAX_SOCKET_NUM);	// 等待队列为
        if(result < 0)
        {  
                MONOFF_DBG_PRINTF(MONOFF_LOCAL_SERVICE, "listen error, %s, errno:%s\n",  __FUNCTION__, strerror(errno));  
                close(sock_fd);  
                return -1;    
        } 
        
        MONOFF_DBG_PRINTF(MONOFF_LOCAL_SERVICE, "local server is listen..., fd:%d\n", sock_fd);  
        return sock_fd;
}


/**
 *@Description: the callback function of uloop
 *@Input: u: the file description of uloop
 *@Input: ev: the event of uloop
 *@Return: void
 *@author: chenzejun 20160323
 */
static void monoff_localserv_handle(struct uloop_fd *u, unsigned int ev)
{
        AP_TLV_DATA *pst_tlv = (AP_TLV_DATA *)msg_buffer;
        int bytes;
        int sock_fd = -1;
        int rt0_count = 0;
        int i_ret = 0;

        if (u == NULL)
        {
                return;
        }
        
        sock_fd = u->fd;
        LIBWL_DBG_PRINTF(LIBWL_CMD_TRACE, "monoff_localserv..., fd:%d\n", sock_fd);  

        /* found new client, process */
        while(1)  
        {

                /* recv data, non block */
                bytes = recv(sock_fd, msg_buffer, LOG_BUFFER_2048, MSG_DONTWAIT);
                if(bytes < 0)
                {
                        if(errno != EAGAIN)  
                        {
                                LIBWL_DBG_PRINTF(LIBWL_CMD_TRACE, "[monoff_localserv] recvmsg end fd:%d, errno:%d, ret:%d\n", sock_fd, errno, bytes); 
                        }

                        break;
                }
                else if(bytes == 0){
                        //if peer socket ctrl+c; it return 0;
                        // count 5 to exit;
                        //当客户端Socket关闭时，服务端的Socket会接收到0字节的通知。
                        if (rt0_count > 5){
                                g_config.uloop_fd_local_service.fd = -1;
                                break;
                        }
                        
                        rt0_count++; 
                        LIBWL_DBG_PRINTF(LIBWL_CMD_TRACE, "[monoff_localserv] next receive, count:%d, %d\n", rt0_count, errno);  
                        continue;
                }



                        
                i_ret = mosquitto_publish(p_mosq_client, NULL, g_mosq_config.topic, bytes-1, ( const void *)msg_buffer, 2, false);

                MONOFF_DBG_PRINTF(MONOFF_MQTT_INFO, "[monoff_localserv]  publish message[%d]: %s\n", i_ret, msg_buffer); 
        }

        LIBWL_DBG_PRINTF(LIBWL_CMD_TRACE, "[monoff_localserv] , exit\n");  
        return;
}


/**
 *@Description: monoff command init
 *@Input: void: void
 *@Return: 0: ok;   -1: fail
 *@author: chenzejun 20160323
 */
static int monoff_localserv_init(void)
{
         struct sockaddr_un serv_address  = {0};


        // localsrv may config
        if (g_config.localsrv_name[0] == 0){
                snprintf(g_config.localsrv_name, sizeof(g_config.localsrv_name), "/var/run/%s.localserv", g_config.my_name);
        }
         
        //it need init clien and service
        serv_address.sun_family = AF_UNIX;
        snprintf(serv_address.sun_path, sizeof(serv_address.sun_path), "%s", g_config.localsrv_name);

        
        /* command service*/
        g_config.uloop_fd_local_service.cb = monoff_localserv_handle;
        g_config.uloop_fd_local_service.fd = libwl_cmd_create_socket(&serv_address);
        if (g_config.uloop_fd_local_service.fd > 0)
        {
                uloop_fd_add(&g_config.uloop_fd_local_service,  ULOOP_READ | ULOOP_EDGE_TRIGGER);
                MONOFF_DBG_PRINTF(MONOFF_LOCAL_SERVICE, "[monoff] add local_service fd:%d\n", g_config.uloop_fd_local_service.fd );  

        }
        
        return 0;
}



/**
 *@Description: monoff command destroy
 *@Input: void: void
 *@Return: 0: ok;   -1: fail
 *@author: chenzejun 20160323
 */
static int monoff_localserv_destroy(void)
{
        if (g_config.uloop_fd_local_service.fd > 0)
        {
                close(g_config.uloop_fd_local_service.fd);
                g_config.uloop_fd_local_service.fd = -1;
        }

        return 0;
}

#endif




#if FUNCTION_DESC("timer function")

static struct uloop_timeout monoff_2s_timer = 
{
        .cb = monoff_uloop_2s_timer,
};
static struct uloop_timeout monoff_10s_timer = 
{
        .cb = monoff_uloop_10s_timer,
};

/**
*@Description: timer function
*@Input: timeout: timeout
*@Return: 0: ok;   -1: fail
*@author: chenzejun 20160323
*/
static void monoff_uloop_2s_timer(struct uloop_timeout *timeout)
{
        MONOFF_DBG_PRINTF(MONOFF_TIMER, "[in] 2s timer.... \n"); 

        uloop_timeout_set(timeout, 2000);


        // get ip by timer, beacuse ip will change
        //monoff_get_router_ip("br-lan", g_config.route_ip, BUF_LEN_64);

        //mosquitto_loop    Parameters: timeout
        //Maximum number of milliseconds to wait for network activity in the select() call before timing out.  
        //Set to 0 for instant return.  
        //Set negative to use the default of 1000ms.
        //mosquitto_loop(p_mosq_client, -1, 1);
        mosquitto_loop(p_mosq_client, 0, 1);
        
        MONOFF_DBG_PRINTF(MONOFF_TIMER, "[out] 2s timer.... \n"); 

        return;
}



/**
*@Description: timer function
*@Input: timeout: timeout
*@Return: 0: ok;   -1: fail
*@author: chenzejun 20160323
*/
static void monoff_uloop_10s_timer(struct uloop_timeout *timeout)
{
        MONOFF_DBG_PRINTF(MONOFF_TIMER, "[in] uloop 10s timer.... \n"); 

        uloop_timeout_set(timeout, 10000);


        //try to connect mosquitto service
        monoff_mqttclient_try_connect();



        // get uci config
        monoff_time_get_config();

        //monoff_mqttclient_publish_test();
        MONOFF_DBG_PRINTF(MONOFF_TIMER, "[out] uloop 10s timer.... \n"); 

        return;
}


/**
*@Description: timer function
*@Input: signo: signal no
*@Return: 0: ok;   -1: fail
*@author: chenzejun 20160323
*/
void monoff_sigroutine(int signo)
{
        static int t_count = 0;
        
        if (signo != SIGALRM)
        {
                return;
        }

        signal(SIGALRM, monoff_sigroutine);
        return;
}

/**
*@Description: create timer
*@Input: void: void
*@Return: 0: ok;   -1: fail
*@author: chenzejun 20160323
*/
static int monoff_timer_create(void)
{
        struct itimerval value, ovalue;          //(1)
        MONOFF_DBG_PRINTF(MONOFF_TIMER, "create timer, process id is %d \n", getpid());
        
        signal(SIGALRM, monoff_sigroutine);

        /* 60 sec */
        value.it_value.tv_sec = 60;
        value.it_value.tv_usec = 0;
        value.it_interval.tv_sec = 60;
        value.it_interval.tv_usec = 0;
        setitimer(ITIMER_REAL, &value, &ovalue);

        return 0;
}


/**
*@Description: signal handle function
*@Input: signo: signo
*@return: 0 ok;  1- fail
*@author: chenzejun 20160123
*@this feature reslove umac.ko not unload in qca device
*@notce signal to process for close netlink socket
*@ralink device has not this issue, it don't unload mt76*.ko
*@SIGUSR1 is create netlink socket
*@SIGUSR2 is close netlink socket
*/
static void monoff_signal_handle(int signo)
{
        if (signo == SIGUSR1)
        {
                MONOFF_DBG_PRINTF(MONOFF_TIMER, "signal handle, signo is SIGUSR1\n");
        }
        else if (signo == SIGUSR2)
        {
                MONOFF_DBG_PRINTF(MONOFF_TIMER, "signal handle, signo is SIGUSR2\n");
        }

        return;
}



/**
*@Description: signal setup
*@Input: void: void
*@return: 0 ok;  1- fail
*@author: chenzejun 20160123
*/
static void monoff_signal_setup(void)
{
        signal(SIGUSR1, monoff_signal_handle);
        signal(SIGUSR2, monoff_signal_handle);

        //start timer
        //signal(SIGALRM, monoff_timer_proc);
        //alarm(10);   //10s  signal
        return;
}



#endif

 

#if FUNCTION_DESC("option function")

static char g_lock_file[] = "/var/lock/monoff.lock";

/**
 *@Description: show monoff client config
 *@Input: void
 *@Return: 0: ok;   -1: fail
 *@author: chenzejun 20160323
 */
static int monoff_show_config(char *buffer, int buff_size)
{
        int  buf_len = 0;  
        time_t timep;
        struct tm *p_tm;
        struct timeval tv;  
        struct timezone tz;  


        if (buffer == NULL)    return 0;

        //time
        time(&timep);
        p_tm = localtime(&timep);
        buf_len += snprintf(&buffer[buf_len], (buff_size - buf_len), "%-30s: %d%02d%02d %02d:%02d:%02d\n", "local time",
                        (1900+p_tm->tm_year), (1+p_tm->tm_mon), p_tm->tm_mday, p_tm->tm_hour, p_tm->tm_min, p_tm->tm_sec);

        p_tm = gmtime(&timep);
        buf_len += snprintf(&buffer[buf_len], (buff_size - buf_len), "%-30s: %d%02d%02d %02d:%02d:%02d\n", "gmt time",
                        (1900+p_tm->tm_year), (1+p_tm->tm_mon), p_tm->tm_mday, p_tm->tm_hour, p_tm->tm_min, p_tm->tm_sec);

        p_tm = localtime(&g_config.uptime);
        buf_len += snprintf(&buffer[buf_len], (buff_size - buf_len), "%-30s: %d%02d%02d %02d:%02d:%02d\n", "start time",
                        (1900+p_tm->tm_year), (1+p_tm->tm_mon), p_tm->tm_mday, p_tm->tm_hour, p_tm->tm_min, p_tm->tm_sec);
                        
        gettimeofday(&tv, &tz);
        buf_len += snprintf(&buffer[buf_len], (buff_size - buf_len), "%-30s: %d, %d\n", "time zone", tz.tz_minuteswest, tz.tz_dsttime);
        buf_len += snprintf(&buffer[buf_len], (buff_size - buf_len), "%-30s: %d\n", "emqtt_yun_link_status", g_mosq_config.mosquitto_conn_flag);
        buf_len += snprintf(&buffer[buf_len], (buff_size - buf_len), "%-30s: %s\n", "version", g_config.version);
        buf_len += snprintf(&buffer[buf_len], (buff_size - buf_len), "%-30s: %s\n", "wan_name", g_config.wan_name);
        buf_len += snprintf(&buffer[buf_len], (buff_size - buf_len), "%-30s: %s\n", "route_mac", g_config.route_mac);
        buf_len += snprintf(&buffer[buf_len], (buff_size - buf_len), "%-30s: %s\n", "route_ip", g_config.route_ip);
        buf_len += snprintf(&buffer[buf_len], (buff_size - buf_len), "%-30s: %s\n", "wan_ip_type", g_config.wan_ip_type);
        buf_len += snprintf(&buffer[buf_len], (buff_size - buf_len), "%-30s: %s\n", "channelpath", g_config.channelpath);
        buf_len += snprintf(&buffer[buf_len], (buff_size - buf_len), "%-30s: %s\n", "topic", g_mosq_config.topic);
        buf_len += snprintf(&buffer[buf_len], (buff_size - buf_len), "%-30s: %s\n", "host", g_mosq_config.host);
        buf_len += snprintf(&buffer[buf_len], (buff_size - buf_len), "%-30s: %d\n", "port", g_mosq_config.port);
        buf_len += snprintf(&buffer[buf_len], (buff_size - buf_len), "%-30s: %d\n", "sequence_number", g_mosq_config.sequence_number);

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
static int monoff_show_debug_switch(char *buffer, int buff_size)
{
        int  buf_len = 0;  

        if (buffer == NULL)    return 0;

        buf_len += snprintf(&buffer[buf_len], (buff_size - buf_len), "%-30s: %d\n", MACROSTR_VALUE(LIBWL_INFO));
        buf_len += snprintf(&buffer[buf_len], (buff_size - buf_len), "%-30s: %d\n", MACROSTR_VALUE(LIBWL_ERROR));
        buf_len += snprintf(&buffer[buf_len], (buff_size - buf_len), "%-30s: %d\n", MACROSTR_VALUE(LIBWL_LOG_TRACE));
        buf_len += snprintf(&buffer[buf_len], (buff_size - buf_len), "%-30s: %d\n", MACROSTR_VALUE(LIBWL_CMD_TRACE));
        buf_len += snprintf(&buffer[buf_len], (buff_size - buf_len), "%-30s: %d\n", MACROSTR_VALUE(LIBWL_API_TRACE));
        buf_len += snprintf(&buffer[buf_len], (buff_size - buf_len), "%-30s: %d\n", MACROSTR_VALUE(MONOFF_INFO));
        buf_len += snprintf(&buffer[buf_len], (buff_size - buf_len), "%-30s: %d\n", MACROSTR_VALUE(MONOFF_ERROR));
        buf_len += snprintf(&buffer[buf_len], (buff_size - buf_len), "%-30s: %d\n", MACROSTR_VALUE(MONOFF_DBG));
        buf_len += snprintf(&buffer[buf_len], (buff_size - buf_len), "%-30s: %d\n", MACROSTR_VALUE(MONOFF_TIMER));
        buf_len += snprintf(&buffer[buf_len], (buff_size - buf_len), "%-30s: %d\n", MACROSTR_VALUE(MONOFF_MQTT_INFO));
        buf_len += snprintf(&buffer[buf_len], (buff_size - buf_len), "%-30s: %d\n", MACROSTR_VALUE(MONOFF_MQTT_ERROR));
        buf_len += snprintf(&buffer[buf_len], (buff_size - buf_len), "%-30s: %d\n", MACROSTR_VALUE(MONOFF_MQTT_CALLBACK_LOG));
        buf_len += snprintf(&buffer[buf_len], (buff_size - buf_len), "%-30s: %d\n", MACROSTR_VALUE(MONOFF_UBUS_INFO));
        buf_len += snprintf(&buffer[buf_len], (buff_size - buf_len), "%-30s: %d\n", MACROSTR_VALUE(MONOFF_UCI_INFO));
        buf_len += snprintf(&buffer[buf_len], (buff_size - buf_len), "%-30s: %d\n", MACROSTR_VALUE(MONOFF_CMD_INFO));
        buf_len += snprintf(&buffer[buf_len], (buff_size - buf_len), "%-30s: %d\n", MACROSTR_VALUE(MONOFF_CMD_TRACE));
        buf_len += snprintf(&buffer[buf_len], (buff_size - buf_len), "%-30s: %d\n", MACROSTR_VALUE(MONOFF_INOTIFY_INFO));      

        // buf_len is string length, buf_len++ will include \0 char to send.
        return ++buf_len;
}

/**
*@Description: print usage
*@Input: void: void
*@return: 0 ok;  1- fail
*@author: chenzejun 20160123
*/
static void monoff_print_usage(void)
{
	printf("version: %s (build date: %s)\n", g_config.version, g_config.buildtime);
	printf("Usage: mac-onoffline [-d] [-h] [-p] [--port port] [--host name]\n");
	printf("               [--conn-num num]\n");
	printf("       mac-onoffline --help\n\n");

	
	printf(" -d : debug switch, output to screen.\n");
	printf(" -l : debug switch, output to log.\n");
	printf(" -h : display this help.\n");
	printf(" -p : start the broker listening on the specified port.\n");
	printf("      Not recommended in conjunction with the -c option.\n");
	printf(" -v : display the version\n");

	printf(" --conn-num : config the number of the connected mac list, between 100 and 5000\n");
	printf(" --port : start the broker listening on the specified port.\n");
	printf(" --host : start the broker listening on the specified host.\n");
	printf(" --publish-log : publish information record to log.\n");
	printf(" mqtt-test : test mqtt function, send fake data to service by 10s interval.\n");
}

/**
*@Description: Process a tokenised single line from a file or set of real argc/argv
*@Input: void: void
*@return: 0 ok;  1- fail
*@author: chenzejun 20160123
*/
int monoff_option_proc(int argc, char *argv[])
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
                        monoff_print_usage();
                        exit(0);
                }
                else if(!strcmp(argv[i], "-v"))
                {
                        printf("[MAC-ONOFFLINE] Welcome to %s (build date:%s)\n"
                                "(C) 2004-19 jindawanxiang.com\n",
                                g_config.version, g_config.buildtime);
                        exit(0);
                }
                else if(!strcmp(argv[i], "-d"))
                {
                        MONOFF_OPTION_CHECK_RET(i, argc);
                
                        num = atoi(argv[i+1]);
                        libwl_cmd_output_printf(num);
                        i++;
                }
                else if(!strcmp(argv[i], "-l"))
                {
                        MONOFF_OPTION_CHECK_RET(i, argc);
                        
                        num = atoi(argv[i+1]);
                        libwl_cmd_output_log(num);
                        i++;
                }
                else if(!strcmp(argv[i], "--port"))
                {
                        MONOFF_OPTION_CHECK_RET(i, argc);
                        
                        g_mosq_config.port = atoi(argv[i+1]);
                        if (g_mosq_config.port < 1 || g_mosq_config.port > 65535)
                        {
                                fprintf(stderr, "Error: Invalid port given: %d\n", g_mosq_config.port);
                                return -1;
                        }
                        i++;
                }
                else if(!strcmp(argv[i], "--host"))
                {
                        MONOFF_OPTION_CHECK_RET(i, argc);
                        
                        snprintf(g_mosq_config.host, sizeof(g_mosq_config.host), "%s", argv[i+1]);
                        i++;
                }
                else if(!strcmp(argv[i], "--localsrv"))
                {
                        MONOFF_OPTION_CHECK_RET(i, argc);
                        
                        snprintf(g_config.localsrv_name, sizeof(g_config.localsrv_name), "%s", argv[i+1]);
                        i++;
                }
                else if(!strcmp(argv[i], "--publish-log"))
                {
                        MONOFF_OPTION_CHECK_RET(i, argc);
                        
                        g_mosq_config.publish_record_log = atoi(argv[i+1]);
                        i++;
                }
                else if(!strcmp(argv[i], "mqtt-test"))
                {
                        g_mosq_config.mosquitto_test = true;
                        MONOFF_MCLIENT_SET_NOTICE_SWITCH(true);
                }
                else if(!strcmp(argv[i], "remote-show"))
                {
                        MONOFF_OPTION_CHECK_RET(i, argc);
                        sockfd = libwl_cmd_client_create(g_config.my_name);
                        if (sockfd > 0)   
                        {
                                libwl_cmd_client_show(sockfd, 
                                        GET_VALID_ARG(i+1, argc, argv), 
                                        GET_VALID_ARG(i+2, argc, argv), 
                                        GET_VALID_ARG(i+3, argc, argv));
                        }
                        exit(0);
                }
                else if(!strcmp(argv[i], "remote-debug"))
                {
                        MONOFF_OPTION_CHECK_RET(i, argc);
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
static int monoff_init(void)
{
        int i_ret = 0;

        //monoff_get_wan_info();
        libwl_get_router_hwaddr_short("br-lan", g_config.route_mac, sizeof(g_config.route_mac));


        uloop_init();



        //uci config load
        i_ret = monoff_uci_load_config();
        if (i_ret != 0)
        {
                return -1;
        }


        //cmd init
        i_ret = monoff_cmd_init();
        if (i_ret != 0)
        {
                return -1;
        }

        
        // try start local service
        i_ret = monoff_localserv_init();
        if (i_ret < 0)
        {
                MONOFF_DBG_PRINTF(MONOFF_ERROR, "mqttclient init fail\n");   
                return -1;
        }


        // try start, possible connect fail,  restart by timer
        i_ret = monoff_mqttclient_init();
        if (i_ret < 0)
        {
                MONOFF_DBG_PRINTF(MONOFF_ERROR, "mqttclient init fail\n");   
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
static int monoff_destroy(void)
{
        monoff_mqttclient_destroy();
        monoff_localserv_destroy();
        monoff_cmd_destroy();
        monoff_uci_unload_config();

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
        monoff_option_proc(argc, argv);


        if (!libwl_inst_is_running(g_lock_file))
        {
                printf("Not support multiple instances, exit!\n");
                exit(0);
        }


        //time
        time(&g_config.uptime);


        //sleep  one rand time, avoid to start at same time.
        srand((int)time(0));
        sleep(rand()%10);

        libwl_printf_currtime();
        monoff_signal_setup();

        // init
        i_ret = monoff_init();
        if (i_ret != 0)
        {
                goto OUT;
        }
        
        uloop_timeout_set(&monoff_2s_timer, 2000);
        uloop_timeout_set(&monoff_10s_timer, 10000);


        //run
        uloop_run();

OUT:

        MONOFF_DBG_PRINTF(MONOFF_INFO, "main exit\n");   
        monoff_destroy();
        return 0;
}


