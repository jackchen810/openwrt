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

#include "mqtt-client.h"


/*
history:

 receive comand type:
 1)
/YunAC/CMD_SET/(type)
/YunAC/CMD_GET/
/YunAC/CMD_EXE/

*/






static struct MQTTCLIENT_GLOBAL_CONFIG g_config =
{
        .my_name = "mqtt-client",
        .version[0] = 0,
        .buildtime[0] = 0,
        .wan_name[0] = 0,
        .route_mac[0] = 0,
        .route_ip[0] = 0,
        .channelpath[0] = 0,
        .localsrv_name[0] = 0,

        .age_time = 0xfff0,


        .uloop_fd_cmd.fd = -1,
        .uloop_fd_cmd.cb = mqttclient_cmd_socket_handle,
        
};







#if FUNCTION_DESC("command function")

static struct LIBWL_CMD_LIST_ST  g_function_list[] = 
{
        {"config", mqttclient_show_config},
        {"debug", mqttclient_show_debug_switch},
        {"connect", mqttclient_show_connect},
};



/**
 *@Description: the callback function of uloop
 *@Input: u: the file description of uloop
 *@Input: ev: the event of uloop
 *@Return: void
 *@author: chenzejun 20160323
 */
static void mqttclient_cmd_socket_handle(struct uloop_fd *u, unsigned int ev)
{
        libwl_cmd_service_callback(u->fd, g_function_list, ARRAY_SIZE(g_function_list));
        return;
}



/**
 *@Description: mqttclient command init
 *@Input: void: void
 *@Return: 0: ok;   -1: fail
 *@author: chenzejun 20160323
 */
static int mqttclient_cmd_init(void)
{
        /* command service*/
        g_config.uloop_fd_cmd.cb = mqttclient_cmd_socket_handle;
        g_config.uloop_fd_cmd.fd = libwl_cmd_service_create(g_config.my_name);
        if (g_config.uloop_fd_cmd.fd > 0)
        {
                uloop_fd_add(&g_config.uloop_fd_cmd,  ULOOP_READ | ULOOP_EDGE_TRIGGER);
                MQTTCLIENT_DBG_PRINTF(MQTTCLIENT_INFO, "mqttclient add cmd fd:%d\n", g_config.uloop_fd_cmd.fd );  

        }
        
        return 0;
}



/**
 *@Description: mqttclient command destroy
 *@Input: void: void
 *@Return: 0: ok;   -1: fail
 *@author: chenzejun 20160323
 */
static int mqttclient_cmd_destroy(void)
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
static void mqttclient_time_get_config(void)  
{  
        static int time_count = 5;

        time_count++;
        if (time_count%6 == 0)
        {
                //libwl_uci_get_list_fast(uci_contex, "mqtt-client", "subscribe", "yunAC", "subscribe_topic", g_config.topic_list, sizeof(g_config.topic_list));
                //MQTTCLIENT_DBG_PRINTF(MQTTCLIENT_UCI_INFO, "g_config.topic_list:%s\n", g_config.topic_list);
                
                

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
                MQTTCLIENT_DBG_PRINTF(MQTTCLIENT_UCI_INFO, "router_ip:%s\n", g_config.route_ip);

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
static int mqttclient_uci_load_config(void)  
{  
        uci_contex = uci_alloc_context();
        if (uci_contex == NULL)
        {
                return -1;
        }

        //get the config
        (void)mqttclient_time_get_config();
      
        return 0;
}  


/*
*@Description: uci unload config
*@Input: void: void
*@Return: 0: ok;   -1: fail
*@author: chenzejun 20160123
*/
static int mqttclient_uci_unload_config(void)  
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
static int mqttclient_connect_add(MCLIENT_NODE_INFO  *pst_node)
{
        return libwl_alist_add(&connect_info, pst_node->client_name, sizeof(pst_node->client_name), pst_node, sizeof(MCLIENT_NODE_INFO));
}
/*
*@Description: delet node by key
*@Input:pc_key: pointer to macaddr
*@return: find id
*@author: chenzejun 20160123
*/
static int mqttclient_connect_del(char  *pc_key)
{
        return libwl_alist_del(&connect_info, (void *)pc_key, BUF_LEN_64);
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
static int mqttclient_connect_replace_oldest(MCLIENT_NODE_INFO  *pst_add, MCLIENT_NODE_INFO  *pst_del)
{
        return libwl_alist_replace(&connect_info, pst_del, pst_add);
}




/**
*@Description: mqttclient client function init
*@Input: void: void
*@return: 0 ok;  1- fail
*@author: chenzejun 20160123
*/
static int mqttclient_connect_init(void)
{
        /* init connect information */
        connect_info.node_count = 0;
        connect_info.tail_id = INVALID_ID;


        //connect info
        connect_info.pst_node =  malloc(connect_info.cfg_num * sizeof(MCLIENT_NODE_INFO));
        if (NULL == connect_info.pst_node)
        {
                MQTTCLIENT_DBG_PRINTF(MQTTCLIENT_ERROR, "malloc connect_info failed\n");
                return -1;
        }
        
        memset(connect_info.pst_node, 0, connect_info.cfg_num * sizeof(MCLIENT_NODE_INFO));



        printf("macscn startup, cfg_num:%d\n",  connect_info.cfg_num);


        return 0;
}


/**
*@Description: mqttclient client function destroy
*@Input: void: void
*@return: 0 ok;  1- fail
*@author: chenzejun 20160123
*/
static int mqttclient_connect_destroy(void)
{
        if (connect_info.pst_node)  free(connect_info.pst_node);
        connect_info.pst_node = NULL;

        return 0;
}



#endif











#if FUNCTION_DESC("mqtt client function")
static MOSQ_CLINENT_CONFIG g_mosq_config =
{
        .notice_switch = false,
        .mosq_id =  "jdwx_router",  
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
static char *mqttclient_publish_msg = NULL;





/*
*@Description: uci load config
*@Input: void: void
*@Return: 0: ok;   -1: fail
*@author: chenzejun 20160123
*/
void mqttclient_uci_subscribe_list_callback(const char * s_name, const char * list_name, const char * list_value){
        if (list_value == NULL)         return;
        MQTTCLIENT_DBG_PRINTF(MQTTCLIENT_MQTT_INFO, "uci get share list, s_name:%s, list:%s, value:%s \n", s_name, list_name, list_value);
        mosquitto_subscribe(p_mosq_client, NULL, list_value, 2);

}



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
static void mqttclient_log_callback(struct mosquitto *mosq, void *obj, int level, const char *str)
{
        MQTTCLIENT_DBG_PRINTF(MQTTCLIENT_MQTT_CALLBACK_LOG, "log callback, log:%s\n", str);
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
static void mqttclient_connect_callback(struct mosquitto *mosq, void *obj, int result)
{ 
        //mqttclient_subscribe_by_config(uci_contex, "mqtt-client", "subscribe", "yunAC", "subscribe_topic");        
        MQTTCLIENT_DBG_PRINTF(MQTTCLIENT_MQTT_INFO, "connect_callback-----------, result:%d\n", result);       
        libwl_uci_find_element_callback(uci_contex, "mqtt-client", "subscribe", "yunAC", "subscribe_topic", mqttclient_uci_subscribe_list_callback);
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
static void mqttclient_disconnect_callback(struct mosquitto *mosq, void *obj, int result)
{
        MQTTCLIENT_DBG_PRINTF(MQTTCLIENT_MQTT_INFO, "disconnect_callback, result:%d\n", result);
        MQTTCLIENT_MCLIENT_SET_CONN_STATUS(false);
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
static void mqttclient_message_callback(struct mosquitto *mosq, void *obj, const struct mosquitto_message *message)
{
        if (message == NULL)    return;
        

        MQTTCLIENT_DBG_PRINTF(MQTTCLIENT_MQTT_INFO, "[down] topic: %s\n", message->topic);
        MQTTCLIENT_DBG_PRINTF(MQTTCLIENT_MQTT_INFO, "[down] message[%d]: %s\n", message->payloadlen, message->payload);

        mqttclient_localserv_sendto_client(message->topic, message->payload, message->payloadlen);
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
static void mqttclient_subscribe_callback(struct mosquitto *mosq, void *obj, int mid, int qos_count, const int *granted_qos)
{

        MQTTCLIENT_DBG_PRINTF(MQTTCLIENT_MQTT_INFO, "Subscribed (mid: %d): %d", mid, granted_qos[0]);

        return;
}



/**
*@Description: try to connect to mosquitto
*@Input: void: void
*@Return: void
*@author: chenzejun 20160323
*/
static void mqttclient_try_connect(void)
{
        int i_ret = 0;


        if (p_mosq_client == NULL)
        {
                MQTTCLIENT_DBG_PRINTF(MQTTCLIENT_MQTT_INFO, "try to mosquitto_lib_init ...........\n");  

                i_ret= mosquitto_lib_init();
                if (i_ret != MOSQ_ERR_SUCCESS)
                {  
                        MQTTCLIENT_DBG_PRINTF(MQTTCLIENT_MQTT_ERROR, "mosquitto_lib_init failedr, ret = %d\n", i_ret);   
                        return;
                }

                p_mosq_client = mosquitto_new(g_mosq_config.mosq_id, true, &g_mosq_config);
                if(NULL == p_mosq_client)
                {
                        MQTTCLIENT_DBG_PRINTF(MQTTCLIENT_MQTT_ERROR, "mosquitto_new error, ret = %d\n", i_ret);   
                        return;
                }

                /* callback function load */
                mosquitto_log_callback_set(p_mosq_client, mqttclient_log_callback);
                mosquitto_subscribe_callback_set(p_mosq_client, mqttclient_subscribe_callback);
                mosquitto_connect_callback_set(p_mosq_client, mqttclient_connect_callback);
                mosquitto_message_callback_set(p_mosq_client, mqttclient_message_callback);
                mosquitto_disconnect_callback_set(p_mosq_client, mqttclient_disconnect_callback);

	  //set username and passsword
	  mosquitto_username_pw_set(p_mosq_client, g_mosq_config.username, g_mosq_config.password);
        }



        if (false == MQTTCLIENT_MCLIENT_GET_CONN_STATUS())
        {
                MQTTCLIENT_DBG_PRINTF(MQTTCLIENT_MQTT_INFO, "try to connect mosquitto ...........\n");  
                i_ret = mosquitto_connect(p_mosq_client, g_mosq_config.host, g_mosq_config.port, g_mosq_config.keepalive);
                if (i_ret == MOSQ_ERR_SUCCESS)
                {
                        MQTTCLIENT_MCLIENT_SET_CONN_STATUS(true);

                        MQTTCLIENT_DBG_PRINTF(MQTTCLIENT_MQTT_INFO, "reconnect mosquitto success\n");  
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
static int mqttclient_mosquitto_init(void)
{
        int i_ret = 0;
        char portstr[BUF_LEN_32] = {0};

        mqttclient_publish_msg = malloc(LOG_BUFFER_4096 + BUF_LEN_512);
        if(NULL == mqttclient_publish_msg)
        {  
                MQTTCLIENT_DBG_PRINTF(MQTTCLIENT_MQTT_ERROR, "malloc mqttclient_publish_msg failed\n");
                return -1;
        }
       
        


        /* try to connect, if connect failed, then connect by timer */
        mqttclient_try_connect();




        libwl_uci_get_option_fast(uci_contex, "mqtt-client", "subscribe", "yunAC", "host", g_mosq_config.host, sizeof(g_mosq_config.host));
        libwl_uci_get_option_fast(uci_contex, "mqtt-client", "subscribe", "yunAC", "user", g_mosq_config.username, sizeof(g_mosq_config.username));
        libwl_uci_get_option_fast(uci_contex, "mqtt-client", "subscribe", "yunAC", "password", g_mosq_config.password, sizeof(g_mosq_config.password));
        libwl_uci_get_option_fast(uci_contex, "mqtt-client", "subscribe", "yunAC", "port", portstr, sizeof(portstr));
        

        g_mosq_config.port = atoi(portstr);


        return 0;
}


/**
*@Description: destroy mqtt client thread
*@Input: void: pointer to void
*@Return:  0: ok
           <0: fail
*@author: chenzejun 20160711
*/
static int mqttclient_mosquitto_destroy(void)
{
        MQTTCLIENT_DBG_PRINTF(MQTTCLIENT_INFO, "mqtt client destroy...\n"); 

        if (p_mosq_client)  
        {
                mosquitto_destroy(p_mosq_client);
                p_mosq_client = NULL;
        }

        (void)mosquitto_lib_cleanup();

        if (mqttclient_publish_msg)
        {
                free(mqttclient_publish_msg);
                mqttclient_publish_msg = NULL;
        }

        return 0;
}




#endif



#if FUNCTION_DESC("local service and client function")

static char msg_buffer[LOG_BUFFER_4096 + BUF_LEN_512] = {0};



/*
*@Description: uci load config
*@Input: void: void
*@Return: 0: ok;   -1: fail
*@author: chenzejun 20160123
*/
void mqttclient_localserv_config_callback(const char * s_type, const char * s_name, int type, const char * op_name, const char * op_value)
{
        MCLIENT_NODE_INFO st_connect = {0};
        MCLIENT_NODE_INFO *pst_node = &st_connect;
        MCLIENT_NODE_INFO *pst_find = NULL;
        int m = 0;

        if (op_value == NULL)         return;


        MQTTCLIENT_DBG_PRINTF(MQTTCLIENT_MQTT_INFO, "uci scan share list, sec_name:%s, op_name:%s, op_value:%s \n", s_name, op_name, op_value);

        // set 0
        memset(&st_connect, 0, sizeof(st_connect));
        strncpy(st_connect.client_name, s_name, sizeof(pst_node->client_name));

        pst_find  = libwl_alist_find(&connect_info, (void *)st_connect.client_name);
        if (pst_find  == NULL)
        {
                // redeirect
                pst_node = &st_connect;
        }
        else{
                pst_node = pst_find;
        }
                
        MQTTCLIENT_DBG_PRINTF(MQTTCLIENT_MQTT_INFO, "connect_info found s_name:%s, pst_find:0x%x\n", s_name, pst_find);

        if (0 == strcmp(op_name, "sun_path"))
        {
                memset(pst_node->st_client_addr.sun_path, 0, sizeof(pst_node->st_client_addr.sun_path));
                pst_node->st_client_addr.sun_family = AF_UNIX;
                strncpy(pst_node->st_client_addr.sun_path, op_value, sizeof(pst_node->st_client_addr.sun_path));
                pst_node->client_addr_len = strlen(pst_node->st_client_addr.sun_path) + sizeof(pst_node->st_client_addr.sun_family);

        }
        else if (0 == strcmp(op_name, "branch_topic"))
        {       
                // add brandch_topic at blank
                for(m = 0; m < sizeof(st_connect.branch_topic)/sizeof(st_connect.branch_topic[0]); m++)
                {
                        if ('\0' == pst_node->branch_topic[m][0]){
                                strncpy((char *)pst_node->branch_topic[m], op_value, sizeof(pst_node->branch_topic[m]));
                                break;
                        }
                }
        }


        // not found
        if (NULL == pst_find)
        {
                mqttclient_connect_add(pst_node);
        }



        MQTTCLIENT_DBG_PRINTF(MQTTCLIENT_MQTT_INFO, "uci scan share list, exit \n");
        //mosquitto_subscribe(p_mosq_client, NULL, list_value, 2);

}



/**
 *@Description: the match function of branch_topic
 *@Input: topic: the topic
 *@Input: sub_topic: the branch topic
 *@Return: void
 *@author: chenzejun 20160323
 */
static int mqttclient_topic_match(char *topic, char * br_topic)
{
        int i = 0;
        int m = 0;
        char *p_pos = NULL;


        if (strlen(topic) < strlen(br_topic))
        {
                return -1;
        }


        //
        for(i = 0; i < 512; i++)
        {
                if (topic[i] == '\0')   break;

                //find first char
                if (topic[i] == br_topic[0] )
                {
                        //find first char
                        p_pos = &topic[i];
                        break;
                }
        }


        if (p_pos == NULL)
        {
                return -1;
        }

        // match
        for(i = 0; i < 512; i++)
        {
                // the same end
                if (topic[i] == '\0' && br_topic[i] == '\0') 
                {
                        break;
                }

                // br_topic end
                if (topic[i] == '/'  && br_topic[i] == '\0') 
                {
                        break;
                }


                // else end
                if (br_topic[i] == '\0')
                {
                        return -1;
                }
                
                if (topic[i] == '\0') 
                {
                        return -1;
                }


              
                if (p_pos[i] != br_topic[i])
                {
                        return -1;
                }

                // # match direct end
                if (br_topic[i] == '/' && br_topic[i + 1] == '#')
                {
                        break;
                }
                
        }

        
        return 0;
}


/**
 *@Description: the callback function of uloop
 *@Input: u: the file description of uloop
 *@Input: ev: the event of uloop
 *@Return: void
 *@author: chenzejun 20160323
 */
static void mqttclient_localserv_sendto_client(char *topic, char * p_msg,  int msg_len)
{
        MCLIENT_NODE_INFO *pst_connect = NULL;
        int sock_fd = g_config.uloop_fd_local_service.fd;
        int i = 1;
        int bytes;
        char *p_topic3 = NULL;
        int index = 0;
        int m = 0;
        int count = 0;
        char* token = NULL;

        // from topic[1], lookup 1
        while (topic[i])
        {
                if (topic[i] == '/'){
                        count++;
                        if (count >=2)          break;
                }
                i++;
        }

#if 0
        // parse topic
        token = strtok( topic, "/");
        for(i = 0; i < 10; i++)
        {
                if (token == NULL )    break;
                /* While there are tokens in "string" */
                printf( "%s ", token );
                /* Get next token: */
                token = strtok( NULL, "/");
        }
#endif

        MQTTCLIENT_DBG_PRINTF(MQTTCLIENT_LOCAL_SERVICE, "[mqttclient] topic[%d]:%s\n", i, &topic[i]);  


        // if 
        //scan connect info, send msg to service
        libwl_alist_for_entry(pst_connect, index,  &connect_info) 
        {
                if (pst_connect == NULL)  break;


                // add brandch_topic at blank
                for(m = 0; m < sizeof(pst_connect->branch_topic)/sizeof(pst_connect->branch_topic[0]); m++)
                {
                        if ('\0' == pst_connect->branch_topic[m][0])       continue;


                        if (0 == mqttclient_topic_match(&topic[i], (char *)&pst_connect->branch_topic[m]))
                        //if (strstr(&topic[i], (char *)&pst_connect->branch_topic[m]))
                        {
                                break;  //found
                        }
                }

                if (m >= sizeof(pst_connect->branch_topic)/sizeof(pst_connect->branch_topic[0]))
                {
                        //not found, not match
                        continue;
                }
                

                // (msg_len + 1) in order to send end char  0
                bytes = sendto(sock_fd, p_msg, (msg_len + 1), 0, (struct sockaddr*)&pst_connect->st_client_addr, pst_connect->client_addr_len);
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
                
                MQTTCLIENT_DBG_PRINTF(MQTTCLIENT_LOCAL_SERVICE, "[mqttclient] sendto client, sun_path:%s\n", pst_connect->st_client_addr.sun_path);  

        }

        

        MQTTCLIENT_DBG_PRINTF(MQTTCLIENT_LOCAL_SERVICE, "[mqttclient] handle local client  exit\n");  
        return;
}







/*
*@Description: receive msg from socket, connect data
*@Input: pc_msg_data: pointer to the msg
*@Input: ui_msg_len: msglen
*@Return: 0: ok;   -1: fail
*@author: chenzejun 20160123
*/
static int mqttclient_localserv_recvfrom_msg(char *pc_msg_data, unsigned int ui_msg_len)
{
        struct cmsghdr *pst_head = (struct cmsghdr *)pc_msg_data;
        CLIENT_TLV_DATA *pst_tlv_data = (CLIENT_TLV_DATA *)(pst_head + 1);
        unsigned int ui_temp_len = sizeof(struct cmsghdr);
        char *pc_topic = NULL;
        char *pc_payload = NULL;
        unsigned int ui_topic_len = 0;
        unsigned int ui_payload_len = 0;
        int i_ret = 0;

        if (pc_msg_data == NULL)
        {
                return -1;
        }


        while(ui_temp_len < ui_msg_len && pst_tlv_data->us_tlv_len)
        {
                //printf("APP  Received ui_msg_len: %d, %d \n", ui_msg_len, pst_tlv_data->us_tlv_type); 

                if (pst_tlv_data->us_tlv_type >= TLV_TYPE_MAX)
                {
                        MQTTCLIENT_DBG_PRINTF(MQTTCLIENT_LOCAL_SERVICE, "break ui_msg_len: %d, %d \n", ui_msg_len, pst_tlv_data->us_tlv_type); 
                        break;
                }
                
                switch (pst_tlv_data->us_tlv_type)
                {
                        case TLV_TYPE_TOPIC:
                        {
                                pc_topic = (char *)(pst_tlv_data+1);
                                ui_topic_len = pst_tlv_data->us_tlv_len;
                                break;
                        }
                        case TLV_TYPE_PAYLOAD:
                        {
                                pc_payload = (char *)(pst_tlv_data+1);
                                ui_payload_len = pst_tlv_data->us_tlv_len;
                                break;
                        }
                        default:
                        {
                                break;
                        }
                }

                //next tlv
                ui_temp_len = ui_temp_len + pst_tlv_data->us_tlv_len;
                pst_tlv_data =  (CLIENT_TLV_DATA *)((char *)pst_tlv_data + pst_tlv_data->us_tlv_len);
        }


        MQTTCLIENT_DBG_PRINTF(MQTTCLIENT_MQTT_INFO, "[mqttclient]  cmsg_len:%d, ui_topic_len:%d, ui_payload_len:%d\n", 
                pst_head->cmsg_len, ui_topic_len, ui_payload_len); 

        if (pc_topic && pc_payload && (ui_payload_len > sizeof(CLIENT_TLV_DATA)))
        {
                ui_payload_len = ui_payload_len - sizeof(CLIENT_TLV_DATA);   //dec  tlv + '\0'
                if (pc_payload[ui_payload_len -1] == 0)    ui_payload_len--;   //'\0'

               
                i_ret = mosquitto_publish(p_mosq_client, NULL, pc_topic, ui_payload_len, ( const void *)pc_payload, 2, false);
                if (i_ret != 0){
                        MQTTCLIENT_DBG_PRINTF(MQTTCLIENT_MQTT_INFO, "[mqttclient]  publish fail, i_ret:%d\n", i_ret); 
                }


                MQTTCLIENT_DBG_PRINTF(MQTTCLIENT_MQTT_INFO, "[mqttclient]  pc_payload[%d] value:%d,  :%d,  :%d, :%d\n", 
                        ui_payload_len, pc_payload[ui_payload_len-2], pc_payload[ui_payload_len-1], pc_payload[ui_payload_len], pc_payload[ui_payload_len+1]); 

                //force  string end, for safe
                pc_topic[ui_topic_len - 1]  = 0;
                pc_payload[ui_payload_len - 1]  = 0;
                MQTTCLIENT_DBG_PRINTF(MQTTCLIENT_MQTT_INFO, "[mqttclient]  publish i_ret:%d,  topic:%s\n", i_ret,  pc_topic); 
                MQTTCLIENT_DBG_PRINTF(MQTTCLIENT_MQTT_INFO, "[mqttclient]  publish paylen:%d, msg:%s\n", ui_payload_len, pc_payload); 
        }

               
        return 0;
}



/**
 *@Description: the callback function of uloop
 *@Input: u: the file description of uloop
 *@Input: ev: the event of uloop
 *@Return: void
 *@author: chenzejun 20160323
 */
static void mqttclient_localserv_recvfrom_handle(struct uloop_fd *u, unsigned int ev)
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
        LIBWL_DBG_PRINTF(LIBWL_CMD_TRACE, "[mqttclient_localserv] in..., fd:%d\n", sock_fd);  

        /* found new client, process */
        while(1)  
        {

                /* recv data, non block */
                bytes = recv(sock_fd, msg_buffer, LOG_BUFFER_4096, MSG_DONTWAIT);
                if(bytes < 0)
                {
                        if(errno != EAGAIN)  
                        {
                                LIBWL_DBG_PRINTF(LIBWL_CMD_TRACE, "[mqttclient_localserv] recvmsg end fd:%d, errno:%d, ret:%d\n", sock_fd, errno, bytes); 
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
                        LIBWL_DBG_PRINTF(LIBWL_CMD_TRACE, "[mqttclient_localserv] next receive, count:%d, %d\n", rt0_count, errno);  
                        continue;
                }



                MQTTCLIENT_DBG_PRINTF(MQTTCLIENT_MQTT_INFO, "[mqttclient_localserv]  receive socket message, bytes:%d\n", bytes); 
                mqttclient_localserv_recvfrom_msg(msg_buffer, bytes);        
                //i_ret = mosquitto_publish(p_mosq_client, NULL, g_mosq_config.topic, bytes-1, ( const void *)msg_buffer, 2, false);
                //MQTTCLIENT_DBG_PRINTF(MQTTCLIENT_MQTT_INFO, "[mqttclient_localserv]  publish message, bytes:%d\n", bytes); 
        }

        LIBWL_DBG_PRINTF(LIBWL_CMD_TRACE, "[mqttclient_localserv] , exit\n");  
        return;
}


/**
 *@Description: mqttclient command init
 *@Input: void: void
 *@Return: 0: ok;   -1: fail
 *@author: chenzejun 20160323
 */
static int mqttclient_localserv_init(void)
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
        g_config.uloop_fd_local_service.cb = mqttclient_localserv_recvfrom_handle;
        g_config.uloop_fd_local_service.fd = libwl_cmd_create_socket(&serv_address);
        if (g_config.uloop_fd_local_service.fd > 0)
        {
                uloop_fd_add(&g_config.uloop_fd_local_service,  ULOOP_READ | ULOOP_EDGE_TRIGGER);
                MQTTCLIENT_DBG_PRINTF(MQTTCLIENT_LOCAL_SERVICE, "[mqttclient] add local_service fd:%d\n", g_config.uloop_fd_local_service.fd );  

        }


        libwl_uci_scan_element_callback(uci_contex, "mqtt-client", "share", NULL, mqttclient_localserv_config_callback);

        //config file check. ingore
        
        return 0;
}



/**
 *@Description: mqttclient command destroy
 *@Input: void: void
 *@Return: 0: ok;   -1: fail
 *@author: chenzejun 20160323
 */
static int mqttclient_localserv_destroy(void)
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

static struct uloop_timeout mqttclient_2s_timer = 
{
        .cb = mqttclient_uloop_2s_timer,
};
static struct uloop_timeout mqttclient_10s_timer = 
{
        .cb = mqttclient_uloop_10s_timer,
};

/**
*@Description: timer function
*@Input: timeout: timeout
*@Return: 0: ok;   -1: fail
*@author: chenzejun 20160323
*/
static void mqttclient_uloop_2s_timer(struct uloop_timeout *timeout)
{
        MQTTCLIENT_DBG_PRINTF(MQTTCLIENT_TIMER, "[in] 2s timer.... \n"); 

        uloop_timeout_set(timeout, 2000);


        // get ip by timer, beacuse ip will change
        //mqttclient_get_router_ip("br-lan", g_config.route_ip, BUF_LEN_64);

        //mosquitto_loop    Parameters: timeout
        //Maximum number of milliseconds to wait for network activity in the select() call before timing out.  
        //Set to 0 for instant return.  
        //Set negative to use the default of 1000ms.
        //mosquitto_loop(p_mosq_client, -1, 1);
        mosquitto_loop(p_mosq_client, 0, 1);
        
        MQTTCLIENT_DBG_PRINTF(MQTTCLIENT_TIMER, "[out] 2s timer.... \n"); 

        return;
}


/**
*@Description: timer function
*@Input: timeout: timeout
*@Return: 0: ok;   -1: fail
*@author: chenzejun 20160323
*/
static void mqttclient_uloop_10s_timer(struct uloop_timeout *timeout)
{
        MQTTCLIENT_DBG_PRINTF(MQTTCLIENT_TIMER, "[in] uloop 10s timer.... \n"); 

        uloop_timeout_set(timeout, 10000);


        //try to connect mosquitto service
        mqttclient_try_connect();


        // get uci config
        mqttclient_time_get_config();

        //mqttclient_publish_test();
        MQTTCLIENT_DBG_PRINTF(MQTTCLIENT_TIMER, "[out] uloop 10s timer.... \n"); 

        return;
}


/**
*@Description: timer function
*@Input: signo: signal no
*@Return: 0: ok;   -1: fail
*@author: chenzejun 20160323
*/
void mqttclient_sigroutine(int signo)
{
        static int t_count = 0;
        
        if (signo != SIGALRM)
        {
                return;
        }

        signal(SIGALRM, mqttclient_sigroutine);
        return;
}

/**
*@Description: create timer
*@Input: void: void
*@Return: 0: ok;   -1: fail
*@author: chenzejun 20160323
*/
static int mqttclient_timer_create(void)
{
        struct itimerval value, ovalue;          //(1)
        MQTTCLIENT_DBG_PRINTF(MQTTCLIENT_TIMER, "create timer, process id is %d \n", getpid());
        
        signal(SIGALRM, mqttclient_sigroutine);

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
static void mqttclient_signal_handle(int signo)
{
        if (signo == SIGUSR1)
        {
                MQTTCLIENT_DBG_PRINTF(MQTTCLIENT_TIMER, "signal handle, signo is SIGUSR1\n");
        }
        else if (signo == SIGUSR2)
        {
                MQTTCLIENT_DBG_PRINTF(MQTTCLIENT_TIMER, "signal handle, signo is SIGUSR2\n");
        }

        return;
}



/**
*@Description: signal setup
*@Input: void: void
*@return: 0 ok;  1- fail
*@author: chenzejun 20160123
*/
static void mqttclient_signal_setup(void)
{
        signal(SIGUSR1, mqttclient_signal_handle);
        signal(SIGUSR2, mqttclient_signal_handle);

        //start timer
        //signal(SIGALRM, mqttclient_timer_proc);
        //alarm(10);   //10s  signal
        return;
}



#endif

 

#if FUNCTION_DESC("option function")


/**
 *@Description: show mqttclient client config
 *@Input: void
 *@Return: 0: ok;   -1: fail
 *@author: chenzejun 20160323
 */
static int mqttclient_show_config(char *buffer, int buff_size)
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
        buf_len += snprintf(&buffer[buf_len], (buff_size - buf_len), "%-30s: %s\n", "my_name", g_config.my_name);
        buf_len += snprintf(&buffer[buf_len], (buff_size - buf_len), "%-30s: %s\n", "localsrv_name", g_config.localsrv_name);
        buf_len += snprintf(&buffer[buf_len], (buff_size - buf_len), "%-30s: %s\n", "lockfile_name", g_config.lockfile_name);
        buf_len += snprintf(&buffer[buf_len], (buff_size - buf_len), "%-30s: %s\n", "wan_name", g_config.wan_name);
        buf_len += snprintf(&buffer[buf_len], (buff_size - buf_len), "%-30s: %s\n", "route_mac", g_config.route_mac);
        buf_len += snprintf(&buffer[buf_len], (buff_size - buf_len), "%-30s: %s\n", "route_ip", g_config.route_ip);
        buf_len += snprintf(&buffer[buf_len], (buff_size - buf_len), "%-30s: %s\n", "wan_ip_type", g_config.wan_ip_type);
        buf_len += snprintf(&buffer[buf_len], (buff_size - buf_len), "%-30s: %s\n", "channelpath", g_config.channelpath);
        buf_len += snprintf(&buffer[buf_len], (buff_size - buf_len), "%-30s: %s\n", "host", g_mosq_config.host);
        buf_len += snprintf(&buffer[buf_len], (buff_size - buf_len), "%-30s: %d\n", "port", g_mosq_config.port);
        buf_len += snprintf(&buffer[buf_len], (buff_size - buf_len), "%-30s: %s\n", "username", g_mosq_config.username);
        buf_len += snprintf(&buffer[buf_len], (buff_size - buf_len), "%-30s: %s\n", "password", g_mosq_config.password);
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
static int mqttclient_show_debug_switch(char *buffer, int buff_size)
{
        int  buf_len = 0;  

        if (buffer == NULL)    return 0;

        buf_len += snprintf(&buffer[buf_len], (buff_size - buf_len), "%-30s: %d\n", MACROSTR_VALUE(LIBWL_INFO));
        buf_len += snprintf(&buffer[buf_len], (buff_size - buf_len), "%-30s: %d\n", MACROSTR_VALUE(LIBWL_ERROR));
        buf_len += snprintf(&buffer[buf_len], (buff_size - buf_len), "%-30s: %d\n", MACROSTR_VALUE(LIBWL_LOG_TRACE));
        buf_len += snprintf(&buffer[buf_len], (buff_size - buf_len), "%-30s: %d\n", MACROSTR_VALUE(LIBWL_CMD_TRACE));
        buf_len += snprintf(&buffer[buf_len], (buff_size - buf_len), "%-30s: %d\n", MACROSTR_VALUE(LIBWL_API_TRACE));
        buf_len += snprintf(&buffer[buf_len], (buff_size - buf_len), "%-30s: %d\n", MACROSTR_VALUE(MQTTCLIENT_INFO));
        buf_len += snprintf(&buffer[buf_len], (buff_size - buf_len), "%-30s: %d\n", MACROSTR_VALUE(MQTTCLIENT_ERROR));
        buf_len += snprintf(&buffer[buf_len], (buff_size - buf_len), "%-30s: %d\n", MACROSTR_VALUE(MQTTCLIENT_DBG));
        buf_len += snprintf(&buffer[buf_len], (buff_size - buf_len), "%-30s: %d\n", MACROSTR_VALUE(MQTTCLIENT_TIMER));
        buf_len += snprintf(&buffer[buf_len], (buff_size - buf_len), "%-30s: %d\n", MACROSTR_VALUE(MQTTCLIENT_MQTT_INFO));
        buf_len += snprintf(&buffer[buf_len], (buff_size - buf_len), "%-30s: %d\n", MACROSTR_VALUE(MQTTCLIENT_MQTT_ERROR));
        buf_len += snprintf(&buffer[buf_len], (buff_size - buf_len), "%-30s: %d\n", MACROSTR_VALUE(MQTTCLIENT_MQTT_CALLBACK_LOG));
        buf_len += snprintf(&buffer[buf_len], (buff_size - buf_len), "%-30s: %d\n", MACROSTR_VALUE(MQTTCLIENT_UBUS_INFO));
        buf_len += snprintf(&buffer[buf_len], (buff_size - buf_len), "%-30s: %d\n", MACROSTR_VALUE(MQTTCLIENT_UCI_INFO));
        buf_len += snprintf(&buffer[buf_len], (buff_size - buf_len), "%-30s: %d\n", MACROSTR_VALUE(MQTTCLIENT_CMD_INFO));
        buf_len += snprintf(&buffer[buf_len], (buff_size - buf_len), "%-30s: %d\n", MACROSTR_VALUE(MQTTCLIENT_CMD_TRACE));
        buf_len += snprintf(&buffer[buf_len], (buff_size - buf_len), "%-30s: %d\n", MACROSTR_VALUE(MQTTCLIENT_INOTIFY_INFO));      

        // buf_len is string length, buf_len++ will include \0 char to send.
        return ++buf_len;
}



/**
 *@Description: show the connection infomation of mac
 *@Input: buffer
 *@Input: buff_size
 *@Return: 0: ok;   -1: fail
 *@author: chenzejun 20160323
 */
static int mqttclient_show_connect(char *buffer, int buff_size)
{
        static int last_id = 0;
        ALIST_HEAD *p_info = &connect_info;
        MCLIENT_NODE_INFO  *pst_connect = NULL;
        int i = 0;
        int  buf_len = 0;  
        int m = 0;


        if (buffer == NULL)    return 0;

        if (p_info->node_count <= 0)
        {
                buf_len += snprintf(&buffer[buf_len], (buff_size - buf_len), "connect list count is 0\n");
                return buf_len;
        }
        else
        {
                buf_len += snprintf(&buffer[buf_len], (buff_size - buf_len), "no\tclient_name\t\t\tsun_path\t\t\t\tbranch_topic\n");
        }

        //connect data for show
        libwl_alist_for_entry(pst_connect, i,  p_info) 
        {
                if (pst_connect == NULL)  break;
                
                //no data
                if (i < last_id)  continue;


                // add brandch_topic at blank
                for(m = 0; m < sizeof(pst_connect->branch_topic)/sizeof(pst_connect->branch_topic[0]); m++)
                {
                        if (pst_connect->branch_topic[m][0]){
                                buf_len += snprintf(&buffer[buf_len], (buff_size - buf_len), "%2d\t%-24s\t%-32s\t%-32s\n",
                                        i,
                                        pst_connect->client_name,
                                        pst_connect->st_client_addr.sun_path, 
                                        (char *)&pst_connect->branch_topic[m]);
                        }

                }

                
                // will to full, break;
                if (buf_len > (LOG_BUFFER_2048 - 1024))
                {
                        last_id = i; //record
                        break;
                }
                
        }

        if (i > p_info->tail_id)    last_id = 0;

        MQTTCLIENT_DBG_PRINTF(MQTTCLIENT_CMD_TRACE, "cmd message[%d]: %s\n", buf_len, buffer); 

        // buf_len is string length, buf_len++ will include \0 char to send.
        return ++buf_len;
}



/**
*@Description: print usage
*@Input: void: void
*@return: 0 ok;  1- fail
*@author: chenzejun 20160123
*/
static void mqttclient_print_usage(void)
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
int mqttclient_option_proc(int argc, char *argv[])
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
                        mqttclient_print_usage();
                        exit(0);
                }
                else if(!strcmp(argv[i], "-v"))
                {
                        printf("[MQTT-CLIENT] Welcome to %s (build date:%s)\n"
                                "(C) 2004-19 jindawanxiang.com\n",
                                g_config.version, g_config.buildtime);
                        exit(0);
                }
                else if(!strcmp(argv[i], "-d"))
                {
                        MQTTCLIENT_OPTION_CHECK_RET(i, argc);
                
                        num = atoi(argv[i+1]);
                        libwl_cmd_output_printf(num);
                        i++;
                }
                else if(!strcmp(argv[i], "-l"))
                {
                        MQTTCLIENT_OPTION_CHECK_RET(i, argc);
                        
                        num = atoi(argv[i+1]);
                        libwl_cmd_output_log(num);
                        i++;
                }
                else if(!strcmp(argv[i], "--port"))
                {
                        MQTTCLIENT_OPTION_CHECK_RET(i, argc);
                        
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
                        MQTTCLIENT_OPTION_CHECK_RET(i, argc);
                        
                        snprintf(g_mosq_config.host, sizeof(g_mosq_config.host), "%s", argv[i+1]);
                        i++;
                }
                else if(!strcmp(argv[i], "--localsrv"))
                {
                        MQTTCLIENT_OPTION_CHECK_RET(i, argc);
                        
                        snprintf(g_config.localsrv_name, sizeof(g_config.localsrv_name), "%s", argv[i+1]);
                        i++;
                }
                else if(!strcmp(argv[i], "--publog"))
                {
                        MQTTCLIENT_OPTION_CHECK_RET(i, argc);
                        
                        g_mosq_config.publish_record_log = atoi(argv[i+1]);
                        i++;
                }
                else if(!strcmp(argv[i], "mqtt-test"))
                {
                        g_mosq_config.mosquitto_test = true;
                        MQTTCLIENT_MCLIENT_SET_NOTICE_SWITCH(true);
                }
                else if(!strcmp(argv[i], "remote-show"))
                {
                        MQTTCLIENT_OPTION_CHECK_RET(i, argc);
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
                        MQTTCLIENT_OPTION_CHECK_RET(i, argc);
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
static int mqttclient_init(void)
{
        int i_ret = 0;

        //mqttclient_get_wan_info();
        libwl_get_router_hwaddr_short("br-lan", g_config.route_mac, sizeof(g_config.route_mac));


        uloop_init();



        i_ret = mqttclient_connect_init();
        if (i_ret != 0)
        {
                return -1;
        }


        //uci config load
        i_ret = mqttclient_uci_load_config();
        if (i_ret != 0)
        {
                return -1;
        }


        //cmd init
        i_ret = mqttclient_cmd_init();
        if (i_ret != 0)
        {
                return -1;
        }

        
        // try start local service
        i_ret = mqttclient_localserv_init();
        if (i_ret < 0)
        {
                MQTTCLIENT_DBG_PRINTF(MQTTCLIENT_ERROR, "mqttclient init fail\n");   
                return -1;
        }


        // try start, possible connect fail,  restart by timer
        i_ret = mqttclient_mosquitto_init();
        if (i_ret < 0)
        {
                MQTTCLIENT_DBG_PRINTF(MQTTCLIENT_ERROR, "mqttclient init fail\n");   
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
static int mqttclient_destroy(void)
{
        mqttclient_mosquitto_destroy();
        mqttclient_localserv_destroy();
        mqttclient_cmd_destroy();
        mqttclient_uci_unload_config();
        mqttclient_connect_destroy();
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
        mqttclient_option_proc(argc, argv);


        snprintf(g_config.lockfile_name, sizeof(g_config.lockfile_name), "/var/lock/%s.lock", g_config.my_name);
        if (!libwl_inst_is_running(g_config.lockfile_name))
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
        mqttclient_signal_setup();

        // init
        i_ret = mqttclient_init();
        if (i_ret != 0)
        {
                goto OUT;
        }
        
        uloop_timeout_set(&mqttclient_2s_timer, 2000);
        uloop_timeout_set(&mqttclient_10s_timer, 10000);


        //run
        uloop_run();

OUT:

        MQTTCLIENT_DBG_PRINTF(MQTTCLIENT_INFO, "main exit\n");   
        mqttclient_destroy();
        return 0;
}


