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
#ifndef __MQTT_CLIENT_H_
#define __MQTT_CLIENT_H_


#define MAXEPOLLSIZE 5
#define MAX_PAYLOAD 1024  /* maximum payload size*/


#define NETLINK_RESTART_MAX   8   //





#define LISTEN_MAX_SOCKET_NUM  20


#define MOSQ_CLIENT_PUB 1
#define MOSQ_CLIENT_PUB_RESP 2
#define MOSQ_CLIENT_SUB 3
#define MOSQ_CLIENT_SUB_RESP 4

enum {
        TLV_TYPE_TOPIC = 1,
        TLV_TYPE_PAYLOAD = 2,
        TLV_TYPE_AF_UNIX_ADDRESS = 3,
        TLV_TYPE_RESP_CODE = 10,
        TLV_TYPE_RESP_MSG = 11,
        TLV_TYPE_MAX = 24
};

typedef struct  CLIENT_TLV_DATA
{
        ushort us_tlv_type;
        ushort us_tlv_len;
}CLIENT_TLV_DATA;






// connect info node
typedef struct  MCLIENT_NODE_INFO
{
        // same to create socket
        // key
        char  client_name[BUF_LEN_64];
        struct sockaddr_un st_client_addr;
        int  client_addr_len;

        // data, dispatch by this field
        char  branch_topic[5][BUF_LEN_128];

}MCLIENT_NODE_INFO;







typedef enum  STA_PUBLISH_STATUS_EN
{
        STA_PUBLISH_NEW = 0,
        STA_PUBLISH_UP = 1,
        STA_PUBLISH_DOWN = 2,
}STA_PUBLISH_STATUS_EN;




typedef struct  MOSQ_CLINENT_CONFIG_st
{
        int  notice_switch;
        char mosq_id[BUF_LEN_64];
        //char topic[BUF_LEN_256];
        char host[BUF_LEN_64];
        int port;
        char username[BUF_LEN_64];
        char password[BUF_LEN_64];
        int keepalive;
        char bind_address[BUF_LEN_64];
        //char topic_list[BUF_LEN_256];

        char mosquitto_conn_flag;
        char publish_record_log;
        char mosquitto_test;     // test flag, it's no use in normal
        unsigned int sequence_number;     // sequence number
}MOSQ_CLINENT_CONFIG;



#define MQTTCLIENT_MCLIENT_SET_CONN_STATUS(dstatus)   ( g_mosq_config.mosquitto_conn_flag = (dstatus))
#define MQTTCLIENT_MCLIENT_GET_CONN_STATUS()              ( g_mosq_config.mosquitto_conn_flag)

#define MQTTCLIENT_MCLIENT_SET_NOTICE_SWITCH(dstatus)   ( g_mosq_config.notice_switch = (dstatus))
#define MQTTCLIENT_MCLIENT_GET_NOTICE_SWITCH()               ( g_mosq_config.notice_switch)

#ifndef UNIX_PATH_MAX
#define UNIX_PATH_MAX	108
#endif

struct  MQTTCLIENT_GLOBAL_CONFIG
{
        char my_name[BUF_LEN_64];
        char version[BUF_LEN_64];
        char buildtime[BUF_LEN_64];
        char channelpath[BUF_LEN_128];
        char wan_name[BUF_LEN_64];
        char wan_ip_type[BUF_LEN_16];
        char route_ip[BUF_LEN_64];
        char route_mac[BUF_LEN_64];
        time_t uptime;
        char localsrv_name[UNIX_PATH_MAX];  //UNIX_PATH_MAX
        char lockfile_name[BUF_LEN_128];
        unsigned int age_time;

        struct uloop_fd uloop_fd_cmd;
        struct uloop_fd uloop_fd_local_service;
};




/* debug pointer, support log or screen to output info */
typedef int (* PF_MQTTCLIENT_PRINT)(const char *, ...);
struct  MQTTCLIENT_GLOBAL_DEBUG
{
        unsigned short debug_flag;
        unsigned char  dbg_switch[BUF_LEN_64];
        PF_MQTTCLIENT_PRINT pf_function;
        pthread_mutex_t log_mutex;
        char *logfilename;
        char logstr[LOG_BUFFER_1024 + BUF_LEN_32];
        int timeout_count;    //cmd timeout count
};



//#define mqttclient_debug(fmt, args...)	printf(fmt, ##args)


/* 0-100, ouput to screen */
/* 100-..., ouput to log*/
enum {
        MQTTCLIENT_INFO  = LIBWL_SWITCH_MAX,
        MQTTCLIENT_ERROR,
        MQTTCLIENT_DBG,
        MQTTCLIENT_TIMER,
        MQTTCLIENT_MQTT_INFO,
        MQTTCLIENT_MQTT_ERROR,
        MQTTCLIENT_MQTT_CALLBACK_LOG,
        MQTTCLIENT_UBUS_INFO,
        MQTTCLIENT_UCI_INFO,
        MQTTCLIENT_CMD_INFO,
        MQTTCLIENT_CMD_TRACE,
        MQTTCLIENT_INOTIFY_INFO,
        MQTTCLIENT_MSGQ_INFO,
        MQTTCLIENT_LOCAL_SERVICE,
};


#define MQTTCLIENT_DBG_PRINTF LIBWL_DBG_PRINTF


#define MQTTCLIENT_OPTION_CHECK_RET(did, dargc) \
if (did == (dargc-1))\
{\
        fprintf(stderr, "Error: argument given but no value specified.\n");\
        goto unknown_option;\
}

static void mqttclient_uloop_2s_timer(struct uloop_timeout *timeout);
static void mqttclient_uloop_10s_timer(struct uloop_timeout *timeout);
static void mqttclient_cmd_socket_handle(struct uloop_fd *u, unsigned int ev);
static int mqttclient_show_config(char *buffer, int buff_size);
static int mqttclient_show_connect(char *buffer, int buff_size);
static void mqttclient_dhcp_inotify_handler(struct uloop_fd *u, unsigned int ev);
static int mqttclient_show_debug_switch(char *buffer, int buff_size);
static void mqttclient_localserv_sendto_client(char *topic, char * p_msg,  int msg_len);



#endif
