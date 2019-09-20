/*
 * Copyright (C) 2011-2014  <chenzejun@kunteng.org>
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
#ifndef __MAC_ONOFFLINE_H_
#define __MAC_ONOFFLINE_H_


#define MAXEPOLLSIZE 5
#define MAX_PAYLOAD 1024  /* maximum payload size*/


#define NETLINK_RESTART_MAX   8   //



typedef enum  STA_PUBLISH_STATUS_EN
{
        STA_PUBLISH_NEW = 0,
        STA_PUBLISH_UP = 1,
        STA_PUBLISH_DOWN = 2,
}STA_PUBLISH_STATUS_EN;


#define MOSQ_CLIENT_PUB 1
#define MOSQ_CLIENT_SUB 2


typedef struct  MOSQ_CLINENT_CONFIG_st
{
        int  notice_switch;
        char mosq_id[BUF_LEN_64];
        char topic[BUF_LEN_256];
        char host[BUF_LEN_64];
        int port;
	 char username[BUF_LEN_64];
	 char password[BUF_LEN_64];
        int keepalive;
        char bind_address[BUF_LEN_64];
        char mosquitto_conn_flag;
        char publish_record_log;
        char mosquitto_test;     // test flag, it's no use in normal
        unsigned int sequence_number;     // sequence number
}MOSQ_CLINENT_CONFIG;


#define MONOFF_MCLIENT_SET_CONN_STATUS(dstatus)   ( g_mosq_config.mosquitto_conn_flag = (dstatus))
#define MONOFF_MCLIENT_GET_CONN_STATUS()              ( g_mosq_config.mosquitto_conn_flag)

#define MONOFF_MCLIENT_SET_NOTICE_SWITCH(dstatus)   ( g_mosq_config.notice_switch = (dstatus))
#define MONOFF_MCLIENT_GET_NOTICE_SWITCH()               ( g_mosq_config.notice_switch)



struct  MONOFF_GLOBAL_CONFIG
{
        char version[BUF_LEN_64];
        char buildtime[BUF_LEN_64];
        char channelpath[BUF_LEN_128];
        char wan_name[BUF_LEN_64];
        char wan_ip_type[BUF_LEN_16];
        char route_ip[BUF_LEN_64];
        char route_mac[BUF_LEN_64];
        time_t uptime;

        unsigned int age_time;

        struct uloop_fd uloop_fd_cmd;
        struct uloop_fd uloop_fd_dhcp_inotify;
};




/* debug pointer, support log or screen to output info */
typedef int (* PF_MONOFF_PRINT)(const char *, ...);
struct  MONOFF_GLOBAL_DEBUG
{
        unsigned short debug_flag;
        unsigned char  dbg_switch[BUF_LEN_64];
        PF_MONOFF_PRINT pf_function;
        pthread_mutex_t log_mutex;
        char *logfilename;
        char logstr[LOG_BUFFER_1024 + BUF_LEN_32];
        int timeout_count;    //cmd timeout count
};



//#define monoff_debug(fmt, args...)	printf(fmt, ##args)


/* 0-100, ouput to screen */
/* 100-..., ouput to log*/
enum {
        MONOFF_INFO  = LIBWL_SWITCH_MAX,
        MONOFF_ERROR,
        MONOFF_DBG,
        MONOFF_TIMER,
        MONOFF_MQTT_INFO,
        MONOFF_MQTT_ERROR,
        MONOFF_MQTT_CALLBACK_LOG,
        MONOFF_UBUS_INFO,
        MONOFF_UCI_INFO,
        MONOFF_CMD_INFO,
        MONOFF_CMD_TRACE,
        MONOFF_INOTIFY_INFO,
};


#define MONOFF_DBG_PRINTF LIBWL_DBG_PRINTF


#define MONOFF_OPTION_CHECK_RET(did, dargc) \
if (did == (dargc-1))\
{\
        fprintf(stderr, "Error: argument given but no value specified.\n");\
        goto unknown_option;\
}

static void monoff_uloop_2s_timer(struct uloop_timeout *timeout);
static void monoff_uloop_10s_timer(struct uloop_timeout *timeout);
static void monoff_cmd_socket_handle(struct uloop_fd *u, unsigned int ev);
static int monoff_show_config(char *buffer, int buff_size);
static int monoff_show_connect(char *buffer, int buff_size);
static void monoff_dhcp_inotify_handler(struct uloop_fd *u, unsigned int ev);
static int monoff_show_debug_switch(char *buffer, int buff_size);



#endif
