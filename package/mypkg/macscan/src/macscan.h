/*
 * Copyright (C) 2011-2014  <jack_chen_mail@163.com>
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
#ifndef __MACSCAN_H_
#define __MACSCAN_H_



#define MAX_PAYLOAD 1024  /* maximum payload size*/
#define MAXEPOLLSIZE 5



//LOG_BUFFER_LEN 长度定义小于syslog被截断的长度
//否则截断后数据格式不对。
//X:\toolchain\uClibc\patches-0.9.33.2\9991-uClibc-syslog-buf-len.patch
//修改syslog最大长度为8192
//消息截断后:"msg_kunteng":[truncated] hiwifi_ac#011
#define LOG_BUFFER_LEN        7680


#define NETLINK_RESTART_MAX   8   //




// connect info node
typedef struct  STA_CONN_NODE_INFO
{
        unsigned char  ac_mac[MAC_LEN_6];
        unsigned char  uc_signal;

        char ac_signal_str[BUF_LEN_16];
        char ac_conn_type_str[BUF_LEN_16];
        char ac_type_wifi_str[BUF_LEN_16];
        char ac_ip_str[BUF_LEN_16];
        char ac_iptype_str[BUF_LEN_16];
        unsigned short  us_idle_count;
}STA_CONN_NODE_INFO;




// scan info node
typedef struct  STA_SCAN_NODE_INFO
{        
        unsigned char  ac_mac[MAC_LEN_6];
        signed char c_rssi;
        signed char c_resv;  //resv field
}STA_SCAN_NODE_INFO;


#define MOSQ_CLIENT_PUB 1
#define MOSQ_CLIENT_SUB 2


typedef struct  MOSQ_CLINENT_CONFIG_st
{
        int  notice_switch;
        char mosq_id[BUF_LEN_64];
        char topic[BUF_LEN_256];
        char host[BUF_LEN_64];
        int port;
        int keepalive;
        char bind_address[BUF_LEN_64];
        char mosquitto_conn_flag;
        char mosquitto_test;     // test flag, it's no use in normal
}MOSQ_CLINENT_CONFIG;


#define MSCAN_MCLIENT_SET_CONN_STATUS(dstatus)   ( g_mosq_config.mosquitto_conn_flag = (dstatus))
#define MSCAN_MCLIENT_GET_CONN_STATUS()              ( g_mosq_config.mosquitto_conn_flag)

#define MSCAN_MCLIENT_SET_NOTICE_SWITCH(dstatus)   ( g_mosq_config.notice_switch = (dstatus))
#define MSCAN_MCLIENT_GET_NOTICE_SWITCH()               ( g_mosq_config.notice_switch)



struct  MSCAN_GLOBAL_CONFIG
{
        char version[BUF_LEN_64];
        char buildtime[BUF_LEN_64];
        char channelpath[BUF_LEN_128];
        char wan_name[BUF_LEN_64];
        char wan_ip_type[BUF_LEN_16];
        char route_ip[BUF_LEN_64];
        char route_mac[BUF_LEN_64];

        unsigned short restart_5g_count;
        unsigned short restart_2g_count;
        
        struct uloop_fd uloop_fd_5g;
        struct uloop_fd uloop_fd_2g;
        struct uloop_fd uloop_fd_cmd;
};






//#define mscan_debug(fmt, args...)	printf(fmt, ##args)

enum {
        MSCAN_INFO = LIBWL_SWITCH_MAX,
        MSCAN_ERROR,
        MSCAN_DBG,
        MSCAN_TIMER,
        MSCAN_SCAN_INFO,
        MSCAN_CONN_INFO,
        MSCAN_MQTT_CALLBACK_LOG,
        MSCAN_UBUS_INFO ,
        MSCAN_UCI_INFO,
        MSCAN_CMD_INFO,
        MSCAN_CMD_TRACE,
};


#define MSCAN_DBG_PRINTF   LIBWL_DBG_PRINTF


#define MSCAN_OPTION_CHECK_RET(did, dargc) \
if (did == (dargc-1))\
{\
        fprintf(stderr, "Error: argument given but no value specified.\n");\
        goto unknown_option;\
}

static void mscan_netlink_handler(struct uloop_fd *u, unsigned int ev);
static void mscan_uloop_10s_timer(struct uloop_timeout *timeout);
static void mscan_cmd_socket_handle(struct uloop_fd *u, unsigned int ev);
static int mscan_show_config(char *buffer, int buff_size);
static int mscan_show_debug_switch(char *buffer, int buff_size);


#endif
