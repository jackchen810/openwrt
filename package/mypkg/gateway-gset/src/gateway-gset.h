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
#ifndef __GATEWAY_GSET_H_
#define __GATEWAY_GSET_H_



#define MAX_PAYLOAD 1024  /* maximum payload size*/
#define MAXEPOLLSIZE 5



//LOG_BUFFER_LEN 长度定义小于syslog被截断的长度
//否则截断后数据格式不对。
//X:\toolchain\uClibc\patches-0.9.33.2\9991-uClibc-syslog-buf-len.patch
//修改syslog最大长度为8192
//消息截断后:"msg_kunteng":[truncated] hiwifi_ac#011
#define LOG_BUFFER_LEN        7680


#define NETLINK_RESTART_MAX   8   //


#define MOSQ_CLIENT_PUB 1
#define MOSQ_CLIENT_SUB 2

enum {
        TLV_TYPE_TOPIC = 1,
        TLV_TYPE_PAYLOAD = 2,
        TLV_TYPE_MAX = 24
};

typedef struct  CLIENT_TLV_DATA
{
        ushort us_tlv_type;
        ushort us_tlv_len;
}CLIENT_TLV_DATA;



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


#define GSET_MCLIENT_SET_CONN_STATUS(dstatus)   ( g_mosq_config.mosquitto_conn_flag = (dstatus))
#define GSET_MCLIENT_GET_CONN_STATUS()              ( g_mosq_config.mosquitto_conn_flag)

#define GSET_MCLIENT_SET_NOTICE_SWITCH(dstatus)   ( g_mosq_config.notice_switch = (dstatus))
#define GSET_MCLIENT_GET_NOTICE_SWITCH()               ( g_mosq_config.notice_switch)


#ifndef UNIX_PATH_MAX
#define UNIX_PATH_MAX	108
#endif

struct  GSET_GLOBAL_CONFIG
{
        char my_name[BUF_LEN_64];
        char version[BUF_LEN_64];
        char buildtime[BUF_LEN_64];
        char channelpath[BUF_LEN_128];
        char wan_name[BUF_LEN_64];
        char wan_ip_type[BUF_LEN_16];
        char route_ip[BUF_LEN_64];
        char route_mac[BUF_LEN_64];
        char dev_type[BUF_LEN_64];
        char srvaddr_name[UNIX_PATH_MAX];
        char lockfile_name[BUF_LEN_128];

        unsigned int sequence_number;     // sequence number
        struct sockaddr_un mqttclient_sockaddr;
        int mqttclient_addr_len;
        
        struct uloop_fd uloop_fd_client;
        struct uloop_fd uloop_fd_cmd;
};



typedef struct GSET_SHELL_CMD_TBL
{
        char *cmd_name;
        char *cmd_shell;
        char uciflag;
}GSET_SHELL_CMD_TBL;




//#define gset_debug(fmt, args...)	printf(fmt, ##args)

enum {
        GSET_INFO = LIBWL_SWITCH_MAX,
        GSET_ERROR,
        GSET_DBG,
        GSET_TIMER,
        GSET_SCAN_INFO,
        GSET_CONN_INFO,
        GSET_MQTT_CALLBACK_LOG,
        GSET_UBUS_INFO ,
        GSET_UCI_INFO,
        GSET_CMD_INFO,
        GSET_CMD_TRACE,
        GSET_GATEWAY,
};


#define GSET_DBG_PRINTF   LIBWL_DBG_PRINTF


#define GSET_OPTION_CHECK_RET(did, dargc) \
if (did == (dargc-1))\
{\
        fprintf(stderr, "Error: argument given but no value specified.\n");\
        goto unknown_option;\
}

static void gset_uloop_10s_timer(struct uloop_timeout *timeout);
static void gset_cmd_socket_handle(struct uloop_fd *u, unsigned int ev);
static int gset_show_config(char *buffer, int buff_size);
static int gset_show_debug_switch(char *buffer, int buff_size);
static int gset_reply_2_mqttclient(char *cmd_item, char *uuId, int ret_code, char* ret_msg);


#endif
