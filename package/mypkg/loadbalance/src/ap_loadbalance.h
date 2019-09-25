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
#ifndef __AP_LOADBALANCE_H_
#define __AP_LOADBALANCE_H_


#define MAX_PAYLOAD 1024  /* maximum payload size*/
#define LBALANCE_MSG_TYPE_NOTICE      1
#define MAXEPOLLSIZE 10


enum {
        LBALANCE_TLV_TYPE_MAC = 1,
        LBALANCE_TLV_TYPE_SSID = 2,
        LBALANCE_TLV_TYPE_GROUP = 3,
        LBALANCE_TLV_TYPE_WLAN_TYPE = 4,
        LBALANCE_TLV_TYPE_COUNT = 5,
        LBALANCE_TLV_TYPE_CHANNEL = 6,
        LBALANCE_TLV_TYPE_DRV_COUNT = 7,
        LBALANCE_TLV_TYPE_MAX = 24
};




enum {
        LBALANCE_WLAN_TYPE_2G = 1,
        LBALANCE_WLAN_TYPE_5G = 2,
        LBALANCE_WLAN_TYPE_MAX
};


#define WIFI_STATUS_OPEN         0x0
#define WIFI_STATUS_CLOSE       0x1
#define WIFI_CHANNEL_KEEP      0x2
#define WIFI_CHANNEL_MODIFY  0x3



typedef struct  STA_CONNECT_NODE
{
        unsigned char ac_mac[MAC_LEN_6];
        char ac_ssid[BUF_LEN_128];
        unsigned short ssid_len;
        unsigned short channel;
        unsigned short reset_channel_cnt;
        unsigned short group_id;      //grupid  unit digit is keep up amount, keepup_amount = st_node.group_id%10
        unsigned short wlan_type;   //LBALANCE_WLAN_TYPE_MAX
        unsigned short us_lb_count;    //us_lb_count =  us_count - lbalance_base
        unsigned short us_drv_count;    //us_drv_count =  us_lb_count + lbalance_base
        unsigned short us_idle_count;    //us_idle_count,  age count
}STA_CONNECT_NODE;

typedef struct  LOACL_WLAN_INFO
{
        char ac_ifname[BUF_LEN_64];
        //unsigned short us_count;     //drv mac count, us_count = lbalance_base + us_lb_count
        unsigned short wifi_status;  // WIFI_STATUS_OPEN or WIFI_STATUS_CLOSE,  driver status
        unsigned int ifstatus;          // ra0 or rai0 up or down
        unsigned int lbalance_base;         //lbalance_base, when it is 0, don't loadbalance
        unsigned short keepup_amount;   // the amount of keep up machine,  keepup_amount = st_node.group_id%10
        unsigned short delay_close_count;   // the count of delay close wifi, avoid up more mac in same time for close all wifi
        STA_CONNECT_NODE st_node;      //node it be mast send
}LOACL_WLAN_INFO;



#define NETLINK_RESTART_MAX   8   //



#define LBALANCE_POLICY_MAX_DISABLE                     1
#define LBALANCE_POLICY_MIN_ENABLE            2
#define LBALANCE_POLICY_MIN_CFG            3

struct  LBALANCE_GLOBAL_CONFIG
{
        char version[BUF_LEN_64];
        char buildtime[BUF_LEN_64];
        char channelpath[BUF_LEN_128];
        char wan_name[BUF_LEN_64];
        char wan_ip[BUF_LEN_64];
        char wan_ip_type[BUF_LEN_16];
        char route_ip[BUF_LEN_64];
        char route_mac[BUF_LEN_64];
        
        char *mcast_addr;
        unsigned int mcast_port;

        unsigned short policy_type;
        unsigned short switch_on;
        unsigned int wan_status;
        unsigned int time_count;     //10s base
        unsigned int time_interval;  // time interval
        unsigned int local_balance;  // flag for 2g and 5g to banlance


        unsigned short restart_5g_count;
        unsigned short restart_2g_count;
        
        LOACL_WLAN_INFO conn_5g;
        LOACL_WLAN_INFO conn_2g;

        
        time_t uptime;
        int sock_fd_lbalance;
        int sock_fd_ipaddr;
        int sock_fd_ifstatus;
        int sock_fd_cmd;
        int sock_fd_5g;
        int sock_fd_2g;
        int inotify_fd_config;
        int epoll_fd;
};




#define lbalance_debug(fmt, args...)           printf(fmt, ##args)


enum {
        LBALANCE_NOT_MISS = LIBWL_SWITCH_MAX,
        LBALANCE_INFO,
        LBALANCE_ERROR,
        LBALANCE_FILE,
        LBALANCE_INOTIFY_INFO,
        LBALANCE_UCI_INFO,
        LBALANCE_CMD_INFO,
        LBALANCE_CMD_TRACE ,
        LBALANCE_WLAN_INFO,
        LBALANCE_MCAST_RECV,
        LBALANCE_MCAST_SEND,
        LBALANCE_TIMER_INFO,
        LBALANCE_IPADDR_INFO,
        LBALANCE_IFSTAUS_INFO,
        LBALANCE_API_2G,
        LBALANCE_API_5G,
};


#define LBALANCE_DBG_PRINTF  LIBWL_DBG_PRINTF



#define LBALANCE_OPTION_CHECK_RET(did, dargc) \
if (did == (dargc-1))\
{\
        fprintf(stderr, "Error: argument given but no value specified.\n");\
        goto unknown_option;\
}

#define LBALANCE_DBG_2G5G(Dlocal)  ((LBALANCE_WLAN_TYPE_5G == Dlocal->st_node.wlan_type) ? LBALANCE_API_5G : LBALANCE_API_2G)


static int lbalance_add_epoll(int epollfd, int sock_fd);
static int lbalance_epoll_socket_create(void);
static void lbalance_epoll_socket_destroy(void);
static void lbalance_connect_compare_action(LOACL_WLAN_INFO  *pst_local);
static int lbalance_try_create_mcast(void);
static void lbalance_send_mcast_msg(int sock_fd, LOACL_WLAN_INFO *pst_local);
static int lbalance_show_config(char *buffer, int buff_size);
static int lbalance_show_connect(char *buffer, int buff_size);
static int lbalance_show_connect_test(char *buffer, int buff_size);
static int lbalance_show_debug_switch(char *buffer, int buff_size);



#endif
