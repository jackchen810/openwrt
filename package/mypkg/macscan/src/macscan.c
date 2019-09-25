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

#include "macscan.h"
//#include   <linux/net.h>

//#include <execinfo.h>

/*
history:

by 2016.1.6:
modify macscan output by josn


by 2016.1.18:
support -d -v
//macscan -d    debug switch
//macscan -v    version

by 2016.1.21:
//macscan -p   ipaddr   support get ip addr by -p

by 2016.1.21:
1.0.3
fix the issue of getting br-lan mac is error

1.0.3


*/




//static char macscan_version[]="1.1.8";




static struct MSCAN_GLOBAL_CONFIG g_config =
{
        .version[0] = 0,
        .buildtime[0] = 0,
        .wan_name[0] = 0,
        .route_mac[0] = 0,
        .route_ip[0] = 0,
        .channelpath[0] = 0,

        .uloop_fd_5g.fd = -1,
        .uloop_fd_5g.cb = mscan_netlink_handler,
        .restart_5g_count = 0,
        
        .uloop_fd_2g.fd = -1,
        .uloop_fd_2g.cb = mscan_netlink_handler,
        .restart_2g_count = 0,

        .uloop_fd_cmd.fd = -1,
        .uloop_fd_cmd.cb = mscan_cmd_socket_handle,
};



#if FUNCTION_DESC("syslog function")

static char mscan_flowlog[LOG_BUFFER_LEN + 512] = {0};
static unsigned int mscan_flowlog_len = 0;
static unsigned int mscan_head_len = 0;

static inline int mscan_syslog_init()
{
        setlogmask(LOG_UPTO(LOG_NOTICE));// set log level >= mask, default mask = LOG_NOTICE
        openlog("kt-macscan", LOG_CONS, LOG_LOCAL0); //use facility, default LOG_LOCAL0

        mscan_head_len = snprintf(mscan_flowlog, LOG_BUFFER_LEN, "hiwifi_ac#011{\"d\":[");
        mscan_flowlog_len = mscan_head_len;
        return 0;
}

static inline int mscan_syslog(const char *var)
{
        syslog(LOG_LOCAL0|LOG_NOTICE, "%s", var);
        return 0;
}

static inline int mscan_syslog_close()
{
        closelog();
        return 0;
}

#endif




#if FUNCTION_DESC("command function")

static struct LIBWL_CMD_LIST_ST  g_function_list[] = 
{
        {"config", mscan_show_config},
        {"debug", mscan_show_debug_switch},
};


/**
 *@Description: the callback function of uloop
 *@Input: u: the file description of uloop
 *@Input: ev: the event of uloop
 *@Return: void
 *@author: chenzejun 20160323
 */
static void mscan_cmd_socket_handle(struct uloop_fd *u, unsigned int ev)
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
static int mscan_cmd_init(void)
{
 
        /* command service*/
        g_config.uloop_fd_cmd.fd = libwl_cmd_service_create("mscan");
        if (g_config.uloop_fd_cmd.fd > 0)
        {
                uloop_fd_add(&g_config.uloop_fd_cmd,  ULOOP_WRITE | ULOOP_READ | ULOOP_EDGE_TRIGGER);
                MSCAN_DBG_PRINTF(MSCAN_INFO, "macscan add cmd fd:%d\n", g_config.uloop_fd_cmd.fd );  

        }
        
        return 0;
}



/**
 *@Description: mscan command destroy
 *@Input: void: void
 *@Return: 0: ok;   -1: fail
 *@author: chenzejun 20160323
 */
static int mscan_cmd_destroy(void)
{
        return libwl_cmd_service_destroy();
}

#endif



#if FUNCTION_DESC("list api function")

static ALIST_HEAD connect_info =
{
        .cfg_num = 256,
        .node_count = 0,
        .tail_id = INVALID_ID,
};

static ALIST_HEAD scan_info =
{
        .cfg_num = 256,
        .node_count = 0,
        .tail_id = INVALID_ID,
};

/*
*@Description: add node to connect info
*@Input: pst_connect: pointer to scan info node
*@Return: 0: ok;   -1: fail
*@author: chenzejun 20160123
*/
static int mscan_connect_add(STA_CONN_NODE_INFO  *pst_connect)
{
        return libwl_alist_add(&connect_info, pst_connect->ac_mac, MAC_LEN_6, pst_connect, sizeof(STA_CONN_NODE_INFO));
}
/*
*@Description: delet node by key
*@Input:pc_key: pointer to macaddr
*@return: find id
*@author: chenzejun 20160123
*/
static int mscan_connect_del(unsigned char  ac_key[])
{
        return libwl_alist_del(&connect_info, (void *)ac_key, MAC_LEN_6);
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
static int mscan_connect_replace_oldest(STA_CONN_NODE_INFO  *pst_add, STA_CONN_NODE_INFO  *pst_del)
{
        return libwl_alist_replace(&connect_info, pst_del, pst_add);
}



/*
*@Description: add node to scan info
*@Input: pc_key: pointer to scan info node
*@Return: 0: ok;   -1: fail
*@author: chenzejun 20160123
*/
static int mscan_scan_add(STA_SCAN_NODE_INFO  *pst_scan)
{
         return libwl_alist_add(&scan_info, pst_scan->ac_mac, MAC_LEN_6, pst_scan, sizeof(STA_SCAN_NODE_INFO));
}




/**
*@Description: mac scan function init
*@Input: void: void
*@return: 0 ok;  1- fail
*@author: chenzejun 20160123
*/
static int mscan_info_init(void)
{
        /* init connect information */
        connect_info.node_count = 0;
        connect_info.tail_id = INVALID_ID;

        /* init scan information */
        scan_info.node_count = 0;
        scan_info.tail_id = INVALID_ID;
   

        //connect info
        connect_info.pst_node =  malloc(connect_info.cfg_num * sizeof(STA_CONN_NODE_INFO));
        if (NULL == connect_info.pst_node)
        {
                MSCAN_DBG_PRINTF(MSCAN_ERROR, "malloc connect_info failed\n");
                return -1;
        }
        
        memset(connect_info.pst_node, 0, connect_info.cfg_num * sizeof(STA_CONN_NODE_INFO));

        //scan info
        scan_info.pst_node =  malloc(scan_info.cfg_num * sizeof(STA_SCAN_NODE_INFO));
        if (NULL == scan_info.pst_node)
        {
                MSCAN_DBG_PRINTF(MSCAN_ERROR, "malloc scan_info failed\n");
                return -1;
        }
        
        memset(scan_info.pst_node, 0, scan_info.cfg_num * sizeof(STA_SCAN_NODE_INFO));


        printf("macscn startup, cfg_num:%d, %d\n",  connect_info.cfg_num, scan_info.cfg_num);


        return 0;
}


/**
*@Description: mac scan function destroy
*@Input: void: void
*@return: 0 ok;  1- fail
*@author: chenzejun 20160123
*/
static int mscan_info_destroy(void)
{
        if (connect_info.pst_node)  free(connect_info.pst_node);
        connect_info.pst_node = NULL;
        
        if (scan_info.pst_node)  free(scan_info.pst_node);
        scan_info.pst_node = NULL;
        
        return 0;
}



#endif





#if FUNCTION_DESC("msg function")


/*
*@Description: parse connect data
*@Input: pc_msg_data: pointer to the msg
*@Input: ui_msg_len: msglen
*@Return: 0: ok;   -1: fail
*@author: chenzejun 20160123
*/
static int mscan_parse_conn_data(int fd, char *pc_msg_data, unsigned int ui_msg_len)
{

        AP_TLV_DATA *pst_tlv_data = (AP_TLV_DATA *)pc_msg_data;
        STA_CONN_NODE_INFO  st_connect;
        STA_CONN_NODE_INFO  st_connect_del;
        unsigned  char    uc_type_wifi = 0xff;
        unsigned short find_flag = 0;
        unsigned int ui_temp_len = 0;
        char ac_mac_str[BUF_LEN_64];
        int i_ret = 0;

        if (pc_msg_data == NULL)
        {
                return -1;
        }

        //if (mscan_debug > 0)  printf("[in] mscan add connect data, ui_msg_len: %d \n", ui_msg_len); 

        memset(&st_connect, 0, sizeof(st_connect));
        
        while(ui_temp_len < ui_msg_len && pst_tlv_data->us_tlv_len)
        {
                //printf("APP  Received ui_msg_len: %d, %d \n", ui_msg_len, pst_tlv_data->us_tlv_type); 

                if (pst_tlv_data->us_tlv_type >= AP_TLV_TYPE_MAX)
                {
                        MSCAN_DBG_PRINTF(MSCAN_INFO, "break ui_msg_len: %d, %d \n", ui_msg_len, pst_tlv_data->us_tlv_type); 
                        break;
                }
                
                switch (pst_tlv_data->us_tlv_type)
                {
                        case AP_TLV_TYPE_MAC:
                        {
                                find_flag = 1;
                                memcpy(st_connect.ac_mac, (unsigned char *)(pst_tlv_data+1), 6);
                                break;
                        }
                        case AP_TLV_TYPE_WIFI_TYPE:
                        {
                                break;
                        }
                        case AP_TLV_TYPE_TX_POWER:
                        {
                                st_connect.uc_signal = *(unsigned char *)(pst_tlv_data+1);
                                break;
                        }
                        case AP_TLV_TYPE_IP:
                        {
                                break;
                        }
                        default:
                        {
                                break;
                        }
                }

                //next tlv
                ui_temp_len = ui_temp_len + pst_tlv_data->us_tlv_len;
                pst_tlv_data =  (AP_TLV_DATA *)((char *)pst_tlv_data + pst_tlv_data->us_tlv_len);
        }
                

        if (1 == find_flag)
        {

                if (fd == g_config.uloop_fd_5g.fd)  snprintf(st_connect.ac_type_wifi_str, sizeof(st_connect.ac_type_wifi_str), "5G");
                if (fd == g_config.uloop_fd_2g.fd)  snprintf(st_connect.ac_type_wifi_str, sizeof(st_connect.ac_type_wifi_str), "2.4G");

                st_connect.us_idle_count = 0;
                i_ret = mscan_connect_add(&st_connect);
                if (TABLE_FULL == i_ret)
                {
                        mscan_connect_replace_oldest(&st_connect, &st_connect_del);
                }
        }

        MSCAN_DBG_PRINTF(MSCAN_CONN_INFO, "[out] add connect data; count:%d, len:%d; flag:%d; %d, type_wifi:%s, mac:%02X%02X%02X%02X%02X%02X \n", 
                libwl_get_alist_count(&connect_info), ui_temp_len, find_flag, uc_type_wifi, st_connect.ac_type_wifi_str,
                st_connect.ac_mac[0], st_connect.ac_mac[1], st_connect.ac_mac[2], st_connect.ac_mac[3], st_connect.ac_mac[4], st_connect.ac_mac[5]);

        return 0;
}

/*
*@Description: parse connect del data
*@Input: pc_msg_data: pointer to the msg
*@Input: ui_msg_len: msglen
*@Return: 0: ok;   -1: fail
*@author: chenzejun 20160123
*/
static int mscan_parse_del_data(char *pc_msg_data, unsigned int ui_msg_len)
{
        AP_TLV_DATA *pst_tlv_data = (AP_TLV_DATA *)pc_msg_data;
        unsigned char  *pc_mac_addr = NULL; 
        unsigned int ui_temp_len = 0;
        unsigned short used_id;

        if (pc_msg_data == NULL)
        {
                return -1;
        }


        //if (mscan_debug > 0)  printf("[in] mscan delete connect data, ui_msg_len: %d \n", ui_msg_len); 
        
        while(ui_temp_len < ui_msg_len && pst_tlv_data->us_tlv_len)
        {
                //printf("APP  Received ui_msg_len: %d, %d \n", ui_msg_len, pst_tlv_data->us_tlv_type); 

                if (pst_tlv_data->us_tlv_type >= AP_TLV_TYPE_MAX)
                {
                        MSCAN_DBG_PRINTF(MSCAN_DBG, "break ui_msg_len: %d, %d \n", ui_msg_len, pst_tlv_data->us_tlv_type); 
                        break;
                }

                if (AP_TLV_TYPE_MAC == pst_tlv_data->us_tlv_type)
                {
                        pc_mac_addr = (unsigned char *)(pst_tlv_data+1);
                        mscan_connect_del(pc_mac_addr);
                        break;
                }

                //next tlv
                ui_temp_len = ui_temp_len + pst_tlv_data->us_tlv_len;
                pst_tlv_data =  (AP_TLV_DATA *)((char *)pst_tlv_data + pst_tlv_data->us_tlv_len);
        }


        MSCAN_DBG_PRINTF(MSCAN_CONN_INFO, "[out] del connect data; count:%d, len:%d; mac:%02X%02X%02X%02X%02X%02X \n", 
                libwl_get_alist_count(&connect_info), ui_temp_len,
                pc_mac_addr[0], pc_mac_addr[1], pc_mac_addr[2], pc_mac_addr[3], pc_mac_addr[4], pc_mac_addr[5]);
        return 0;
}

/*
*@Description: parse scan data
*@Input: pc_msg_data: pointer to the msg
*@Input: ui_msg_len: msglen
*@Return: 0: ok;   -1: fail
*@author: chenzejun 20160123
*/
static int mscan_parse_scan_data(char *pc_msg_data, unsigned int ui_msg_len)
{

        AP_TLV_DATA *pst_tlv_data = (AP_TLV_DATA *)pc_msg_data;
        STA_SCAN_NODE_INFO  st_scan;
        unsigned  char    uc_type_wifi;
        unsigned int ui_temp_len = 0;
        unsigned short find_flag = 0;

        if (pc_msg_data == NULL)
        {
                return -1;
        }

        //if (mscan_debug > 0)  printf("[in] mscan add scan data,  ui_msg_len: %d \n", ui_msg_len); 
        
        while(ui_temp_len < ui_msg_len && pst_tlv_data->us_tlv_len)
        {
                //printf("APP  Received ui_msg_len: %d, %d \n", ui_msg_len, pst_tlv_data->us_tlv_type); 

                if (pst_tlv_data->us_tlv_type >= AP_TLV_TYPE_MAX)
                {
                        MSCAN_DBG_PRINTF(MSCAN_DBG, "break ui_msg_len: %d, %d \n", ui_msg_len, pst_tlv_data->us_tlv_type); 
                        break;
                }
                
                switch (pst_tlv_data->us_tlv_type)
                {
                        case AP_TLV_TYPE_MAC:
                        {
                                memcpy(st_scan.ac_mac, (unsigned char *)(pst_tlv_data+1), 6);
                                find_flag = 1;
                                break;
                        }
                        case AP_TLV_TYPE_RSSI:
                        {
                                st_scan.c_rssi = *((signed char *)(pst_tlv_data+1));  
                                break;
                        }
                        default:
                        {
                                break;
                        }
                }

                //next tlv
                ui_temp_len = ui_temp_len + pst_tlv_data->us_tlv_len;
                pst_tlv_data =  (AP_TLV_DATA *)((char *)pst_tlv_data + pst_tlv_data->us_tlv_len);
        }
                

        if (1 == find_flag)
        {
                mscan_scan_add(&st_scan);
        }


        MSCAN_DBG_PRINTF(MSCAN_SCAN_INFO, "[out] add scan data; count:%d, len:%d; flag:%d; mac:%02X%02X%02X%02X%02X%02X; rssi:%d\n", 
                libwl_get_alist_count(&scan_info), ui_temp_len, find_flag,
                st_scan.ac_mac[0], st_scan.ac_mac[1], st_scan.ac_mac[2], st_scan.ac_mac[3], st_scan.ac_mac[4], st_scan.ac_mac[5],
                st_scan.c_rssi); 

        return 0;
}


/**
*@Description: age the node
*@Input:over_num: the time
*@return: void
*@author: chenzejun 20160123
if the mac is being hit by query, then clear us_idle_count.
*/
static void mscan_connect_data_age(ushort over_num)
{
        ALIST_HEAD *p_info = &connect_info;
        STA_CONN_NODE_INFO  *pst_connect = NULL;
        int i = 0;

        //connect data for age
        libwl_alist_for_entry(pst_connect, i,  p_info) 
        {
                if (pst_connect == NULL)  break;
        
                pst_connect->us_idle_count++;   //entry count

                //age
                if (pst_connect->us_idle_count > over_num)
                {
                        MSCAN_DBG_PRINTF(MSCAN_CONN_INFO, "[age] connect data; idle_count:%d; i:%d, %d, mac:%02X %02X %02X %02X %02X %02X \n",
                                pst_connect->us_idle_count, i, p_info->tail_id,
                                pst_connect->ac_mac[0], pst_connect->ac_mac[1], pst_connect->ac_mac[2], 
                                pst_connect->ac_mac[3], pst_connect->ac_mac[4], pst_connect->ac_mac[5]); 

                                
                        mscan_connect_del(pst_connect->ac_mac);
                }                
        }

        return;
}

#endif




#if FUNCTION_DESC("epoll and socket function")

static struct nlmsghdr *nl_header = NULL;  



/**
*@Description: send msg to kernel
*@Input: epollfd: epoll fd
*@Input: sock_fd: socket fd
*@Return:  0: ok
           <0: fail
*@author: chenzejun 20160323
*/
int mscan_sendmsg_2_kernel(int sock_fd)
{
        struct sockaddr_nl dest_addr;  
        struct iovec iov;  
        struct nlmsghdr *nlh = nl_header;
        struct msghdr msg;  
        int state_smg = 0; 


        memset(&dest_addr,0,sizeof(dest_addr));  
        dest_addr.nl_family = AF_NETLINK;  
        dest_addr.nl_pid = 0; //kernal 
        dest_addr.nl_groups = 0;  

       
        //msg header
        memset(&msg, 0, sizeof(msg));  
         
        msg.msg_name = (void *)&dest_addr;  
        msg.msg_namelen = sizeof(dest_addr);  
        msg.msg_iov = &iov;  
        msg.msg_iov->iov_base =  (void *)nlh;  
        msg.msg_iov->iov_len =  NLMSG_SPACE(MAX_PAYLOAD);  
        msg.msg_iovlen = 1;  

        //nl header
        memset(nlh, 0, NLMSG_SPACE(MAX_PAYLOAD));  
        
        nlh->nlmsg_len = NLMSG_SPACE(MAX_PAYLOAD);  
        nlh->nlmsg_pid = AP_NLMSG_PID_MACSCAN;  
        nlh->nlmsg_flags = 0;  
        nlh->nlmsg_type = 0;
        strcpy(NLMSG_DATA(nlh), "macscan");  


        state_smg = sendmsg(sock_fd, &msg, 0);  
        if(state_smg == -1)
        {  
                MSCAN_DBG_PRINTF(MSCAN_ERROR, "sock_fd get error sendmsg = %s\n", strerror(errno));
                return -1;    
        }  

        return 0;
}




/**
*@Description: the callback function of netlink
*@Input: u: the file description of uloop
*@Input: ev: the event of uloop
*@Return: void
*@author: chenzejun 20160323
*/
static void mscan_netlink_handler(struct uloop_fd *u, unsigned int ev)
{
        int retval;  
        struct iovec iov;  
        struct msghdr msg;
        struct epoll_event events[MAXEPOLLSIZE];  


        //msg
        memset(&msg, 0, sizeof(msg));  
        msg.msg_iov = &iov;  
        msg.msg_iov->iov_base =  (void *)nl_header;  
        msg.msg_iov->iov_len =  NLMSG_SPACE(MAX_PAYLOAD);  
        msg.msg_iovlen = 1;  

        while(1)  
        {
                retval = recvmsg(u->fd, &msg, MSG_DONTWAIT);  
                if(retval < 0)
                {
                        if(errno != EAGAIN)  
                        {
                                MSCAN_DBG_PRINTF(MSCAN_INFO, "recvmsg end fd:%d, errno:%d, ret:%d\n", u->fd, errno, retval); 
                        }

                        break;
                }

                MSCAN_DBG_PRINTF(MSCAN_INFO, "[in] mscan recv data, fd:%d, msg_type:%d, ui_msg_len: %d \n", u->fd, nl_header->nlmsg_type, (nl_header->nlmsg_len - NLMSG_HDRLEN)); 

                
                //parse data
                if (AP_MSG_TYPE_CONNECT == nl_header->nlmsg_type)
                {
                        MSCAN_DBG_PRINTF(MSCAN_CONN_INFO, "[in] receive connect data, fd:%d, msgtype:%d, len:%d \n", u->fd, nl_header->nlmsg_type, (nl_header->nlmsg_len - NLMSG_HDRLEN)); 
                        (void)mscan_parse_conn_data(u->fd, NLMSG_DATA(nl_header), (nl_header->nlmsg_len - NLMSG_HDRLEN));
                }
                else if (AP_MSG_TYPE_SCAN == nl_header->nlmsg_type)
                {
                        MSCAN_DBG_PRINTF(MSCAN_SCAN_INFO, "[in] receive scan data, fd:%d, msgtype:%d, len:%d \n", u->fd, nl_header->nlmsg_type, (nl_header->nlmsg_len - NLMSG_HDRLEN)); 
                        (void)mscan_parse_scan_data(NLMSG_DATA(nl_header), (nl_header->nlmsg_len - NLMSG_HDRLEN));
                }
                else if (AP_MSG_TYPE_CONN_DEL == nl_header->nlmsg_type)
                {
                        MSCAN_DBG_PRINTF(MSCAN_CONN_INFO, "[in] receive connect data, msgtype:%d, len:%d \n", nl_header->nlmsg_type, (nl_header->nlmsg_len - NLMSG_HDRLEN)); 
                        (void)mscan_parse_del_data(NLMSG_DATA(nl_header), (nl_header->nlmsg_len - NLMSG_HDRLEN));
                }
        }
        
        return;

}


/**
*@Description: try to start socket of 5g
*@Input: void: void
*@Return: void
*@author: chenzejun 20160323
*/
static void mscan_try_netlink_5g(void)
{
         // try to start 5g, Create a socket ,  if count > 8,  the dev hasn't 5g, don't start it.
        if (g_config.restart_5g_count < NETLINK_RESTART_MAX && g_config.uloop_fd_5g.fd <= 0)
        {
                g_config.uloop_fd_5g.fd = libwl_create_netlink_socket(NETLINK_5G);
                if(g_config.uloop_fd_5g.fd > 0)
                {
                        MSCAN_DBG_PRINTF(MSCAN_INFO, "macscan add  5G fd:%d\n", g_config.uloop_fd_5g.fd);  
                        
                        // epoll add
                        (void)mscan_sendmsg_2_kernel(g_config.uloop_fd_5g.fd);  
                        	uloop_fd_add(&g_config.uloop_fd_5g, ULOOP_READ | ULOOP_EDGE_TRIGGER);
                }               
                else
                {  
                        g_config.restart_5g_count++;
                } 
        }

        return;
}



/**
*@Description: try to start socket of 2.4g
*@Input: void: void
*@Return: void
*@author: chenzejun 20160323
*/
static void mscan_try_netlink_24g(void)
{
         // try to start 2.4g, Create a socket ,  if count > 8,  the dev hasn't 2.4g, don't start it.
        if (g_config.restart_2g_count < NETLINK_RESTART_MAX && g_config.uloop_fd_2g.fd <= 0)
        {
                g_config.uloop_fd_2g.fd = libwl_create_netlink_socket(NETLINK_24G);
                if(g_config.uloop_fd_2g.fd > 0)
                {
                        MSCAN_DBG_PRINTF(MSCAN_INFO, "macscan add 2.4G fd:%d\n", g_config.uloop_fd_2g.fd );  

                        // epoll add
                        (void)mscan_sendmsg_2_kernel(g_config.uloop_fd_2g.fd); 
                        	uloop_fd_add(&g_config.uloop_fd_2g, ULOOP_READ | ULOOP_EDGE_TRIGGER);
                }               
                else
                {  
                        g_config.restart_2g_count++;
                } 
        }

        return;
}




/**
*@Description: try to close socket of 5g 2.4g
*@Input: void: void
*@Return: void
*@author: chenzejun 20160323
*/
static void mscan_try_close_netlink(void)
{
         // try to close 5g socket
        if (g_config.uloop_fd_5g.fd > 0)
        {
                uloop_fd_delete(&g_config.uloop_fd_5g);
                close(g_config.uloop_fd_5g.fd);
                g_config.uloop_fd_5g.fd = -1;
        }

        
        if (g_config.uloop_fd_2g.fd > 0)
        {
                uloop_fd_delete(&g_config.uloop_fd_2g);
                close(g_config.uloop_fd_2g.fd);
                g_config.uloop_fd_2g.fd = -1;
        }
        

        return;
}



/**
*@Description: mac scan function init
*@Input: void: void
*@return: 0 ok;  1- fail
*@author: chenzejun 20160123
*/
static int mscan_netlink_init(void)
{

        // To prepare recvmsg  
        nl_header = (struct nlmsghdr *)malloc(NLMSG_SPACE(MAX_PAYLOAD));  
        if(!nl_header)
        {  
                MSCAN_DBG_PRINTF(MSCAN_ERROR, "malloc nl_header failed\n");
                return -1;
        } 

        /* Create a socket 2.4G and 5G */
        mscan_try_netlink_24g();
        mscan_try_netlink_5g();

        return 0;

}

/**
*@Description: mac scan function destroy
*@Input: void: void
*@return: 0 ok;  1- fail
*@author: chenzejun 20160123
*/
static int mscan_netlink_destroy(void)
{
        
        if (nl_header)  free(nl_header);
        nl_header = NULL;

        mscan_try_close_netlink();
        
        return 0;
}

#endif





#if FUNCTION_DESC("timer function")

static struct uloop_timeout mscan_10s_timer = 
{
        .cb = mscan_uloop_10s_timer,
};


/**
*@Description: send conect log information
*@Input: void: pointer to void
*@Return:  0: ok
           <0: fail
*@author: chenzejun 20160711
*/
static void mscan_send_connect_log(int timeout)
{
        STA_CONN_NODE_INFO  *pst_connect = NULL;
        int i = 0;
        unsigned int resv_len = 0;
        static int time_count = 5;
        
        // send connect msg, 60s
        time_count++;
        if (time_count < timeout)
        {
                return;
        }
        
        time_count = 0;

        MSCAN_DBG_PRINTF(MSCAN_DBG, " connect send data....   %d, tail_id:%d \n", mscan_flowlog_len, connect_info.tail_id); 
        mscan_flowlog_len = mscan_head_len + 1;
        
        //scan connect info, send msg to service
        libwl_alist_for_entry(pst_connect, i,  &connect_info) 
        {
                if (pst_connect == NULL)  break;

                resv_len = LOG_BUFFER_LEN - mscan_flowlog_len;
                if (resv_len < 150)   //剩余长度不足
                {
                        break;
                }
                
                mscan_flowlog_len += snprintf(&mscan_flowlog[mscan_flowlog_len-1], resv_len, "{\"mac\":\"%02X%02X%02X%02X%02X%02X\",\"type\":\"wifi\",\"name\":\"\",\"rpt\":\"\",\"type_wifi\":\"%s\",\"signal\":\"%d\",\"ip\":\"\"},", 
                        pst_connect->ac_mac[0], pst_connect->ac_mac[1], pst_connect->ac_mac[2], pst_connect->ac_mac[3], pst_connect->ac_mac[4], pst_connect->ac_mac[5],
                        pst_connect->ac_type_wifi_str,
                        pst_connect->uc_signal);              
        }

        mscan_flowlog_len += snprintf(&mscan_flowlog[mscan_flowlog_len-2], 512, "],\"s\":\"conn\",\"v\":\"%c\"} \"127.0.0.1\" \"%s\"", g_config.version[0], g_config.route_mac);
        
        MSCAN_DBG_PRINTF(MSCAN_INFO, "connet message: %s \n", mscan_flowlog); 
        mscan_syslog(mscan_flowlog);



        return;
}

/**
*@Description: send scan log information
*@Input: void: pointer to void
*@Return:  0: ok
           <0: fail
*@author: chenzejun 20160711
*/
static void mscan_send_scan_log(int timeout)
{
        STA_SCAN_NODE_INFO  *pst_scan = NULL;
        int i = 0;
        unsigned int resv_len = 0;
        static int time_count = 5;
        
        // send scan msg, 60s
        time_count++;
        if (time_count < timeout)
        {
                return;
        }
        time_count = 0;

        
        //MSCAN_DBG_PRINTF(MSCAN_DBG, "scan send data....  %d, tail_id:%d \n", mscan_flowlog_len, scan_info.tail_id); 
        mscan_flowlog_len = mscan_head_len + 1;
        
        //scan scan info, send msg to service
        libwl_alist_for_entry(pst_scan, i,  &scan_info) 
        {
                if (pst_scan == NULL)  break;
                
                resv_len = LOG_BUFFER_LEN - mscan_flowlog_len;
                if (resv_len < 100)   //left length is too short
                {
                        break;
                }
                
                mscan_flowlog_len += snprintf(&mscan_flowlog[mscan_flowlog_len-1], resv_len, "{\"rssi\":\"%d\",\"macaddr\":\"%02X%02X%02X%02X%02X%02X\"},", 
                        pst_scan->c_rssi,
                        pst_scan->ac_mac[0], pst_scan->ac_mac[1], pst_scan->ac_mac[2], pst_scan->ac_mac[3], pst_scan->ac_mac[4], pst_scan->ac_mac[5]);              
        }

        mscan_flowlog_len += snprintf(&mscan_flowlog[mscan_flowlog_len-2], 512, "],\"s\":\"scan\",\"v\":\"%c\"} \"127.0.0.1\" \"%s\"", g_config.version[0], g_config.route_mac);
        
        MSCAN_DBG_PRINTF(MSCAN_INFO, "scan message: %s \n", mscan_flowlog); 
        mscan_syslog(mscan_flowlog);

        //scan info restart
        libwl_alist_clear_all(&scan_info);
   
        return;
}



/**
*@Description: timer function
*@Input: timeout: timeout
*@Return: 0: ok;   -1: fail
*@author: chenzejun 20160323
*/
static void mscan_uloop_10s_timer(struct uloop_timeout *timeout)
{
        MSCAN_DBG_PRINTF(MSCAN_TIMER, "[in] uloop 10s timer.... \n"); 

        uloop_timeout_set(timeout, 10000);

         // try to start 5g, 2.4g
        mscan_try_netlink_5g();
        mscan_try_netlink_24g();


        //connect data for age
        mscan_connect_data_age(0xfff0);


        // send connect msg
        mscan_send_connect_log(6);

        // send scan msg
        mscan_send_scan_log(6);


        MSCAN_DBG_PRINTF(MSCAN_TIMER, "[out] uloop 10s timer.... \n"); 

        return;
}




/**
*@Description: timer function
*@Input: sig: signal no
*@Return: 0: ok;   -1: fail
*@author: chenzejun 20160323
*/
static void mscan_timer_proc(int sig)
{

        MSCAN_DBG_PRINTF(MSCAN_TIMER, "[in] timer.... \n"); 

        //signal(SIGALRM, mscan_age_data);
        alarm(10);


         // try to start 5g, 2.4g
        mscan_try_netlink_5g();
        mscan_try_netlink_24g();

        //connect data for age
        mscan_connect_data_age(0xfff0);


        // send connect msg
        mscan_send_connect_log(6);
        
        // send scan msg
        mscan_send_scan_log(6);


        MSCAN_DBG_PRINTF(MSCAN_TIMER, "[out] timer.... \n"); 

        return;
}


/**
*@Description: timer function
*@Input: signo: signal no
*@Return: 0: ok;   -1: fail
*@author: chenzejun 20160323
*/
void mscan_sigroutine(int signo)
{
        static int t_count = 0;
        
        if (signo != SIGALRM)
        {
                return;
        }

        signal(SIGALRM, mscan_sigroutine);
        return;
}

/**
*@Description: create timer
*@Input: void: void
*@Return: 0: ok;   -1: fail
*@author: chenzejun 20160323
*/
static int mscan_timer_create(void)
{
        struct itimerval value, ovalue;          //(1)
        MSCAN_DBG_PRINTF(MSCAN_TIMER, "create timer, process id is %d \n", getpid());
        
        signal(SIGALRM, mscan_sigroutine);

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
static void mscan_signal_handle(int signo)
{
        if (signo == SIGUSR1)
        {
                MSCAN_DBG_PRINTF(MSCAN_TIMER, "signal handle, signo is SIGUSR1\n");
                g_config.restart_5g_count = 0;
                g_config.restart_2g_count = 0;
        }
        else if (signo == SIGUSR2)
        {
                MSCAN_DBG_PRINTF(MSCAN_TIMER, "signal handle, signo is SIGUSR2\n");
                g_config.restart_5g_count = NETLINK_RESTART_MAX;
                g_config.restart_2g_count = NETLINK_RESTART_MAX;
                mscan_try_close_netlink();
        }

        return;
}



/**
*@Description: signal setup
*@Input: void: void
*@return: 0 ok;  1- fail
*@author: chenzejun 20160123
*/
static void mscan_signal_setup(void)
{
        signal(SIGUSR1, mscan_signal_handle);
        signal(SIGUSR2, mscan_signal_handle);

        //start timer
        //signal(SIGALRM, mscan_timer_proc);
        //alarm(10);   //10s  signal
        return;
}



#endif


#if FUNCTION_DESC("option function")

static char g_lock_file[] = "/var/lock/mscan.lock";


/**
 *@Description: show mac scan config
 *@Input: void
 *@Return: 0: ok;   -1: fail
 *@author: chenzejun 20160323
 */
static int mscan_show_config(char *buffer, int buff_size)
{
        int  buf_len = 0;  

        if (buffer == NULL)    return 0;
        
        buf_len += snprintf(&buffer[buf_len], (buff_size - buf_len), "%-30s: %s\n", "version", g_config.version);
        buf_len += snprintf(&buffer[buf_len], (buff_size - buf_len), "%-30s: %s\n", "route_mac", g_config.route_mac);
        buf_len += snprintf(&buffer[buf_len], (buff_size - buf_len), "%-30s: %d\n", "connect.cfg_num", connect_info.cfg_num);
        buf_len += snprintf(&buffer[buf_len], (buff_size - buf_len), "%-30s: %d\n", "scan.cfg_num", scan_info.cfg_num);
        buf_len += snprintf(&buffer[buf_len], (buff_size - buf_len), "%-30s: %d\n", "connect.node_count",  connect_info.node_count);
        buf_len += snprintf(&buffer[buf_len], (buff_size - buf_len), "%-30s: %d\n", "scan.node_count", scan_info.node_count);
        buf_len += snprintf(&buffer[buf_len], (buff_size - buf_len), "%-30s: %d\n", "connect.tail_id", connect_info.tail_id);

        buf_len += snprintf(&buffer[buf_len], (buff_size - buf_len), "%-30s: %d\n", "uloop_fd_2g.fd", g_config.uloop_fd_2g.fd);
        buf_len += snprintf(&buffer[buf_len], (buff_size - buf_len), "%-30s: %d\n", "uloop_fd_5g.fd", g_config.uloop_fd_5g.fd);
        buf_len += snprintf(&buffer[buf_len], (buff_size - buf_len), "%-30s: %d\n", "restart_2g_count", g_config.restart_2g_count);
        buf_len += snprintf(&buffer[buf_len], (buff_size - buf_len), "%-30s: %d\n", "restart_5g_count", g_config.restart_5g_count);

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
static int mscan_show_debug_switch(char *buffer, int buff_size)
{
        int  buf_len = 0;  

        if (buffer == NULL)    return 0;

        buf_len += snprintf(&buffer[buf_len], (buff_size - buf_len), "%-30s: %d\n", MACROSTR_VALUE(LIBWL_INFO));
        buf_len += snprintf(&buffer[buf_len], (buff_size - buf_len), "%-30s: %d\n", MACROSTR_VALUE(LIBWL_ERROR));
        buf_len += snprintf(&buffer[buf_len], (buff_size - buf_len), "%-30s: %d\n", MACROSTR_VALUE(LIBWL_LOG_TRACE));
        buf_len += snprintf(&buffer[buf_len], (buff_size - buf_len), "%-30s: %d\n", MACROSTR_VALUE(LIBWL_CMD_TRACE));
        buf_len += snprintf(&buffer[buf_len], (buff_size - buf_len), "%-30s: %d\n", MACROSTR_VALUE(LIBWL_API_TRACE));
        buf_len += snprintf(&buffer[buf_len], (buff_size - buf_len), "%-30s: %d\n", MACROSTR_VALUE(MSCAN_INFO));
        buf_len += snprintf(&buffer[buf_len], (buff_size - buf_len), "%-30s: %d\n", MACROSTR_VALUE(MSCAN_ERROR));
        buf_len += snprintf(&buffer[buf_len], (buff_size - buf_len), "%-30s: %d\n", MACROSTR_VALUE(MSCAN_DBG));
        buf_len += snprintf(&buffer[buf_len], (buff_size - buf_len), "%-30s: %d\n", MACROSTR_VALUE(MSCAN_TIMER));
        buf_len += snprintf(&buffer[buf_len], (buff_size - buf_len), "%-30s: %d\n", MACROSTR_VALUE(MSCAN_SCAN_INFO));
        buf_len += snprintf(&buffer[buf_len], (buff_size - buf_len), "%-30s: %d\n", MACROSTR_VALUE(MSCAN_CONN_INFO));
        buf_len += snprintf(&buffer[buf_len], (buff_size - buf_len), "%-30s: %d\n", MACROSTR_VALUE(MSCAN_MQTT_CALLBACK_LOG));
        buf_len += snprintf(&buffer[buf_len], (buff_size - buf_len), "%-30s: %d\n", MACROSTR_VALUE(MSCAN_UBUS_INFO));
        buf_len += snprintf(&buffer[buf_len], (buff_size - buf_len), "%-30s: %d\n", MACROSTR_VALUE(MSCAN_UCI_INFO));
        buf_len += snprintf(&buffer[buf_len], (buff_size - buf_len), "%-30s: %d\n", MACROSTR_VALUE(MSCAN_CMD_INFO));
        buf_len += snprintf(&buffer[buf_len], (buff_size - buf_len), "%-30s: %d\n", MACROSTR_VALUE(MSCAN_CMD_TRACE));

        // buf_len is string length, buf_len++ will include \0 char to send.
        return ++buf_len;
}


/**
*@Description: get the information of router by wan
*@Input: void: void
*@return: 0 ok;  1- fail
*@author: chenzejun 20160123
*/
void mscan_get_wan_info()
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
*@Description: send mascan test log
*@Input:pkg_count: the count of pkg
*@return: 0 ok;  1- fail
*@author: chenzejun 20160123
*/
static void mscan_send_scan_log_test(unsigned int pkg_count)
{
        STA_SCAN_NODE_INFO  *pst_scan = NULL;
        unsigned int i = 0;
        unsigned int resv_len = 0;

        if (pkg_count > 20 || pkg_count == 0)
        {
                return;
        }


        mscan_flowlog_len = mscan_head_len + 1;

        //scan scan info, send msg to service
        for(i = 0; i < pkg_count; i++) 
        {
                resv_len = LOG_BUFFER_LEN - mscan_flowlog_len;
                if (resv_len < 100)   //if resverse len too short, then break
                {
                        break;
                }
                
                mscan_flowlog_len += snprintf(&mscan_flowlog[mscan_flowlog_len-1], resv_len, "{\"rssi\":\"%d\",\"macaddr\":\"%02X%02X%02X%02X%02X%02X\"},", 
                        100,
                        0xaa, 0xbb, 0xcc, 0xdd, 0xee, i);              
        }

        mscan_flowlog_len += snprintf(&mscan_flowlog[mscan_flowlog_len-2], 512, "],\"s\":\"scan\",\"v\":\"%c\"} \"127.0.0.1\" \"%s\"", g_config.version[0], g_config.route_mac);
        
        MSCAN_DBG_PRINTF(MSCAN_INFO, "send test message: %s\n", mscan_flowlog); 
        mscan_syslog(mscan_flowlog);

        return;
}

/**
*@Description: print usage
*@Input: void: void
*@return: 0 ok;  1- fail
*@author: chenzejun 20160123
*/
static void mscan_print_usage(void)
{
	printf("macscan version %s (build date %s)\n", g_config.version, g_config.buildtime);
	printf("Usage: macscan [-d] [-l] [-h] [--conn-num num] [--scan-num num]\n");
	printf("               [test]\n");
	printf("       macscan --help\n\n");

	
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
int mscan_option_proc(int argc, char *argv[])
{
        int i;
        int test_count = 0;
        int num;
        int remote_flag = 0;
        int sockfd = -1;

        for (i=1; i<argc; i++)
        {
                
                if (!strncmp(argv[i], "test", 4))
                {
                        test_count = 1;

                        if ((i+1) < argc && argv[i+1])
                        {
                                test_count = atoi(argv[i+1]);
                        }
                        
                        /* macscan test code */
                        mscan_syslog_init();
                        libwl_get_router_hwaddr_short("br-lan", g_config.route_mac, sizeof(g_config.route_mac));
                        mscan_send_scan_log_test(test_count);
                        
                        exit(0);
                }
                else if(!strcmp(argv[i], "-h") || !strcmp(argv[i], "--help"))
                {
                        mscan_print_usage();
                        exit(0);
                }
                else if(!strcmp(argv[i], "-v"))
                {
                        printf("[MAC-SCAN] Welcome to macscan, Revision:%s (build date:%s)\n"
                                "(C) 2004-16 kunteng.org\n",
                                g_config.version, g_config.buildtime);
                        exit(0);
                }
                else if(!strcmp(argv[i], "-d"))
                {
                        MSCAN_OPTION_CHECK_RET(i, argc);
                
                        num = atoi(argv[i+1]);
                        libwl_cmd_output_printf(num);
                        i++;
                }
                else if(!strcmp(argv[i], "-l"))
                {
                        MSCAN_OPTION_CHECK_RET(i, argc);
                        
                        num = atoi(argv[i+1]);
                        libwl_cmd_output_log(num);
                        i++;
                }
                else if(!strcmp(argv[i], "--conn-num"))
                {
                        MSCAN_OPTION_CHECK_RET(i, argc);
                        
                        num = atoi(argv[i+1]);
                        if (num > 100 && num < 5000)      connect_info.cfg_num= num;
                        i++;
                }
                else if(!strcmp(argv[i], "--scan-num"))
                {
                        MSCAN_OPTION_CHECK_RET(i, argc);
                        
                        num = atoi(argv[i+1]);
                        if (num > 100 && num < 5000)      connect_info.cfg_num= num;
                        i++;
                }
                else if(!strcmp(argv[i], "remote-show"))
                {
                        MSCAN_OPTION_CHECK_RET(i, argc);
                        sockfd = libwl_cmd_client_create("mscan");
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
                        MSCAN_OPTION_CHECK_RET(i, argc);
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
        
                sockfd = libwl_cmd_client_create("mscan");
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
static int mscan_init(void)
{
        int i_ret = 0;

        mscan_syslog_init();

        //mscan_get_wan_info();
        libwl_get_router_hwaddr_short("br-lan", g_config.route_mac, sizeof(g_config.route_mac));


        uloop_init();


        i_ret = mscan_info_init();
        if (i_ret != 0)
        {
                return -1;
        }
        
        i_ret = mscan_netlink_init();
        if (i_ret != 0)
        {
                return -1;
        }


        //cmd init
        i_ret = mscan_cmd_init();
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
static int mscan_destroy(void)
{
        mscan_cmd_destroy();
        mscan_netlink_destroy();
        mscan_syslog_close();
        mscan_info_destroy();
        
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
        mscan_option_proc(argc, argv);


        if (!libwl_inst_is_running(g_lock_file))
        {
                printf("Not support multiple instances, exit!\n");
                exit(0);
        }

        //sleep  one rand time, avoid to start at same time.
        srand((int)time(0));
        sleep(rand()%10);

        libwl_printf_currtime();
        mscan_signal_setup();

        // init
        i_ret = mscan_init();
        if (i_ret != 0)
        {
                goto OUT;
        }
        
        uloop_timeout_set(&mscan_10s_timer, 10000);


        //run
        uloop_run();

OUT:

        MSCAN_DBG_PRINTF(MSCAN_INFO, "main exit\n");   
        mscan_destroy();
        return 0;
}


