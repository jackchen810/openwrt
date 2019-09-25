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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <asm/types.h>
//need before netlink.h to avoid "__kernel_sa_family" undefine
#include <sys/socket.h>  
#include <linux/netlink.h>
#include <syslog.h>
//#include "ccan/list/list.h"
#include <time.h>  
#include <signal.h>  
#include <unistd.h>
#include <sched.h>
#include <net/if_arp.h>
#include <netinet/in.h>
#include <linux/sockios.h>
#include <sys/socket.h>    
#include <sys/epoll.h>   
#include <sys/file.h>
#include <sys/ioctl.h>  
#include <sys/un.h>
#include <fcntl.h>   
#include <stdarg.h>
#include <unistd.h>
#include <signal.h>
#include <time.h>
#include<dirent.h>
#include <sys/time.h>
#include <pthread.h>
#include <linux/rtnetlink.h> 
#include <linux/if.h>
#include <sys/stat.h>  
#include <sys/types.h>
#include <sys/wait.h>
#include <linux/netlink.h>
//#include   <linux/net.h>
#include <linux/wireless.h>
#include <libubox/utils.h>
#include <libubox/usock.h>
#include <libubox/list.h>
#include <sys/inotify.h>
#include <uci.h>  

//#include <execinfo.h>
#include "libwl/libwl_mscan_pub.h"
#include "libwl/libwl_api_pub.h"
#include "libwl/libwl_dbg_pub.h"
#include "libwl/libwl_alist_pub.h"
#include "ap_loadbalance.h"

/*
history:
function 1: ip of wan will change
function 2: ssid of config will change
function 3: add group for load balance

condition of load balance
1) accord for ssid
2) accord for group id

*/


#define MCAST_PORT g_config.mcast_port
#define MCAST_ADDR g_config.mcast_addr
//static struct LBALANCE_GLOBAL_CONFIG *g_debug_config ;
static struct LBALANCE_GLOBAL_CONFIG g_config =
{
        .version[0] = 0,
        .buildtime[0] = 0,
        .wan_name[0] = 0,
        .wan_ip[0] = 0,
        .wan_ip_type[0] = 0,
        .route_mac[0] = 0,
        .route_ip[0] = 0,
        .channelpath[0] = 0,
        .wan_status = 2,    //unknwon
        .time_count = 55,
        .time_interval = 60,    //600s update for one times
        .local_balance = 1,

        //mcast config
        .mcast_addr = "224.0.0.1",
        .mcast_port = 31313,

        .sock_fd_lbalance = -1,
        .sock_fd_ipaddr = -1,
        .sock_fd_ifstatus = -1,
        .sock_fd_cmd = -1,
        .sock_fd_5g = -1,
        .sock_fd_2g = -1,
        .inotify_fd_config = -1,
        .epoll_fd = -1,

        .restart_2g_count = 0,
        .restart_5g_count = 0,

        .conn_2g.keepup_amount = 1,
        .conn_2g.ac_ifname[0] = 0,
        .conn_2g.lbalance_base = 0,
        .conn_2g.st_node.us_drv_count = 0,
        .conn_2g.wifi_status = WIFI_STATUS_OPEN,
        .conn_2g.st_node.group_id = 11,
        .conn_2g.st_node.wlan_type = LBALANCE_WLAN_TYPE_2G,

        .conn_5g.keepup_amount = 1,
        .conn_5g.ac_ifname[0] = 0,
        .conn_5g.lbalance_base = 0,
        .conn_5g.st_node.us_drv_count = 0,
        .conn_5g.wifi_status = WIFI_STATUS_OPEN,
        .conn_5g.st_node.group_id = 21,
        .conn_5g.st_node.wlan_type = LBALANCE_WLAN_TYPE_5G,


         //loadbalance config
        .policy_type = LBALANCE_POLICY_MIN_CFG,    //policy
        .switch_on = 1,
        
};





#if FUNCTION_DESC("command function")


static struct LIBWL_CMD_LIST_ST  g_function_list[] = 
{
        {"config", lbalance_show_config},
        {"connect", lbalance_show_connect},
        {"debug", lbalance_show_debug_switch},
};



/**
 *@Description: command init
 *@Input: void: void
 *@Return: 0: ok;   -1: fail
 *@author: chenzejun 20160323
 */
static int lbalance_cmd_init(void)
{
        int retval;  

        /* command service*/
        if (g_config.sock_fd_cmd < 0)
        {
                // Create a socket ip
                g_config.sock_fd_cmd = libwl_cmd_service_create("lb");
                if(g_config.sock_fd_cmd < 0)
                {  
                        LBALANCE_DBG_PRINTF(LBALANCE_ERROR, "cmd create socket failed: %s\n", strerror(errno));
                        return -1;  
                }  

                //add epoll
                retval = libwl_add_epoll(g_config.epoll_fd, g_config.sock_fd_cmd); 
                if(retval != 0)
                {  
                        LBALANCE_DBG_PRINTF(LBALANCE_ERROR, "cmd socket add epoll fail: %s\n", strerror(errno)); 
                        return -1;  
                }
                
                LBALANCE_DBG_PRINTF(LBALANCE_CMD_INFO, "cmd create socket ok, fd:%d\n", g_config.sock_fd_cmd);  
        }

        return 0;
}

/**
 *@Description: command destroy
 *@Input: void: void
 *@Return: 0: ok;   -1: fail
 *@author: chenzejun 20160323
 */
static int lbalance_cmd_destroy(void)
{
        return libwl_cmd_service_destroy();
}



/**
 *@Description: the callback function of uloop
 *@Input: u: the file description of uloop
 *@Input: ev: the event of uloop
 *@Return: void
 *@author: chenzejun 20160323
 */
static void lbalance_cmd_socket_handle(int sock_fd)
{
        libwl_cmd_service_callback(sock_fd, g_function_list, ARRAY_SIZE(g_function_list));
        return;
}



#endif

#if FUNCTION_DESC("list api function")

static struct nlmsghdr *nl_header = NULL;  
static ALIST_HEAD connect_info =
{
        .pst_node = NULL,
        .cfg_num = 256,
        .node_count = 0,
        .tail_id = INVALID_ID,
};

static STA_CONNECT_NODE *connect_qsort = NULL;


/*
*@Description: add node to connect info
*@Input: pst_connect: pointer to scan info node
*@Return: 0: ok;   -1: fail
*@author: chenzejun 20160123
*/
static int lbalance_connect_add(STA_CONNECT_NODE  *pst_connect)
{
        return libwl_alist_add(&connect_info, pst_connect->ac_mac, MAC_LEN_6, pst_connect, sizeof(STA_CONNECT_NODE));
}
/*
*@Description: delet node by key
*@Input:pc_key: pointer to macaddr
*@return: find id
*@author: chenzejun 20160123
*/
static int lbalance_connect_del(unsigned char  ac_key[])
{
        return libwl_alist_del(&connect_info, (void *)ac_key, MAC_LEN_6);
}





/**
*@Description: mac scan function init
*@Input: void: void
*@return: 0 ok;  1- fail
*@author: chenzejun 20160123
*/
static int lbalance_info_init(void)
{

        //connect info, key + data
        connect_info.pst_node =  malloc(connect_info.cfg_num * sizeof(STA_CONNECT_NODE) * 2);
        if (NULL == connect_info.pst_node)
        {
                LBALANCE_DBG_PRINTF(LBALANCE_ERROR, "malloc connect_info failed\n");
                return -1;
        }
        memset(connect_info.pst_node, 0, connect_info.cfg_num * sizeof(STA_CONNECT_NODE) * 2);

        //connect_qsort info
        connect_qsort = (STA_CONNECT_NODE *)((char *)connect_info.pst_node + connect_info.cfg_num * sizeof(STA_CONNECT_NODE));


        // To prepare recvmsg  
        nl_header = (struct nlmsghdr *)malloc(NLMSG_SPACE(MAX_PAYLOAD));  
        if(NULL == nl_header)
        {  
                LBALANCE_DBG_PRINTF(LBALANCE_ERROR, "malloc nlmsghdr error!\n");  
                return -1;
        }

        LBALANCE_DBG_PRINTF(LBALANCE_INFO, "loadbalance startup, cfg_num:%d\n", connect_info.cfg_num);
        return 0;
}


/**
*@Description: mac info destroy
*@Input: void: void
*@return: 0 ok;  1- fail
*@author: chenzejun 20160123
*/
static int lbalance_info_destroy(void)
{
        if (connect_info.pst_node)  free(connect_info.pst_node);
        connect_info.pst_node = NULL;

        if (nl_header)   free(nl_header);
        nl_header = NULL;        
        
        return 0;
}







#endif

#if FUNCTION_DESC("uci function")

static struct uci_context  *uci_contex = NULL;




/*
*@Description: get value of the uci config
*@Input: ifname: the pointern of uci_ctx
*@Input:pst_local: local node info 
*@Return: 0: ok;   -1: fail
*@author: chenzejun 20160123
*/
static int lbalance_uci_get_wireless(char *ifname, LOACL_WLAN_INFO *pst_local)  
{  
        struct uci_context *uci_ctx = uci_contex;
        struct uci_package * pkg = NULL;  
        struct uci_element *e;  
        const char *pc_ifname;
        const char *pc_ssidname;
        const char *pc_lbbase;
        const char *pc_lbgroup;
        char *pc_amount;

        if (uci_ctx == NULL || ifname == NULL || pst_local == NULL)
        {
                return -1;
        }

        if (UCI_OK != uci_load(uci_ctx, "wireless", &pkg))
        {  
                return -1;
        }

        uci_foreach_element(&pkg->sections, e)  
        {
                struct uci_section *s = uci_to_section(e);

                if (strcmp(s->type, "wifi-iface") != 0)
                {
                        continue;
                }

                //printf("lookup type:%s\n", s->type);
                pc_ifname = uci_lookup_option_string(uci_ctx, s, "ifname");
                if (pc_ifname == NULL)
                {
                        continue;
                }

                //ifname not match
                if (strcmp(pc_ifname, ifname) != 0)
                {
                        continue;
                }
                

                // get ssid
                pc_ssidname = uci_lookup_option_string(uci_ctx, s, "ssid");
                if (pc_ssidname == NULL)
                {
                        continue;
                }

                snprintf(pst_local->st_node.ac_ssid, sizeof(pst_local->st_node.ac_ssid), "%s", pc_ssidname);
                pst_local->st_node.ssid_len = strlen(pst_local->st_node.ac_ssid) + 1;


                // get load balance flag
                pc_lbbase = uci_lookup_option_string(uci_ctx, s, "loadbalancebase");
                if (pc_lbbase == NULL)
                {
                        pst_local->lbalance_base = 0;
                }
                else
                {
                        pst_local->lbalance_base = atoi(pc_lbbase);
                }


                // get load balance group, set default value
                pst_local->st_node.group_id = 0;
                pst_local->keepup_amount = 0;
                pc_lbgroup = uci_lookup_option_string(uci_ctx, s, "loadbalancegroup");
                if (pc_lbgroup != NULL)
                {
                        //"12345.67";   group_id=12345
                        pst_local->st_node.group_id = atoi(pc_lbgroup);

                        pc_amount = strchr(pc_lbgroup, '.');
                        if (pc_amount != NULL)
                        {
                                pst_local->keepup_amount = atoi(pc_amount + 1);
                        }
                }

                //printf("found value:%s\n", value_name);
                uci_unload(uci_ctx, pkg);
                return 0;
        }
        

        uci_unload(uci_ctx, pkg);
        return -1;
}  


/*
*@Description: update config
*@Input: void: void
*@Return: void: void
*@author: chenzejun 20160123
*/
static void lbalance_update_config(void)  
{  
        int port_no = -1;
        int retval; 
        LOACL_WLAN_INFO *pst_local = NULL;
        STA_CONNECT_NODE *pst_connect = NULL;
        int channel = 0; 


        /* get 2g ssid */
        pst_local = &g_config.conn_2g;
        pst_connect = &g_config.conn_2g.st_node;
        retval = libwl_get_2g_port_no(pst_local->ac_ifname, sizeof(pst_local->ac_ifname), &port_no);
        if (retval == 0)     
        {
                lbalance_uci_get_wireless(pst_local->ac_ifname, pst_local);
                //qca device, ifname is wifi0 in here
                //if (strstr(port_name, "ath"))  lbalance_uci_get_ssid(other_name, pst_node->ac_ssid, sizeof(pst_node->ac_ssid));

                //default group 11
                if (pst_connect->group_id == 0)  pst_connect->group_id = 11;
                if (pst_local->keepup_amount == 0 || pst_local->keepup_amount > 10)  pst_local->keepup_amount = 1;
                
                libwl_get_router_mac(pst_local->ac_ifname, pst_connect->ac_mac, sizeof(pst_connect->ac_mac));
                libwl_get_router_channel(pst_local->ac_ifname, &channel);
                pst_connect->channel = channel; 

                LBALANCE_DBG_PRINTF(LBALANCE_UCI_INFO, "2g ifname:%s, mac:%02X%02X%02X%02X%02X%02X\n", 
                        pst_local->ac_ifname, pst_connect->ac_mac[0], pst_connect->ac_mac[1], pst_connect->ac_mac[2], 
                        pst_connect->ac_mac[3], pst_connect->ac_mac[4], pst_connect->ac_mac[5]);
        }

        /* get 5g ssid */
        pst_local = &g_config.conn_5g;
        pst_connect = &g_config.conn_5g.st_node;
        retval = libwl_get_5g_port_no(pst_local->ac_ifname, sizeof(pst_local->ac_ifname), &port_no);
        if (retval == 0)
        {
                lbalance_uci_get_wireless(pst_local->ac_ifname, pst_local);

                //default group 21
                if (pst_connect->group_id == 0)  pst_connect->group_id = 21;
                if (pst_local->keepup_amount == 0 || pst_local->keepup_amount > 10)  pst_local->keepup_amount = 1;

                libwl_get_router_mac(pst_local->ac_ifname, pst_connect->ac_mac, sizeof(pst_connect->ac_mac));
                libwl_get_router_channel(pst_local->ac_ifname, &channel);
                pst_connect->channel = channel; 

                LBALANCE_DBG_PRINTF(LBALANCE_UCI_INFO, "5g ifname:%s, mac:%02X%02X%02X%02X%02X%02X\n", 
                        pst_local->ac_ifname, pst_connect->ac_mac[0], pst_connect->ac_mac[1], pst_connect->ac_mac[2], 
                        pst_connect->ac_mac[3], pst_connect->ac_mac[4], pst_connect->ac_mac[5]);
        }

        /* get wan name */
        if (g_config.wan_name[0] == 0 || g_config.wan_name[1] == 0)
        {
                libwl_uci_get_option_fast(uci_contex, "network", "interface", "wan", "ifname", g_config.wan_name, sizeof(g_config.wan_name));

                /* get ip type */
                libwl_uci_get_option_fast(uci_contex, "network", "interface", "wan", "proto", g_config.wan_ip_type, sizeof(g_config.wan_ip_type));

                /* if the proto is pppoe, ip interface is pppoe-wan */
                if (0 == strcmp(g_config.wan_ip_type, "pppoe"))
                {
                        libwl_get_router_ip("pppoe-wan", g_config.wan_ip, BUF_LEN_64);
                }
                else
                {
                        libwl_get_router_ip(g_config.wan_name, g_config.wan_ip, BUF_LEN_64);
                }
        }
 
        LBALANCE_DBG_PRINTF(LBALANCE_UCI_INFO, "wan_name:%s, wan_ip:%s, ssid[2g]:%s, ssid[5g]:%s\n", 
                g_config.wan_name, g_config.wan_ip, g_config.conn_2g.st_node.ac_ssid, g_config.conn_5g.st_node.ac_ssid);
        return;
}  



/*
*@Description: set time value for delay update
*@Input: void: void
*@Return: void: void
*@author: chenzejun 20160123
         read portNo5G or portNo2G will fail, so delay time, beacause it is being update
*/
static void lbalance_time_delay_update(void)  
{  
        if (g_config.time_count < g_config.time_interval) 
        {
                LBALANCE_DBG_PRINTF(LBALANCE_UCI_INFO, "delay time update\n");
                g_config.time_count = g_config.time_interval - 2;
        }

        return;
}  




/*
*@Description: get config by timer
*@Input: void: void
*@Return: void: void
*@author: chenzejun 20160123
*/
static void lbalance_time_get_config(void)  
{  
        g_config.time_count++;
        if (g_config.time_count%g_config.time_interval == 0)
        {
                LBALANCE_DBG_PRINTF(LBALANCE_UCI_INFO, "timeout update config\n");
                lbalance_update_config();

                g_config.time_count = 0;
        }
 
        return;
}  

/*
*@Description: uci load config
*@Input: void: void
*@Return: 0: ok;   -1: fail
*@author: chenzejun 20160123
*/
static int lbalance_uci_load_config(void)  
{  
        uci_contex = uci_alloc_context();
        if (uci_contex == NULL)
        {
                return -1;
        }

        //get the config
        (void)lbalance_time_get_config();
      
        return 0;
}  


/*
*@Description: uci unload config
*@Input: void: void
*@Return: 0: ok;   -1: fail
*@author: chenzejun 20160123
*/
static int lbalance_uci_unload_config(void)  
{  
        
        if (uci_contex)
        {
                uci_free_context(uci_contex);
                uci_contex = NULL;
        }
      
        return 0;
}  



#endif



#if FUNCTION_DESC("api function")

static int g_2g_channel_list[] =
{
        1,
        2,
        3,
        4,
        5,
        6,
        7,
        8,
        9,
        10,
        11,
        12,      
};
static int g_5g_channel_list[] =
{
        149,
        153,
        157,
        161,
        165,    
};


/**
*@Description: qca getlan comand
*@Input:if_name: the name of dev
*@Return: 0 ok;  1- fail
*@author: chenzejun 20160123
*/
static int lbalance_qca_get_hide(char *if_name)
{
        int sock_fd = 0;
        struct iwreq	wrq;

        if (if_name == NULL)    return -1;

        //LBALANCE_DBG_PRINTF(LBALANCE_INFO, "get qca hideflag; if_name:%s\n", if_name);

        sock_fd = socket(AF_INET, SOCK_STREAM, 0);
        if(sock_fd < 0)
        {
                perror("error sock");
                return -1;
        }

        (void) memset(&wrq, 0, sizeof(wrq));
        (void) snprintf(wrq.ifr_name, sizeof(wrq.ifr_name), if_name);

        //ieee80211_ioctl.h
        //IEEE80211_PARAM_HIDESSID	= 19,	/* hide SSID mode (on, off) */

        wrq.u.param.value = 0x13;
        wrq.u.param.fixed = 0;
        wrq.u.param.disabled = 0;
        wrq.u.param.flags = 0;

        //    (iw_handler) ieee80211_ioctl_getparam,      /* SIOCWFIRSTPRIV+1 */
        if (ioctl(sock_fd, (SIOCIWFIRSTPRIV + 0x1), &wrq) < 0)
        {
                perror("error ioctl hidessid");
                close(sock_fd);
                return -1;
        }

        //printf("-lbalance_qca_get_hide:%d\n", wrq.u.param.value);     
        LBALANCE_DBG_PRINTF(LBALANCE_INFO, "get qca hideflag; if_name:%s, return:%d\n", if_name, wrq.u.param.value);

        close(sock_fd);
        return wrq.u.param.value;
}




/**
*@Description: qca set wlan comand
*@Input:if_name: the name of dev
*@Input:hide_flag: hide ssid flag
*@Return: 0 ok;  1- fail
*@author: chenzejun 20160123
*/
static int lbalance_qca_set_hide(char *if_name, int hide_flag)
{
        int sock_fd = 0;
        struct iwreq	wrq;

        if (if_name == NULL)    return -1;


        sock_fd = socket(AF_INET, SOCK_STREAM, 0);
        if(sock_fd < 0)
        {
                perror("error sock");
                return -1;
        }

        (void) memset(&wrq, 0, sizeof(wrq));
        (void) snprintf(wrq.ifr_name, sizeof(wrq.ifr_name), if_name);

        //ieee80211_ioctl.h
        //IEEE80211_PARAM_HIDESSID	= 19,	/* hide SSID mode (on, off) */

        wrq.u.param.value = 0x13;
        wrq.u.param.fixed = 0;
        wrq.u.param.disabled = 0;
        wrq.u.param.flags = hide_flag;

        //    (iw_handler) ieee80211_ioctl_setparam,      /* SIOCWFIRSTPRIV+0 */
        if (ioctl(sock_fd, (SIOCIWFIRSTPRIV), &wrq) < 0)
        {
                perror("qca error ioctl set");
                close(sock_fd);
                return -1;
        }

        close(sock_fd);
        return 0;
}



/**
*@Description: ralink set wlan comand
*@Input:if_name: the name of dev
*@Input:hide_flag: hide ssid flag
*@Return: 0 ok;  1- fail
*@author: chenzejun 20160123
*/
static int lbalance_ralink_set_hide(char *if_name, int hide_flag)
{
        int sock_fd = 0;
        struct iwreq	wrq;
        char cmd_hide[] = "HideSSID=1";
        char cmd_not_hide[] = "HideSSID=0"; 
        
        if (if_name == NULL) 
        {
                return -1;
        }

        sock_fd = socket(AF_INET, SOCK_STREAM, 0);
        if(sock_fd < 0)
        {
                perror("ralink error sock");
                return -1;
        }

        (void) memset(&wrq, 0, sizeof(wrq));
        (void) snprintf(wrq.ifr_name, sizeof(wrq.ifr_name), if_name);


        //command
        if (hide_flag == 0)
        {
                wrq.u.data.pointer = (void *)cmd_not_hide;
                wrq.u.data.length = strlen(cmd_not_hide) + 1;
                wrq.u.data.flags = 0;
        }
        else
        {
                wrq.u.data.pointer = (void *)cmd_hide;
                wrq.u.data.length = strlen(cmd_hide) + 1;
                wrq.u.data.flags = 0;
        }
                

        //#define RTPRIV_IOCTL_SET	(SIOCIWFIRSTPRIV + 0x02)
        if (ioctl(sock_fd, (SIOCIWFIRSTPRIV + 0x02), &wrq) < 0)
        {
                perror("ralink error ioctl set");
                close(sock_fd);
                return -1;
        }

        close(sock_fd);
        return 0;
}


/**
*@Description: wan set command
*@Input:pst_local: local node info 
*@Input:hide_flag: the flag of wlan ssid, 1 is hide
*@Return: 0 ok;  1- fail
*@author: chenzejun 20160123
*/
static int lbalance_wlan_set_hide(LOACL_WLAN_INFO  *pst_local, int hide_flag)
{
        int retval = 0; 
        char *if_name = NULL;
        
        if (pst_local == NULL)
        {
                return -1;
        }

        if_name = pst_local->ac_ifname;

        //delay hide in first time, avoid all wifi hide in same time
        if (hide_flag == 1 && pst_local->wifi_status != hide_flag)   
        {
                sleep(1);
        }
        pst_local->wifi_status = hide_flag;

        if (strstr(if_name, "ath")) 
        {
                // qca device
                if (hide_flag != lbalance_qca_get_hide(if_name))
                {
                        retval = lbalance_qca_set_hide(if_name, hide_flag);
                        LBALANCE_DBG_PRINTF(LBALANCE_DBG_2G5G(pst_local), "set wlan; cmd:%d, result:%d\n", hide_flag, retval);
                }
        }
        else
        {
                retval = lbalance_ralink_set_hide(if_name, hide_flag);
                LBALANCE_DBG_PRINTF(LBALANCE_DBG_2G5G(pst_local), "set wlan; cmd:%d, result:%d\n", hide_flag, retval);
        }

        return retval;
}




/**
*@Description: try open wlan
*@Input:pst_local: local node info 
*@Return: 0 ok;  1- fail
*@author: chenzejun 20160123
*/
static int lbalance_try_open_wlan(LOACL_WLAN_INFO  *pst_local)
{
        pst_local->delay_close_count = 0;
        
        LBALANCE_DBG_PRINTF(LBALANCE_DBG_2G5G(pst_local), "local wifi action; if_name:%s, curr_status:%s, action:open\n", 
                pst_local->ac_ifname, (pst_local->wifi_status == WIFI_STATUS_CLOSE) ? "close" : "open");
                
        return lbalance_wlan_set_hide(pst_local, WIFI_STATUS_OPEN);
}

/**
*@Description: try close wlan
*@Input:pst_local: local node info 
*@Return: 0 ok;  1- fail
*@author: chenzejun 20160123
*/
static int lbalance_try_close_wlan(LOACL_WLAN_INFO  *pst_local)
{
        if (pst_local->wifi_status != WIFI_STATUS_CLOSE)
        {
                pst_local->delay_close_count++;
        }

        if (pst_local->delay_close_count < 2)
        {
                LBALANCE_DBG_PRINTF(LBALANCE_DBG_2G5G(pst_local), "local wifi action; if_name:%s, curr_status:%s, action:close, but delay\n", 
                        pst_local->ac_ifname, (pst_local->wifi_status == WIFI_STATUS_CLOSE) ? "close" : "open");
                return 0;
        }

        LBALANCE_DBG_PRINTF(LBALANCE_DBG_2G5G(pst_local), "local wifi action; if_name:%s, curr_status:%s, action:close\n", 
                pst_local->ac_ifname, (pst_local->wifi_status == WIFI_STATUS_CLOSE) ? "close" : "open");
        return lbalance_wlan_set_hide(pst_local, WIFI_STATUS_CLOSE);
}



/**
*@Description: disable wlan 2g and 5g
*@Input:void: void
*@Return: 0 ok;  1- fail
*@author: chenzejun 20160123
*/
static int lbalance_wlan_enable_all(void)
{
        int retval;  
        int port_no = -1;
        LOACL_WLAN_INFO  *pst_local = NULL;

        pst_local = &g_config.conn_2g;
        retval = libwl_get_2g_port_no(pst_local->ac_ifname, sizeof(pst_local->ac_ifname), &port_no);
        if (retval == 0) 
        {
                lbalance_wlan_set_hide(pst_local, WIFI_STATUS_OPEN);
        }

        pst_local = &g_config.conn_5g;
        retval = libwl_get_5g_port_no(pst_local->ac_ifname, sizeof(pst_local->ac_ifname), &port_no);
        if (retval == 0) 
        {
                lbalance_wlan_set_hide(pst_local, WIFI_STATUS_OPEN);
        }
        
        return 0;
}




/**
*@Description: disable wlan 2g and 5g
*@Input:void: void
*@Return: 0 ok;  1- fail
*@author: chenzejun 20160123
*/
static int lbalance_wlan_disable_all(void)
{
        int retval;  
        int port_no = -1;
        LOACL_WLAN_INFO  *pst_local = NULL;

        pst_local = &g_config.conn_2g;
        retval = libwl_get_2g_port_no(pst_local->ac_ifname, sizeof(pst_local->ac_ifname), &port_no);
        if (retval == 0) 
        {
                lbalance_wlan_set_hide(pst_local, WIFI_STATUS_CLOSE);
        }

        pst_local = &g_config.conn_5g;
        retval = libwl_get_5g_port_no(pst_local->ac_ifname, sizeof(pst_local->ac_ifname), &port_no);
        if (retval == 0) 
        {
                lbalance_wlan_set_hide(pst_local, WIFI_STATUS_CLOSE);
        }
        
        return 0;
}



/**
*@Description: get max count in connection group
*@Input:pst_local: the pointer of local wlan
*@Return: 0 ok;  1- fail
*@author: chenzejun 20160123
*/
static int lbalance_connect_max_count(LOACL_WLAN_INFO  *pst_local)
{
        ALIST_HEAD *p_info = &connect_info;
        STA_CONNECT_NODE  *pst_node = NULL;
        int i = 0;
        int max_count = -1;
        ushort oldest_id = INVALID_ID;


        //connect data for list
        libwl_alist_for_entry(pst_node, i,  p_info) 
        {
                if (pst_node == NULL)  break;

                //local node 
                if (pst_node->ac_mac[0] == pst_local->st_node.ac_mac[0] &&
                    pst_node->ac_mac[1] == pst_local->st_node.ac_mac[1] &&
                    pst_node->ac_mac[2] == pst_local->st_node.ac_mac[2] &&
                    pst_node->ac_mac[3] == pst_local->st_node.ac_mac[3] &&
                    pst_node->ac_mac[4] == pst_local->st_node.ac_mac[4] &&
                    pst_node->ac_mac[5] == pst_local->st_node.ac_mac[5])
                {
                        continue;
                }

                //the oldest count
                LBALANCE_DBG_PRINTF(LBALANCE_INFO, "compare; mac:%02X%02X%02X%02X%02X%02X, group_id:%d, lbcount:%d\n", 
                        pst_node->ac_mac[0], pst_node->ac_mac[1], pst_node->ac_mac[2], 
                        pst_node->ac_mac[3], pst_node->ac_mac[4], pst_node->ac_mac[5], pst_node->group_id, pst_node->us_lb_count);
                        
                if ((0 == strncmp(pst_local->st_node.ac_ssid, pst_node->ac_ssid, sizeof(pst_node->ac_ssid))) &&
                     (pst_local->st_node.group_id == pst_node->group_id) &&
                     (pst_node->us_lb_count > max_count))
                {
                        oldest_id = i;
                        max_count = pst_node->us_lb_count;
                }                
        }

        //if not found, -1
        if (oldest_id == INVALID_ID)  return  -1;
                
        return max_count;
}






/**
*@Description: compare the node
*@Input:pst_local: local node info 
*@return: void
*@author: chenzejun 20160123
    if the mac is being hit by query, then clear us_idle_count.
*/
static void lbalance_policy_max_disable(LOACL_WLAN_INFO  *pst_local)
{
        int retval;  
        int max_count = 0;

        if (pst_local->st_node.ssid_len == 0 || pst_local->lbalance_base == 0)
        {
                //lbalance_wlan_set_hide(pst_local, 0);
                return;
        }
        
        max_count = lbalance_connect_max_count(pst_local);
        if (max_count < 0)
        {
                // not found , set up
                lbalance_try_open_wlan(pst_local);
                return;
        }
        
        LBALANCE_DBG_PRINTF(LBALANCE_DBG_2G5G(pst_local), 
                "compare max; name:%s, base_cnt:%d, local_cnt:%d, max_cnt:%d\n",
                pst_local->ac_ifname, pst_local->lbalance_base, pst_local->st_node.us_lb_count, max_count);

        //if max count, then disable
        if (pst_local->st_node.us_lb_count > max_count)
        {
                //stop wlan
                lbalance_try_close_wlan(pst_local);
        }
        else
        {
                lbalance_try_open_wlan(pst_local);
        }
        
        return;
}




/**
*@Description: get max count in connection group
*@Input:pst_local: the pointer of local wlan
*@Return: 0 ok;  1- fail
*@author: chenzejun 20160123
*/
static int lbalance_connect_min_count(LOACL_WLAN_INFO  *pst_local)
{
        ALIST_HEAD *p_info = &connect_info;
        STA_CONNECT_NODE  *pst_node = NULL;
        int i = 0;
        int min_count = 0xff;
        int oldest_id = INVALID_ID;

        //connect data for list
        libwl_alist_for_entry(pst_node, i,  p_info) 
        {
                if (pst_node == NULL)  break;
                
                //local node 
                if (pst_node->ac_mac[0] == pst_local->st_node.ac_mac[0] &&
                    pst_node->ac_mac[1] == pst_local->st_node.ac_mac[1] &&
                    pst_node->ac_mac[2] == pst_local->st_node.ac_mac[2] &&
                    pst_node->ac_mac[3] == pst_local->st_node.ac_mac[3] &&
                    pst_node->ac_mac[4] == pst_local->st_node.ac_mac[4] &&
                    pst_node->ac_mac[5] == pst_local->st_node.ac_mac[5])
                {
                        continue;
                }

                //the oldest count
                LBALANCE_DBG_PRINTF(LBALANCE_DBG_2G5G(pst_local), "compare; mac:%02X%02X%02X%02X%02X%02X, group_id:%d, lbcount:%d\n", 
                        pst_node->ac_mac[0], pst_node->ac_mac[1], pst_node->ac_mac[2], 
                        pst_node->ac_mac[3], pst_node->ac_mac[4], pst_node->ac_mac[5], pst_node->group_id, pst_node->us_lb_count);
                        
                if ((0 == strncmp(pst_local->st_node.ac_ssid, pst_node->ac_ssid, sizeof(pst_node->ac_ssid))) &&
                     (pst_local->st_node.group_id == pst_node->group_id) &&
                     (pst_node->us_lb_count < min_count))
                {
                        oldest_id = i;
                        min_count = pst_node->us_lb_count;
                }                
        }

        //if not found, -1
        if (oldest_id == INVALID_ID)  return  -1;
                
        return min_count;
}


/**
*@Description: compare the node
*@Input:pst_local: local node info 
*@return: void
*@author: chenzejun 20160123
    if the mac is being hit by query, then clear us_idle_count.
*/
static void lbalance_policy_min_enable(LOACL_WLAN_INFO  *pst_local)
{
        int retval;  
        int min_count = 0;

        if (pst_local->st_node.ssid_len == 0 || pst_local->lbalance_base == 0)
        {
                //lbalance_wlan_set_hide(pst_local, 0);
                return;
        }
        
        min_count = lbalance_connect_min_count(pst_local);
        if (min_count < 0)
        {
                // not found , set up
                lbalance_try_open_wlan(pst_local);
                return;
        }
        
        LBALANCE_DBG_PRINTF(LBALANCE_DBG_2G5G(pst_local), "compare min; name:%s, base_cnt:%d, local_cnt:%d, min_count:%d\n",
                pst_local->ac_ifname, pst_local->lbalance_base, pst_local->st_node.us_lb_count, min_count);

        //if min count, then enable
        if (pst_local->st_node.us_lb_count <= min_count)
        {
                lbalance_try_open_wlan(pst_local);
        }
        else
        {
                //stop wlan
                lbalance_try_close_wlan(pst_local);
        }
        
        return;
}


/**
*@Description: compare function
*@Input:_f0: the pointer of data
*@Input:_f1: the pointer of data
*@Return: 0 ok;  1- fail
*@author: chenzejun 20160123
*/
static int lbalance_connect_cmp(const void *_f0, const void *_f1)
{
        const struct STA_CONNECT_NODE *f0 = _f0;
        const struct STA_CONNECT_NODE *f1 = _f1;

        if (f0->us_lb_count > f1->us_lb_count)
        {
                return 1;
        }
        else
        {
                return -1;
        }
}

/**
*@Description: get max count in connection group
*@Input:pst_local: the pointer of local wlan
*@Return: 0 ok;  1- fail
*@author: chenzejun 20160123
*/
static int lbalance_connect_up_max_lbcount(LOACL_WLAN_INFO  *pst_local)
{
        ALIST_HEAD *p_info = &connect_info;
        STA_CONNECT_NODE  *pst_qsort = connect_qsort;
        STA_CONNECT_NODE  *pst_node = NULL;
        int i = 0;
        int qsort_id = 0;
        int id = 0;

        //connect data for list
        libwl_alist_for_entry(pst_node, i,  p_info) 
        {
                if (pst_node == NULL)  break;
                
                //copy to array for qsort
                if ((0 == strncmp(pst_local->st_node.ac_ssid, pst_node->ac_ssid, sizeof(pst_node->ac_ssid))) &&
                     (pst_local->st_node.group_id == pst_node->group_id))
                {
                        LBALANCE_DBG_PRINTF(LBALANCE_DBG_2G5G(pst_local), 
                                "compare[%d]; mac:%02X%02X%02X%02X%02X%02X, group_id:%d, type:%s, lbcount:%d\n", 
                                i, pst_node->ac_mac[0], pst_node->ac_mac[1], pst_node->ac_mac[2], 
                                pst_node->ac_mac[3], pst_node->ac_mac[4], pst_node->ac_mac[5], 
                                pst_node->group_id, (pst_node->wlan_type == LBALANCE_WLAN_TYPE_5G) ? "5G" : "2G",  pst_node->us_lb_count);
                
                        memcpy(&pst_qsort[qsort_id], &p_info->pst_node[i], sizeof(p_info->pst_node[i]));
                        qsort_id++;
                }
        }

        // calc keep up amount
        pst_local->keepup_amount = pst_local->st_node.group_id%10;
        if (pst_local->keepup_amount == 0)      pst_local->keepup_amount = 1;


        if (qsort_id)
        {
                //sort, from small to large
                qsort(pst_qsort, qsort_id, sizeof(struct STA_CONNECT_NODE), lbalance_connect_cmp);

                //max us_lb_count of permit up, accord group
                id = (pst_local->keepup_amount < qsort_id) ? pst_local->keepup_amount : qsort_id;

                if (id)   id--;

                LBALANCE_DBG_PRINTF(LBALANCE_DBG_2G5G(pst_local), "qsort calc; qsort_id:%d, keepup_amount:%d, id:%d\n", qsort_id, pst_local->keepup_amount, id);

                //max us_lb_count of permit up, accord group
                return pst_qsort[id].us_lb_count;
        }

 
        return -1;
}





/**
*@Description: copy connect info to table
*@Input:pst_local: the pointer of local wlan
*@Return: 0 ok;  1- fail
*@author: chenzejun 20160123
*/
static int lbalance_copy_connect_2_table(LOACL_WLAN_INFO  *pst_local)
{
        ALIST_HEAD *p_info = &connect_info;
        STA_CONNECT_NODE  *pst_qsort = connect_qsort;
        STA_CONNECT_NODE  *pst_node = NULL;
        int i = 0;
        int qsort_id = 0;

        //connect data for list
        libwl_alist_for_entry(pst_node, i,  p_info) 
        {
                if (pst_node == NULL)  break;
                
                //copy to array for qsort
                if ((0 == strncmp(pst_local->st_node.ac_ssid, pst_node->ac_ssid, sizeof(pst_node->ac_ssid))) &&
                     (pst_local->st_node.group_id == pst_node->group_id))
                {
                        LBALANCE_DBG_PRINTF(LBALANCE_DBG_2G5G(pst_local), 
                                "copy to qsort list[%d]; mac:%02X%02X%02X%02X%02X%02X, type:%s, group_id:%d, lbcount:%d\n", 
                                i, pst_node->ac_mac[0], pst_node->ac_mac[1], pst_node->ac_mac[2], 
                                pst_node->ac_mac[3], pst_node->ac_mac[4], pst_node->ac_mac[5],
                                (pst_node->wlan_type == LBALANCE_WLAN_TYPE_5G) ? "5G" : "2G", 
                                pst_node->group_id, pst_node->us_lb_count);
                
                        memcpy(&pst_qsort[qsort_id], pst_node, sizeof(STA_CONNECT_NODE));
                        qsort_id++;
                }
        }

        return qsort_id;
}

/**
*@Description: get local wifi action
*@Input:pst_local: the pointer of local wlan
*@Return: 0 ok;  1- fail
*@author: chenzejun 20160123
*/
static int lbalance_get_local_hide_action(LOACL_WLAN_INFO  *pst_local, STA_CONNECT_NODE  *pst_qsort, int qsort_num)
{
        STA_CONNECT_NODE  *pst_node = NULL;
        unsigned int i = 0;
        int mac_local = 0;
        int wifi_action = 0;
        int loacl_wifi_action = WIFI_STATUS_OPEN;

        if (qsort_num == 0 ||pst_qsort == NULL)
        {
                return WIFI_STATUS_OPEN;
        }

        LBALANCE_DBG_PRINTF(LBALANCE_DBG_2G5G(pst_local), "qsort list; qsort_num:%d, keepup_amount:%d, lbalance_base:%d\n", 
                qsort_num, pst_local->keepup_amount, pst_local->lbalance_base);

        //sort, from small to large
        qsort(pst_qsort, qsort_num, sizeof(struct STA_CONNECT_NODE), lbalance_connect_cmp);

        //connect data for list
        for(i = 0; i < qsort_num; i++) 
        {
                pst_node = &pst_qsort[i];

                //mac require active, need calc by keepup_amount
                if (i < pst_local->keepup_amount)
                {
                        wifi_action = WIFI_STATUS_OPEN;
                }
                else if (pst_node->us_lb_count == pst_qsort[pst_local->keepup_amount -1].us_lb_count)
                {                      
                        // if all us_lb_count is == , then open
                        wifi_action = WIFI_STATUS_OPEN;
                }
                else
                {
                        wifi_action = WIFI_STATUS_CLOSE;
                }
                        
                //if mac is local 
                if (0 == memcmp(pst_node->ac_mac, pst_local->st_node.ac_mac, MAC_LEN_6))
                {
                         //local wifi active
                        if (wifi_action == WIFI_STATUS_CLOSE)   loacl_wifi_action = WIFI_STATUS_CLOSE;
                        if (wifi_action == WIFI_STATUS_OPEN)   loacl_wifi_action = WIFI_STATUS_OPEN;
                        
                        mac_local = true;
                }
                else
                {
                        mac_local = false;
                }

                LBALANCE_DBG_PRINTF(LBALANCE_DBG_2G5G(pst_local), 
                        "hidessid action table[%d]; group_id:%d, mac:%02X%02X%02X%02X%02X%02X, type:%s, lb_count:%d, action:%s%s\n", 
                        i, pst_node->group_id,
                        pst_node->ac_mac[0], pst_node->ac_mac[1], pst_node->ac_mac[2], 
                        pst_node->ac_mac[3], pst_node->ac_mac[4], pst_node->ac_mac[5], 
                        (pst_node->wlan_type == LBALANCE_WLAN_TYPE_5G) ? "5G" : "2G", 
                        pst_node->us_lb_count,
                        (wifi_action == WIFI_STATUS_CLOSE) ? "close" : "open",
                        (mac_local == true) ? ", [local]" : "");
                        
        }


        return loacl_wifi_action;
}




/**
*@Description: compare function
*@Input:_f0: the pointer of data
*@Input:_f1: the pointer of data
*@Return: 0 ok;  1- fail
*@author: chenzejun 20160123
*/
static int lbalance_connect_cmp_mac(const void *_f0, const void *_f1)
{
        const struct STA_CONNECT_NODE *f0 = _f0;
        const struct STA_CONNECT_NODE *f1 = _f1;
        int i = 0;

        for (i = 0; i < MAC_LEN_6; i++)
        {
                if (f0->ac_mac[i] != f1->ac_mac[i])
                {
                        if (f0->ac_mac[i] > f1->ac_mac[i])
                        {
                                return 1;
                        }
                        else
                        {
                                return -1;
                        }
                }
        }
        
        return -1;
}


/**
*@Description: get local wifi action
*@Input:pst_local: the pointer of local wlan
*@Return: 0 ok;  1- fail
*@author: chenzejun 20160123
*/
static int lbalance_get_local_channel_action(LOACL_WLAN_INFO  *pst_local, STA_CONNECT_NODE  *pst_qsort, int qsort_num)
{
        STA_CONNECT_NODE  *pst_node = NULL;
        unsigned int i = 0;
        unsigned int j = 0;
        int mac_local = false;
        int wifi_action = WIFI_CHANNEL_KEEP;
        int loacl_wifi_action = WIFI_CHANNEL_KEEP;

        if (qsort_num == 0 ||pst_qsort == NULL)
        {
                return WIFI_CHANNEL_KEEP;
        }

        //sort, from small to large
        qsort(pst_qsort, qsort_num, sizeof(struct STA_CONNECT_NODE), lbalance_connect_cmp_mac);

        //connect data for list
        for(i = 0; i < qsort_num; i++) 
        {
                pst_node = &pst_qsort[i];


                wifi_action = WIFI_CHANNEL_KEEP;
                for(j = i + 1; j < qsort_num; j++) 
                {
                        //channel
                        if (pst_qsort[i].channel == pst_qsort[j].channel)
                        {
                                wifi_action = WIFI_CHANNEL_MODIFY;
                                break;
                        }
                }

                //if mac is least, and it is local, and channel is same, then modify its channel
                if (0 == memcmp(pst_node->ac_mac, pst_local->st_node.ac_mac, MAC_LEN_6))
                {
                        mac_local = true;
                        //if mac is least, i == 0
                        if (i == 0 && wifi_action == WIFI_CHANNEL_MODIFY)     loacl_wifi_action = WIFI_CHANNEL_MODIFY;
                }
                else
                {
                        mac_local = false;
                }

                LBALANCE_DBG_PRINTF(LBALANCE_DBG_2G5G(pst_local), 
                        "channel action table[%d]; group_id:%d, mac:%02X%02X%02X%02X%02X%02X, type:%s, channel:%d, action:%s%s\n", 
                        i, pst_node->group_id,
                        pst_node->ac_mac[0], pst_node->ac_mac[1], pst_node->ac_mac[2], 
                        pst_node->ac_mac[3], pst_node->ac_mac[4], pst_node->ac_mac[5], 
                        (pst_node->wlan_type == LBALANCE_WLAN_TYPE_5G) ? "5G" : "2G", 
                        pst_node->channel,
                        (wifi_action == WIFI_CHANNEL_MODIFY) ? "modify" : "keep",
                        (mac_local == true) ? ", [local]" : "");
                        
        }


        return loacl_wifi_action;
}



/**
*@Description: try modify loacl channel
*@Input:pst_local: local node info 
*@Return: 0 ok;  1- fail
*@author: chenzejun 20160123
*/
static int lbalance_try_modify_channel(LOACL_WLAN_INFO  *pst_local)
{
        static int i2 = 0;
        static int i5 = 0;
        char channel[BUF_LEN_16] = {0};
        
        if (pst_local->st_node.wlan_type == LBALANCE_WLAN_TYPE_5G)
        {
                for (i2 = 0; i2 < ARRAY_SIZE(g_5g_channel_list); i2++)
                {
                        if (pst_local->st_node.channel != g_5g_channel_list[i2])
                        {
                                snprintf(channel, sizeof(channel), "%d", g_5g_channel_list[i2]);

                                LBALANCE_DBG_PRINTF(LBALANCE_API_5G, "local wifi action; if_name:%s, channel:%s\n", 
                                        pst_local->ac_ifname, channel);
                                
                                libwl_uci_set_wifi_device(uci_contex, "5G", "channel", channel);
                                system("wifi reload");
                                pst_local->st_node.channel = g_5g_channel_list[i2];
                                pst_local->st_node.reset_channel_cnt++;
                                break;
                        }
                }
        }
        else if (pst_local->st_node.wlan_type == LBALANCE_WLAN_TYPE_2G)
        {
                for (i5 = 0; i5 < ARRAY_SIZE(g_2g_channel_list); i5++)
                {
                        if (pst_local->st_node.channel != g_2g_channel_list[i5])
                        {
                                snprintf(channel, sizeof(channel), "%d", g_2g_channel_list[i5]);

                                LBALANCE_DBG_PRINTF(LBALANCE_API_2G, "local wifi action; if_name:%s, channel:%s\n", 
                                        pst_local->ac_ifname, channel);
                                
                                libwl_uci_set_wifi_device(uci_contex, "2.4G", "channel", channel);
                                system("wifi reload");
                                pst_local->st_node.channel = g_2g_channel_list[i5];
                                pst_local->st_node.reset_channel_cnt++;
                                break;
                        }
                }
        }
        return 0;
}




/**
*@Description: the policy for config
*@Input:pst_local: local node info 
*@return: void
*@author: chenzejun 20160123
*/
static void lbalance_policy_use_config(LOACL_WLAN_INFO  *pst_local)
{
        int retval;  
        int qsort_num = 0;

        //pst_local->us_count=0 is not receive count data
        if (pst_local->st_node.ssid_len == 0 || pst_local->lbalance_base == 0 || pst_local->st_node.us_drv_count == 0)
        {
                //lbalance_wlan_set_hide(pst_local, 0);
                return;
        }

        qsort_num = lbalance_copy_connect_2_table(pst_local);

        //.2 hide action
        retval = lbalance_get_local_hide_action(pst_local, connect_qsort, qsort_num);
        if (retval == WIFI_STATUS_OPEN)
        {
                lbalance_try_open_wlan(pst_local);
        }
        else if (retval == WIFI_STATUS_CLOSE)
        {
                //stop wlan
                lbalance_try_close_wlan(pst_local);
        }

        return;
}




/**
*@Description: compare the node
*@Input:pst_local: local node info 
*@return: void
*@author: chenzejun 20160123
*/
static void lbalance_connect_compare_action(LOACL_WLAN_INFO  *pst_local)
{

        //policy type
        if (g_config.policy_type == LBALANCE_POLICY_MAX_DISABLE)
        {
                //only close 1 ssid; this plolicy is possible not average for balance
                //lbalance_connect_max_disable(pst_local);
        }
        else if (g_config.policy_type == LBALANCE_POLICY_MIN_ENABLE)
        {
                // only open 1 ssid; this plolicy is possible close all 2.4g
                //lbalance_connect_min_enable(pst_local);
        }
        else if (g_config.policy_type == LBALANCE_POLICY_MIN_CFG)
        {
                // this plolicy is open cfg ssid
                lbalance_policy_use_config(pst_local);
        }
        
        return;
}






/*
*@Description: get config by timer
*@Input: void: void
*@Return: void: void
*@author: chenzejun 20160123
*/
static void lbalance_time_check_channel(int time_interval)  
{
        int retval;  
        int qsort_num = 0;
        static int time_count = 55;
        LOACL_WLAN_INFO  *pst_local = NULL;

        time_count++;
        if (time_count > time_interval)
        {
                time_count = 0;

                LBALANCE_DBG_PRINTF(LBALANCE_UCI_INFO, "timeout check channel\n");
                pst_local = &g_config.conn_2g;
                qsort_num = lbalance_copy_connect_2_table(pst_local);

                //.3 set channel action
                retval = lbalance_get_local_channel_action(pst_local, connect_qsort, qsort_num);
                if (retval == WIFI_CHANNEL_MODIFY)
                {
                        lbalance_try_modify_channel(pst_local);
                }



                pst_local = &g_config.conn_5g;
                qsort_num = lbalance_copy_connect_2_table(pst_local);

                //.3 set channel action
                retval = lbalance_get_local_channel_action(pst_local, connect_qsort, qsort_num);
                if (retval == WIFI_CHANNEL_MODIFY)
                {
                        lbalance_try_modify_channel(pst_local);
                }


                time_count = 0;
        }
 
        return;
}  




#endif





#if FUNCTION_DESC("router netlink function")

/**
 *@Description: create socket
 *@Input: protocol: socket protocol type
 *@Return: 0: ok;   -1: fail
 *@author: chenzejun 20160323
 */
static int lbalance_create_ipaddr_socket(int protocol)
{
        struct sockaddr_nl receiver_addr;  
        int sock_fd, retval;  
        int on = 1; 

         // Create a socket 
        sock_fd = socket(AF_NETLINK,  SOCK_RAW,  protocol);
        if(sock_fd == -1)
        {  
                /*LBALANCE_DBG_PRINTF(LBALANCE_ERROR, "error getting socket: %s\n", strerror(errno));  */
                //kernel create before userplace create, if not it return error code 10043. it mean "Protocol not supported"
                return -2;    
        }  

        /* Enable address reuse */
        setsockopt(sock_fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));

        
        // To prepare binding  
        //memset(&msg,0,sizeof(msg));  
        memset(&receiver_addr, 0, sizeof(receiver_addr));  
        receiver_addr.nl_family = AF_NETLINK;  
        receiver_addr.nl_pid = 0; // self pid  
        receiver_addr.nl_groups = RTMGRP_IPV4_IFADDR; // multi cast  


        retval = bind(sock_fd, (struct sockaddr*)&receiver_addr, sizeof(receiver_addr));  
        if(retval < 0)
        {  
                LBALANCE_DBG_PRINTF(LBALANCE_ERROR, "ipaddr socket bind failed: %s\n", strerror(errno));  
                close(sock_fd);  
                return -1;    
        } 

        return sock_fd;
}


/*
Description: check dnsmasq is valid or invalid
Input: void
Return: 0: ok;   -1: fail
author: chenzejun 20160123
*/
int lbalance_parse_ipaddr_msg(struct nlmsghdr *nlh, int op)  
{  
        static uint32_t wan_ipaddr = 0;  
        struct ifaddrmsg *ifa = (struct ifaddrmsg *) NLMSG_DATA(nlh);  
        struct rtattr *rth = IFA_RTA(ifa);  
        int rtl = IFA_PAYLOAD(nlh);
        char name[IFNAMSIZ];
        uint32_t ipaddr = 0;      

        
        while (rtl && RTA_OK(rth, rtl)) 
        {  
                if (rth->rta_type == IFA_LOCAL)
                {  
                        /* Loopback port */
                        if (0 == strcmp("lo", name))
                        {
                                return -1;
                        }
                
                        ipaddr = htonl(*((uint32_t *)RTA_DATA(rth)));  
                        if_indextoname(ifa->ifa_index, name); 

                        /* address info */
                        LBALANCE_DBG_PRINTF(LBALANCE_IPADDR_INFO, "%s %s address %d.%d.%d.%d\n",  
                                name, (op != 0)?"add":"del",  
                                (ipaddr >> 24) & 0xff,  
                                (ipaddr >> 16) & 0xff,  
                                (ipaddr >> 8) & 0xff,  
                                ipaddr & 0xff); 
                        
                        if ((wan_ipaddr !=  ipaddr) && (0 == strcmp(name, g_config.wan_name)) && op == 1)
                        {
                                wan_ipaddr = ipaddr;
                                snprintf(g_config.wan_ip, sizeof(g_config.wan_ip), "%d.%d.%d.%d",
                                        (ipaddr >> 24) & 0xff,  
                                        (ipaddr >> 16) & 0xff,  
                                        (ipaddr >> 8) & 0xff,  
                                        ipaddr & 0xff);
                                lbalance_update_config();
                                break;
                        }
                        else if ((wan_ipaddr == ipaddr) && (0 == strcmp(name, g_config.wan_name)) && op == 0)
                        {
                                wan_ipaddr = 0;
                        }
                }  
                rth = RTA_NEXT(rth, rtl);  
        }  
        return 0;
}  


/**
*@Description: receive msg by socket
*@Input: void: void
*@Return:  0: ok
           <0: fail
*@author: chenzejun 20160323
*/
static int lbalance_socket_ipaddr_handle(int sock_fd)
{
        int retval; 

        // Read message from kernel  
        //int temp = 0;
        //it need read until to null  in ET module
        while(1)           //ET
        {
                retval = recvfrom(sock_fd, (char *)nl_header, MAX_PAYLOAD, 0, NULL, NULL);
                if(retval < 0)
                {
                        if(errno == EAGAIN)  
                        {
                                break;
                        }
                        else
                        {  
                                LBALANCE_DBG_PRINTF(LBALANCE_ERROR, "lbalance recvmsg return -1, errno:%s\n", strerror(errno)); 
                                return -1;
                        }  
                }

                //parse data
                if (RTM_NEWADDR == nl_header->nlmsg_type)
                {
                        LBALANCE_DBG_PRINTF(LBALANCE_IPADDR_INFO, "[in] receive ipaddr data, RTM_NEWADDR\n"); 
                        retval = lbalance_parse_ipaddr_msg(nl_header, 1);
                        retval = lbalance_try_create_mcast();
                        LBALANCE_DBG_PRINTF(LBALANCE_IPADDR_INFO, "[out] receive ipaddr data, RTM_NEWADDR\n"); 

                }
                else if (RTM_DELADDR == nl_header->nlmsg_type)
                {
                        LBALANCE_DBG_PRINTF(LBALANCE_IPADDR_INFO, "[in] receive ipaddr data, RTM_DELADDR\n"); 
                        retval = lbalance_parse_ipaddr_msg(nl_header, 0);
                        LBALANCE_DBG_PRINTF(LBALANCE_IPADDR_INFO, "[out] receive ipaddr data, RTM_DELADDR\n"); 
                }
                else
                {
                        LBALANCE_DBG_PRINTF(LBALANCE_IPADDR_INFO, "[out] receive unknown ipaddr data, msgtype:%d, len:%d\n", nl_header->nlmsg_type, nl_header->nlmsg_len); 
                }

        }

        return 0;
}


#endif


#if FUNCTION_DESC("if updown function")

/**
 *@Description: create socket
 *@Input: protocol: socket protocol type
 *@Return: 0: ok;   -1: fail
 *@author: chenzejun 20160323
 */
static int lbalance_create_ifstatus_socket(int protocol)
{
        struct sockaddr_nl receiver_addr;  
        int sock_fd, retval;  
        int on = 1; 

         // Create a socket 
        sock_fd = socket(AF_NETLINK,  SOCK_RAW,  protocol);
        if(sock_fd == -1)
        {  
                /*LBALANCE_DBG_PRINTF(LBALANCE_ERROR, "error getting socket: %s\n", strerror(errno));  */
                //kernel create before userplace create, if not it return error code 10043. it mean "Protocol not supported"
                return -2;    
        }  

        /* Enable address reuse */
        setsockopt(sock_fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));

        
        // To prepare binding  
        //memset(&msg,0,sizeof(msg));  
        memset(&receiver_addr, 0, sizeof(receiver_addr));  
        receiver_addr.nl_family = AF_NETLINK;  
        receiver_addr.nl_pid = 0; // self pid  
        receiver_addr.nl_groups = RTNLGRP_LINK; // multi cast  


        retval = bind(sock_fd, (struct sockaddr*)&receiver_addr, sizeof(receiver_addr));  
        if(retval < 0)
        {  
                LBALANCE_DBG_PRINTF(LBALANCE_ERROR, "ipaddr socket bind failed: %s\n", strerror(errno));  
                close(sock_fd);  
                return -1;    
        } 

        return sock_fd;
}


/*
Description: check dnsmasq is valid or invalid
Input: void
Return: 0: ok;   -1: fail
author: chenzejun 20160123
*/
int lbalance_parse_ifstatus_msg(struct nlmsghdr *nlh)  
{  
        struct ifinfomsg *ifinfo = (struct ifinfomsg *)NLMSG_DATA(nlh);;
        struct rtattr *attr;
        unsigned int ifstatus = ifinfo->ifi_flags & IFF_LOWER_UP;
        int len = 0; 
        char name[IFNAMSIZ];  
        if_indextoname(ifinfo->ifi_index, name);  
        LOACL_WLAN_INFO *pst_local = &g_config.conn_2g;

       
        LBALANCE_DBG_PRINTF(LBALANCE_IFSTAUS_INFO, "if status change, name:%s, ifindex:[%u]: %s\n", name, ifinfo->ifi_index,  
                ifstatus ? "up" : "down" ); 


        /* get 2g ssid */
        pst_local = &g_config.conn_2g;
        if ((0 == strcmp(name, pst_local->ac_ifname)) &&
            (ifstatus) &&
            (ifstatus != pst_local->ifstatus))
        {
                pst_local->ifstatus = ifstatus;
                LBALANCE_DBG_PRINTF(LBALANCE_IFSTAUS_INFO, "2g delay time update, ifstatus:%d\n", ifstatus);
                //lbalance_update_config();   
                //read portNo2G will fail, so delay time, beacause it is being update
                lbalance_time_delay_update();
                return 0;
        }
        else if ((0 == strcmp(name, pst_local->ac_ifname)) &&
            (ifstatus == 0) &&
            (ifstatus != pst_local->ifstatus))
        {
                pst_local->ifstatus = ifstatus;
                return 0;
        }


        /* get 5g ssid */
        pst_local = &g_config.conn_5g;
        if ((0 == strcmp(name, pst_local->ac_ifname)) &&
            (ifstatus) &&
            (ifstatus != pst_local->ifstatus))
        {
                pst_local->ifstatus = ifstatus;
                LBALANCE_DBG_PRINTF(LBALANCE_IFSTAUS_INFO, "5g delay time update, ifstatus:%d\n", ifstatus);
                //read portNo5G will fail, so delay time, beacause it is being update
                lbalance_time_delay_update();
                return 0;
        }
        else if ((0 == strcmp(name, pst_local->ac_ifname)) &&
            (ifstatus == 0) &&
            (ifstatus != pst_local->ifstatus))
        {
                pst_local->ifstatus = ifstatus;
                return 0;
        }

       /* get wan name */
        if (0 == strcmp(name, g_config.wan_name))
        {
                g_config.wan_status = ifstatus;
        }


        //back         
        #if 0
        attr = (struct rtattr*)(((char*)nlh) + NLMSG_SPACE(sizeof(*ifinfo)));  
        len = nlh->nlmsg_len - NLMSG_SPACE(sizeof(*ifinfo));  
        for (; RTA_OK(attr, len); attr = RTA_NEXT(attr, len))  
        {  
                if (attr->rta_type == IFLA_IFNAME)  
                {  
                    LBALANCE_DBG_PRINTF(LBALANCE_IFSTAUS_INFO, "RTA_DATA: %s\n", (char*)RTA_DATA(attr));  
                    break;  
                }  
        }  
        #endif

        return 0;
}  


/**
*@Description: receive msg by socket
*@Input: void: void
*@Return:  0: ok
           <0: fail
*@author: chenzejun 20160323
*/
static int lbalance_socket_ifstatus_handle(int sock_fd)
{
        int retval; 

        // Read message from kernel  
        //int temp = 0;
        //it need read until to null  in ET module
        while(1)           //ET
        {
                retval = recvfrom(sock_fd, (char *)nl_header, MAX_PAYLOAD, 0, NULL, NULL);
                if(retval < 0)
                {
                        if(errno == EAGAIN)  
                        {
                                break;
                        }
                        else
                        {  
                                LBALANCE_DBG_PRINTF(LBALANCE_ERROR, "lbalance recvmsg return -1, errno:%s\n", strerror(errno)); 
                                return -1;
                        }  
                }

                //parse data
                if (RTM_NEWLINK == nl_header->nlmsg_type)
                {
                        LBALANCE_DBG_PRINTF(LBALANCE_IFSTAUS_INFO, "[in] receive ifstatus data, RTM_NEWLINK\n"); 
                        lbalance_parse_ifstatus_msg(nl_header);
                        LBALANCE_DBG_PRINTF(LBALANCE_IFSTAUS_INFO, "[out] receive ifstatus data, RTM_NEWLINK\n"); 
                }
                else
                {
                        LBALANCE_DBG_PRINTF(LBALANCE_IFSTAUS_INFO, "[out] receive unknown ifstatus data, msgtype:%d, len:%d\n", nl_header->nlmsg_type, nl_header->nlmsg_len); 
                }

        }

        return 0;
}


#endif



#if FUNCTION_DESC("lbalance mcast function")


/**
 *@Description: create mcast socket
 *@Input: protocol: socket protocol type
 *@Return: 0: ok;   -1: fail
 *@author: chenzejun 20160323
 */
static int lbalance_create_mcast_socket(void)
{
        struct sockaddr_in  receiver_addr;  
        int sock_fd;
        int retval;  
        int loop = 0;
        char ttl = 255;
        int on = 1; 
        struct ip_mreq mreq = {0};

        // Create a socket , udp
        sock_fd = socket(AF_INET,  SOCK_DGRAM,  0);
        if(sock_fd == -1)
        {
                LBALANCE_DBG_PRINTF(LBALANCE_ERROR, "create lbalance socket failed: %s\n", strerror(errno));
                return -1;    
        }  

        /* Enable address reuse */
        setsockopt(sock_fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));

        // To prepare connect  
        memset(&receiver_addr, 0, sizeof(receiver_addr));  
        receiver_addr.sin_family = AF_INET;  
        receiver_addr.sin_port = htons(MCAST_PORT); // port  
        receiver_addr.sin_addr.s_addr = htonl(INADDR_ANY);

        retval = bind(sock_fd, (struct sockaddr*)&receiver_addr, sizeof(receiver_addr));  
        if(retval < 0)
        {  
                LBALANCE_DBG_PRINTF(LBALANCE_ERROR, "create lbalance socket bind failed: %s\n", strerror(errno));
                close(sock_fd);  
                return -1;  
        } 

        //loop = 0
        setsockopt(sock_fd, IPPROTO_IP, IP_MULTICAST_LOOP,&loop, sizeof(loop));
        setsockopt(sock_fd, IPPROTO_IP, IP_MULTICAST_TTL, &ttl, sizeof(ttl));


        //struct in_addr addr;
        //addr.s_addr = inet_addr(g_config.wan_ip);
        //setsockopt(sock_fd, IPPROTO_IP, IP_MULTICAST_IF, (&addr), sizeof(addr));


        /* join broadcast */
        mreq.imr_multiaddr.s_addr = inet_addr(MCAST_ADDR);
        mreq.imr_interface.s_addr = htonl(INADDR_ANY);
        //mreq.imr_interface.s_addr = inet_addr("192.168.99.228");
        //mreq.imr_interface.s_addr = inet_addr(g_config.wan_ip);

        retval = setsockopt(sock_fd, IPPROTO_IP, IP_ADD_MEMBERSHIP, &mreq, sizeof(mreq));
        if(retval < 0)
        {  
                LBALANCE_DBG_PRINTF(LBALANCE_ERROR, "lbalance socket add memeber failed: %s\n", strerror(errno));
                close(sock_fd);  
                return -1;  
        } 

        //the first send
        if (g_config.sock_fd_2g > 0)        lbalance_send_mcast_msg(g_config.sock_fd_lbalance, &g_config.conn_2g);
        if (g_config.sock_fd_5g > 0)        lbalance_send_mcast_msg(g_config.sock_fd_lbalance, &g_config.conn_5g);
        
        LBALANCE_DBG_PRINTF(LBALANCE_MCAST_RECV, "create lbalance socket is ok, ssid[2g]:%s, ssid[5g]:%s, ip:%s\n", 
                g_config.conn_2g.st_node.ac_ssid, g_config.conn_5g.st_node.ac_ssid, g_config.wan_ip);
        return sock_fd;
}




/*
*@Description: parse connect data
*@Input: pc_msg_data: pointer to the msg
*@Input: ui_msg_len: msglen
*@Return: 0: ok;   -1: fail
*@author: chenzejun 20160123
*/
static int lbalance_parse_mcast_data(int fd, char *pc_msg_data, unsigned int ui_msg_len)
{

        AP_TLV_DATA *pst_tlv_data = (AP_TLV_DATA *)pc_msg_data;
        STA_CONNECT_NODE  st_connect;
        STA_CONNECT_NODE  *pst_node;
        unsigned short find_flag = 0;
        unsigned int ui_temp_len = 0;
        char ac_mac_str[BUF_LEN_64];
        int i_ret = 0;
        unsigned short used_id;

        if (pc_msg_data == NULL)
        {
                return -1;
        }

        //if (lbalance_debug > 0)  printf("[in] lbalance add connect data, ui_msg_len: %d \n", ui_msg_len); 
        memset(&st_connect, 0, sizeof(st_connect));
        
        while(ui_temp_len < ui_msg_len && ntohs(pst_tlv_data->us_tlv_len))
        {
                //printf("APP  Received ui_msg_len: %d, %d \n", ui_msg_len, pst_tlv_data->us_tlv_type); 

                if (ntohs(pst_tlv_data->us_tlv_type) >= AP_TLV_TYPE_MAX)
                {
                        LBALANCE_DBG_PRINTF(LBALANCE_MCAST_RECV, "break ui_msg_len: %d, %d \n", ui_msg_len, ntohs(pst_tlv_data->us_tlv_type)); 
                        break;
                }
                
                switch (ntohs(pst_tlv_data->us_tlv_type))
                {
                        case LBALANCE_TLV_TYPE_MAC:
                        {
                                find_flag = 1;
                                memcpy(st_connect.ac_mac, (unsigned char *)(pst_tlv_data+1), MAC_LEN_6);
                                break;
                        }
                        case LBALANCE_TLV_TYPE_SSID:
                        {
                                if (ntohs(pst_tlv_data->us_tlv_len) > sizeof(AP_TLV_DATA))
                                {
                                        st_connect.ssid_len = ntohs(pst_tlv_data->us_tlv_len) - sizeof(AP_TLV_DATA);
                                }
                                memcpy(st_connect.ac_ssid, (unsigned char *)(pst_tlv_data+1), st_connect.ssid_len);
                                break;
                        }
                        case LBALANCE_TLV_TYPE_GROUP:
                        {
                                st_connect.group_id = ntohs(*(unsigned short *)(pst_tlv_data+1));
                                break;
                        }
                        case LBALANCE_TLV_TYPE_WLAN_TYPE:
                        {
                                st_connect.wlan_type = ntohs(*(unsigned short *)(pst_tlv_data+1));
                                break;
                        }
                        case LBALANCE_TLV_TYPE_COUNT:
                        {
                                st_connect.us_lb_count = ntohs(*(unsigned short *)(pst_tlv_data+1));
                                break;
                        }
                        case LBALANCE_TLV_TYPE_DRV_COUNT:
                        {
                                st_connect.us_drv_count = ntohs(*(unsigned short *)(pst_tlv_data+1));
                                break;
                        }
                        case LBALANCE_TLV_TYPE_CHANNEL:
                        {
                                st_connect.channel = ntohs(*(unsigned short *)(pst_tlv_data+1));
                                break;
                        }
                        default:
                        {
                                break;
                        }
                }

                //next tlv
                ui_temp_len = ui_temp_len + ntohs(pst_tlv_data->us_tlv_len);
                pst_tlv_data =  (AP_TLV_DATA *)((char *)pst_tlv_data + ntohs(pst_tlv_data->us_tlv_len));
        }

        //  
        if (st_connect.ssid_len == 0)    return 0;

        if ((1 == find_flag) && 
        ((0 == memcmp(st_connect.ac_ssid, g_config.conn_2g.st_node.ac_ssid, st_connect.ssid_len)) ||
          (0 == memcmp(st_connect.ac_ssid, g_config.conn_5g.st_node.ac_ssid, st_connect.ssid_len))))
        {
                st_connect.us_idle_count = 0;
                (void)lbalance_connect_add(&st_connect);


                if (g_config.sock_fd_2g > 0)       lbalance_connect_compare_action(&g_config.conn_2g);
                if (g_config.sock_fd_5g > 0)       lbalance_connect_compare_action(&g_config.conn_5g);
        }


        LBALANCE_DBG_PRINTF(LBALANCE_MCAST_RECV, "[TLV] mcast msg; ssid:%s; mac:%02X%02X%02X%02X%02X%02X, type:%s, lb_count:%d, local lb_count:%d\n", 
                st_connect.ac_ssid,
                st_connect.ac_mac[0], st_connect.ac_mac[1], st_connect.ac_mac[2], st_connect.ac_mac[3], st_connect.ac_mac[4], st_connect.ac_mac[5],
                (st_connect.wlan_type == LBALANCE_WLAN_TYPE_5G) ? "5G" : "2G",
                st_connect.us_lb_count,
                (st_connect.wlan_type == LBALANCE_WLAN_TYPE_5G) ? st_connect.us_lb_count : st_connect.us_lb_count);

        return 0;
}


/**
*@Description: lbalance_send_mcast_msg
*@Input: void: void
*@Return: 0: ok;   -1: fail
*@author: chenzejun 20160323
*/
static void lbalance_send_mcast_msg(int sock_fd, LOACL_WLAN_INFO *p_loacl)
{
        struct sockaddr_in to;
        int len = 0;
        int tlv_len = 0;
        int retval;
        char   *pc_msg_data;  
        AP_TLV_DATA *pst_tlv_data;
        STA_CONNECT_NODE  *pst_node = &p_loacl->st_node;
        int slen = NLMSG_HDRLEN;  

        if (sock_fd < 0 || p_loacl == NULL)
        {
                return;
        }

        //
        if (p_loacl->lbalance_base == 0)
        {
                return;
        }

        memset(&to, 0, sizeof(to));
        to.sin_family = AF_INET;
        to.sin_port = htons(MCAST_PORT); // port  
        to.sin_addr.s_addr = inet_addr(MCAST_ADDR);


        memset(nl_header, 0, sizeof(struct nlmsghdr));
        nl_header->nlmsg_type = htons(LBALANCE_MSG_TYPE_NOTICE);
        nl_header->nlmsg_seq = htonl(nl_header->nlmsg_seq + 1);

        //tlv: mac
        pc_msg_data = (char   *)(nl_header + 1);
        pst_tlv_data = (AP_TLV_DATA *)pc_msg_data;
        pst_tlv_data->us_tlv_type = htons(LBALANCE_TLV_TYPE_MAC);
        tlv_len = (sizeof(AP_TLV_DATA) + sizeof(pst_node->ac_mac));
        pst_tlv_data->us_tlv_len =  htons(tlv_len);
        memcpy((char *)(pst_tlv_data + 1), pst_node->ac_mac, sizeof(pst_node->ac_mac));  
        slen = slen + tlv_len; 

        //tlv: ssid
        pc_msg_data = pc_msg_data + tlv_len;
        pst_tlv_data = (AP_TLV_DATA *)pc_msg_data;
        pst_tlv_data->us_tlv_type = htons(LBALANCE_TLV_TYPE_SSID);
        tlv_len =  sizeof(AP_TLV_DATA) + pst_node->ssid_len;
        pst_tlv_data->us_tlv_len =  htons(tlv_len);
        memcpy((char *)(pst_tlv_data + 1), pst_node->ac_ssid, pst_node->ssid_len);  
        slen = slen + tlv_len; 

        //tlv: group
        pc_msg_data = pc_msg_data + tlv_len;
        pst_tlv_data = (AP_TLV_DATA *)pc_msg_data;
        pst_tlv_data->us_tlv_type = htons(LBALANCE_TLV_TYPE_GROUP);
        tlv_len =  sizeof(AP_TLV_DATA) + sizeof(pst_node->group_id);
        pst_tlv_data->us_tlv_len =  htons(tlv_len);
        *((unsigned short *)(pst_tlv_data + 1)) = htons(pst_node->group_id);
        slen = slen + tlv_len; 

        //tlv: wlan type
        pc_msg_data = pc_msg_data + tlv_len;
        pst_tlv_data = (AP_TLV_DATA *)pc_msg_data;
        pst_tlv_data->us_tlv_type = htons(LBALANCE_TLV_TYPE_WLAN_TYPE);
        tlv_len =  sizeof(AP_TLV_DATA) + sizeof(pst_node->wlan_type);
        pst_tlv_data->us_tlv_len =  htons(tlv_len);
        *((unsigned short *)(pst_tlv_data + 1)) = htons(pst_node->wlan_type);
        slen = slen + tlv_len; 

        //tlv: count
        pc_msg_data = pc_msg_data + tlv_len;
        pst_tlv_data = (AP_TLV_DATA *)pc_msg_data;
        pst_tlv_data->us_tlv_type = htons(LBALANCE_TLV_TYPE_COUNT);
        tlv_len =  sizeof(AP_TLV_DATA) + sizeof(pst_node->us_lb_count);
        pst_tlv_data->us_tlv_len =  htons(tlv_len);
        *((unsigned short *)(pst_tlv_data + 1)) = htons(pst_node->us_lb_count);
        slen = slen + tlv_len; 

        //tlv: drv count
        pc_msg_data = pc_msg_data + tlv_len;
        pst_tlv_data = (AP_TLV_DATA *)pc_msg_data;
        pst_tlv_data->us_tlv_type = htons(LBALANCE_TLV_TYPE_DRV_COUNT);
        tlv_len =  sizeof(AP_TLV_DATA) + sizeof(pst_node->us_drv_count);
        pst_tlv_data->us_tlv_len =  htons(tlv_len);
        *((unsigned short *)(pst_tlv_data + 1)) = htons(pst_node->us_drv_count);
        slen = slen + tlv_len; 

        //tlv: channel
        pc_msg_data = pc_msg_data + tlv_len;
        pst_tlv_data = (AP_TLV_DATA *)pc_msg_data;
        pst_tlv_data->us_tlv_type = htons(LBALANCE_TLV_TYPE_CHANNEL);
        tlv_len =  sizeof(AP_TLV_DATA) + sizeof(pst_node->channel);
        pst_tlv_data->us_tlv_len =  htons(tlv_len);
        *((unsigned short *)(pst_tlv_data + 1)) = htons(pst_node->channel);
        slen = slen + tlv_len; 


        nl_header->nlmsg_len = htonl(slen);
        nl_header->nlmsg_type = htons(LBALANCE_MSG_TYPE_NOTICE);

        retval = sendto(sock_fd, nl_header, slen, 0, (struct sockaddr *)&to, sizeof(to));  
        if(retval < 0)
        {  
                LBALANCE_DBG_PRINTF(LBALANCE_ERROR, "lbalance send fail; fd:%d, errno:%s\n", sock_fd, strerror(errno));
                return;
        }
        
        LBALANCE_DBG_PRINTF(LBALANCE_MCAST_SEND, "lbalance send ok; local ssid:%s, local mac:%02X%02X%02X%02X%02X%02X, local lb_count:%d\n", 
                pst_node->ac_ssid,  pst_node->ac_mac[0], pst_node->ac_mac[1], pst_node->ac_mac[2], 
                pst_node->ac_mac[3], pst_node->ac_mac[4], pst_node->ac_mac[5], pst_node->us_lb_count);

        return;
}



/**
*@Description: lbalance_send_mcast_msg
*@Input: void: void
*@Return: 0: ok;   -1: fail
*@author: chenzejun 20160323
*/
void lbalance_send_test_msg(int sock_fd)
{
        struct sockaddr_in to;
        struct sockaddr_in  receiver_addr;  
        int len = 0;
        int retval;
        char   *pc_msg_data;  
        AP_TLV_DATA *pst_tlv_data;
        int slen = NLMSG_HDRLEN;  
        unsigned int msg_len = 0;
        static unsigned int i = 0;
        char buff[MAX_PAYLOAD];

        if (sock_fd < 0)     return;

        memset(&to, 0, sizeof(to));
        to.sin_family = AF_INET;
        to.sin_port = htons(MCAST_PORT); // port  
        to.sin_addr.s_addr = inet_addr(MCAST_ADDR);


        // To prepare connect  
        memset(&receiver_addr, 0, sizeof(receiver_addr));  
        receiver_addr.sin_family = AF_INET;  
        receiver_addr.sin_port = htons(MCAST_PORT); // port  
        receiver_addr.sin_addr.s_addr = inet_addr(MCAST_ADDR);


        msg_len = snprintf(buff, 2048,  "this is joylink test, index=%d", i++);
        retval = sendto(sock_fd, buff, msg_len, 0, (struct sockaddr *)&receiver_addr, sizeof(receiver_addr));  
        if(retval < 0)
        {  
                LBALANCE_DBG_PRINTF(LBALANCE_ERROR, "lbalance test send fail; fd:%d, errno:%s\n", sock_fd, strerror(errno));
                return;
        }

        LBALANCE_DBG_PRINTF(LBALANCE_MCAST_RECV, "lbalance test send ok, len:%d\n", slen); 
        return;
}


/**
*@Description: receive msg by socket
*@Input: void: void
*@Return:  0: ok
           <0: fail
*@author: chenzejun 20160323
*/
static int lbalance_socket_mcast_handle(int sock_fd)
{
        int retval; 

        // Read message from kernel  
        //int temp = 0;
        //it need read until to null  in ET module
        while(1)           //ET
        {
                retval = recvfrom(sock_fd, (char *)nl_header, MAX_PAYLOAD, 0, NULL, NULL);
                if(retval < 0)
                {
                        if(errno == EAGAIN)  
                        {
                                break;
                        }
                        else
                        {  
                                LBALANCE_DBG_PRINTF(LBALANCE_ERROR, "lbalance recvmsg return -1, errno:%s\n", strerror(errno)); 
                                return -1;
                        }  
                }

                //parse data
                if (LBALANCE_MSG_TYPE_NOTICE == ntohs(nl_header->nlmsg_type))
                {
                        LBALANCE_DBG_PRINTF(LBALANCE_MCAST_RECV, "[in] receive lbalance data, msgtype:%d, len:%d\n", ntohs(nl_header->nlmsg_type), ntohl(nl_header->nlmsg_len)); 
                        lbalance_parse_mcast_data(sock_fd, NLMSG_DATA(nl_header), (ntohl(nl_header->nlmsg_len) - NLMSG_HDRLEN));
                        LBALANCE_DBG_PRINTF(LBALANCE_MCAST_RECV, "[out] receive lbalance data, retval:%d\n", retval); 
                }
                else
                {
                        LBALANCE_DBG_PRINTF(LBALANCE_MCAST_RECV, "[in] receive unknown data, msgtype:%d, len:%d, retval:%d\n", ntohs(nl_header->nlmsg_type), ntohl(nl_header->nlmsg_len), retval); 
                }

        }

        return 0;
}



/**
 *@Description: lb try to close mcast
 *@Input: void: void
 *@Return: 0: ok;   -1: fail
 *@author: chenzejun 20160323
 */
static int lbalance_try_close_mcast(void)
{
        /* loadbalance service*/
        if (g_config.sock_fd_lbalance > 0)  
        {
                close(g_config.sock_fd_lbalance);
                g_config.sock_fd_lbalance = -1;
        }

        return 0;
}





/**
 *@Description: lb try to create mcast
 *@Input: void: void
 *@Return: 0: ok;   -1: fail
 *@author: chenzejun 20160323
 */
static int lbalance_try_create_mcast(void)
{
        int retval;  

        /* loadbalance service*/
        if (g_config.sock_fd_lbalance < 0)
        {
                // Create a socket ip
                g_config.sock_fd_lbalance = lbalance_create_mcast_socket();
                if(g_config.sock_fd_lbalance < 0)
                {  
                        LBALANCE_DBG_PRINTF(LBALANCE_ERROR, "mcast create socket failed: %s\n", strerror(errno));
                        return -1;  
                }  

                //add epoll
                retval = libwl_add_epoll(g_config.epoll_fd, g_config.sock_fd_lbalance); 
                if(retval != 0)
                {  
                        lbalance_try_close_mcast();
                        LBALANCE_DBG_PRINTF(LBALANCE_ERROR, "mcast add epoll fail\n"); 
                        return -1;  
                }
                
                LBALANCE_DBG_PRINTF(LBALANCE_INFO, "mcast create socket ok, fd:%d\n", g_config.sock_fd_lbalance);  
        }

        return 0;
}



#endif



#if FUNCTION_DESC("wlan function")




/**
*@Description: send msg to kernel
*@Input: epollfd: epoll fd
*@Input: sock_fd: socket fd
*@Return:  0: ok
           <0: fail
*@author: chenzejun 20160323
*/
int lbalance_sendmsg_2_kernel(int sock_fd)
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
        strcpy(NLMSG_DATA(nlh), "loadbalance");  


        state_smg = sendmsg(sock_fd, &msg, 0);  
        if(state_smg == -1)
        {  
                LBALANCE_DBG_PRINTF(LBALANCE_ERROR, "sock_fd get error sendmsg = %s\n", strerror(errno));
                return -1;    
        }  

        return 0;
}




/**
*@Description: try to start socket of 2g
*@Input: void: void
*@Return: void
*@author: chenzejun 20160323
*/
static void lbalance_try_netlink_2g(void)
{
        int retval;  

         // try to start 5g, Create a socket ,  if count > 8,  the dev hasn't 5g, don't start it.
        if (g_config.restart_2g_count < NETLINK_RESTART_MAX && g_config.sock_fd_2g <= 0)
        {
                // Create a socket 2.4G
                g_config.sock_fd_2g = libwl_create_netlink_socket(NETLINK_24G);
                if(g_config.sock_fd_2g < 0)
                {  
                        LBALANCE_DBG_PRINTF(LBALANCE_ERROR, "wifi 2g create socket failed: %s\n", strerror(errno));
                        g_config.restart_2g_count++;
                        return;  
                }  

                //add epoll
                retval = libwl_add_epoll(g_config.epoll_fd, g_config.sock_fd_2g); 
                if(retval != 0)
                {  
                        LBALANCE_DBG_PRINTF(LBALANCE_ERROR, "wifi 2g add epoll fail\n"); 
                        return;  
                }  

                (void)lbalance_sendmsg_2_kernel(g_config.sock_fd_2g);  
        }

        return;
}




/**
*@Description: try to start socket of 5g
*@Input: void: void
*@Return: void
*@author: chenzejun 20160323
*/
static void lbalance_try_netlink_5g(void)
{
        int retval;  

         // try to start 5g, Create a socket ,  if count > 8,  the dev hasn't 5g, don't start it.
        if (g_config.restart_5g_count < NETLINK_RESTART_MAX && g_config.sock_fd_5g <= 0)
        {
                // Create a socket 2.4G
                g_config.sock_fd_5g = libwl_create_netlink_socket(NETLINK_5G);
                if(g_config.sock_fd_5g < 0)
                {  
                        LBALANCE_DBG_PRINTF(LBALANCE_ERROR, "wifi 5g create socket failed: %s\n", strerror(errno));
                        g_config.restart_5g_count++;
                        return;  
                }  

                //add epoll
                retval = libwl_add_epoll(g_config.epoll_fd, g_config.sock_fd_5g); 
                if(retval != 0)
                {  
                        LBALANCE_DBG_PRINTF(LBALANCE_ERROR, "wifi 5g add epoll fail\n"); 
                        return;  
                } 
                
                (void)lbalance_sendmsg_2_kernel(g_config.sock_fd_5g);  
        }

        return;
}



/**
*@Description: try to close socket of 5g 2.4g
*@Input: void: void
*@Return: void
*@author: chenzejun 20160323
*/
static void lbalance_try_close_netlink(void)
{
         // try to close 5g socket
        if (g_config.sock_fd_5g > 0)
        {
                close(g_config.sock_fd_5g);
                g_config.sock_fd_5g = -1;
        }

        
        if (g_config.sock_fd_2g > 0)
        {
                close(g_config.sock_fd_2g);
                g_config.sock_fd_2g = -1;
        }
        

        return;
}


/*
*@Description: parse connect data
*@Input: pc_msg_data: pointer to the msg
*@Input: ui_msg_len: msglen
*@Return: 0: ok;   -1: fail
*@author: chenzejun 20160123
*/
static int lbalance_parse_conn_data(int fd, char *pc_msg_data, unsigned int ui_msg_len)
{

        AP_TLV_DATA *pst_tlv_data = (AP_TLV_DATA *)pc_msg_data;
        unsigned short us_count = 0;
        unsigned short find_flag = 0;
        unsigned int ui_temp_len = 0;
        LOACL_WLAN_INFO *pst_local = NULL;

        if (pc_msg_data == NULL)
        {
                return -1;
        }

        //if (lbalance_debug > 0)  printf("[in] lbalance add connect data, ui_msg_len: %d \n", ui_msg_len); 
        
        while(ui_temp_len < ui_msg_len && pst_tlv_data->us_tlv_len)
        {
                //printf("APP  Received ui_msg_len: %d, %d \n", ui_msg_len, pst_tlv_data->us_tlv_type); 

                if (pst_tlv_data->us_tlv_type >= AP_TLV_TYPE_MAX)
                {
                        LBALANCE_DBG_PRINTF(LBALANCE_WLAN_INFO, "break ui_msg_len: %d, %d \n", ui_msg_len, pst_tlv_data->us_tlv_type); 
                        break;
                }
                
                switch (pst_tlv_data->us_tlv_type)
                {
                        case AP_TLV_TYPE_CONN_COUNT:
                        {
                                find_flag = 1;
                                us_count = *(unsigned short *)(pst_tlv_data+1);
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
                

        // 2g or 5g
        if (fd == g_config.sock_fd_5g)
        {
                pst_local = &g_config.conn_5g;
                //pst_local->st_node.wlan_type = LBALANCE_WLAN_TYPE_5G;
        }
        else if (fd == g_config.sock_fd_2g)
        {
                pst_local = &g_config.conn_2g;
                //pst_local->st_node.wlan_type = LBALANCE_WLAN_TYPE_2G;
        }
        else
        {
                pst_local = NULL;
        }

        // find and valid
        if (1 == find_flag && pst_local && us_count)
        {
                pst_local->st_node.us_drv_count = us_count;
                pst_local->st_node.us_lb_count = (us_count > pst_local->lbalance_base) ? (us_count - pst_local->lbalance_base) : 0;
                pst_local->st_node.us_idle_count = 0;

                if (pst_local->lbalance_base)
                {
                        //local node to load balance
                        if (g_config.local_balance)     (void)lbalance_connect_add(&pst_local->st_node);
                        lbalance_send_mcast_msg(g_config.sock_fd_lbalance, pst_local);
                }
                
                //this not need. avoid the wifi all hide because the local count bump up. then update it in mcast msg 
                //this is to avoid all wifi close
                //the operation of close wifi must trigger by mcast package, not trigger by here. need delay close. 
                //lbalance_connect_compare_action(pst_local);

                LBALANCE_DBG_PRINTF(LBALANCE_WLAN_INFO, "[TLV] add msg, %s wlan; count:%d, us_lb_count:%d\n", 
                        (fd == g_config.sock_fd_2g) ? "2g" : "5g", us_count, pst_local->st_node.us_lb_count);
        }
        else
        {
                LBALANCE_DBG_PRINTF(LBALANCE_WLAN_INFO, "[TLV] add connect data; not found, us_count:%d\n", us_count);
        }

        return 0;
}

/*
*@Description: parse connect del data
*@Input: pc_msg_data: pointer to the msg
*@Input: ui_msg_len: msglen
*@Return: 0: ok;   -1: fail
*@author: chenzejun 20160123
*/
static int lbalance_parse_del_data(int fd, char *pc_msg_data, unsigned int ui_msg_len)
{
        STA_CONNECT_NODE *pst_node = NULL;
        AP_TLV_DATA *pst_tlv_data = (AP_TLV_DATA *)pc_msg_data;
        unsigned int ui_temp_len = 0;
        unsigned short find_flag;
        unsigned short us_count = 0;
        LOACL_WLAN_INFO *pst_local = NULL;

        if (pc_msg_data == NULL)
        {
                return -1;
        }


        //if (lbalance_debug > 0)  printf("[in] lbalance delete connect data, ui_msg_len: %d \n", ui_msg_len); 
        
        while(ui_temp_len < ui_msg_len && pst_tlv_data->us_tlv_len)
        {
                //printf("APP  Received ui_msg_len: %d, %d \n", ui_msg_len, pst_tlv_data->us_tlv_type); 

                if (pst_tlv_data->us_tlv_type >= AP_TLV_TYPE_MAX)
                {
                        LBALANCE_DBG_PRINTF(LBALANCE_WLAN_INFO, "break ui_msg_len: %d, %d \n", ui_msg_len, pst_tlv_data->us_tlv_type); 
                        break;
                }

                switch (pst_tlv_data->us_tlv_type)
                {
                        case AP_TLV_TYPE_CONN_COUNT:
                        {
                                find_flag = 1;
                                us_count = *(unsigned short *)(pst_tlv_data+1);
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


        // 2g or 5g
        if (fd == g_config.sock_fd_5g)
        {
                pst_local = &g_config.conn_5g;
                //pst_local->st_node.wlan_type = LBALANCE_WLAN_TYPE_5G;
        }
        else if (fd == g_config.sock_fd_2g)
        {
                pst_local = &g_config.conn_2g;
                //pst_local->st_node.wlan_type = LBALANCE_WLAN_TYPE_2G;
        }
        else
        {
                pst_local = NULL;
        }

        
        // find and valid
        if (1 == find_flag && pst_local)
        {
                pst_local->st_node.us_drv_count = us_count;
                pst_local->st_node.us_lb_count = (us_count > pst_local->lbalance_base) ? (us_count - pst_local->lbalance_base) : 0;
                pst_local->st_node.us_idle_count = 0;

                if (pst_local->lbalance_base)
                {       
                        //connect_add for update count
                        if (g_config.local_balance)     (void)lbalance_connect_add(&pst_local->st_node);
                        lbalance_send_mcast_msg(g_config.sock_fd_lbalance, pst_local);
                }
                
                lbalance_connect_compare_action(pst_local);
                
                LBALANCE_DBG_PRINTF(LBALANCE_WLAN_INFO, "[TLV] delete msg, %s wlan; count:%d, us_lb_count:%d\n", 
                        (fd == g_config.sock_fd_2g) ? "2g" : "5g", us_count, pst_local->st_node.us_lb_count);
        }
        else
        {
                LBALANCE_DBG_PRINTF(LBALANCE_WLAN_INFO, "[TLV] delete connect data; not found, us_count:%d\n", us_count);
        }

        return 0;
}


/**
*@Description: age the node
*@Input:over_num: the time
*@return: void
*@author: chenzejun 20160123
if the mac is being hit by query, then clear us_idle_count.
*/
static void lbalance_connect_data_age(ushort over_num)
{
        ALIST_HEAD *p_info = &connect_info;
        STA_CONNECT_NODE  *pst_connect = NULL;
        LOACL_WLAN_INFO *pst_local = NULL;
        int i = 0;
        unsigned int age_flag = 0;

        //connect data for age
        libwl_alist_for_entry(pst_connect, i,  p_info) 
        {
                if (pst_connect == NULL)  break;
                
                // local node is not age
                pst_local = &g_config.conn_2g;
                if (pst_connect->ac_mac[0] == pst_local->st_node.ac_mac[0] &&
                    pst_connect->ac_mac[1] == pst_local->st_node.ac_mac[1] &&
                    pst_connect->ac_mac[2] == pst_local->st_node.ac_mac[2] &&
                    pst_connect->ac_mac[3] == pst_local->st_node.ac_mac[3] &&
                    pst_connect->ac_mac[4] == pst_local->st_node.ac_mac[4] &&
                    pst_connect->ac_mac[5] == pst_local->st_node.ac_mac[5])
                {
                        continue;
                }

                // local node is not age
                pst_local = &g_config.conn_5g;
                if (pst_connect->ac_mac[0] == pst_local->st_node.ac_mac[0] &&
                    pst_connect->ac_mac[1] == pst_local->st_node.ac_mac[1] &&
                    pst_connect->ac_mac[2] == pst_local->st_node.ac_mac[2] &&
                    pst_connect->ac_mac[3] == pst_local->st_node.ac_mac[3] &&
                    pst_connect->ac_mac[4] == pst_local->st_node.ac_mac[4] &&
                    pst_connect->ac_mac[5] == pst_local->st_node.ac_mac[5])
                {
                        continue;
                }


                // external node, age 
                pst_connect->us_idle_count++;   //entry count

                //timeout to age
                if (pst_connect->us_idle_count > over_num)
                {
                        LBALANCE_DBG_PRINTF(LBALANCE_WLAN_INFO, "[age] connect data; idle_count:%d; i:%d, tail_id:%d, mac:%02X %02X %02X %02X %02X %02X \n",
                                pst_connect->us_idle_count, i, p_info->tail_id,
                                pst_connect->ac_mac[0], pst_connect->ac_mac[1], pst_connect->ac_mac[2], 
                                pst_connect->ac_mac[3], pst_connect->ac_mac[4], pst_connect->ac_mac[5]); 

                        lbalance_connect_del(pst_connect->ac_mac);
                        age_flag = 1;
                }   
        }

        if (age_flag)
        {
                if (g_config.sock_fd_2g > 0)       lbalance_connect_compare_action(&g_config.conn_2g);
                if (g_config.sock_fd_5g > 0)       lbalance_connect_compare_action(&g_config.conn_5g);
        }

        return;
}




/**
*@Description: the callback function of netlink
*@Input: u: the file description of uloop
*@Input: ev: the event of uloop
*@Return: void
*@author: chenzejun 20160323
*/
static void lbalance_netlink_handler(int sock_fd)
{
        int retval;  

        while(1)  
        {
                retval = recvfrom(sock_fd, (char *)nl_header, MAX_PAYLOAD, 0, NULL, NULL);
                if(retval < 0)
                {
                        if(errno != EAGAIN)  
                        {
                                LBALANCE_DBG_PRINTF(LBALANCE_WLAN_INFO, "recvmsg end fd:%d, errno:%d, ret:%d\n", sock_fd, errno, retval); 
                        }

                        break;
                }

                
                //parse data
                if (AP_MSG_TYPE_CONNECT == nl_header->nlmsg_type)
                {
                        LBALANCE_DBG_PRINTF(LBALANCE_WLAN_INFO, "[in] add connect data, fd:%d\n", sock_fd); 
                        (void)lbalance_parse_conn_data(sock_fd, NLMSG_DATA(nl_header), (nl_header->nlmsg_len - NLMSG_HDRLEN));
                        LBALANCE_DBG_PRINTF(LBALANCE_WLAN_INFO, "[out] add connect data, fd:%d\n", sock_fd); 
                }
                else if (AP_MSG_TYPE_CONN_DEL == nl_header->nlmsg_type)
                {
                        LBALANCE_DBG_PRINTF(LBALANCE_WLAN_INFO, "[in] delete connect data, fd:%d\n", sock_fd); 
                        (void)lbalance_parse_del_data(sock_fd, NLMSG_DATA(nl_header), (nl_header->nlmsg_len - NLMSG_HDRLEN));
                        LBALANCE_DBG_PRINTF(LBALANCE_WLAN_INFO, "[out] delete connect data, fd:%d\n", sock_fd); 
                }
        }
        
        return;

}

/**
*@Description: mqtt client connect up test
*@Input: ac_mac: mac address
*@Input: uc_type_wifi: type
*@Input: uc_signal: signal
*@Input: ui_count: count
*@Return:  0: ok
           <0: fail
*@author: chenzejun 20160323
*/
int lbalance_connect_up_test(const unsigned char ac_mac[], unsigned char uc_type_wifi, unsigned char uc_signal, unsigned short ui_count)
{
        char msg[512] = {0};
        AP_TLV_DATA *pst_tlv_data;
        char  *pc_msg_data = msg; 
        int slen = 0;  


        //tlv:  mac addr
        pc_msg_data =  (char *)msg;  
        pst_tlv_data = (AP_TLV_DATA *)pc_msg_data;
        pst_tlv_data->us_tlv_type = AP_TLV_TYPE_MAC;
        pst_tlv_data->us_tlv_len =  sizeof(AP_TLV_DATA) + MAC_LEN_6;
        memcpy((char *)(pst_tlv_data + 1), ac_mac, MAC_LEN_6);  
        slen = slen + pst_tlv_data->us_tlv_len;

        //tlv: type_wifi
        pc_msg_data = pc_msg_data + pst_tlv_data->us_tlv_len;
        pst_tlv_data = (AP_TLV_DATA *)pc_msg_data;
        pst_tlv_data->us_tlv_type = AP_TLV_TYPE_WIFI_TYPE;
        pst_tlv_data->us_tlv_len =  sizeof(AP_TLV_DATA) + sizeof(uc_type_wifi);
        memcpy((char *)(pst_tlv_data + 1), &uc_type_wifi, sizeof(uc_type_wifi));  
        slen = slen + pst_tlv_data->us_tlv_len; 

        //tlv: signal
        pc_msg_data = pc_msg_data + pst_tlv_data->us_tlv_len;
        pst_tlv_data = (AP_TLV_DATA *)pc_msg_data;
        pst_tlv_data->us_tlv_type = AP_TLV_TYPE_TX_POWER;
        pst_tlv_data->us_tlv_len =  sizeof(AP_TLV_DATA) + sizeof(uc_signal);
        memcpy((char *)(pst_tlv_data + 1), &uc_signal, sizeof(uc_signal));  
        slen = slen + pst_tlv_data->us_tlv_len; 

	//tlv: sta count on ic
        pc_msg_data = pc_msg_data + pst_tlv_data->us_tlv_len;
        pst_tlv_data = (AP_TLV_DATA *)pc_msg_data;
        pst_tlv_data->us_tlv_type = AP_TLV_TYPE_CONN_COUNT;
        pst_tlv_data->us_tlv_len =  sizeof(AP_TLV_DATA) + sizeof(ui_count);
        memcpy((char *)(pst_tlv_data + 1), &ui_count, sizeof(ui_count));
        slen = slen + pst_tlv_data->us_tlv_len;
       
        //printk("kernel send message");  
        
        (void)lbalance_parse_conn_data(g_config.sock_fd_5g, msg, slen);

        return;
}


/**
*@Description: mqtt client connect down test
*@Input: ac_mac: mac address
*@Input: uc_type_wifi: type
*@Input: uc_signal: signal
*@Input: ui_count: count
*@Return:  0: ok
           <0: fail
*@author: chenzejun 20160323
*/void lbalance_connect_down_test(const unsigned char ac_mac[], unsigned short ui_count)  
{  
        char msg[512] = {0};
        AP_TLV_DATA *pst_tlv_data;
        char  *pc_msg_data = msg; 
        int slen = 0;  


        //tlv:  mac addr
        pc_msg_data =  (char *)msg;  
        pst_tlv_data = (AP_TLV_DATA *)pc_msg_data;
        pst_tlv_data->us_tlv_type = AP_TLV_TYPE_MAC;
        pst_tlv_data->us_tlv_len =  sizeof(AP_TLV_DATA) + MAC_LEN_6;
        memcpy((char *)(pst_tlv_data + 1), ac_mac, MAC_LEN_6);  
        slen = slen + pst_tlv_data->us_tlv_len;

	//tlv: count
        pc_msg_data = pc_msg_data + pst_tlv_data->us_tlv_len;
        pst_tlv_data = (AP_TLV_DATA *)pc_msg_data;
        pst_tlv_data->us_tlv_type = AP_TLV_TYPE_CONN_COUNT;
        pst_tlv_data->us_tlv_len =  sizeof(AP_TLV_DATA) + sizeof(ui_count);
        memcpy((char *)(pst_tlv_data + 1), &ui_count, sizeof(ui_count));
        slen = slen + pst_tlv_data->us_tlv_len;

        //printk("kernel send message");  
        (void)lbalance_parse_del_data(g_config.sock_fd_5g, msg, slen);
        return;
}  



#endif




#if FUNCTION_DESC("file notifiy function")

static char *inotify_path[] = {
        "/etc/config/wireless",
        "/etc/config/network",
};
static char inotify_buffer[BUF_LEN_256] = {0};



/**
*@Description: the callback function of inotify
*@Input: u: the file description of uloop
*@Input: ev: the event of uloop
*@Return: void
*@author: chenzejun 20160323
*/
static void lbalance_inotify_handler(int sock_fd)
{
        int i = 0;  
        int length = 0;
        int temp_len = 0;
        struct inotify_event *event = NULL;  
        int wd;

        LBALANCE_DBG_PRINTF(LBALANCE_INOTIFY_INFO, "handle inotify enter:%d\n", sock_fd);
       
        while(1)
        {
                //read file
                length = read(sock_fd, inotify_buffer, BUF_LEN_256);
                if (length <= 0)
                {
                        if(errno != EAGAIN)  
                        {
                                // EAGAIN 
                                LBALANCE_DBG_PRINTF(LBALANCE_INOTIFY_INFO, "inotify read length:%d, error:%s\n", length, strerror(errno));
                        }
                        break;
                }
                
                LBALANCE_DBG_PRINTF(LBALANCE_INOTIFY_INFO, "inotify fd:%d, read length:%d\n", sock_fd, length);

                //parse buffer

                temp_len = 0;
                while (temp_len < length)   
                {  
                        event = (struct inotify_event *) &inotify_buffer[i];  
                        if (event->mask & IN_MODIFY)   
                        {
                                LBALANCE_DBG_PRINTF(LBALANCE_INOTIFY_INFO, "IN_MODIFY, inotify:%d, length:%d, event->mask:0x%x\n", sock_fd, length, event->mask);
                        }
                        else if (event->mask & IN_ATTRIB)
                        {
                                // if use uci set and uci commit, it trigger remove wd, the reason is unknow.
                                // if path is not change, wd of return is not change
                                // if path is already remove. return value of inotify_add_watch will be increase
                                for(i = 0; i < sizeof(inotify_path)/sizeof(inotify_path[0]); i++)   
                                {
                                        wd = inotify_add_watch(g_config.inotify_fd_config, inotify_path[i], IN_ALL_EVENTS);
                                        LBALANCE_DBG_PRINTF(LBALANCE_INOTIFY_INFO, "inotify, i:%d, inotify_path:%s, wd:%d\n", i, inotify_path[i], wd);
                                }
                        }
                        

                        LBALANCE_DBG_PRINTF(LBALANCE_INOTIFY_INFO, "i:%d, length:%d, event->len:0x%x, mask:0x%x, wd:%d\n", temp_len, length, event->len, event->mask, event->wd);

                        temp_len += sizeof (struct inotify_event) + event->len;  
                }  
        }

        LBALANCE_DBG_PRINTF(LBALANCE_INOTIFY_INFO, "handle inotify exit.\n");

        return;
}


/**
 *@Description: create inotify
 *@Input: void: void
 *@Return: 0: ok;   -1: fail
 *@author: chenzejun 20160323
 */
static int lbalance_create_inotify(void)
{
        int inotify_fd;
        int wd;
        int i;

        inotify_fd = inotify_init();
        if(inotify_fd  < 0)  
        {
                LBALANCE_DBG_PRINTF(LBALANCE_ERROR, "inotify_init failed\n");
                return -1;
        }

        
        for (i = 0; i < sizeof(inotify_path)/sizeof(inotify_path[0]); i++)
        {
                LBALANCE_DBG_PRINTF(LBALANCE_INFO, "inotify path:%s\n", inotify_path[i]); 

                wd = inotify_add_watch(inotify_fd, inotify_path[i], IN_ALL_EVENTS);
                if (wd < 0)
                {
                        LBALANCE_DBG_PRINTF(LBALANCE_ERROR, "inotify_add_watch failed\n");
                        return -1;
                }
        }

        return inotify_fd;        
}




/**
 *@Description: init inotify fd
 *@Input: void: void
 *@Return: 0: ok;   -1: fail
 *@author: chenzejun 20160323
 */
static int lbalance_inotify_init(void)
{
        int retval;  

        /* inotify_fd_config service*/
        if (g_config.inotify_fd_config < 0)
        {
                // Create a inotify fd
                g_config.inotify_fd_config = lbalance_create_inotify();
                if(g_config.inotify_fd_config < 0)
                {  
                        LBALANCE_DBG_PRINTF(LBALANCE_ERROR, "inotify create socket failed: %s\n", strerror(errno));
                        return -1;  
                }  

                //add epoll
                retval = libwl_add_epoll(g_config.epoll_fd, g_config.inotify_fd_config); 
                if(retval != 0)
                {  
                        LBALANCE_DBG_PRINTF(LBALANCE_ERROR, "inotify add epoll fail\n"); 
                        return -1;  
                }              
        }

        LBALANCE_DBG_PRINTF(LBALANCE_INFO, "inotify add epoll ok\n"); 
        return 0;
}



/**
 *@Description: destroy inotify fd
*@Input: void: void
 *@Return: 0: ok;   -1: fail
 *@author: chenzejun 20160323
 */
static int lbalance_inotify_destroy(void)
{
        //if (g_config.inotify_fd_config)
        //{
        //        (void) inotify_rm_watch(g_config.inotify_fd_config, g_watcher);
        //}
        
        if (g_config.inotify_fd_config)
        {
                close(g_config.inotify_fd_config);    //it will delete all watcher description
                g_config.inotify_fd_config = -1;
        }
        return 0;
}

#endif




#if FUNCTION_DESC("socket function")


/**
*@Description: receive msg by epoll
*@Input: void: void
*@Return:  0: ok
           <0: fail
*@author: chenzejun 20160323
*/
static int lbalance_epoll_wait_msg(void)
{
        int retval;  
        struct epoll_event events[MAXEPOLLSIZE];  
        int num, i;  

        // Read message from kernel  
        while (1)
        {
                
                //epoll wait package
                num = epoll_wait (g_config.epoll_fd , events, MAXEPOLLSIZE, -1);  
                for (i = 0; i < num; i++)  
                {  
                        //LBALANCE_DBG_PRINTF(LBALANCE_INFO, "epoll wait ok, num:%d, fd:%d\n", num,  events[i].data.fd);  

                        if ((events[i].events & EPOLLERR) || (events[i].events & EPOLLHUP) || (!(events[i].events & EPOLLIN)))  
                        {  
                                /* An error has occured on this fd, or the socket is not ready for reading (why were we notified then?) */  
                                LBALANCE_DBG_PRINTF(LBALANCE_ERROR, "epoll_wait error, %d, %d, %d\n", i, events[i].data.fd, events[i].events);  
                                continue;  
                        }  
                        else if (g_config.sock_fd_lbalance == events[i].data.fd) 
                        {
                                LBALANCE_DBG_PRINTF(LBALANCE_INFO, "sock_fd_lbalance, fd:%d\n", events[i].data.fd);  
                                lbalance_socket_mcast_handle(events[i].data.fd);
                        }  
                        else if (g_config.sock_fd_ipaddr == events[i].data.fd) 
                        {
                                LBALANCE_DBG_PRINTF(LBALANCE_INFO, "sock_fd_ipaddr, fd:%d\n", events[i].data.fd);  
                                lbalance_socket_ipaddr_handle(events[i].data.fd);
                        }  
                        else if (g_config.sock_fd_ifstatus == events[i].data.fd) 
                        {
                                LBALANCE_DBG_PRINTF(LBALANCE_INFO, "sock_fd_ifstatus, fd:%d\n", events[i].data.fd);  
                                lbalance_socket_ifstatus_handle(events[i].data.fd);
                        }   
                        else if (g_config.sock_fd_cmd == events[i].data.fd) 
                        {
                                LBALANCE_DBG_PRINTF(LBALANCE_INFO, "sock_fd_cmd, fd:%d\n", events[i].data.fd);  
                                lbalance_cmd_socket_handle(events[i].data.fd);
                        }   
                        else if (g_config.sock_fd_5g == events[i].data.fd) 
                        {
                                //LBALANCE_DBG_PRINTF(LBALANCE_INFO, "sock_fd_5g, fd:%d\n", events[i].data.fd);  
                                lbalance_netlink_handler(events[i].data.fd);
                        } 
                        else if (g_config.sock_fd_2g == events[i].data.fd) 
                        {
                                //LBALANCE_DBG_PRINTF(LBALANCE_INFO, "sock_fd_2g, fd:%d\n", events[i].data.fd);  
                                lbalance_netlink_handler(events[i].data.fd);
                        }
                        else if (g_config.inotify_fd_config == events[i].data.fd) 
                        {
                                LBALANCE_DBG_PRINTF(LBALANCE_INFO, "inotify_fd_config, fd:%d\n", events[i].data.fd);  
                                lbalance_inotify_handler(events[i].data.fd);
                        }
                }
        }

        return 0;
}

/**
*@Description: create epoll
*@Input: pc_key: pointer to mac address
*@Return:  0: ok
           <0: fail
*@author: chenzejun 20160323
*/
static int lbalance_epoll_socket_create(void)
{
        int retval;  

        if (g_config.epoll_fd < 0)
        {
                /* create tpoll handle */
                g_config.epoll_fd = epoll_create(MAXEPOLLSIZE);
                if(g_config.epoll_fd  < 0)
                {  
                        LBALANCE_DBG_PRINTF(LBALANCE_ERROR, "epoll create fail: %s\n", strerror(errno));  
                        return -1;  
                }  
        }


        /* checking of ip conflict */
        if (g_config.sock_fd_ipaddr < 0)
        {
                // Create a socket ip
                g_config.sock_fd_ipaddr = lbalance_create_ipaddr_socket(NETLINK_ROUTE);
                if(g_config.sock_fd_ipaddr < 0)
                {  
                        LBALANCE_DBG_PRINTF(LBALANCE_ERROR, "ipaddr create socket failed: %s\n", strerror(errno));
                        return -1;  
                }  

                //add epoll
                retval = libwl_add_epoll(g_config.epoll_fd, g_config.sock_fd_ipaddr); 
                if(retval != 0)
                {  
                        LBALANCE_DBG_PRINTF(LBALANCE_ERROR, "ipaddr add epoll fail\n"); 
                        return -1;  
                }
                
                LBALANCE_DBG_PRINTF(LBALANCE_INFO, "ipaddr create socket ok, fd:%d\n", g_config.sock_fd_ipaddr);  
        }

        /* checking of ifstatus */
        if (g_config.sock_fd_ifstatus < 0)
        {
                // Create a socket ip
                g_config.sock_fd_ifstatus = lbalance_create_ifstatus_socket(NETLINK_ROUTE);
                if(g_config.sock_fd_ifstatus < 0)
                {  
                        LBALANCE_DBG_PRINTF(LBALANCE_ERROR, "ifstatus create socket failed: %s\n", strerror(errno));
                        return -1;  
                }  

                //add epoll
                retval = libwl_add_epoll(g_config.epoll_fd, g_config.sock_fd_ifstatus); 
                if(retval != 0)
                {  
                        LBALANCE_DBG_PRINTF(LBALANCE_ERROR, "ifstatus add epoll fail\n"); 
                        return -1;  
                }
                
                LBALANCE_DBG_PRINTF(LBALANCE_INFO, "ifstatus create socket ok, fd:%d\n", g_config.sock_fd_ifstatus);  
        }


        

        return 0;
}


/**
*@Description: destroy epoll
*@Input: pc_key: pointer to mac address
*@Return:  0: ok
           <0: fail
*@author: chenzejun 20160323
*/
static void lbalance_epoll_socket_destroy(void)
{
        if (g_config.sock_fd_lbalance > 0)  
        {
                close(g_config.sock_fd_lbalance);
                g_config.sock_fd_lbalance = -1;
        }

        if (g_config.sock_fd_ifstatus > 0)  
        {
                close(g_config.sock_fd_ifstatus);
                g_config.sock_fd_ifstatus = -1;
        }
        
        if (g_config.sock_fd_ipaddr > 0)  
        {
                close(g_config.sock_fd_ipaddr);
                g_config.sock_fd_ipaddr = -1;
        }
        
        if (g_config.sock_fd_2g > 0)  
        {
                close(g_config.sock_fd_2g);
                g_config.sock_fd_2g = -1;
        }
        
        if (g_config.sock_fd_5g > 0)  
        {
                close(g_config.sock_fd_5g);
                g_config.sock_fd_5g = -1;
        }

        if (g_config.epoll_fd > 0)
        {
                close(g_config.epoll_fd);
                g_config.epoll_fd = -1;
        }
        return;
}


/**
*@Description: create epoll main process
*@Input: void: void
*@Return:  0: ok
           <0: fail
*@author: chenzejun 20160323
*/
static int lbalance_epoll_main(void)
{
        int retval;  
        LOACL_WLAN_INFO *pst_local = NULL;
        int count = 0;  


        lbalance_update_config();


        // 2g
        pst_local = &g_config.conn_2g;
        retval = libwl_get_access_amount("ralink", pst_local->ac_ifname, &count);
        if (retval < 0)
        {
                retval = libwl_get_access_amount("qca", pst_local->ac_ifname, &count);
        }
        
        if (retval == 0)
        {
                pst_local->st_node.us_drv_count = count;
                pst_local->st_node.us_lb_count = (count > pst_local->lbalance_base) ? (count - pst_local->lbalance_base) : 0;
                pst_local->st_node.us_idle_count = 0;
                if (pst_local->lbalance_base)
                {
                        //local node to load balance
                        if (g_config.local_balance)     (void)lbalance_connect_add(&pst_local->st_node);
                }
        }

        
        //5g
        pst_local = &g_config.conn_5g;
        retval = libwl_get_access_amount("ralink", pst_local->ac_ifname, &count);
        if (retval < 0)
        {
                retval = libwl_get_access_amount("qca", pst_local->ac_ifname, &count);
        }

        if (retval == 0)
        {
                pst_local->st_node.us_drv_count = count;
                pst_local->st_node.us_lb_count = (count > pst_local->lbalance_base) ? (count - pst_local->lbalance_base) : 0;
                pst_local->st_node.us_idle_count = 0;
                if (pst_local->lbalance_base)
                {
                        //local node to load balance
                        if (g_config.local_balance)     (void)lbalance_connect_add(&pst_local->st_node);
                }
        }


        /**/
        retval = lbalance_epoll_socket_create();
        if(retval != 0)
        {  
                LBALANCE_DBG_PRINTF(LBALANCE_ERROR, "create epoll socket fail\n"); 
                goto fail;
        } 

        // if wan is not up, this init will fail,  it return fail in follow
        // setsockopt(sock_fd, IPPROTO_IP, IP_ADD_MEMBERSHIP, ..); return "Cannot assign requested address"
        // so, need jude if wan up.
        lbalance_try_create_mcast();

        /**/
        retval = lbalance_cmd_init();
        if(retval != 0)
        {  
                LBALANCE_DBG_PRINTF(LBALANCE_ERROR, "cmd create epoll socket fail\n"); 
                goto fail;
        } 
       
        LBALANCE_DBG_PRINTF(LBALANCE_INFO, "waiting receive msg... \n");  


        // Read message from kernel  
        retval = lbalance_epoll_wait_msg();
        if(retval != 0)
        {  
                LBALANCE_DBG_PRINTF(LBALANCE_ERROR, "epoll wait return error\n"); 
                goto fail;
        }  

fail:        
        lbalance_cmd_destroy();
        lbalance_try_close_mcast();
        lbalance_epoll_socket_destroy();
        return 0;
}
#endif








#if FUNCTION_DESC("timer function")



/**
*@Description: create timer
*@Input: void: void
*@Return: 0: ok;   -1: fail
*@author: chenzejun 20160323
*/
void lbalance_sigroutine(int signo)
{
        LBALANCE_DBG_PRINTF(LBALANCE_TIMER_INFO, "[in] 10s timer.... \n"); 

        if (signo != SIGALRM)
        {
                return;
        }

        signal(SIGALRM, lbalance_sigroutine);

        //lbalance_printf_currtime();

        if (g_config.sock_fd_2g > 0)        lbalance_send_mcast_msg(g_config.sock_fd_lbalance, &g_config.conn_2g);
        if (g_config.sock_fd_5g > 0)        lbalance_send_mcast_msg(g_config.sock_fd_lbalance, &g_config.conn_5g);
        
        lbalance_time_get_config();

        lbalance_try_netlink_2g();
        lbalance_try_netlink_5g();


        lbalance_connect_data_age(0x3);

        lbalance_time_check_channel(60);

        return;
}

/**
*@Description: create timer
*@Input: void: void
*@Return: 0: ok;   -1: fail
*@author: chenzejun 20160323
*/
static int lbalance_timer_create(void)
{
        struct itimerval value, ovalue;          //(1)
        
        signal(SIGALRM, lbalance_sigroutine);

        /* 10 sec */
        value.it_value.tv_sec = 8;
        value.it_value.tv_usec = 0;
        value.it_interval.tv_sec = 8;
        value.it_interval.tv_usec = 0;
        setitimer(ITIMER_REAL, &value, &ovalue);

        LBALANCE_DBG_PRINTF(LBALANCE_INFO, "create timer, process id is %d \n", getpid());

        return 0;
}


/**
*@Description: signal handle function
*@Input: signo: signo
*@return: 0 ok;  1- fail
*@author: chenzejun 20160123
        this feature reslove umac.ko not unload in qca device
        notce signal to process for close netlink socket
        ralink device has not this issue, it don't unload mt76*.ko
        SIGUSR1 is create netlink socket
        SIGUSR2 is close netlink socket
*/
static void lbalance_signal_handle(int signo)
{
        if (signo == SIGUSR1)
        {
                LBALANCE_DBG_PRINTF(LBALANCE_TIMER_INFO, "signal handle, signo is SIGUSR1\n");
                g_config.restart_5g_count = 0;
                g_config.restart_2g_count = 0;
        }
        else if (signo == SIGUSR2)
        {
                LBALANCE_DBG_PRINTF(LBALANCE_TIMER_INFO, "signal handle, signo is SIGUSR2\n");
                g_config.restart_5g_count = -1;
                g_config.restart_2g_count = -1;
                lbalance_try_close_netlink();
        }

        return;
}



/**
*@Description: signal setup
*@Input: void: void
*@return: void;  void
*@author: chenzejun 20160123
*/
static void lbalance_signal_setup(void)
{
        signal(SIGUSR1, lbalance_signal_handle);
        signal(SIGUSR2, lbalance_signal_handle);
        return;
}



#endif


#if FUNCTION_DESC("option function")

static char g_lock_file[] = "/var/lock/lbalance.lock";


/**
 *@Description: show loadbalance config
 *@Input: buffer
 *@Input: buff_size
 *@Return: 0: ok;   -1: fail
 *@author: chenzejun 20160323
 */
static int lbalance_show_config(char *buffer, int buff_size)
{
        int  buf_len = 0;  
        time_t timep;
        struct tm *p_tm;


        if (buffer == NULL)    return 0;

        //time
        time(&timep);
        p_tm = localtime(&timep);
        buf_len += snprintf(&buffer[buf_len], (buff_size - buf_len), "%-30s: %d%02d%02d %02d:%02d:%02d\n", "local time",
                        (1900+p_tm->tm_year), (1+p_tm->tm_mon), p_tm->tm_mday, p_tm->tm_hour, p_tm->tm_min, p_tm->tm_sec);

        p_tm = localtime(&g_config.uptime);
        buf_len += snprintf(&buffer[buf_len], (buff_size - buf_len), "%-30s: %d%02d%02d %02d:%02d:%02d\n", "start time",
                        (1900+p_tm->tm_year), (1+p_tm->tm_mon), p_tm->tm_mday, p_tm->tm_hour, p_tm->tm_min, p_tm->tm_sec);
                        
        buf_len += snprintf(&buffer[buf_len], (buff_size - buf_len), "%-30s: %s\n", "version", g_config.version);
        buf_len += snprintf(&buffer[buf_len], (buff_size - buf_len), "%-30s: %s\n", "wan_name", g_config.wan_name);
        buf_len += snprintf(&buffer[buf_len], (buff_size - buf_len), "%-30s: %s\n", "route_ip", g_config.wan_ip);
        buf_len += snprintf(&buffer[buf_len], (buff_size - buf_len), "%-30s: %s\n", "wan_status", (g_config.wan_status == 2) ? "unknown" : (g_config.wan_status ? "up" : "down"));
        buf_len += snprintf(&buffer[buf_len], (buff_size - buf_len), "%-30s: %d\n", "connect.cfg_num", connect_info.cfg_num);
        buf_len += snprintf(&buffer[buf_len], (buff_size - buf_len), "%-30s: %s\n", "mcast_addr", g_config.mcast_addr);
        buf_len += snprintf(&buffer[buf_len], (buff_size - buf_len), "%-30s: %d\n", "mcast_port", g_config.mcast_port);
        buf_len += snprintf(&buffer[buf_len], (buff_size - buf_len), "%-30s: %d\n", "local_balance", g_config.local_balance);
        buf_len += snprintf(&buffer[buf_len], (buff_size - buf_len), "%-30s: %d\n\n", "sock_fd_lbalance", g_config.sock_fd_lbalance);
        
        
        buf_len += snprintf(&buffer[buf_len], (buff_size - buf_len), "%-30s: %02X%02X%02X%02X%02X%02X\n", "2g.ac_mac", 
                        g_config.conn_2g.st_node.ac_mac[0], g_config.conn_2g.st_node.ac_mac[1], g_config.conn_2g.st_node.ac_mac[2], 
                        g_config.conn_2g.st_node.ac_mac[3], g_config.conn_2g.st_node.ac_mac[4], g_config.conn_2g.st_node.ac_mac[5]);
        buf_len += snprintf(&buffer[buf_len], (buff_size - buf_len), "%-30s: %s\n", "2g.ac_ifname", g_config.conn_2g.ac_ifname);
        buf_len += snprintf(&buffer[buf_len], (buff_size - buf_len), "%-30s: %d\n", "2g.channel", g_config.conn_2g.st_node.channel);
        buf_len += snprintf(&buffer[buf_len], (buff_size - buf_len), "%-30s: %s\n", "2g.ac_ssid", g_config.conn_2g.st_node.ac_ssid);
        buf_len += snprintf(&buffer[buf_len], (buff_size - buf_len), "%-30s: %s\n", "2g.wifi_status", (g_config.conn_2g.wifi_status == WIFI_STATUS_CLOSE) ? "close" : "open");
        buf_len += snprintf(&buffer[buf_len], (buff_size - buf_len), "%-30s: %d\n", "2g.lbalance_base", g_config.conn_2g.lbalance_base);
        buf_len += snprintf(&buffer[buf_len], (buff_size - buf_len), "%-30s: %d\n", "2g.lbalance_group", g_config.conn_2g.st_node.group_id);
        buf_len += snprintf(&buffer[buf_len], (buff_size - buf_len), "%-30s: %d\n", "2g.keepup_amount",  g_config.conn_2g.keepup_amount);
        buf_len += snprintf(&buffer[buf_len], (buff_size - buf_len), "%-30s: %d\n", "2g.lbalance_count", g_config.conn_2g.st_node.us_lb_count);
        buf_len += snprintf(&buffer[buf_len], (buff_size - buf_len), "%-30s: %d\n", "2g.drv_count", g_config.conn_2g.st_node.us_drv_count);
        buf_len += snprintf(&buffer[buf_len], (buff_size - buf_len), "%-30s: %d\n", "2g.sock_fd_2g", g_config.sock_fd_2g);
        buf_len += snprintf(&buffer[buf_len], (buff_size - buf_len), "%-30s: %d\n", "2g.restart_2g_count", g_config.restart_2g_count);
        buf_len += snprintf(&buffer[buf_len], (buff_size - buf_len), "%-30s: %d\n", "2g.reset_channel_cnt", g_config.conn_2g.st_node.reset_channel_cnt);

        buf_len += snprintf(&buffer[buf_len], (buff_size - buf_len), "\n%-30s: %02X%02X%02X%02X%02X%02X\n", "5g.ac_mac", 
                        g_config.conn_5g.st_node.ac_mac[0], g_config.conn_5g.st_node.ac_mac[1], g_config.conn_5g.st_node.ac_mac[2], 
                        g_config.conn_5g.st_node.ac_mac[3], g_config.conn_5g.st_node.ac_mac[4], g_config.conn_5g.st_node.ac_mac[5]);
        buf_len += snprintf(&buffer[buf_len], (buff_size - buf_len), "%-30s: %s\n", "5g.ac_ifname", g_config.conn_5g.ac_ifname);
        buf_len += snprintf(&buffer[buf_len], (buff_size - buf_len), "%-30s: %d\n", "5g.channel", g_config.conn_5g.st_node.channel);
        buf_len += snprintf(&buffer[buf_len], (buff_size - buf_len), "%-30s: %s\n", "5g.ac_ssid", g_config.conn_5g.st_node.ac_ssid);
        buf_len += snprintf(&buffer[buf_len], (buff_size - buf_len), "%-30s: %s\n", "5g.wifi_status", (g_config.conn_5g.wifi_status == WIFI_STATUS_CLOSE) ? "close" : "open");
        buf_len += snprintf(&buffer[buf_len], (buff_size - buf_len), "%-30s: %d\n", "5g.lbalance_base", g_config.conn_5g.lbalance_base);
        buf_len += snprintf(&buffer[buf_len], (buff_size - buf_len), "%-30s: %d\n", "5g.lbalance_group", g_config.conn_5g.st_node.group_id);
        buf_len += snprintf(&buffer[buf_len], (buff_size - buf_len), "%-30s: %d\n", "5g.keepup_amount",  g_config.conn_5g.keepup_amount);
        buf_len += snprintf(&buffer[buf_len], (buff_size - buf_len), "%-30s: %d\n", "5g.lbalance_count", g_config.conn_5g.st_node.us_lb_count);
        buf_len += snprintf(&buffer[buf_len], (buff_size - buf_len), "%-30s: %d\n", "5g.drv_count", g_config.conn_5g.st_node.us_drv_count);
        buf_len += snprintf(&buffer[buf_len], (buff_size - buf_len), "%-30s: %d\n", "5g.sock_fd_5g", g_config.sock_fd_5g);
        buf_len += snprintf(&buffer[buf_len], (buff_size - buf_len), "%-30s: %d\n", "5g.restart_5g_count", g_config.restart_5g_count);
        buf_len += snprintf(&buffer[buf_len], (buff_size - buf_len), "%-30s: %d\n", "5g.reset_channel_cnt", g_config.conn_5g.st_node.reset_channel_cnt);
        
        LBALANCE_DBG_PRINTF(LBALANCE_CMD_TRACE, "lbalance_show_config, buf_len:%d\n", buf_len);  

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
static int lbalance_show_connect(char *buffer, int buff_size)
{
        static int last_id = 0;
        ALIST_HEAD *p_info = &connect_info;
        STA_CONNECT_NODE  *pst_connect = NULL;
        int i = 0;
        int  buf_len = 0;  


        if (buffer == NULL)    return 0;

        if (p_info->node_count <= 0)
        {
                buf_len += snprintf(&buffer[buf_len], (buff_size - buf_len), "connect list count is 0\n");
                return buf_len;
        }
        else
        {
                buf_len += snprintf(&buffer[buf_len], (buff_size - buf_len), "no\tmac address\t\tssid\t\t\t\t\tgroup\ttype\tlbcount\tdrvcount\n");
        }

        //connect data for show
        libwl_alist_for_entry(pst_connect, i,  p_info) 
        {
                if (pst_connect == NULL)  break;
                
                //no data
                if (i < last_id)  continue;

                buf_len += snprintf(&buffer[buf_len], (buff_size - buf_len), "%2d\t%.2x:%.2x:%.2x:%.2x:%.2x:%.2x\t%-32s\t%d\t%s\t%d\t%d\n",
                        i,
                        pst_connect->ac_mac[0], pst_connect->ac_mac[1], pst_connect->ac_mac[2], pst_connect->ac_mac[3], pst_connect->ac_mac[4], pst_connect->ac_mac[5],
                        pst_connect->ac_ssid,  pst_connect->group_id, 
                        (pst_connect->wlan_type == LBALANCE_WLAN_TYPE_5G) ? "5G" : "2G",
                        pst_connect->us_lb_count, pst_connect->us_drv_count);

                // will to full, break;
                if (buf_len > (LOG_BUFFER_2048 - 1024))
                {
                        last_id = i; //record
                        break;
                }
                
        }

        if (i > p_info->tail_id)    last_id = 0;

        LBALANCE_DBG_PRINTF(LBALANCE_CMD_TRACE, "cmd message[%d]: %s\n", buf_len, buffer); 

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
static int lbalance_show_debug_switch(char *buffer, int buff_size)
{
        int  buf_len = 0;  

        if (buffer == NULL)    return 0;

        buf_len += snprintf(&buffer[buf_len], (buff_size - buf_len), "%-30s: %d\n", MACROSTR_VALUE(LIBWL_INFO));
        buf_len += snprintf(&buffer[buf_len], (buff_size - buf_len), "%-30s: %d\n", MACROSTR_VALUE(LIBWL_ERROR));
        buf_len += snprintf(&buffer[buf_len], (buff_size - buf_len), "%-30s: %d\n", MACROSTR_VALUE(LIBWL_LOG_TRACE));
        buf_len += snprintf(&buffer[buf_len], (buff_size - buf_len), "%-30s: %d\n", MACROSTR_VALUE(LIBWL_CMD_TRACE));
        buf_len += snprintf(&buffer[buf_len], (buff_size - buf_len), "%-30s: %d\n", MACROSTR_VALUE(LIBWL_API_TRACE));
        buf_len += snprintf(&buffer[buf_len], (buff_size - buf_len), "%-30s: %d\n", MACROSTR_VALUE(LBALANCE_NOT_MISS));
        buf_len += snprintf(&buffer[buf_len], (buff_size - buf_len), "%-30s: %d\n", MACROSTR_VALUE(LBALANCE_INFO));
        buf_len += snprintf(&buffer[buf_len], (buff_size - buf_len), "%-30s: %d\n", MACROSTR_VALUE(LBALANCE_ERROR));
        buf_len += snprintf(&buffer[buf_len], (buff_size - buf_len), "%-30s: %d\n", MACROSTR_VALUE(LBALANCE_FILE));
        buf_len += snprintf(&buffer[buf_len], (buff_size - buf_len), "%-30s: %d\n", MACROSTR_VALUE(LBALANCE_INOTIFY_INFO));
        buf_len += snprintf(&buffer[buf_len], (buff_size - buf_len), "%-30s: %d\n", MACROSTR_VALUE(LBALANCE_UCI_INFO));
        buf_len += snprintf(&buffer[buf_len], (buff_size - buf_len), "%-30s: %d\n", MACROSTR_VALUE(LBALANCE_CMD_INFO));
        buf_len += snprintf(&buffer[buf_len], (buff_size - buf_len), "%-30s: %d\n", MACROSTR_VALUE(LBALANCE_CMD_TRACE));
        buf_len += snprintf(&buffer[buf_len], (buff_size - buf_len), "%-30s: %d\n", MACROSTR_VALUE(LBALANCE_WLAN_INFO));
        buf_len += snprintf(&buffer[buf_len], (buff_size - buf_len), "%-30s: %d\n", MACROSTR_VALUE(LBALANCE_MCAST_RECV));
        buf_len += snprintf(&buffer[buf_len], (buff_size - buf_len), "%-30s: %d\n", MACROSTR_VALUE(LBALANCE_MCAST_SEND));
        buf_len += snprintf(&buffer[buf_len], (buff_size - buf_len), "%-30s: %d\n", MACROSTR_VALUE(LBALANCE_TIMER_INFO));
        buf_len += snprintf(&buffer[buf_len], (buff_size - buf_len), "%-30s: %d\n", MACROSTR_VALUE(LBALANCE_IPADDR_INFO));
        buf_len += snprintf(&buffer[buf_len], (buff_size - buf_len), "%-30s: %d\n", MACROSTR_VALUE(LBALANCE_IFSTAUS_INFO)); 
        buf_len += snprintf(&buffer[buf_len], (buff_size - buf_len), "%-30s: %d\n", MACROSTR_VALUE(LBALANCE_API_2G));  
        buf_len += snprintf(&buffer[buf_len], (buff_size - buf_len), "%-30s: %d\n", MACROSTR_VALUE(LBALANCE_API_5G));         

        // buf_len is string length, buf_len++ will include \0 char to send.
        return ++buf_len;
}



/**
*@Description: lbalance_main_exit
*@Input: void: void
*@Return: 0 ok;  1- fail
*@author: chenzejun 20160123
*/
static void lbalance_main_exit(void)
{
        lbalance_wlan_enable_all();
        
        printf("exit, cleanup....\n");
        return;
}

/**
*@Description: print usage
*@Input: void: void
*@return: 0 ok;  1- fail
*@author: chenzejun 20160123
*/
static void lbalance_print_usage(void)
{
        printf("version: %s (build date: %s)\n", g_config.version, g_config.buildtime);
        printf("Usage: loadbalance [-d] [-h] [-p] [--port port] [--host name]\n");
        printf("               [--conn-num num]\n");
        printf("       loadbalance --help\n\n");


        printf(" -d : debug switch, output to screen.\n");
        printf(" -l : debug switch, output to log.\n");
        printf(" -h : display this help.\n");
        printf(" -v : display the version\n");

        printf(" --conn-num : config the number of the connected mac list, between 100 and 5000\n");
}


/**
*@Description: lbalance parse options
*@Input: argc: parameter number
*@Input: argv: parameter list
*@Return:  0: ok
           <0: fail   
*@author: chenzejun 20160323
info:    lbalance -d    debug switch    
*/
static int lbalance_option_proc(int argc, char **argv)
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
                        lbalance_print_usage();
                        exit(0);
                }
                else if(!strcmp(argv[i], "-v"))
                {
                        printf("[LOADBALANCE] Welcome to loadbalance, Revision:%s (build date:%s)\n"
                                "(C) 2004-16 kunteng.org\n",
                                g_config.version, g_config.buildtime);

                        exit(0);
                }
                else if(!strcmp(argv[i], "-d"))
                {
                        LBALANCE_OPTION_CHECK_RET(i, argc);
                
                        num = atoi(argv[i+1]);
                        libwl_cmd_output_printf(num);
                        i++;
                }
                else if(!strcmp(argv[i], "-l"))
                {
                        LBALANCE_OPTION_CHECK_RET(i, argc);
                        
                        num = atoi(argv[i+1]);
                        libwl_cmd_output_log(num);
                        i++;
                }
                else if(!strcmp(argv[i], "--switch-on"))
                {
                        LBALANCE_OPTION_CHECK_RET(i, argc);
                        
                        g_config.switch_on = atoi(argv[i+1]);
                        i++;
                }
                else if(!strcmp(argv[i], "--conn-num"))
                {
                        LBALANCE_OPTION_CHECK_RET(i, argc);
                        
                        num = atoi(argv[i+1]);
                        if (num > 100 && num < 5000)      connect_info.cfg_num= num;
                        i++;
                }
                else if(!strcmp(argv[i], "--up2g-amount"))
                {
                        LBALANCE_OPTION_CHECK_RET(i, argc);
                        
                        num = atoi(argv[i+1]);
                        if (num > 0)  g_config.conn_5g.keepup_amount = num;
                        i++;
                }
                else if(!strcmp(argv[i], "--up5g-amount"))
                {
                        LBALANCE_OPTION_CHECK_RET(i, argc);
                        
                        num = atoi(argv[i+1]);
                        if (num > 0)  g_config.conn_5g.keepup_amount = num;
                        i++;
                }
                else if(!strcmp(argv[i], "--hide"))
                {
                        lbalance_uci_load_config();
                        libwl_uci_set_wifi_device(uci_contex, "2.4G", "channel", argv[i+1]);
                        lbalance_uci_unload_config();
                        LBALANCE_OPTION_CHECK_RET(i, argc);
                        
                        if (0 == atoi(argv[i+1]))
                        {
                                lbalance_wlan_enable_all();
                        }
                        else
                        {
                                lbalance_wlan_disable_all();
                        }

                        exit(0);
                }
                else if(!strcmp(argv[i], "remote-show"))
                {
                        LBALANCE_OPTION_CHECK_RET(i, argc);

                        sockfd = libwl_cmd_client_create("lb");
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
                        LBALANCE_OPTION_CHECK_RET(i, argc);
                        remote_flag = 1;
                }
  
        }

        /* client */
        if (remote_flag == 1)
        {
                signal(SIGUSR1, SIG_IGN);
                signal(SIGUSR2, SIG_IGN);

                //start timer, exit after 0.5 hour
                //signal(SIGALRM, libwl_cmd_client_timeout);
                //alarm(1800); 

                sockfd = libwl_cmd_client_create("lb");
                if (sockfd > 0)   libwl_cmd_client_debug(sockfd);
                exit(0);
        }

        return 0;

unknown_option:

        exit(0);
        return 0;
}

/**
*@Description: lbalance SIGCHLD process
*@Input: signo: parameter singal
*@Return:  void   
*@author: chenzejun 20160323
*/
void lbalance_signal_chld(int signo) 
{ 
       pid_t   pid; 
       int     stat; 
        
       while((pid = waitpid(-1, &stat, WNOHANG)) > 0){ 
               printf("child %d terminated\n", pid); 
       } 
        return; 
} 

#endif

int main(int argc, char **argv)
{
        int retval = 0;

        /* zombie process */
        //signal(SIGCHLD, lbalance_signal_chld); 
        //signal(SIGCHLD,SIG_IGN);

        /* init version */
        #ifdef PKG_RELEASE
        snprintf(g_config.version, BUF_LEN_64, PKG_RELEASE);
        #endif
        #ifdef TIMESTAMP
        snprintf(g_config.buildtime, BUF_LEN_64, TIMESTAMP);
        #endif


        lbalance_option_proc(argc, argv);


        if (!libwl_inst_is_running(g_lock_file))
        {
                printf("Not support multiple instances, exit!\n");
                exit(0);
        }
        
        // timer create in here,  callback is able to call
        lbalance_timer_create();

        //time
        time(&g_config.uptime);
        lbalance_signal_setup();


        retval = lbalance_info_init();
        if(retval < 0)
        {  
                LBALANCE_DBG_PRINTF(LBALANCE_ERROR, "lbalance_info_init failed!\n");  
                return 0;
        }

        //lbalance_uci_load_config
        retval = lbalance_uci_load_config();
        if(retval < 0)
        {  
                LBALANCE_DBG_PRINTF(LBALANCE_ERROR, "lbalance_uci_load_config failed!\n");  
                return 0;
        }
        
        // timer create in here,  callback is disable to call
        //lbalance_timer_create();

        atexit(lbalance_main_exit);
        lbalance_wlan_enable_all();

        libwl_printf_currtime();

        lbalance_epoll_main();


fail:        
        LBALANCE_DBG_PRINTF(LBALANCE_INFO, "exit\n");
        lbalance_info_destroy();
        return 0;
}


