/*
 * Copyright (C) 2011-2014  chenzejun <jack_chen_mail@163.com>
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
#include <linux/wireless.h>
#include <sys/stat.h>  
#include <sys/time.h>
#include <sys/socket.h>    
#include <sys/epoll.h>   
#include <sys/file.h>
#include <fcntl.h>  
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdarg.h>
#include <pthread.h>
//#include <net/if.h>
#include <sys/ioctl.h>  
#include <sys/un.h>
#include <uci.h>  
#include <libubox/uloop.h>
#include <libubox/utils.h>
#include <libubox/usock.h>
#include <sys/inotify.h>
#include "libwl_api_pub.h"
#include "libwl_api.h"
#include "libwl_mscan_pub.h"
#include "libwl_dbg_pub.h"
#include "libwl_dbg.h"
#include "libwl_alist_pub.h"
#include "libwl_alist.h"


/*
history:

20170331:chenzejun create file


*/



#if FUNCTION_DESC("socket function")

/**
*@Description: set socket to nonblock
*@Input: sock_fd: socket file description
*@Return: 0: ok;   -1: fail
*@author: chenzejun 20160123
*/
static int libwl_setnonblocking(int sock_fd)
{   
        int opts;   
         
        opts = fcntl(sock_fd, F_GETFL);   
        if(opts < 0) 
        {   
                perror("fcntl(F_GETFL)\n");   
                return -1;    
        }   
        
        opts = (opts | O_NONBLOCK);   
        if(fcntl(sock_fd, F_SETFL, opts) < 0)
        {   
                perror("fcntl(F_SETFL)\n");   
                return -1;    
        }  
        return 0;
}  



/**
*@Description: add socket fd to epoll fd
*@Input: epollfd: epoll fd
*@Input: sock_fd: socket fd
*@Return:  0: ok
           <0: fail
*@author: chenzejun 20160323
*/
 int libwl_add_epoll(int epollfd, int sock_fd)
{
        struct epoll_event ev;
        int retval;  

        //set socket to nonblock
        retval = libwl_setnonblocking(sock_fd);
        if(retval < 0)
        {  
                LIBWL_DBG_PRINTF(LIBWL_ERROR, "setnonblocking failed: %s\n", strerror(errno));  
                return -1;    
        } 


        //add to epoll
        ev.events = EPOLLIN | EPOLLET;
        ev.data.fd = sock_fd;
        if (epoll_ctl(epollfd , EPOLL_CTL_ADD, sock_fd, &ev) < 0) 
        {
                LIBWL_DBG_PRINTF(LIBWL_ERROR, "epoll set insertion error: fd=%d\n", sock_fd);
                return -1;
        }

        return 0;
}


/**
 *@Description: create socket
 *@Input: protocol: socket protocol type
 *@Return: 0: ok;   -1: fail
 *@author: chenzejun 20160323
 */
int libwl_create_netlink_socket(int protocol)
{
        struct sockaddr_nl receiver_addr;  
        int sock_fd;
        int retval;    


         // Create a socket 
        sock_fd = socket(AF_NETLINK,  SOCK_RAW,  protocol);
        if(retval < 0)
        {  
                //printf("error getting socket: %s\n", strerror(errno));  
                //kernel create before userplace create, if not it return error code 10043. it mean "Protocol not supported"
                LIBWL_DBG_PRINTF(LIBWL_ERROR, "socket error, %s, protocol:%d, errno:%s\n",  __FUNCTION__, protocol, strerror(errno));
                return -2;    
        }  
        
        // To prepare binding  
        //memset(&msg,0,sizeof(msg));  
        memset(&receiver_addr, 0, sizeof(receiver_addr));  
        receiver_addr.nl_family = AF_NETLINK;  
        receiver_addr.nl_pid = getpid(); // self pid  
        receiver_addr.nl_groups = AP_NLMSG_GROUPS; // multi cast  


        retval = bind(sock_fd, (struct sockaddr*)&receiver_addr, sizeof(receiver_addr));  
        if(retval < 0)
        {  
                LIBWL_DBG_PRINTF(LIBWL_ERROR, "bind error, %s, protocol:%d, errno:%s\n",  __FUNCTION__, protocol, strerror(errno));
                close(sock_fd);  
                return -1;    
        } 


        return sock_fd;
}



#endif








#if FUNCTION_DESC("uci api function")

static struct uci_context  *uci_contex = NULL;


/*
*@Description: uci load config
*@Input: void: void
*@Return: 0: ok;   -1: fail
*@author: chenzejun 20160123
*/
int libwl_uci_load_config(void)  
{  
        if (uci_contex == NULL)
        {
                uci_contex = uci_alloc_context();
                if (uci_contex == NULL)
                {
                        return -1;
                }
        }
      
        return 0;
}  


/*
*@Description: uci unload config
*@Input: void: void
*@Return: 0: ok;   -1: fail
*@author: chenzejun 20160123
*/
int libwl_uci_unload_config(void)  
{  
        
        if (uci_contex)
        {
                uci_free_context(uci_contex);
                uci_contex = NULL;
        }
      
        return 0;
}  




/*
*@Description: fast get value of the uci config
*@Input: uci_ctx: the pointern of uci_ctx
*@Input: pkg_name: package name
*@Input: op_name: option name
*@Output: ret_value: the array of return value
*@Input: ret_len: the length of ret_value array
*@Return: 0: ok;   -1: fail
*@author: chenzejun 20160123
*/
int libwl_uci_get_option_fast(struct uci_context *uci_ctx, char *pkg_name, char *section_type, char *section_name, char *op_name, char ret_value[], int ret_len)  
{ 
        struct uci_package * pkg = NULL;  
        struct uci_element *e;  
        const char *value_name;

        if (uci_ctx == NULL || pkg_name == NULL || op_name == NULL || ret_value == NULL || ret_len <= 0)
        {
                LIBWL_DBG_PRINTF(LIBWL_ERROR, "parameter error, %s\n",  __FUNCTION__);
                return -1;
        }

        if (UCI_OK != uci_load(uci_ctx, pkg_name, &pkg))
        {  
                LIBWL_DBG_PRINTF(LIBWL_ERROR, "uci_load error, %s\n",  __FUNCTION__);
                return -1;
        }

        LIBWL_DBG_PRINTF(LIBWL_INFO, "uci get option, package:%s, section type:%s, section name:%s\n", pkg_name, section_type, section_name);
        uci_foreach_element(&pkg->sections, e)  
        {  
                struct uci_section *s = uci_to_section(e);  

                //LIBWL_DBG_PRINTF(LIBWL_INFO, "uci get, package:%s, s->type:%s, s->name:%s\n", pkg_name, s->type, s->e.name);
                if (section_type){
                        if(strcmp(s->type, section_type) != 0)   continue;
                }

                if (section_name){
                        if(strcmp(s->e.name, section_name) != 0)   continue;
                }


                if (NULL != (value_name = uci_lookup_option_string(uci_ctx, s, op_name)))  
                {  
                        snprintf(ret_value, ret_len, "%s", value_name);
                        LIBWL_DBG_PRINTF(LIBWL_INFO, "uci get option, option:%s, value:%s \n", op_name, value_name); 
                }  
        }

        uci_unload(uci_ctx, pkg);
 
        return 0;
}  







/*
*@Description: fast get value of the uci config
*@Input: uci_ctx: the pointern of uci_ctx
*@Input: pkg_name: package name
*@Input: op_name: option name
*@Output: ret_value: the array of return value
*@Input: ret_len: the length of ret_value array
*@Return: 0: ok;   -1: fail
*@author: chenzejun 20160123
*/
int libwl_uci_get_list_fast(struct uci_context *uci_ctx, char *pkg_name, char *section_type, char *section_name, char *op_name, char ret_value[], int ret_len)  
{ 
        struct uci_package * pkg = NULL;  
        struct uci_element *e;  
        const char *value_name;
        int slen = 0;
        int resv_len = ret_len;

        if (uci_ctx == NULL || pkg_name == NULL || op_name == NULL || ret_value == NULL || ret_len <= 0)
        {
                LIBWL_DBG_PRINTF(LIBWL_ERROR, "parameter error, %s\n",  __FUNCTION__);
                return -1;
        }

        if (UCI_OK != uci_load(uci_ctx, pkg_name, &pkg))
        {  
                LIBWL_DBG_PRINTF(LIBWL_ERROR, "uci_load error, %s\n",  __FUNCTION__);
                return -1;
        }

        LIBWL_DBG_PRINTF(LIBWL_INFO, "uci get list, package:%s, section type:%s, section name:%s\n", pkg_name, section_type, section_name);
        uci_foreach_element(&pkg->sections, e)  
        {  
                struct uci_section *s = uci_to_section(e);  

                //LIBWL_DBG_PRINTF(LIBWL_INFO, "uci get, package:%s, s->type:%s, s->name:%s\n", pkg_name, s->type, s->e.name);
                if (section_type){
                        if(strcmp(s->type, section_type) != 0)   continue;
                }

                if (section_name){
                        if(strcmp(s->e.name, section_name) != 0)   continue;
                }

                struct uci_option * o = uci_lookup_option(uci_ctx, s, op_name);  
                if(NULL == o)   continue;

                 //o存在 且 类型是 UCI_TYPE_LIST则可以继续.  
                if ((NULL != o) && (UCI_TYPE_LIST == o->type))
                {  
                        struct uci_element *oe;  
                        uci_foreach_element(&o->v.list, oe)  
                        {  
                                //这里会循环遍历 list  
                                // e->name 的值依次是 index.html, index.php, default.html  
                                //slen--;
                                slen += snprintf(ret_value + slen, resv_len, "%s ", oe->name);
                                LIBWL_DBG_PRINTF(LIBWL_INFO, "uci get list, list:%s, value:%s \n", op_name, oe->name);
                                resv_len = (ret_len > slen) ? (ret_len - slen) : 0;
                        }  
                }  

        }

        uci_unload(uci_ctx, pkg);
 
        return 0;
}  





/*
*@Description: fast get value of the uci config
*@Input: uci_ctx: the pointern of uci_ctx
*@Input: pkg_name: package name
*@Input: op_name: option name
*@Output: ret_value: the array of return value
*@Input: ret_len: the length of ret_value array
*@Return: 0: ok;   -1: fail
*@author: chenzejun 20160123
*/
int libwl_uci_find_element_callback(struct uci_context *uci_ctx, char *pkg_name, char *section_type, char *section_name, char *op_name, PF_UCI_SCAN_CALLBACK pf_calllback)  
{ 
        struct uci_package * pkg = NULL;  
        struct uci_element *e;  
        const char *value_name;

        if (uci_ctx == NULL || pkg_name == NULL || op_name == NULL || pf_calllback == NULL)
        {
                LIBWL_DBG_PRINTF(LIBWL_ERROR, "parameter error, %s\n",  __FUNCTION__);
                return -1;
        }

        if (UCI_OK != uci_load(uci_ctx, pkg_name, &pkg))
        {  
                LIBWL_DBG_PRINTF(LIBWL_ERROR, "uci_load error, %s\n",  __FUNCTION__);
                return -1;
        }

        //LIBWL_DBG_PRINTF(LIBWL_INFO, "uci get list, package:%s, section type:%s, section name:%s\n", pkg_name, section_type, section_name);
        uci_foreach_element(&pkg->sections, e)  
        {  
                struct uci_section *s = uci_to_section(e);  

                //LIBWL_DBG_PRINTF(LIBWL_INFO, "uci get, package:%s, s->type:%s, s->name:%s\n", pkg_name, s->type, s->e.name);
                if (section_type){
                        if(strcmp(s->type, section_type) != 0)   continue;
                }

                if (section_name){
                        if(strcmp(s->e.name, section_name) != 0)   continue;
                }

                struct uci_option * o = uci_lookup_option(uci_ctx, s, op_name);  
                if(NULL == o)   continue;

                 //o存在 且 类型是 UCI_TYPE_LIST则可以继续.  
                if (UCI_TYPE_LIST == o->type)
                {  
                        struct uci_element *oe;  
                        uci_foreach_element(&o->v.list, oe)  
                        {  
                                  pf_calllback(s->e.name, op_name, oe->name);
                        }  
                }  
                else if (UCI_TYPE_STRING == o->type)
                {
                        value_name = uci_lookup_option_string(uci_ctx, s, op_name);  
                        pf_calllback(s->e.name, op_name, value_name);
                }
        }

        uci_unload(uci_ctx, pkg);
 
        return 0;
}  








/*
*@Description: fast get value of the uci config
*@Input: uci_ctx: the pointern of uci_ctx
*@Input: pkg_name: package name
*@Input: op_name: option name
*@Output: ret_value: the array of return value
*@Input: ret_len: the length of ret_value array
*@Return: 0: ok;   -1: fail
*@author: chenzejun 20160123
*/
int libwl_uci_scan_element_callback(struct uci_context *uci_ctx, char *pkg_name, char *section_type, char *section_name, PF_UCI_SCAN_ALL_CALLBACK pf_calllback)  
{ 
        struct uci_package * pkg = NULL;  
        struct uci_element *e;  
        const char *value_name;

        if (uci_ctx == NULL || pkg_name == NULL || pf_calllback == NULL)
        {
                LIBWL_DBG_PRINTF(LIBWL_ERROR, "parameter error, %s\n",  __FUNCTION__);
                return -1;
        }

        if (UCI_OK != uci_load(uci_ctx, pkg_name, &pkg))
        {  
                LIBWL_DBG_PRINTF(LIBWL_ERROR, "uci_load error, %s\n",  __FUNCTION__);
                return -1;
        }

        //LIBWL_DBG_PRINTF(LIBWL_INFO, "uci get list, package:%s, section type:%s, section name:%s\n", pkg_name, section_type, section_name);
        uci_foreach_element(&pkg->sections, e)  
        {  
                struct uci_section *s = uci_to_section(e);  

                //LIBWL_DBG_PRINTF(LIBWL_INFO, "uci get, package:%s, s->type:%s, s->name:%s\n", pkg_name, s->type, s->e.name);
                if (section_type){
                        if(strcmp(s->type, section_type) != 0)   continue;
                }

                if (section_name){
                        if(strcmp(s->e.name, section_name) != 0)   continue;
                }


                struct uci_element *oe;  
                uci_foreach_element(&s->options, oe)  
                {  
                        struct uci_option * option = uci_lookup_option(uci_ctx, s, oe->name);  
                        if(NULL == option)   continue;

                         //o存在 且 类型是 UCI_TYPE_LIST则可以继续.  
                        if (UCI_TYPE_STRING == option->type)
                        {  
                                value_name = uci_lookup_option_string(uci_ctx, s, oe->name);  
                                //LIBWL_DBG_PRINTF(LIBWL_INFO, "uci get, type:%d, s->type:%s, s->name:%s, oname:%s, vname:%s\n", option->type, s->type, s->e.name, oe->name, value_name);
                                pf_calllback(s->type, s->e.name, option->type, oe->name, value_name);
                        }  
                        
                        if (UCI_TYPE_LIST == option->type)
                        {  
                                struct uci_element *loe;  
                                uci_foreach_element(&option->v.list, loe)  
                                {  
                                        //LIBWL_DBG_PRINTF(LIBWL_INFO, "uci get, type:%d, s->type:%s, s->name:%s, oname:%s, vname:%s\n", option->type, s->type, s->e.name, oe->name, loe->name);
                                        pf_calllback(s->type, s->e.name, option->type, oe->name, loe->name);
                                }  
                        }  
                        
                        //pf_calllback(s->e.name, op_name, oe->name);
                } 

        
        }

        uci_unload(uci_ctx, pkg);
 
        return 0;
}  










/*
*@Description: fast get value of the uci config
*@Input: uci_ctx: the pointern of uci_ctx
*@Input: pkg_name: package name
*@Input: op_name: option name
*@Output: ret_value: the array of return value
*@Input: ret_len: the length of ret_value array
*@Return: 0: ok;   -1: fail
*@author: chenzejun 20160123
*/
int libwl_uci_scan_section_callback(struct uci_context *uci_ctx, char *pkg_name, char *section_type, char *section_name, PF_UCI_SECTION_CALLBACK pf_calllback)  
{ 
        struct uci_package * pkg = NULL;  
        struct uci_element *e;  
        const char *value_name;

        if (uci_ctx == NULL || pkg_name == NULL || pf_calllback == NULL)
        {
                LIBWL_DBG_PRINTF(LIBWL_ERROR, "parameter error, %s\n",  __FUNCTION__);
                return -1;
        }

        if (UCI_OK != uci_load(uci_ctx, pkg_name, &pkg))
        {  
                LIBWL_DBG_PRINTF(LIBWL_ERROR, "uci_load error, %s\n",  __FUNCTION__);
                return -1;
        }

        //LIBWL_DBG_PRINTF(LIBWL_INFO, "uci get list, package:%s, section type:%s, section name:%s\n", pkg_name, section_type, section_name);
        uci_foreach_element(&pkg->sections, e)  
        {  
                struct uci_section *s = uci_to_section(e);  

                //LIBWL_DBG_PRINTF(LIBWL_INFO, "uci get, package:%s, s->type:%s, s->name:%s\n", pkg_name, s->type, s->e.name);
                if (section_type){
                        if(strcmp(s->type, section_type) != 0)   continue;
                }

                if (section_name){
                        if(strcmp(s->e.name, section_name) != 0)   continue;
                }


                //LIBWL_DBG_PRINTF(LIBWL_INFO, "uci get, s->type:%s, s->name:%s\n", s->type, s->e.name);
                pf_calllback(s->type, s->e.name);
        
        }

        uci_unload(uci_ctx, pkg);
 
        return 0;
}  



/*
*@Description: get value of the uci config
*@Input: uci_ctx: the pointern of uci_ctx
*@Input: pkg_name: package name
*@Input: op_name: option name
*@Output: ret_value: the array of return value
*@Input: ret_len: the length of ret_value array
*@Return: 0: ok;   -1: fail
*@author: chenzejun 20160123
*/
int libwl_uci_get_option_api(char *pkg_name, char *section_type, char *section_name, char *op_name, char ret_value[], int ret_len)  
{ 
        struct uci_context *uci_ctx = uci_contex;
        struct uci_package * pkg = NULL;  
        struct uci_element *e;  
        const char *value_name;

        if (uci_ctx == NULL || pkg_name == NULL || section_type == NULL  || section_name == NULL || op_name == NULL || ret_value == NULL || ret_len <= 0)
        {
                LIBWL_DBG_PRINTF(LIBWL_ERROR, "parameter error, %s\n",  __FUNCTION__);
                return -1;
        }

        if (UCI_OK != uci_load(uci_ctx, pkg_name, &pkg))
        {  
                LIBWL_DBG_PRINTF(LIBWL_ERROR, "uci_load error, %s\n",  __FUNCTION__);
                return -1;
        }

        LIBWL_DBG_PRINTF(LIBWL_INFO, "uci get option, package:%s, section type:%s, section name:%s\n", pkg_name, section_type, section_name);
        uci_foreach_element(&pkg->sections, e)  
        {  
                struct uci_section *s = uci_to_section(e);  

                //LIBWL_DBG_PRINTF(LIBWL_INFO, "uci get, package:%s, section->type:%s, section->name:%s\n", pkg_name, s->type, s->e.name);
                if(strcmp(s->type, section_type) != 0)   continue;
                if(strcmp(s->e.name, section_name) != 0)   continue;

                if (NULL != (value_name = uci_lookup_option_string(uci_ctx, s, op_name)))  
                {  
                        snprintf(ret_value, ret_len, "%s", value_name);
                        LIBWL_DBG_PRINTF(LIBWL_INFO, "uci get option, option:%s, value:%s \n", op_name, value_name); 
                }  
        }

        uci_unload(uci_ctx, pkg);
 
        return 0;
}  





/*
*@Description: get lan name by uci interface
*@Input: uci_ctx: the pointern of uci_ctx
*@Input: pkg_name: package name
*@Input: op_name: option name
*@Output: ret_value: the array of return value
*@Input: ret_len: the length of ret_value array
*@Return: void: void
*@author: chenzejun 20160123
*/
int libwl_uci_get_option(char *pkg_name, char *section_type, char *section_name, char *op_name, char ret_value[], int ret_len)  
{
        int retval;  

        libwl_uci_load_config();

        /* get lan name */
        retval = libwl_uci_get_option_api(pkg_name, section_type, section_name, op_name, ret_value, ret_len);

        libwl_uci_unload_config();
        return retval;
}  


/*
*@Description: get value of the uci config
*@Input: uci_ctx: the pointern of uci_ctx
*@Input: op_name: option name
*@Output: ret_value: the array of return value
*@Input: ret_len: the length of ret_value array
*@Return: 0: ok;   -1: fail
*@author: chenzejun 20160123
*/
int libwl_uci_get_network_ifname(struct uci_context *uci_ctx, char *section_type, char *section_name, char *op_name, char ret_value[], int ret_len)  
{  
        struct uci_package * pkg = NULL;  
        struct uci_element *e;  
        const char *value_name;

        if (uci_ctx == NULL || section_type == NULL  || section_name == NULL || op_name == NULL || ret_value == NULL || ret_len <= 0)
        {
                return -1;
        }

        if (UCI_OK != uci_load(uci_ctx, "network", &pkg))
        {  
                return -1;
        }

        uci_foreach_element(&pkg->sections, e)  
        {  
                struct uci_section *s = uci_to_section(e);  

                if(strcmp(s->type, section_type) != 0)   continue;
                if(strcmp(s->e.name, section_name) != 0)   continue;

                if (NULL != (value_name = uci_lookup_option_string(uci_ctx, s, op_name)))  
                {  
                        snprintf(ret_value, ret_len, "%s", value_name);
                }  
        }

        uci_unload(uci_ctx, pkg);
 
        return 0;
}  


/*
*@Description: get interface name of the uci config
*@Input: uci_ctx: the pointern of uci_ctx
*@Input: pkg_name: package name
*@Input: op_name: option name
*@Output: ret_value: the array of return value
*@Input: ret_len: the length of ret_value array
*@Return: 0: ok;   -1: fail
*@author: chenzejun 20160123
*/
int libwl_uci_get_wireless_ifname(struct uci_context *uci_ctx, char *band, char ret_value[], int ret_len)  
{  
        struct uci_package * pkg = NULL;  
        struct uci_element *e;  
        const char *value_name;
        const char *driver_name;

        if (uci_ctx == NULL || band == NULL || ret_value == NULL || ret_len <= 0)
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

                //printf("uci get wireless s->type:%s, %s\n", s->type, s->e.name);
                if (strcmp(s->type, "wifi-device") != 0)
                {
                        continue;
                }

                value_name = uci_lookup_option_string(uci_ctx, s, "band");
                if (strcmp(value_name, band) != 0)
                {
                        continue;
                }

                driver_name = uci_lookup_option_string(uci_ctx, s, "type");
                if (driver_name == NULL)
                {
                        continue;
                }

                //printf("uci lookup option string, band:%s, type:%s\n", value_name, driver_name);
                goto find_iface;

        }


        uci_unload(uci_ctx, pkg);
        return -1;

find_iface:


        uci_foreach_element(&pkg->sections, e)  
        {
                struct uci_section *s = uci_to_section(e);

                if (strcmp(s->type, "wifi-iface") != 0)
                {
                        continue;
                }

                //printf("lookup type:%s\n", s->type);
                value_name = uci_lookup_option_string(uci_ctx, s, "ifname");
                if (value_name == NULL)
                {
                        continue;
                }

                //printf("found value:%s\n", value_name);
                snprintf(ret_value, ret_len, "%s", value_name);
                break;
        }
        

        uci_unload(uci_ctx, pkg);
        return 0;
}  





/*
*@Description: get value of the uci config
*@Input: uci_ctx: the pointern of uci_ctx
*@Input: pkg_name: package name
*@Input: op_name: option name
*@Output: ret_value: the array of return value
*@Input: ret_len: the length of ret_value array
*@Return: 0: ok;   -1: fail
*@author: chenzejun 20160123
*/
int libwl_uci_get_wifi_device(struct uci_context *uci_ctx, char *band, char *op_name, char ret_value[], int ret_len)  
{  
        struct uci_package * pkg = NULL;  
        struct uci_element *e;  
        const char *value_name;

        if (uci_ctx == NULL || band == NULL || op_name == NULL || ret_value == NULL || ret_len <= 0)
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

                //printf("uci get wireless s->type:%s, %s\n", s->type, s->e.name);
                if (strcmp(s->type, "wifi-device") != 0)
                {
                        continue;
                }

                value_name = uci_lookup_option_string(uci_ctx, s, "band");
                if (strcmp(value_name, band) != 0)
                {
                        continue;
                }

                value_name = uci_lookup_option_string(uci_ctx, s, op_name);
                if (value_name == NULL)
                {
                        continue;
                }

                //printf("uci lookup option string, band:%s, type:%s\n", value_name, driver_name);
                snprintf(ret_value, ret_len, "%s", value_name);

                uci_unload(uci_ctx, pkg);
                return 0;
        }

        uci_unload(uci_ctx, pkg);
        return -1;
}  



/*
*@Description: get value of the uci config
*@Input: uci_ctx: the pointern of uci_ctx
*@Input: pkg_name: package name
*@Input: op_name: option name
*@Output: ret_value: the array of return value
*@Input: ret_len: the length of ret_value array
*@Return: 0: ok;   -1: fail
*@author: chenzejun 20160123
*/
int libwl_uci_get_wifi_iface(struct uci_context *uci_ctx, char *ifname, char *op_name, char ret_value[], int ret_len)  
{  
        struct uci_package * pkg = NULL;  
        struct uci_element *e;  
        const char *value_name;
        const char *driver_name;

        if (uci_ctx == NULL || ifname == NULL || op_name == NULL || ret_value == NULL || ret_len <= 0)
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

                //printf("uci get wireless s->type:%s, %s\n", s->type, s->e.name);
                if (strcmp(s->type, "wifi-iface") != 0)
                {
                        continue;
                }

                value_name = uci_lookup_option_string(uci_ctx, s, "ifname");
                if (strcmp(value_name, ifname) != 0)
                {
                        continue;
                }

                value_name = uci_lookup_option_string(uci_ctx, s, op_name);
                if (value_name == NULL)
                {
                        continue;
                }

                //printf("uci lookup option string, band:%s, type:%s\n", value_name, driver_name);
                snprintf(ret_value, ret_len, "%s", value_name);

                uci_unload(uci_ctx, pkg);
                return 0;
        }

        uci_unload(uci_ctx, pkg);
        return -1;
}  


/*
*@Description: set value of the uci config
*@Input: pkg_name: package name
*@Input: section: section name
*@Input: op_name: option name
*@Input: op_value: the array of return value
*@Return: 0: ok;   -1: fail
*@author: chenzejun 20160123
*/
int libwl_uci_set_option(struct uci_context *uci_ctx, char *pkg_name, char *section_name, char *op_name, char *op_value)  
{  
        struct uci_package * pkg = NULL;  
        struct uci_ptr ptr ={  
                .package = pkg_name,  
                .section = section_name,  
                .option = op_name,  
                .value = op_value,  
        };  


        if (uci_ctx == NULL || pkg_name == NULL || section_name == NULL  || op_name == NULL || op_value == NULL)
        {
                return -1;
        }
        
        if (UCI_OK != uci_load(uci_ctx, ptr.package, &pkg))
        {
                return -1;
        }

        uci_set(uci_ctx, &ptr); //
        uci_commit(uci_ctx, &pkg, false); //
        uci_unload(uci_ctx, pkg); //      

        return 0;
}  




/*
*@Description: get value of the uci config
*@Input: uci_ctx: the pointern of uci_ctx
*@Input: pkg_name: package name
*@Input: op_name: option name
*@Output: ret_value: the array of return value
*@Input: ret_len: the length of ret_value array
*@Return: 0: ok;   -1: fail
*@author: chenzejun 20160123
*/
int libwl_uci_set_wifi_device(struct uci_context *uci_ctx, char *band, char *op_name, char *op_value)  
{  
        struct uci_package * pkg = NULL;  
        struct uci_element *e;  
        const char *value_name;
        struct uci_ptr ptr ={  
                .package = "wireless",  
                .section = NULL,  
                .option = op_name,  
                .value = op_value,  
        };  


        if (uci_ctx == NULL || band == NULL || op_name == NULL || op_value == NULL)
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

                //printf("uci get wireless s->type:%s, %s\n", s->type, s->e.name);
                if (strcmp(s->type, "wifi-device") != 0)
                {
                        continue;
                }

                value_name = uci_lookup_option_string(uci_ctx, s, "band");
                if (strcmp(value_name, band) != 0)
                {
                        continue;
                }

                //update section to name.
                ptr.section = s->e.name;
                LIBWL_DBG_PRINTF(LIBWL_INFO, "band:%s, wifi-device section name:%s\n", band, s->e.name);

                uci_set(uci_ctx, &ptr); //
                uci_commit(uci_ctx, &pkg, false); //

                uci_unload(uci_ctx, pkg);
                return 0;
        }


        uci_unload(uci_ctx, pkg);
        return -1;
}  



/*
*@Description: get value of the uci config
*@Input: uci_ctx: the pointern of uci_ctx
*@Input: pkg_name: package name
*@Input: op_name: option name
*@Output: ret_value: the array of return value
*@Input: ret_len: the length of ret_value array
*@Return: 0: ok;   -1: fail
*@author: chenzejun 20160123
*/
int libwl_uci_set_wifi_iface(struct uci_context *uci_ctx, char *ifname, char *op_name, char *op_value)  
{  
        struct uci_package * pkg = NULL;  
        struct uci_element *e;  
        const char *value_name;
        struct uci_ptr ptr ={  
                .package = "wireless",  
                .section = NULL,  
                .option = op_name,  
                .value = op_value,  
        };  


        if (uci_ctx == NULL || ifname == NULL || op_name == NULL || op_value == NULL)
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

                //printf("uci get wireless s->type:%s, %s\n", s->type, s->e.name);
                if (strcmp(s->type, "wifi-iface") != 0)
                {
                        continue;
                }

                value_name = uci_lookup_option_string(uci_ctx, s, "ifname");
                if (strcmp(value_name, ifname) != 0)
                {
                        continue;
                }

                //update section to name.
                ptr.section = s->e.name;
                LIBWL_DBG_PRINTF(LIBWL_INFO, "ifname:%s, wifi-iface section name:%s\n", ifname, s->e.name);

                uci_set(uci_ctx, &ptr); //
                uci_commit(uci_ctx, &pkg, false); //

                uci_unload(uci_ctx, pkg);
                return 0;
        }


        uci_unload(uci_ctx, pkg);
        return -1;
}  

/*
*@Description: get 5g name by uci interface
*@Input: if_name: the name of interface
*@Input: buf_len: the length of return value
*@Return: 0: ok;   -1: fail
*@author: chenzejun 20160123
*/
int libwl_get_5g_name(char *if_name, int buf_len)  
{
        int retval;
        libwl_uci_load_config();
        
        /* get wan name */
        retval = libwl_uci_get_wireless_ifname(uci_contex, "5G", if_name, buf_len);

        libwl_uci_unload_config();
        return retval;
}  
/*
*@Description: get 2.4g name by uci interface
*@Input: if_name: the name of interface
*@Input: buf_len: the length of return value
*@Return: 0: ok;   -1: fail
*@author: chenzejun 20160123
*/
int libwl_get_2g_name(char *if_name, int buf_len)  
{
        int retval;
        libwl_uci_load_config();
        
        /* get wan name */
        retval = libwl_uci_get_wireless_ifname(uci_contex, "2.4G", if_name, buf_len);

        libwl_uci_unload_config();
        return retval;
}  

/*
*@Description: get lan name by uci interface
*@Input: if_name: the name of interface
*@Input: buf_len: the length of return value
*@Return: 0: ok;   -1: fail
*@author: chenzejun 20160123
*/
int libwl_get_lan_name(char *if_name, int buf_len)  
{  
        int retval;
        
        libwl_uci_load_config();

        /* get lan name */
        retval = libwl_uci_get_network_ifname(uci_contex, "interface", "lan", "ifname", if_name, buf_len);

        libwl_uci_unload_config();
        return retval;
}  



/*
*@Description: get wan name by uci interface
*@Input: if_name: the name of interface
*@Input: buf_len: the length of return value
*@Return: 0: ok;   -1: fail
*@author: chenzejun 20160123
*/
int libwl_get_wan_name(char *if_name, int buf_len)  
{
        int retval;
        
        libwl_uci_load_config();

        /* get wan name */
        retval = libwl_uci_get_network_ifname(uci_contex, "interface", "wan", "ifname", if_name, buf_len);
        
        libwl_uci_unload_config();
        return retval;
}  

#endif


#if FUNCTION_DESC("socket api function")



/**
*@Description: get port no for 2g wireless card
*@Output:port_name: the name of port, output parameter
*@Input:buf_len: the length of port name, the length must greater than 16
*@Output:port_no: the no or port, output parameter
*@Return: 0: ok;   -1: fail
*@author: chenzejun 20160123
        mtk: portNo2G and portNo5G  generation by openwrt-cc\target\linux\ramips\base-files\lib\wifi\ralink_common.sh
        qca: portNo2G and portNo5G  generation by openwrt-cc\package\kernel\qca\wlan_10_2\qca-wifi\files\lib\wifi\qcawifi.sh
*/
int libwl_get_2g_port_no(char *port_name, int buf_len, int *port_no)
{
        FILE *fp;
        int num;
        char line[BUF_LEN_64] = {0};

        //ioctl, #define IF_NAMESIZE	16
        if (buf_len < BUF_LEN_16 || port_no == NULL || port_name == NULL) 
        {
                LIBWL_DBG_PRINTF(LIBWL_ERROR, "parameter error, %s, buf_len:%d\n",  __FUNCTION__, buf_len);
                return -1;
        }

        fp = fopen("/tmp/portNo2G", "r");
        if (fp == NULL)
        {
                LIBWL_DBG_PRINTF(LIBWL_ERROR, "fopen error, %s, port_name:%s, errno:%s\n",  __FUNCTION__, port_name, strerror(errno));  
                return -1;
        }        

        /* Read the file cache entries. */
        while (fgets(line, sizeof(line), fp))
        {
                /* All these strings can't overflow
                * because fgets above reads limited amount of data */
                if (buf_len < BUF_LEN_16)  break;

                num = sscanf(line, "%16s 0x%x\n", port_name, port_no);
                if (num != 2)                break;

                fclose(fp);
                return 0;
                
        }

        fclose(fp);
        return -1;
}



/**
*@Description: get port no for 5g wireless card
*@Output:port_name: the name of port, output parameter
*@Input:buf_len: the length of port name, the length must greater than 16
*@Output:port_no: the no or port, output parameter
*@Return: 0: ok;   -1: fail
*@author: chenzejun 20160123
        mtk: portNo2G and portNo5G  generation by openwrt-cc\target\linux\ramips\base-files\lib\wifi\ralink_common.sh
        qca: portNo2G and portNo5G  generation by openwrt-cc\package\kernel\qca\wlan_10_2\qca-wifi\files\lib\wifi\qcawifi.sh
*/
int libwl_get_5g_port_no(char *port_name, int buf_len, int *port_no)
{
        FILE *fp;
        int num;
        char line[BUF_LEN_64] = {0};

        if (buf_len < BUF_LEN_16 || port_no == NULL || port_name == NULL) 
        {
                LIBWL_DBG_PRINTF(LIBWL_ERROR, "parameter error, %s, buf_len:%d\n",  __FUNCTION__, buf_len);
                return -1;
        }

        fp = fopen("/tmp/portNo5G", "r");
        if (fp == NULL)
        {
                LIBWL_DBG_PRINTF(LIBWL_ERROR, "fopen error, %s, port_name:%s, errno:%s\n",  __FUNCTION__, port_name, strerror(errno));  
                return -1;
        }        
        

        /* Read the file cache entries. */
        while (fgets(line, sizeof(line), fp))
        {
                /* All these strings can't overflow
                * because fgets above reads limited amount of data */
                if (buf_len < BUF_LEN_16)  break;
                
                num = sscanf(line, "%16s 0x%x\n", port_name, port_no);
                if (num != 2)                break;

                fclose(fp);
                return 0;
                
        }

        fclose(fp);
        return -1;
}






/**
*@Description: get board name for router
*@Output:board_name: the name of board, output parameter
*@Input:buf_len: the length of port name, the length must greater than 16
*@Return: 0: ok;   -1: fail
*@author: chenzejun 20190923
*/
int libwl_get_board_name(char *board_name, int buf_len)
{
        FILE *fp;
        int num;
        char line[BUF_LEN_64] = {0};

        if (buf_len < BUF_LEN_64 ||board_name == NULL) 
        {
                LIBWL_DBG_PRINTF(LIBWL_ERROR, "parameter error, %s, buf_len:%d\n",  __FUNCTION__, buf_len);
                return -1;
        }

        fp = fopen("/tmp/sysinfo/board_name", "r");
        if (fp == NULL)
        {
                LIBWL_DBG_PRINTF(LIBWL_ERROR, "fopen error, %s, board_name:%s, errno:%s\n",  __FUNCTION__, board_name, strerror(errno));  
                return -1;
        }        
        

        /* Read the file cache entries. */
        while (fgets(line, sizeof(line), fp))
        {
                /* All these strings can't overflow
                * because fgets above reads limited amount of data */
                if (buf_len < sizeof(line))  break;
                
                num = sscanf(line, "%s\n", board_name);

                fclose(fp);
                return 0;
                
        }

        fclose(fp);
        return -1;
}



/**
*@Description: get the mac of router by dev name
*@Input:if_name: the name of dev
*@Output:mac: the pointer to mac, output parameter
*@Input:buf_len: the buffer length of mac pointer
*@Return: 0 ok;  1- fail
*@author: chenzejun 20160123
*/
int libwl_get_router_mac(const char *if_name, char *mac, int buf_len)
{
        int sock_fd = 0;
        struct ifreq ifreq = {0};

        if (buf_len < MAC_LEN_6 || mac == NULL) 
        {
                LIBWL_DBG_PRINTF(LIBWL_ERROR, "parameter error, %s, buf_len:%d\n",  __FUNCTION__, buf_len);
                return -1;
        }

        sock_fd = socket(AF_INET, SOCK_STREAM, 0);
        if(sock_fd < 0)
        {
                LIBWL_DBG_PRINTF(LIBWL_ERROR, "socket error, %s, if_name:%s, errno:%s\n",  __FUNCTION__, if_name, strerror(errno));  
                return -1;
        }

        snprintf(ifreq.ifr_name, sizeof(ifreq.ifr_name), "%s", if_name);
        if (ioctl(sock_fd, SIOCGIFHWADDR, &ifreq) < 0)
        {
                LIBWL_DBG_PRINTF(LIBWL_ERROR, "ioctl error, %s, if_name:%s, errno:%s\n",  __FUNCTION__, if_name, strerror(errno));  
                close(sock_fd);
                return -1;
        }

        mac[0] = (unsigned char)ifreq.ifr_hwaddr.sa_data[0];
        mac[1] = (unsigned char)ifreq.ifr_hwaddr.sa_data[1];
        mac[2] = (unsigned char)ifreq.ifr_hwaddr.sa_data[2];
        mac[3] = (unsigned char)ifreq.ifr_hwaddr.sa_data[3];
        mac[4] = (unsigned char)ifreq.ifr_hwaddr.sa_data[4];
        mac[5] = (unsigned char)ifreq.ifr_hwaddr.sa_data[5];
        
        close(sock_fd);
        return 0;
}


/**
*@Description: get the mac of router by dev name
*@Input:if_name: the name of dev
*@Output:mac: the pointer to mac, output parameter
*@Input:buf_len: the buffer length of mac pointer
*@return: 0 ok;  1- fail
*@author: chenzejun 20160123
*/
int libwl_get_router_hwaddr(const char *if_name, char *hwaddr, int buf_len)
{
        int sock_fd = 0;
        struct ifreq ifreq = {0};

        if (buf_len < 20 || hwaddr == NULL)
        {
                LIBWL_DBG_PRINTF(LIBWL_ERROR, "parameter error, %s, buf_len:%d\n",  __FUNCTION__, buf_len);
                return -1;
        }

        sock_fd = socket(AF_INET, SOCK_STREAM, 0);
        if(sock_fd < 0)
        {
                LIBWL_DBG_PRINTF(LIBWL_ERROR, "socket error, %s, if_name:%s, errno:%s\n",  __FUNCTION__, if_name, strerror(errno));  
                return -1;
        }

        snprintf(ifreq.ifr_name, sizeof(ifreq.ifr_name), "%s", if_name);
        if (ioctl(sock_fd, SIOCGIFHWADDR, &ifreq) < 0)
        {
                LIBWL_DBG_PRINTF(LIBWL_ERROR, "ioctl error, %s, if_name:%s, errno:%s\n",  __FUNCTION__, if_name, strerror(errno));  
                close(sock_fd);
                return -1;
        }

        snprintf(hwaddr, buf_len, "%02X:%02X:%02X:%02X:%02X:%02X", 
                (unsigned char)ifreq.ifr_hwaddr.sa_data[0],
                (unsigned char)ifreq.ifr_hwaddr.sa_data[1],
                (unsigned char)ifreq.ifr_hwaddr.sa_data[2],
                (unsigned char)ifreq.ifr_hwaddr.sa_data[3],
                (unsigned char)ifreq.ifr_hwaddr.sa_data[4],
                (unsigned char)ifreq.ifr_hwaddr.sa_data[5]);

        //printf("router_mac:%s\n", mac);
        close(sock_fd);
        return 0;
}


/**
*@Description: get the mac of router by dev name
*@Input:if_name: the name of dev
*@Output:mac: the pointer to mac, output parameter
*@Input:buf_len: the buffer length of mac pointer
*@return: 0 ok;  1- fail
*@author: chenzejun 20160123
*/
int libwl_get_router_hwaddr_short(const char *if_name, char *hwaddr, int buf_len)
{
        int sock_fd = 0;
        struct ifreq ifreq = {0};

        if (buf_len < 20 || hwaddr == NULL)
        {
                LIBWL_DBG_PRINTF(LIBWL_ERROR, "parameter error, %s, buf_len:%d\n",  __FUNCTION__, buf_len);
                return -1;
        }

        sock_fd = socket(AF_INET, SOCK_STREAM, 0);
        if(sock_fd < 0)
        {
                LIBWL_DBG_PRINTF(LIBWL_ERROR, "socket error, %s, if_name:%s, errno:%s\n",  __FUNCTION__, if_name, strerror(errno));  
                return -1;
        }

        snprintf(ifreq.ifr_name, sizeof(ifreq.ifr_name), "%s", if_name);
        if (ioctl(sock_fd, SIOCGIFHWADDR, &ifreq) < 0)
        {
                LIBWL_DBG_PRINTF(LIBWL_ERROR, "ioctl error, %s, if_name:%s, errno:%s\n",  __FUNCTION__, if_name, strerror(errno));  
                close(sock_fd);
                return -1;
        }

        snprintf(hwaddr, buf_len, "%02X%02X%02X%02X%02X%02X", 
                (unsigned char)ifreq.ifr_hwaddr.sa_data[0],
                (unsigned char)ifreq.ifr_hwaddr.sa_data[1],
                (unsigned char)ifreq.ifr_hwaddr.sa_data[2],
                (unsigned char)ifreq.ifr_hwaddr.sa_data[3],
                (unsigned char)ifreq.ifr_hwaddr.sa_data[4],
                (unsigned char)ifreq.ifr_hwaddr.sa_data[5]);

        //printf("router_mac:%s\n", mac);
        close(sock_fd);
        return 0;
}



/**
*@Description: get the mac of router by dev name
*@Input:if_name: the name of dev
*@Output:ip: the pointer to ip, output parameter
*@Input:buf_len: the buffer length of ip pointer
*@return: 0 ok;  1- fail
*@author: chenzejun 20160123
*/
int libwl_get_router_ip(const char *if_name, char *ip, int buf_len)
{
        int sock_fd = 0;
        struct ifreq ifreq = {0};

        if (buf_len < 18 || ip == NULL)
        {
                LIBWL_DBG_PRINTF(LIBWL_ERROR, "parameter error, %s, buf_len:%d\n",  __FUNCTION__, buf_len);
                return -1;
        }

        sock_fd = socket(AF_INET, SOCK_STREAM, 0);
        if(sock_fd < 0)
        {
                LIBWL_DBG_PRINTF(LIBWL_ERROR, "socket error, %s, if_name:%s, errno:%s\n",  __FUNCTION__, if_name, strerror(errno));  
                return -1;
        }

        snprintf(ifreq.ifr_name, sizeof(ifreq.ifr_name), "%s", if_name);
        if (ioctl(sock_fd, SIOCGIFADDR, &ifreq) < 0)
        {
                LIBWL_DBG_PRINTF(LIBWL_ERROR, "ioctl error, %s, if_name:%s, errno:%s\n",  __FUNCTION__, if_name, strerror(errno));  
                close(sock_fd);
                return -1;
        }
        snprintf(ip, buf_len, "%s", inet_ntoa(((struct sockaddr_in *) &ifreq.ifr_addr)->sin_addr));

        //printf("router_ip:%s\n", ip);
        close(sock_fd);
        return 0;
}



/**
*@Description: frequence change to float
*@Input:ifname: ifname
*@Output:channel: channel
*@Return: -1- fail;
*@author: chenzejun 20160123
*/
static double libwl_freq2float(const struct iw_freq *in)
{
	int		i;
	double	res = (double) in->m;
	for(i = 0; i < in->e; i++) res *= 10;
	return res;
}




/**
*@Description: get wireless channel
*@Input:ifname: ifname
*@Output:channel: channel
*@Return: -1- fail;
*@author: chenzejun 20160123
*/
int libwl_get_router_channel(const char *if_name, int *channel)
{
        int sock_fd = 0;
        struct iwreq wrq = {0};
        struct iw_range range = {0};
        double freq;
        int i;

        if (if_name == NULL || channel == NULL)        
        {
                LIBWL_DBG_PRINTF(LIBWL_ERROR, "parameter error, %s\n",  __FUNCTION__);
                return -1;
        }

        sock_fd = socket(AF_INET, SOCK_STREAM, 0);
        if(sock_fd < 0)
        {
                LIBWL_DBG_PRINTF(LIBWL_ERROR, "socket error, %s, if_name:%s, errno:%s\n",  __FUNCTION__, if_name, strerror(errno));  
                return -1;
        }
        
        //fcntl(sock_fd, F_SETFD, fcntl(sock_fd, F_GETFD) | FD_CLOEXEC);
        
        (void) memset(&wrq, 0, sizeof(wrq));
        (void) snprintf(wrq.ifr_name, sizeof(wrq.ifr_name), "%s", if_name);

        if (ioctl(sock_fd, SIOCGIWFREQ, &wrq) < 0)
        {
                LIBWL_DBG_PRINTF(LIBWL_ERROR, "ioctl error, %s, if_name:%s, errno:%s\n",  __FUNCTION__, if_name, strerror(errno));  
                close(sock_fd);
                return -1;
        }

        LIBWL_DBG_PRINTF(LIBWL_API_TRACE, "get channel, if_name: %s, channel:%d\n", if_name, wrq.u.freq.m); 
        
        //this is copy by iwinfo code
        if( wrq.u.freq.m >= 1000 )
        {
                freq = libwl_freq2float(&wrq.u.freq);
                wrq.u.data.pointer = (caddr_t) &range;
                wrq.u.data.length  = sizeof(struct iw_range);
                wrq.u.data.flags   = 0;

                if (ioctl(sock_fd, SIOCGIWRANGE, &wrq) < 0)
                {
                        LIBWL_DBG_PRINTF(LIBWL_ERROR, "ioctl SIOCGIWRANGE error, %s, if_name:%s, errno:%s\n",  __FUNCTION__, if_name, strerror(errno));  
                        close(sock_fd);
                        return -1;
                }

                //
                for(i = 0; i < range.num_frequency; i++)
                {
                        if( libwl_freq2float(&range.freq[i]) == freq)
                        {
                                *channel = range.freq[i].i;
                                close(sock_fd);
                                return 0;
                        }
                }
        }
        else
        {
                *channel = wrq.u.freq.m;
                close(sock_fd);
                return 0;
        }

        close(sock_fd);
        return -1;        
}





/**
*@Description: show mac list count
*@Input:if_name: the name of dev
*@Output:count: count
*@Return: 0 ok;  1- fail
        the device is ralink
*@author: chenzejun 20160123
*/
int libwl_get_ralink_access_count(char *if_name, int *ret_count)
{
        int sock_fd = 0;
        struct iwreq wrq = {0};
        char *buffer = NULL;
        int i = 0;

        if (ret_count == NULL || if_name == NULL)         
        {
                LIBWL_DBG_PRINTF(LIBWL_ERROR, "parameter error, %s\n",  __FUNCTION__);
                return -1;
        }

        buffer = malloc(LIST_STATION_ALLOC_SIZE);
        if(!buffer) 
        {
                fprintf (stderr, "Unable to allocate memory for station list\n");
                return -1;
        } 

        sock_fd = socket(AF_INET, SOCK_STREAM, 0);
        if(sock_fd < 0)
        {
                LIBWL_DBG_PRINTF(LIBWL_ERROR, "socket error, %s, if_name:%s, errno:%s\n",  __FUNCTION__, if_name, strerror(errno));  
                free(buffer);
                return -1;
        }

        (void) memset(&wrq, 0, sizeof(wrq));
        (void) snprintf(wrq.ifr_name, sizeof(wrq.ifr_name), "%s", if_name);
        
        wrq.u.data.pointer = (void *)buffer;
        wrq.u.data.length = LIST_STATION_ALLOC_SIZE;
        wrq.u.data.flags = 0;

        LIBWL_DBG_PRINTF(LIBWL_API_TRACE, "get mac table, if_name: %s\n", if_name); 

         //#define RTPRIV_IOCTL_GET_MAC_TABLE    (SIOCIWFIRSTPRIV + 0x0F)
        if (ioctl(sock_fd, (SIOCIWFIRSTPRIV + 0x0F), &wrq) < 0)
        {
                LIBWL_DBG_PRINTF(LIBWL_ERROR, "ioctl error, %s, if_name:%s, errno:%s\n",  __FUNCTION__, if_name, strerror(errno));  
                free(buffer);
                close(sock_fd);
                return -1;
        }

        *ret_count = 0;
        for (i = 0; (i + 12) < wrq.u.data.length; i++)
        {
                if (buffer[i] == '\0')   break;

                //e8:4e:06:2e:14:09	
                if (buffer[i] == ':' && buffer[i+3] == ':' && buffer[i+6] == ':' && buffer[i+9] == ':' && buffer[i+12] == ':')
                {
                        i = i + 50;
                        (*ret_count)++;
                }                
        }

        LIBWL_DBG_PRINTF(LIBWL_API_TRACE, "get mac table, if_name: %s, length:%d, count:%d\n", if_name, wrq.u.data.length, *ret_count); 

        free(buffer);
        close(sock_fd);
        return 0;
}




/**
*@Description: show mac list count
*@Input:if_name: the name of dev
*@Output:count: count
*@Return: 0 ok;  1- fail
*@author: chenzejun 20160123
*/
int libwl_get_access_amount(char *dev_type, char *if_name, int *count)
{
        if (dev_type == NULL || count == NULL)
        {
                LIBWL_DBG_PRINTF(LIBWL_ERROR, "parameter error, %s\n",  __FUNCTION__);
                return -1;
        }

        if (!strncmp(dev_type, "ralink", 6))
        {
                return libwl_get_ralink_access_count(if_name, count);
        }
        else if (!strncmp(dev_type, "qca", 3))
        {
                return -1;
        }

        return -1;
}


/**
*@Description: find ip by arp table
*@Input:argc: para num
*@Input:argv: pointer to para
*@return: 0 ok;  1- fail
*@author: chenzejun 20160123
*/
int libwl_get_ip_by_mac(unsigned char *p_mac, char *dest_ip, int buf_len)
{
        FILE *file_fd;
        int type, flags;
        int num;
        char ip[BUF_LEN_64];
        char hwa[BUF_LEN_64];
        char mask[BUF_LEN_64];
        char line[BUF_LEN_128];
        char dev[BUF_LEN_128];

        if (dest_ip == NULL || p_mac == NULL)    
        {
                LIBWL_DBG_PRINTF(LIBWL_ERROR, "parameter error, %s\n",  __FUNCTION__);
                return -1;
        }
        
        dest_ip[0] = 0;

        file_fd = fopen("/proc/net/arp", "r");
        if (NULL == file_fd)
        {
                LIBWL_DBG_PRINTF(LIBWL_ERROR, "fopen error, %s, p_mac:%s, errno:%s\n",  __FUNCTION__, p_mac, strerror(errno));
                return -1;
        }
       
        /* Bypass header -- read one line */
        fgets(line, sizeof(line), file_fd);

        /* Read the ARP cache entries. */
        while (fgets(line, sizeof(line), file_fd))
        {
                /* All these strings can't overflow
                * because fgets above reads limited amount of data */
                num = sscanf(line, "%s 0x%x 0x%x %s %s %s\n", ip, &type, &flags, hwa, mask, dev);
                if (num < 4)                break;
                if (!(flags & ATF_COM))   continue;
                
	   if (0 == strncmp(p_mac, hwa, 17))
                {
                        LIBWL_DBG_PRINTF(LIBWL_API_TRACE, "ip:%s\n", ip);
                        snprintf(dest_ip, buf_len, "%s", ip);
                        fclose(file_fd);
                        return 0;
                }
        }

        fclose(file_fd);
        return -1;
}



/**
*@Description: get the status of wan
*@Input:argc: para num
*@Input:argv: pointer to para
*@return: 0 ok;  1- fail
*@author: chenzejun 20160123
*/
int libwl_get_wan_status(void)
{
        FILE *fp;
        char line[BUF_LEN_128];
        

        fp = fopen("/tmp/wanstatus", "r");
        if (fp == NULL)
        {
                LIBWL_DBG_PRINTF(LIBWL_ERROR, "fopen error, %s, errno:%s\n",  __FUNCTION__, strerror(errno));
                return -1;
        }        
        
        /* Read the ARP cache entries. */
        if (fgets(line, sizeof(line), fp))
        {
                if (line[0] == '1')
                {
                        //printf("up\n");
                        fclose(fp);
                        return 1;
                }
                else
                {
                        //printf("down\n");
                        fclose(fp);
                        return 0;
                }
        }

        fclose(fp);
        return 0;
}






/**
*@Description:  converts an hw address address into mac.
*@Input:hwaddr: hw address, string
*@Input:mac: pointer to mac buffer
*@Input:len: the mac buffer length
*@return: 0 ok;  1- fail
*@author: chenzejun 20160123
*/
int libwl_hwaddr_htoa(const char *hwaddr, char mac[], int len)
{
        char * pend; 
        char * pbegin = (char *)hwaddr;
        if (hwaddr == NULL || mac == NULL || len < MAC_LEN_6)
        {
                return -1;
        }


        mac[0] = strtoul(pbegin, &pend, 16);
        pbegin = pend + 1;
        mac[1] = strtoul(pbegin, &pend, 16);
        pbegin = pend + 1;
        mac[2] = strtoul(pbegin, &pend, 16);
        pbegin = pend + 1;
        mac[3] = strtoul(pbegin, &pend, 16);
        pbegin = pend + 1;
        mac[4] = strtoul(pbegin, &pend, 16);
        pbegin = pend + 1;
        mac[5] = strtoul(pbegin, &pend, 16);

        return 0;
}



#endif


