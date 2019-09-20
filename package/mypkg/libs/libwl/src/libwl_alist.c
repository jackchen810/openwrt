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
#include <pthread.h>
#include <net/if.h>
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

#if FUNCTION_DESC("list api function")



/**
*@Description: lookup unused id from array list
*@Input: head:  the pointer of alist head
*@Input: key: the pointer of key
*@Return: < head->cfg_num: ok
               INVALID_ID: fail
*@author: chenzejun 20160123
*/
static int libwl_alist_lookup(ALIST_HEAD *head, void *key)
{
        int i = 0;

        if (head->tail_id < 0)
        {
                return -1;
        }

        //scan to compare
        for (i = 0; i <= head->tail_id; i++) 
        {
                if (0 == memcmp(key, ((char *)head->pst_node + i*head->data_size), head->key_size))
                {
                        return i;
                }
        }

        return -1;
}

/*
*@Description: add node to array list
*@Input: head:  the pointer of alist head
*@Input: key:  the pointer of alist key
*@Input: keysize:  the size of key
*@Input: data:  the pointer of alist data
*@Input: datasize:  the size of data
*@Return: 0: ok;   -1: fail
*@author: chenzejun 20160123
*/
int libwl_alist_add(ALIST_HEAD *head, void *key, int keysize, void *data, int datasize)
{
        int used_id;
        
        if (NULL == head || NULL == key || NULL == data)
        {
                LIBWL_DBG_PRINTF(LIBWL_ERROR, "parameter error, %s, head:0x%x\n",  __FUNCTION__, head);
                return -1;
        }

        if (NULL == head->pst_node)
        {
                LIBWL_DBG_PRINTF(LIBWL_ERROR, "pst_node null, %s, head:0x%x\n",  __FUNCTION__, head);
                return -1;
        }


        if (keysize != head->key_size && head->node_count)
        {
                LIBWL_DBG_PRINTF(LIBWL_ERROR, "size different, %s, head->key_size:%d, key:%d\n",  __FUNCTION__, head->key_size, keysize);
                return -1;
        }

        if (datasize != head->data_size && head->node_count)
        {
                LIBWL_DBG_PRINTF(LIBWL_ERROR, "size different, %s, head->data_size:%d, datasize:%d\n",  __FUNCTION__, head->data_size, datasize);
                return -1;
        }


        used_id = libwl_alist_lookup(head, key);
        if (used_id < 0)
        {
                //if no find, new node add to tail
                if (head->tail_id < 0)
                {
                        used_id = 0;
                        head->node_count = 0;
                        head->key_size = keysize;
                        head->data_size = datasize;
                        //head->block_size = keysize + datasize;
                }
                else
                {
                        used_id = head->tail_id + 1;
                }

                //if no find, new node add to tail
                if (used_id < head->cfg_num)
                {
                        //new add
                        memcpy(((char *)head->pst_node + used_id*head->data_size), data, datasize);
                        head->tail_id = used_id;
                        head->node_count++;
                        return 0;
                }
                else
                {
                        //full, discard
                        return TABLE_FULL;
                }
        }
        else
        {
                //if find, cover it , only data
                //memcpy(&head->pst_node[used_id], data, datasize);
                memcpy(((char *)head->pst_node + used_id*head->data_size), data, datasize);
                return 0;
        }

        return -1;
}
/*
*@Description: delet node by key
*@Input: head:  the pointer of alist head
*@Input: key:  the pointer of alist key
*@Input: keysize:  the size of key
*@Return: 0: ok;   -1: fail
*@author: chenzejun 20160123
*/
int libwl_alist_del(ALIST_HEAD *head, void *key, int keysize)
{
        int used_id;

        if (NULL == head || NULL == key)
        {
                LIBWL_DBG_PRINTF(LIBWL_ERROR, "parameter error, %s, head:0x%x\n",  __FUNCTION__, head);
                return -1;
        }
        
        if (NULL == head->pst_node)
        {
                LIBWL_DBG_PRINTF(LIBWL_ERROR, "pst_node null, %s, head:0x%x\n",  __FUNCTION__, head);
                return -1;
        }

        if (keysize != head->key_size && head->node_count)
        {
                LIBWL_DBG_PRINTF(LIBWL_ERROR, "size different, %s, head->key_size:%d, key:%d\n",  __FUNCTION__, head->key_size, keysize);
                return -1;
        }
        
        used_id = libwl_alist_lookup(head, key);
        if (used_id < 0 || used_id >= head->cfg_num)
        {
                //no find
                return 0;
        }


        if (used_id < head->tail_id)
        {
                //cover the current, key and data
                memcpy(((char *)head->pst_node + used_id*head->data_size), 
                              ((char *)head->pst_node + head->tail_id*head->data_size),
                              head->data_size);
                if (head->tail_id)         head->tail_id--;
                if (head->node_count)   head->node_count--;
        }
        else if (used_id == head->tail_id)
        {
                if (head->tail_id == 0)
                {
                        // count = 1, count = 0 when delete node
                        head->tail_id = INVALID_ID;    
                        head->node_count = 0;
                }
                else
                {
                        // count > 1, delete node
                        if (head->tail_id)           head->tail_id--;
                        if (head->node_count)   head->node_count--;
                }
        }
        else
        {
                return -1;
        }

        return 0;
}



/**
*@Description: replace the oldest data
*@Input: head:  the pointer of alist head
*@Input: old: the old node need to replace
*@Input: new: the new node
*@Input: size:  the size of node
*@Return: 0: ok;   -1: fail
*@author: chenzejun 20160123
*/
int libwl_alist_replace(ALIST_HEAD *head, void *old, void *new)
{
        if (NULL == head)
        {
                LIBWL_DBG_PRINTF(LIBWL_ERROR, "parameter error, %s, head:0x%x\n",  __FUNCTION__, head);
                return -1;
        }


        if (NULL == head->pst_node)
        {
                LIBWL_DBG_PRINTF(LIBWL_ERROR, "pst_node null, %s, head:0x%x\n",  __FUNCTION__, head);
                return -1;
        }

        
        //if not full, return 0;
        if (head->tail_id + 1 < head->cfg_num)
        {
                return -1;
        }

        //replace data for age
        memcpy(old, (char *)head->pst_node, head->data_size);
        memcpy((char *)head->pst_node, new, head->data_size);
        return 0;
}




/**
*@Description: lookup unused id from array list
*@Input: head:  the pointer of alist head
*@Input: key: the pointer of key
*@Return: NULL: not found node
               *:  the pointer of node
*@author: chenzejun 20160123
*/
void *libwl_alist_find(ALIST_HEAD *head, void *key)
{
        int i = 0;

        if (head->tail_id < 0)
        {
                return NULL;
        }

        //scan to compare
        for (i = 0; i <= head->tail_id; i++) 
        {
                if (0 == memcmp(key, ((char *)head->pst_node + i*head->data_size), head->key_size))
                {
                        return (char *)head->pst_node + i*head->data_size;
                }
        }

        return NULL;
}




/**
*@Description: clean all the data
*@Input: head:  the pointer of alist head
*@Return: 0: ok;   -1: fail
*@author: chenzejun 20160123
*/
int libwl_alist_clear_all(ALIST_HEAD *head)
{
        if (NULL == head)
        {
                LIBWL_DBG_PRINTF(LIBWL_ERROR, "parameter error, %s, head:0x%x\n",  __FUNCTION__, head);
                return -1;
        }

        head->tail_id = INVALID_ID;
        head->node_count = 0;
        return 0;
}



#endif




