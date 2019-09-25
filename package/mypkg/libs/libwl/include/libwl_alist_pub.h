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
#ifndef __LIBWL_ALIST_PUB_H_
#define __LIBWL_ALIST_PUB_H_



#define INVALID_ID      (-1)
#define TABLE_FULL      0x1



typedef struct  ALIST_HEAD_ST
{
        int               cfg_num;   //cfg_num£¬the config of user
        int               tail_id;       //tail id, point to tail id,  add node or del node use it
        unsigned int  key_size;   //the size of node
        unsigned int  data_size;  //the size of node, node include key
        //unsigned int  block_size;  //the size of block = key + data
        unsigned int  node_count; //the count of node
        char  *pst_node;
}ALIST_HEAD;



#define libwl_alist_for_entry(dnode, did, dalist)	   \
        for (did = 0, dnode = ((dalist)->tail_id < 0 ? NULL : &((typeof(dnode))(dalist)->pst_node)[did]); \
                (int)did <= (dalist)->tail_id; \
                did++,  dnode = ((dalist)->tail_id < 0 ? NULL : &((typeof(dnode))(dalist)->pst_node)[did]))

#define  libwl_get_alist_count(dalist)   ((dalist)->node_count)
#define  libwl_get_node_by_id(dalist, did)   ((dalist)->tail_id < 0 ? NULL : ((char *)(dalist)->pst_node + did*(dalist)->data_size))


void *libwl_alist_find(ALIST_HEAD *head, void *key);
int libwl_alist_add(ALIST_HEAD *head, void *key, int keysize, void *data, int datasize);
int libwl_alist_del(ALIST_HEAD *head, void *key, int keysize);
int libwl_alist_replace(ALIST_HEAD *head, void *old, void *new);
int libwl_alist_clear_all(ALIST_HEAD *head);



#endif
