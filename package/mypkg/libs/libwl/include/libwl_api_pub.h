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
#ifndef __LIBWL_API_PUB_H_
#define __LIBWL_API_PUB_H_


#define MAC_LEN_6        6
#define BUF_LEN_16       16
#define BUF_LEN_32       32
#define BUF_LEN_64       64
#define BUF_LEN_128      128
#define BUF_LEN_256      256
#define BUF_LEN_512      512
#define BUF_LEN_1024     1024
#define BUF_LEN_2048     2048
#define BUF_LEN_4096     4096

#define LOG_BUFFER_1024      1024
#define LOG_BUFFER_2048      2048
#define LOG_BUFFER_4096      4096
#define LOG_BUFFER_8192      8192


int libwl_create_netlink_socket(int protocol);
int libwl_add_epoll(int epollfd, int sock_fd);


int libwl_uci_load_config(void);
int libwl_uci_unload_config(void);
int libwl_uci_get_option(char *pkg_name, char *section_type, char *section_name, char *op_name, char ret_value[], int ret_len);
int libwl_uci_get_option_fast(struct uci_context *uci_ctx, char *pkg_name, char *section_type, char *section_name, char *op_name, char ret_value[], int ret_len);
int libwl_uci_get_wireless_ifname(struct uci_context *uci_ctx, char *band, char ret_value[], int ret_len);
int libwl_uci_get_wifi_device(struct uci_context *uci_ctx, char *band, char *op_name, char ret_value[], int ret_len) ;
int libwl_uci_get_wifi_iface(struct uci_context *uci_ctx, char *ifname, char *op_name, char ret_value[], int ret_len);

int libwl_uci_set_option(struct uci_context *uci_ctx, char *pkg_name, char *section, char *op_name, char *op_value);
int libwl_uci_set_wifi_iface(struct uci_context *uci_ctx, char *ifname, char *op_name, char *op_value);
int libwl_uci_set_wifi_device(struct uci_context *uci_ctx, char *band, char *op_name, char *op_value);

int libwl_get_5g_name(char *if_name, int buf_len);
int libwl_get_2g_name(char *if_name, int buf_len);
int libwl_get_lan_name(char *if_name, int buf_len);
int libwl_get_wan_name(char *if_name, int buf_len);


int libwl_get_2g_port_no(char *port_name, int buf_len, int *port_no);
int libwl_get_5g_port_no(char *port_name, int buf_len, int *port_no);
int libwl_get_router_mac(const char *if_name, char *mac, int buf_len);
int libwl_get_router_hwaddr(const char *if_name, char *hwaddr, int buf_len);
int libwl_get_router_hwaddr_short(const char *if_name, char *hwaddr, int buf_len);
int libwl_get_router_ip(const char *if_name, char *ip, int buf_len);
int libwl_get_ip_by_mac(unsigned char *p_mac, char *dest_ip, int buf_len);
int libwl_get_router_channel(const char *if_name, int *channel);
int libwl_get_access_amount(char *dev_type, char *if_name, int *count);
int libwl_get_wan_status(void);
int libwl_get_lan_name(char *if_name, int buf_len);
int libwl_get_wan_name(char *if_name, int buf_len);
int libwl_hwaddr_htoa(const char *hwaddr, char mac[], int len);





#endif
