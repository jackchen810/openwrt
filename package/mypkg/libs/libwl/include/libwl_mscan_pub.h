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
#ifndef __LIBWL_MSCAN_PUB_H_
#define __LIBWL_MSCAN_PUB_H_




typedef struct  AP_TLV_DATA
{
        ushort us_tlv_type;
        ushort us_tlv_len;
}AP_TLV_DATA;

enum {
        AP_TLV_TYPE_MAC = 1,
        AP_TLV_TYPE_RSSI = 2,
        AP_TLV_TYPE_STA_STAUS = 3,
        AP_TLV_TYPE_TIME = 4,
        AP_TLV_TYPE_CHANNEL = 5,
        AP_TLV_TYPE_WIFI_TYPE = 6,
        AP_TLV_TYPE_TX_POWER  = 7,
        AP_TLV_TYPE_CONN_TYPE = 8,
        AP_TLV_TYPE_IP = 9,
        AP_TLV_TYPE_CONN_COUNT = 10,
        AP_TLV_TYPE_MAX = 24
};

#define AP_MSG_TYPE_SCAN          1
#define AP_MSG_TYPE_CONNECT     2
#define AP_MSG_TYPE_CONN_DEL   3


 
#define AP_NLMSG_PID_MACSCAN            0x1001
#define AP_NLMSG_GROUPS            0x4


#define NETLINK_5G 25
#define NETLINK_24G 24

#endif
