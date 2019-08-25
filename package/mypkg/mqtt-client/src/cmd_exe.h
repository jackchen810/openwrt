/*
 * CMD_EXE process task for mqtt-client
 */

#ifndef __CMD_EXE_H__
#define __CMD_EXE_H__

#define DHCP_RANGE_BUF_LENGTH 64

int lan_if_opt(json_object *IN_object, char *desc);
int lan_dhcp_opt(json_object *IN_object, char *desc);
int wifidog_mode_opt(json_object *IN_object, char *desc);
int wireless_if_opt(json_object *IN_object);
#endif // __CMD_EXE_H__
