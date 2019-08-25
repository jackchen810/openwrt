/*
 * CMD_GET process task for mqtt-client
 */

#ifndef __CMD_GET_H__
#define __CMD_GET_H__

void *SYS_task(void *argv);

int cmd_method_get(void *reply_buf, char *payload);
void generate_netinfo(void *reply_buf, char *sysinfo, char *id);
void get_net_speed_addr(void *reply_buf, char *sysinfo, char *id, const char *curl_addr);

#endif // __CMD_GET_H__
