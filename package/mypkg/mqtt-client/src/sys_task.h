/*
 * system process task 4 mqtt-client
 * Copyright (c) 2016, victortang <tangronghua@kunteng.org>
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */

#ifndef _SYS_TASK_H_
#define _SYS_TASK_H_

void *SYS_task(void *argv);
int Mqtt_operateWirelessSettings(const char *ssid, 
								const char *encryption, 
								const char *key, 
								const char *channel24, 
								const char *channel5);

int Check_wirelessparam_invalidornot(const char *ssid, 
									const char *encryption, 
									const char *key, 
									const char *channel24, 
									const char *channel5);
#endif
