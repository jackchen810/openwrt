/*
 * Common providing some basic function 4 mqtt-client
 * Copyright (c) 2016, victortang <tangronghua@kunteng.org>
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */

#ifndef _COMMON_H_
#define _COMMON_H_
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <sys/types.h>
#include <sys/ipc.h>
#include <sys/msg.h>
#include <errno.h>
#include <assert.h>
#include <json-c/json.h>
#include <mosquitto.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <uci.h>
#include <pthread.h>
#include <dirent.h>
#include <unistd.h>
#include <stdarg.h>
#include <sys/time.h>

/*
 * structure used to hold mosquitto_message mosquitto structure.
 */
typedef struct _MQTT_C_MSQ_
{
	long msgtype;
	char* content[3];
}mqtt_c_msq;

typedef unsigned int	UINT32;
typedef unsigned short	UINT16;
typedef unsigned char	UINT8;

#define MQTT_CLINET_PROC_MAME "mqtt-client"
#define STARTED_BY_SERVICE 1

#define SEM_SETS_COUNT 3
#define SYS_MSGKEY 5000
#define WD_MSGKEY 5001
#define BUF_STM_CMD_LEN 256
#define BUF_STM_RESULT_LEN 256

#define         STRCMP(a, R, b)         (strcmp(a, b) R 0)
#define			BUF_SIZE				(1024*6)
#define 		LEN_SSID 				30

#define			SNYNC_TARGET			"YunAC"

#define			SNYNC_ID				"ROMSYNC"
#define			SNYNC_MODIFY			"ROMMODIFY"

#define MAXLOGSIZE (1024*512*1) //512k
//#define MAXLOGSIZE (1024*10) //10K

#ifndef os_malloc
#define os_malloc(s) malloc((s))
#endif
#ifndef os_memset
#define os_memset(s, c, n) memset(s, c, n)
#endif
#ifndef os_free
#define os_free(p) free((p))
#endif

#define WITH_DESC 0 //return command exec state desc or not

#define KT_WIRELESS_OP "/usr/sbin/kt_wireless_op.lua"
#define CMD_TIMEOUT_PATH "/etc/mqtt_timeout"

#define SHELL_CMD_BUFFER 5120 //5*1024
#define DESC_BUFF_LEN 1024
#define APPS_COUTN_MAX 64
#define WIRELESS_BAND_TYPE_LEN 8
#define WIRELESS_CHANNEL_LEN 8
#define WIRELESS_KEY_LEN 64

typedef struct _SYS_INFO {
	char *cmd_name;
	char *cmd_shell;
	char uciflag;
}sys_info;

typedef struct _UCI_INFO {
	struct uci_context *wireless_ctx;
	struct uci_package *wireless_pkg;
	struct uci_context *system_ctx;
	struct uci_package *system_pkg;
	struct uci_context *firmwareinfo_ctx;
	struct uci_package *firmwareinfo_pkg;
	struct uci_context *rsyslog_ctx;
	struct uci_package *rsyslog_pkg;
}uci_info;

typedef struct _CMD_OPT {
	char *name;
	char *cmd_shell;
}cmd_opt;

typedef enum _SET_OPTION_ {
	CMD_SET = 1,
	CMD_SYNC = 2,
	CMD_EXE = 3
}set_option;

static int sys_msqid = -1, wd_msqid = -1;

int ExecuateShellCMD(const char * shellCMD, char * r_buffer, int len);
int ExecuateShellCMD_log(const char * shellCMD, char * r_buffer);
int ExecuateShellCMD_desc(char * shellCMD, char *r_buffer, int len, char *desc);
int GetRouterMAC(char *buf, char *mac, int mac_len);
int Mqtt_parse_INtopic_OUTsubtopic(char *subtopic, int olen, char *INtopic);
int Mqtt_generate_newTopic(char *newtopic, int new_topic_len, char *oldtopic);
int local_message_queues_init(void);
int send_msq(void *mosq, char *topic, char *payload, char *subtopic);
int read_all_file(char * fname, char * content);
int CollectionOfAPPName(char *table, int *num);
int CollectionOfAPPVersion(char *name, char *content, int content_len);
int Mqtt_generate_SYSINFO(void *reply_buf, char *payload);
void Mqtt_SYSINFO_error(void *reply_buf, char *payload);
void Mqtt_generate_SYSinfo(void *reply_buf, char *sysinfo, char *id);
int _mqtt_log_printf(int priority, const char *fmt, ...);
// int Mqtt_Get_SYSinfo(void *reply_buf, char *payload);
void destory_message_queues(void);
char *get_board_info(const char *board_info);

/* wireless arguments check, 1: illegal, 0:ok */
int wireless_ssid_check(const char *ssid);
int wireless_encryption_check(const char *encryption, const char *key);
int wireless_channel_check(const char *band_type, const char *channel);

int IsInvalidchannel24(const char *channel);
int wireless_opts(const char *band_type, 
				const char *ssid, 
				const char *encryption, 
				const char *key, 
				const char *channel,
				const char *disabled);

int curl_download(char *url, char *target_filename, int resume_enable);
int clean_dead_pids(char *cmd_head, int proc_ancestor_pid);
int check_md5sum_popen(const char *md5list_file);
// int script_download(char *cmd_path, char *target_filename);
#endif
