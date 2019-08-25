#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifndef WIN32
#include <unistd.h>
#include <time.h>
#else
#include <process.h>
#include <winsock2.h>
#define snprintf sprintf_s
#endif

#include "mqtt-client.h"
#include "base64.h"
#include "common.h"
#include "sys_task.h"
#include "set_sync_task.h"
#include "cmd_get.h"
#include "utils.h"

sys_info netinfo_cmd_list[] = {
	{"lan_gateway", 			"uci get network.lan.ipaddr 2>/dev/null", 0},
	{NULL, NULL},
};

// cmd_method_get "CMD_GET" topic handler
int 
cmd_method_get(void *reply_buf, char *payload) {
	if (payload == NULL) {
		return 1;
	}

	json_object *IN_object = NULL;
	json_object *item_object = NULL, *id_object = NULL;
	int ret = 1;

	IN_object = json_tokener_parse(payload);/*translate string to object*/
	if( !IN_object || json_object_get_type(IN_object) != json_type_object ) {
		_mqtt_log_printf(MOSQ_LOG_ERR, "Failed to parse sysinfo message data.\n");
		goto OUT;
	}

	if( !json_object_object_get_ex(IN_object, "id", &id_object) ) {
		/*whether or not the key exists*/
		_mqtt_log_printf(MOSQ_LOG_ERR, "sysinfo: id field not exist.\n");
		goto OUT;
	}
	char id_buf[128] = {0};
	const char *subjson_id = json_object_get_string(id_object);
	if (subjson_id == NULL) {
		goto OUT;
	}
	snprintf(id_buf, sizeof(id_buf), "%s", (strlen(subjson_id) == 0)?"unknown":subjson_id);

	if( !json_object_object_get_ex(IN_object, "item", &item_object) ) {
		/*whether or not the key exists*/
		_mqtt_log_printf(MOSQ_LOG_ERR, "sysinfo: item field not exist.\n");
		goto OUT;
	}
	char item_buf[128] = {0}/*be used for cut prefix " and suffix "*/;
	const char *subjson_item = json_object_get_string(item_object);
	if (subjson_item == NULL) {
		goto OUT;
	}
	snprintf(item_buf, sizeof(item_buf), "%s",
		(strlen(subjson_item) == 0)?"unknown":subjson_item);

	if( STRCMP(item_buf, ==, "sysinfo") ) {
		Mqtt_generate_SYSinfo(reply_buf, "sysinfo", id_buf);
	} else if( STRCMP(item_buf, ==, "netinfo") ) {
		generate_netinfo(reply_buf, "netinfo", id_buf);
	} else if( STRCMP(item_buf, ==, "net_speed_addr") ) {
		json_object *curl_addr = NULL;
		if( !json_object_object_get_ex(IN_object, "curl_addr", &curl_addr) ) {
			/*whether or not the key exists*/
			_mqtt_log_printf(MOSQ_LOG_ERR, 
				"CMD_GET: net_speed_addr [curl_addr] field not exist.\n");
			goto OUT;
		}
		
		const char *subjson_curl_addr = json_object_get_string(curl_addr);
		if (subjson_curl_addr == NULL) {
			goto OUT;
		}
		get_net_speed_addr(reply_buf, "net_speed_addr", id_buf, subjson_curl_addr);
	} else {
		_mqtt_log_printf(MOSQ_LOG_ERR, "CMD_GET failed, no such item:%s\n", item_buf);
		goto OUT;
	}

	ret = 0;

OUT:
	json_object_put(IN_object);

	return ret;
}

// generate_netinfo generate netinfo 
void 
generate_netinfo(void *reply_buf, char *sysinfo, char *id) {
	int i = 0;
	char ROM_MAC[32] = {0};
	char cmd_buffer[128] = {0};			/*ues to store shell CMD result*/ 
	char buf[128] = {0};			/*use to cut prefix " and suffix "*/
	char timestamp_buf[32] = {0};
	char key_name[32] = {0};

	/*Creating a json array for apps*/
	json_object *OUT_object = json_object_new_object();

	/* add timestamp field */
	long int sec = 0, usec = 0;
	get_timestamp_millisecond(&sec, &usec);
	snprintf(timestamp_buf, sizeof(timestamp_buf), "%ld.%ld", sec, usec);
	json_object_object_add(OUT_object, "date", json_object_new_string(Trim(timestamp_buf)));

	json_object_object_add(OUT_object, "item", json_object_new_string(sysinfo));
	json_object_object_add(OUT_object, "id", json_object_new_string(id));

	/* get LAN DHCP range:
	*  eg: 100,250 is min:192.168.199.100, max:192.168.199.250 
	*/
	char dhcp_start_ip[16] = {0};
	char dhcp_limit_num[16] = {0};
	char dhcp_result_buf[16] = {0};
	char dhcp_range_buf[16] = {0};
	int exe_rest = 0;
	int dhcp_start_int = 0, dhcp_limit_int = 0, dhcp_end_int = 0;
	char *startptr = NULL, *limitptr = NULL;

	snprintf(key_name, sizeof(key_name), "%s", "lan_dhcp_range");
	snprintf(cmd_buffer, sizeof(cmd_buffer), "%s", "uci get dhcp.lan.start 2>/dev/null");
	exe_rest = ExecuateShellCMD(cmd_buffer, dhcp_result_buf, sizeof(dhcp_result_buf));
	if( exe_rest ) {
		_mqtt_log_printf(MOSQ_LOG_ERR, "NETINFO error, cmd=%s\n", cmd_buffer);
		json_object_object_add(OUT_object, key_name, json_object_new_string("unkown"));
	}else{
		if (dhcp_result_buf == NULL || strlen(dhcp_result_buf) == 0) {
			snprintf(dhcp_range_buf, sizeof(dhcp_range_buf), "%s", 
					"unknown");
		} else {
			substring(dhcp_start_ip, sizeof(dhcp_start_ip),
				dhcp_result_buf, 0, strlen(dhcp_result_buf)-1); // '\n'

			memset(dhcp_result_buf, 0, sizeof(dhcp_result_buf));
			memset(cmd_buffer, sizeof(cmd_buffer), 0);
			snprintf(cmd_buffer, sizeof(cmd_buffer), "%s", "uci get dhcp.lan.limit 2>/dev/null");
			exe_rest = ExecuateShellCMD(cmd_buffer, 
										dhcp_result_buf, 
										sizeof(dhcp_result_buf));
			if( exe_rest ) {
				_mqtt_log_printf(MOSQ_LOG_ERR, "NETINFO error, cmd=%s\n", cmd_buffer);
				snprintf(dhcp_range_buf, sizeof(dhcp_range_buf), "%s", 
					"unknown");
			}else{
				if (dhcp_result_buf == NULL || strlen(dhcp_result_buf)-1 <= 0) {
					_mqtt_log_printf(MOSQ_LOG_ERR, "NETINFO error2, cmd=%s\n", cmd_buffer);
					snprintf(dhcp_range_buf, sizeof(dhcp_range_buf), "%s", 
						"unknown");
				}else{
					substring(dhcp_limit_num, sizeof(dhcp_limit_num),
						dhcp_result_buf, 0, strlen(dhcp_result_buf)-1); // '\n'
					dhcp_start_int = strtoimax(dhcp_start_ip, &startptr, 10);
					dhcp_limit_int = strtoimax(dhcp_limit_num, &limitptr, 10);

					dhcp_end_int = dhcp_start_int + dhcp_limit_int;
					snprintf(dhcp_range_buf, sizeof(dhcp_range_buf), "%d,%d", 
						dhcp_start_int, dhcp_end_int);
					}
			}
		}
	}

	json_object_object_add(OUT_object, 
							key_name, 
							json_object_new_string(dhcp_range_buf));

	/* generate field from key-list */
	char result_buf[128] = {0};
	for( i=0; netinfo_cmd_list[i].cmd_name != NULL; i++ ) {
		/* init exec arg */
		exe_rest = 0;
		memset(cmd_buffer, 0, sizeof(cmd_buffer));
		memset(buf, 0, sizeof(buf));
		strncpy(cmd_buffer, netinfo_cmd_list[i].cmd_shell, sizeof(cmd_buffer));

		exe_rest = ExecuateShellCMD(cmd_buffer, 
									result_buf, 
									sizeof(result_buf));

		if( exe_rest ) {
			_mqtt_log_printf(MOSQ_LOG_ERR, 
				"NETINFO error: cmd=%s\n", cmd_buffer);
			json_object_object_add(OUT_object, netinfo_cmd_list[i].cmd_name, 
				json_object_new_string("unknown"));

			continue;
		}

		if (result_buf == NULL || strlen(result_buf) == 0) {
			snprintf(buf, sizeof(buf), "%s", "unknown");
		} else {
			if ( 0 == netinfo_cmd_list[i].uciflag ) {
				substring(buf, sizeof(buf), result_buf, 0, strlen(result_buf) - 1);	
				/* cut suffix \n */
			} else if( 1 == netinfo_cmd_list[i].uciflag ){	
				/* uci prefix ' and suffix '\n */
				substring(buf, sizeof(buf), result_buf, 1, strlen(result_buf) - 2);
			}
		}

		json_object_object_add(OUT_object, netinfo_cmd_list[i].cmd_name, 
			json_object_new_string(buf));
	}

OUT:
	strncpy((char *)reply_buf, json_object_to_json_string(OUT_object), BUF_SIZE-1);

	if(!is_error(OUT_object)) {
		json_object_put(OUT_object);
	}
	
	return;
}

void 
get_net_speed_addr(void *reply_buf, char *item_name, char *id, const char *curl_addr) {
	if (curl_addr == NULL || strlen(curl_addr) == 0) {
		_mqtt_log_printf(MOSQ_LOG_ERR, 
				"CMD_GET: net_speed_addr [curl_addr] is unvalid.\n");
		return;
	}

	int i = 0;
	char ROM_MAC[32] = {0};
	char cmd_buffer[128] = {0};			/*ues to store shell CMD result*/ 
	char buf[128] = {0};			/*use to cut prefix " and suffix "*/
	char timestamp_buf[32] = {0};

	/*Creating a json array for apps*/
	json_object *OUT_object = json_object_new_object();

	/* add timestamp field */
	long int sec = 0, usec = 0;
	get_timestamp_millisecond(&sec, &usec);
	snprintf(timestamp_buf, sizeof(timestamp_buf), "%ld.%ld", sec, usec);
	json_object_object_add(OUT_object, "date", json_object_new_string(Trim(timestamp_buf)));

	json_object_object_add(OUT_object, "item", json_object_new_string(item_name));
	json_object_object_add(OUT_object, "id", json_object_new_string(id));

	/* get LAN DHCP range:
	*  eg: 100,250 is min:192.168.199.100, max:192.168.199.250 
	*/
	char target_url_addr[512] = {0};
	int exe_rest = 0;
	int dhcp_start_int = 0, dhcp_limit_int = 0, dhcp_end_int = 0;
	char *startptr = NULL, *limitptr = NULL;

	char key_name[32] = {0};
	snprintf(key_name, sizeof(key_name), "%s", "addr");
	snprintf(cmd_buffer, 
			sizeof(cmd_buffer), 
			"curl %s 2>/dev/null",
			curl_addr);

	exe_rest = ExecuateShellCMD(cmd_buffer, target_url_addr, sizeof(target_url_addr));
	if( exe_rest || target_url_addr == NULL || strlen(target_url_addr) == 0 ) {
		_mqtt_log_printf(MOSQ_LOG_ERR, "net_speed_addr error, cmd [%s]\n", cmd_buffer);
		snprintf(target_url_addr, sizeof(target_url_addr), "%s", "unknown");
	}

	json_object_object_add(OUT_object, 
							key_name, 
							json_object_new_string(target_url_addr));

	strncpy((char *)reply_buf, json_object_to_json_string(OUT_object), BUF_SIZE-1);

	if(!is_error(OUT_object)) {
		json_object_put(OUT_object);
	}
	
	return;
}