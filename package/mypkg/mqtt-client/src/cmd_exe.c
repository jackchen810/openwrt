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
#include "utils.h"
#include "ktmarket.h"
#include "cmd_exe.h"


#define WIFIDOG_INIT "/etc/init.d/wifidog"

/*
 * return:		0-		wireless parameter is valid.
			1-		parameter is invalid.
*/
int 
wireless_if_opt(json_object *IN_object) {
	int ret = 1;
	int disabled_is_set = 0;

	json_object *ssid_object = NULL, *channel_object = NULL;
	json_object *band_type_object = NULL, *en_object = NULL, *key_object = NULL;
	json_object *disabled_object = NULL;

	if( json_object_object_get_ex(IN_object, "band_type", &band_type_object) == 0 ){
		return ret;
	}

	if( json_object_object_get_ex(IN_object, "ssid", &ssid_object) == 0 ){
		return ret;
	}
	
	if( json_object_object_get_ex(IN_object, "channel", &channel_object) == 0 ){
		return ret;
	}
	
	if( json_object_object_get_ex(IN_object, "encryption", &en_object) == 0 ){
		return ret;
	}
	if( json_object_object_get_ex(IN_object, "key", &key_object) == 0 ){
		return ret;
	}

	if( json_object_object_get_ex(IN_object, "disabled", &disabled_object) == 0 ){
		; // key name "disabled" my be not exist 
	}else{
		disabled_is_set = 1;
		_mqtt_log_printf(MOSQ_LOG_INFO, "wireless config set disabled argument!\n");
	}

	/* Check_wirelessparam_invalidornot: 1-invalid, 0-valid */
	const char *ssid = json_object_get_string(ssid_object);
	const char *encrypt = json_object_get_string(en_object);
	const char *key = json_object_get_string(key_object);
	const char *band_type = json_object_get_string(band_type_object);
	const char *channel = json_object_get_string(channel_object);
	const char *disabled = NULL;
	if (disabled_is_set) {
		disabled = json_object_get_string(disabled_object);
		if (disabled == NULL) {
			_mqtt_log_printf(MOSQ_LOG_ERR, "wireless config setted but json get NULL!\n");
			return ret;
		}
	}
	
	// if (disabled != NULL) {
	// 	_mqtt_log_printf(MOSQ_LOG_INFO, "wireless config set disabled %s\n", disabled);
	// }
	if (wireless_ssid_check(ssid) ||
		wireless_encryption_check(encrypt, key) ||
		wireless_channel_check(band_type, channel)) {
		
		_mqtt_log_printf(MOSQ_LOG_ERR, "wireless value check failed!\n");
		return ret;
	}

	char encrypt_mode[64] = {0};
	if( STRCMP(encrypt, ==, "psk-mixed+tkip+ccmp") || 
		STRCMP(encrypt, ==, "1")){
		snprintf(encrypt_mode, sizeof(encrypt_mode), "%s", "psk-mixed+tkip+ccmp");
	}else{ //don't encrypt	
		memset(encrypt_mode, 0, sizeof(encrypt_mode));
	}

	int wireless_opt_result = 0;
	/* wireless_opt_result: 0-exeuted succeed; 1-failed */
	wireless_opt_result = wireless_opts(
		band_type,
		ssid,
		encrypt_mode,
		key,
		channel,
		disabled);
	if (wireless_opt_result) {
		return ret;
	}
	
	return 0;
}

int 
lan_if_opt(json_object *IN_object, char *desc) {
	json_object  *lan_gateway_jo = NULL;

	char buf[70] = {0};
	char cmd_result_buf[1024*5] = {0};
	char operation[256] = {0};
	char content_out[256] = {0};
	int len = 0;

	memset(buf, 0, sizeof(buf));
	memset(operation, 0, sizeof(operation));
	memset(content_out, 0, sizeof(content_out));

	if( json_object_object_get_ex(IN_object, "lan_gateway", &lan_gateway_jo) == 0 ){
		snprintf(desc, DESC_BUFF_LEN, "CMD_EXE: lan_if_opt key word '%s' not exist.", 
			"lan_gateway");
		_mqtt_log_printf(MOSQ_LOG_ERR, "CMD_EXE: %s\n", desc);

		return 1;
	}

	const char * lan_gateway_value = json_object_get_string(lan_gateway_jo);
	int uci_exec_result = 1; // record uci command execed or not
	if( lan_gateway_value != NULL && STRCMP(lan_gateway_value, !=, "") ){
		if (! is_valid_ip_address(lan_gateway_value)) {
			snprintf(desc, DESC_BUFF_LEN, 
				"CMD_EXE: lan_if_opt value '%s' of key[%s] is illegal.", 
				lan_gateway_value, "lan_gateway");

			_mqtt_log_printf(MOSQ_LOG_ERR, "CMD_EXE: %s\n", desc);
			return 1;
		}
		snprintf(operation, sizeof(operation), 
			"uci set network.lan.ipaddr='%s'", lan_gateway_value);
		uci_exec_result = ExecuateShellCMD_desc(operation, content_out, sizeof(content_out), desc);
		if (uci_exec_result) {
			return 1;
		}

		memset(content_out, 0, sizeof(content_out));
		uci_exec_result = ExecuateShellCMD_desc("uci commit network", buf, sizeof(buf), desc);
		if (uci_exec_result) {
			return 1;
		}

		char buf_stm_cmd[BUF_STM_CMD_LEN] = {0};
		char buf_stm_result[BUF_STM_RESULT_LEN] = {0};
		snprintf(buf_stm_cmd, sizeof(buf_stm_cmd), "%s", "sync");
		ExecuateShellCMD(buf_stm_cmd, buf_stm_result, sizeof(buf_stm_result));
		s_sleep(0, 500000); //0.5s

		memset(cmd_result_buf, 0, sizeof(cmd_result_buf));
		// int dnsmasq_state = 0;
		// dnsmasq_state = ExecuateShellCMD_desc("/etc/init.d/dnsmasq restart", 
		// 	cmd_result_buf, sizeof(cmd_result_buf), desc);

		// if (dnsmasq_state) {
		// 	return 1;
		// }

		// if( PackageIsExist("apfree_wifidog") ){/* check wifidog is running */
		// 	memset(buf, 0, sizeof(buf));
		// 	memset(cmd_result_buf, 0, sizeof(cmd_result_buf));
		// 	snprintf(buf, sizeof(buf), "%s", "/usr/bin/pgrep wifidog");
		// 	int ret = ExecuateShellCMD(buf, cmd_result_buf, sizeof(cmd_result_buf));
		// 	if (ret) {
		// 		_mqtt_log_printf(MOSQ_LOG_WARNING, 
		// 			"CMD_EXE: wifidog restart failed but go on setting lan_if_opt\n");
		// 	}else{
		// 		if (strlen(cmd_result_buf) >= 2) {
		// 			/* wifidog is running, and restart it */
		// 			memset(buf, 0, sizeof(buf));
		// 			memset(cmd_result_buf, 0, sizeof(cmd_result_buf));
		// 			snprintf(buf, sizeof(buf), "%s stop", WIFIDOG_INIT);
		// 			ExecuateShellCMD(buf, cmd_result_buf, sizeof(cmd_result_buf));

		// 			memset(buf, 0, sizeof(buf));
		// 			memset(cmd_result_buf, 0, sizeof(cmd_result_buf));
		// 			snprintf(buf, sizeof(buf), "%s start", WIFIDOG_INIT);
		// 			ExecuateShellCMD(buf, cmd_result_buf, sizeof(cmd_result_buf));
		// 		}
		// 	}

		// 	s_sleep(1, 0);
		// }

		uci_exec_result = ExecuateShellCMD_desc("/usr/sbin/lan-gateway-reload", 
			cmd_result_buf, sizeof(cmd_result_buf), desc);
		if (uci_exec_result) {
			return 1;
		}
		s_sleep(10, 0); //wate network restart
	}

	return 0;
}

// lan_dhcp_opt 
// return 1: error 0:OK
int 
lan_dhcp_opt(json_object *IN_object, char *desc) {
	json_object *lan_dhcp_range_jo = NULL;
	char buf[128] = {0};
	char cmd_result_buf[1024*5] = {0};
	int len = 0;

	memset(buf, 0, sizeof(buf));

	//json_object_object_get_ex == 0 not exist
	if(json_object_object_get_ex(IN_object, "lan_dhcp_range", &lan_dhcp_range_jo) == 0 ){
		snprintf(desc, DESC_BUFF_LEN, "CMD_EXE: lan_dhcp_opt key word '%s' not exist.", 
			"lan_dhcp_range");
		_mqtt_log_printf(MOSQ_LOG_ERR, "CMD_EXE: %s\n", desc);
		return 1;
	}

	const char *lan_dhcp_range_value = json_object_get_string(lan_dhcp_range_jo);
	if (is_error(lan_dhcp_range_value)) {
		return 1;
	}
	/* split dhcp range value by ',' single */
	if( STRCMP(lan_dhcp_range_value, !=, "") ){
		char start_str[DHCP_RANGE_BUF_LENGTH]= {0}, end_str[DHCP_RANGE_BUF_LENGTH] = {0};
		int fill_to_end = 0;
		int start_i = 0, end_i = 0;
		int end_str_start = 0; //index in lan_dhcp_range_value to fill in end_str buffer
		int field_len = strlen(lan_dhcp_range_value);
		int field_i = 0;
		for(;field_i < field_len; field_i++) {
			if (fill_to_end == 0) {
				if(lan_dhcp_range_value[field_i] == ',') {
					fill_to_end++;
					end_str_start = field_i + 1;
					continue;
				}
				start_str[field_i] = lan_dhcp_range_value[field_i];
			}else{
				end_str[field_i - end_str_start] = lan_dhcp_range_value[field_i];
			}
		}

		int start_is_int = 0, end_is_int = 0;
		int start_len = 0, end_len = 0;
		int dhcp_start_int = 0;
		int dhcp_end_int = 0;

		char *endptr;

		start_is_int = is_digits(start_str);
		end_is_int = is_digits(end_str);
		start_len = strlen(start_str);
		end_len = strlen(end_str);
		
		if (fill_to_end > 1 || fill_to_end == 0 || start_is_int == 0 || 
			end_is_int == 0 || start_len == 0 || end_len == 0) { 
			snprintf(desc, DESC_BUFF_LEN, "CMD_EXE: lan_dhcp_range [%s] not legal.", 
				lan_dhcp_range_value);
			_mqtt_log_printf(MOSQ_LOG_ERR, "%s\n", desc);
			return 1;
		}

		//dnsmasq while -1 at the end
		dhcp_start_int = strtoimax(start_str, &endptr, 10); 
		dhcp_end_int = strtoimax(end_str, &endptr, 10);

		int limit = dhcp_end_int - dhcp_start_int;
		if (limit <= 0 || dhcp_end_int >= 255) {
			snprintf(desc, DESC_BUFF_LEN, "CMD_EXE: lan_dhcp_range [%s] not legal.", 
				lan_dhcp_range_value);
			_mqtt_log_printf(MOSQ_LOG_ERR, "%s\n", desc);
			return 1;
		}

		char operation[256] = {0};
		char content_out[256] = {0};
		int uci_exec_result = 1; // record uci command execed or not
		snprintf(operation, sizeof(operation), "uci set dhcp.lan.start='%d'", 
			dhcp_start_int);

		uci_exec_result = ExecuateShellCMD_desc(operation, content_out, sizeof(content_out), desc);
		if (uci_exec_result) {
			return 1;
		}

		memset(operation, 0, sizeof(operation));
		memset(content_out, 0, sizeof(content_out));
		snprintf(operation, sizeof(operation), "uci set dhcp.lan.limit='%d'", limit);
		uci_exec_result = ExecuateShellCMD_desc(operation, content_out, sizeof(content_out), desc);
		if (uci_exec_result) {
			return 1;
		}

		uci_exec_result = ExecuateShellCMD_desc("uci commit dhcp", buf, sizeof(buf), desc);
		if (uci_exec_result) {
			return 1;
		}
		
		char buf_stm_cmd[BUF_STM_CMD_LEN] = {0};
		char buf_stm_result[BUF_STM_RESULT_LEN] = {0};
		snprintf(buf_stm_cmd, sizeof(buf_stm_cmd), "%s", "sync");
		ExecuateShellCMD(buf_stm_cmd, buf_stm_result, sizeof(buf_stm_cmd));
		s_sleep(0, 500000); //0.5s

		char network_uci_buf[1024*5] = {0};
		uci_exec_result = ExecuateShellCMD_desc("/etc/init.d/network restart", 
			network_uci_buf, sizeof(network_uci_buf), desc);
		if (uci_exec_result) {
			return 1;
		}
		s_sleep(10, 0); //wate network restart

		memset(cmd_result_buf, 0, sizeof(cmd_result_buf));
		int dnsmasq_state = 0;
		dnsmasq_state = ExecuateShellCMD_desc("/etc/init.d/dnsmasq restart", 
			cmd_result_buf, sizeof(cmd_result_buf), desc);

		if (dnsmasq_state) {
			return 1;
		}
		s_sleep(2, 0); // restart dnsmasq
	}

	return 0;
}

// wifidog_mode_opt 
// return 1: error, 0: OK
int wifidog_mode_opt(json_object *IN_object, char *desc) {
	json_object  *net_access_jo = NULL;
	json_object  *wd_active_jo = NULL;

	char operation[256] = {0};
	char content_out[256] = {0};
	int len = 0;

	if( !PackageIsExist("apfree_wifidog") ){
		snprintf(desc, DESC_BUFF_LEN, "CMD_EXE: wifidog_mode_opt wifidog doesn't exit");
		_mqtt_log_printf(MOSQ_LOG_ERR, "%s\n", desc);
		return 1;
	}
	int js_exist = 0;
	int do_net_access = json_object_object_get_ex(IN_object, "net_access", &net_access_jo);
	int do_wd_active = json_object_object_get_ex(IN_object, "wd_active", &wd_active_jo);

	if (do_net_access) {
		const char *net_access_value = json_object_get_string(net_access_jo);
		if (is_error(net_access_value)) {
			return 1;
		}
		char n_a_value[32] = {0};
		if( (STRCMP(net_access_value, !=, "enable")) && 
			(STRCMP(net_access_value, !=, "disable")) ){

			snprintf(desc, DESC_BUFF_LEN, "CMD_EXE: wifidog_mode_opt %s:%s is illegal.", 
				"net_access", net_access_value);
			_mqtt_log_printf(MOSQ_LOG_ERR, "CMD_EXE: %s\n", desc);
			return 1;
		}else{
			snprintf(n_a_value, sizeof(n_a_value), "%s", net_access_value);
		}

		snprintf(operation, sizeof(operation), "wifidog_op net_access %s", n_a_value);
		int w_op_exec_result = ExecuateShellCMD_desc(operation, 
													content_out, 
													sizeof(content_out), 
													desc);
		if (w_op_exec_result) {
			return 1;
		}
	}

	if (do_wd_active) {
		const char *active_jo_value = json_object_get_string(wd_active_jo);
		if (is_error(active_jo_value)) {
			return 1;
		}

		if( (STRCMP(active_jo_value, !=, "enable")) && 
			(STRCMP(active_jo_value, !=, "disable")) ){

			snprintf(desc, DESC_BUFF_LEN, "CMD_EXE: wifidog_mode_opt %s:%s is illegal.", 
				"wd_active", active_jo_value);
			_mqtt_log_printf(MOSQ_LOG_ERR, "CMD_EXE: %s\n", desc);
			return 1;
		}

		memset(operation, 0, sizeof(operation));
		memset(content_out, 0, sizeof(content_out));

		snprintf(operation, sizeof(operation), "wifidog_op wifidog %s", active_jo_value);
		int w_op_exec_result = ExecuateShellCMD_desc(operation, 
													content_out, 
													sizeof(content_out), 
													desc);
		if (w_op_exec_result) {
			return 1;
		}

		// gukq 20170213 using ExecuateShellCMD instead of system-func
		char buf_stm_cmd[BUF_STM_CMD_LEN] = {0};
		char buf_stm_result[BUF_STM_RESULT_LEN] = {0};
		if (STRCMP(active_jo_value, ==, "disable")) {
			snprintf(buf_stm_cmd, sizeof(buf_stm_cmd), 
				"%s", "/etc/init.d/wifidog disable");
			ExecuateShellCMD(buf_stm_cmd, buf_stm_result, sizeof(buf_stm_cmd));
			s_sleep(0, 500000); //0.5s

			memset(buf_stm_cmd, 0, sizeof(buf_stm_cmd));
			memset(buf_stm_result, 0, sizeof(buf_stm_result));

			snprintf(buf_stm_cmd, sizeof(buf_stm_cmd), "%s", 
				"/etc/init.d/wifidog stop");
			ExecuateShellCMD(buf_stm_cmd, buf_stm_result, sizeof(buf_stm_cmd));
		}else{
			snprintf(buf_stm_cmd, sizeof(buf_stm_cmd), "%s", 
				"/etc/init.d/wifidog enable");
			ExecuateShellCMD(buf_stm_cmd, buf_stm_result, sizeof(buf_stm_cmd));
			s_sleep(0, 500000); //0.5s

			memset(buf_stm_cmd, 0, sizeof(buf_stm_cmd));
			memset(buf_stm_result, 0, sizeof(buf_stm_result));
			snprintf(buf_stm_cmd, sizeof(buf_stm_cmd), "%s", 
				"/etc/init.d/wifidog start");
			ExecuateShellCMD(buf_stm_cmd, buf_stm_result, sizeof(buf_stm_cmd));
		}
	}

	return 0;
}