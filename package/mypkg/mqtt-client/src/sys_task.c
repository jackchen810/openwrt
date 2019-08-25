/*
 * system process task 4 mqtt-client
 * Copyright (c) 2016, victortang <tangronghua@kunteng.org>
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */

/*
 * Contributors:
 * Victor Tang @20160712- initial implementation and documentation.
 */

#include <curl/curl.h>
#include <stdio.h>

#include <fcntl.h>
#include "utils.h"
#include "sys_task.h"
#include "common.h"
#include "base64.h"
#include "ktmarket.h"
#include "cmd_exe.h"

#define PASSWD_LEN_MAX 128
#define QR_LEN_MAX 240
#define UP_DOWN_RATE_MAX 8
#define UP_DOWN_RATE_LIMIT 1024000

#define EXEC_SHELL 0

#define QOS_BIN "/usr/bin/aqos"

#define FN_FIELD_NUM 10 //9 fields word and 1 NULL field
#define FN_FIELD_LEN 128
#define FN_LEN 1152 //128*9
#define F_URL_LEN 1664 //128*13
#define FN_BOARD_INDEX 6 //7-1
#define FN_SYSUPGRADE_INDEX 8 // 9-1

int Mqtt_write_file(const char *content, char *filename) {
	FILE *f_halder = NULL;
	unsigned char *p_write = NULL;
	int len = 0;

	p_write = base64_decode(content, strlen(content), &len);

	f_halder = fopen(filename, "wb");
	if( f_halder == NULL ){
		return 1;
	}
	fwrite(p_write, len, 1, f_halder);

	fclose(f_halder);
	free(p_write);

	return 0;
}

/*
 * return:	0-wireless parameter is valid.
 *			1-parameter is invalid.
*/
int Check_wirelessparam_invalidornot(const char *ssid, 
										const char *encryption, 
										const char *key,
										const char *channel24, 
										const char *channel5) {
	if( ssid == NULL || strlen(ssid) > LEN_SSID ) {
		_mqtt_log_printf(MOSQ_LOG_ERR, "sys_task: invalid ssid:%s.\n", ssid);
		return 1;
	}

	if( encryption == NULL || STRCMP(encryption, ==, "none") || 
			STRCMP(encryption, ==, "psk-mixed+tkip+ccmp") || 
			STRCMP(encryption, ==, "") ){

		if( STRCMP(encryption, ==, "psk-mixed+tkip+ccmp") ){
			if (key != NULL && strlen(key) > 8) {	// with subfix ""

				if( IsALNUMornot(key) ){
					return 1;
				}

				if( strlen(key) > 63 ){
					return 1;
				}
			}else{
				_mqtt_log_printf(MOSQ_LOG_ERR, "sys_task: invalid wireless-key:%s\n", key);
				return 1;
			}
		}
	} else {
		_mqtt_log_printf(MOSQ_LOG_ERR, "sys_task: invalid encryption:%s\n", encryption);
		return 1;
	}

	if( IsInvalidchannel24(channel24) ){
		_mqtt_log_printf(MOSQ_LOG_ERR, "sys_task: invalid channel24:%s\n", channel24);
		return 1;
	}

	if ( channel5 == NULL) {
		return 1;
	}
	if( STRCMP(channel5, ==, "0") || STRCMP(channel5, ==, "149") ||
		STRCMP(channel5, ==, "153") || STRCMP(channel5, ==, "157") ||
		STRCMP(channel5, ==, "161") || STRCMP(channel5, ==, "165") || 
		STRCMP(channel5, ==, "")){

		return 0;
	}

	_mqtt_log_printf(MOSQ_LOG_ERR, "sys_task: invalid channel5:%s\n", channel5);
	return 1;
}

/*
 * return:		0-success; 1-error
*/
int Mqtt_operateWirelessSettings(const char *ssid, 
								const char *encryption, 
								const char *key, 
								const char *channel24, 
								const char *channel5){
	char buf[32] = {0}, operation[128] = {0};
	int wirelesscnt = 0, i = 0;

	if (!ssid || !encryption || !key || !channel24 || !channel5) {
		return 1;
	}

	//check howmany ssid in this router
	ExecuateShellCMD("uci show wireless | grep channel | wc -l", buf, sizeof(buf));
	if (strlen(buf) == 0) {
		return 1;
	}
	wirelesscnt = buf[0]-'0';

	for(i=0; i<wirelesscnt; i++) {
		if( STRCMP(ssid, !=, "") ){
			snprintf(operation, sizeof(operation), "uci set wireless.@wifi-iface[%d].ssid='%s'",i,ssid);
			ExecuateShellCMD(operation, buf, sizeof(buf));
		}
		if( STRCMP(encryption, !=, "") ){
			snprintf(operation, sizeof(operation), "uci set wireless.@wifi-iface[%d].encryption='%s'", i, encryption);
			ExecuateShellCMD(operation, buf, sizeof(buf));
		}
		if( STRCMP(encryption, ==, "psk-mixed+tkip+ccmp" ) ){
			snprintf(operation, sizeof(operation), "uci set wireless.@wifi-iface[%d].key='%s'", i, key);
			ExecuateShellCMD(operation, buf, sizeof(buf));
		}
		// liudf added 20160217
		memset(operation, 0, sizeof(operation));
		memset(buf, 0, sizeof(buf));
	}
	/*channel is different*/
	// liudf added 20160215
	if(wirelesscnt == 2) {
		if( STRCMP(channel5, !=, "" ) ){
			snprintf(operation, 100,  "/usr/sbin/kt_wireless_op.lua chan set 5 '%s'", channel5);
			ExecuateShellCMD(operation, buf, sizeof(buf));
		}
		// liudf added 20160217
		memset(operation, 0, sizeof(operation));
		memset(buf, 0, sizeof(buf));
	}

	if( STRCMP(channel24, !=, "" ) ){
		snprintf(operation, sizeof(operation), "/usr/sbin/kt_wireless_op.lua chan set 2 '%s'", channel24);
		ExecuateShellCMD(operation, buf, sizeof(buf));
	}

	ExecuateShellCMD("uci commit wireless", buf, sizeof(buf));
	s_sleep(0, 500);
	ExecuateShellCMD("wifi reload", buf, sizeof(buf));

	return 0;
}

/*
 * return:		0-		wireless parameter is valid.
			1-		parameter is invalid.
*/
int Mqtt_operationWireless(json_object *IN_object) {
	json_object *ssid_object = NULL, *channel24_object = NULL;
	json_object *channel5_object = NULL, *en_object = NULL, *key_object = NULL;

	if( json_object_object_get_ex(IN_object, "ssid", &ssid_object) == 0 ){
		return 1;
	}
		
	if( json_object_object_get_ex(IN_object, "channel_2.4", &channel24_object) == 0 ){
		return 1;
	}
		
	if( json_object_object_get_ex(IN_object, "channel_5", &channel5_object) == 0 ){
		return 1;
	}
		
	if( json_object_object_get_ex(IN_object, "encryption", &en_object) == 0 ){
		return 1;
	}
		
	if( json_object_object_get_ex(IN_object, "key", &key_object) == 0 ){
		return 1;
	}

	/* Check_wirelessparam_invalidornot: 1-invalid, 0-valid */
	if( Check_wirelessparam_invalidornot(json_object_get_string(ssid_object),
			json_object_get_string(en_object), 
			json_object_get_string(key_object),
			json_object_get_string(channel24_object), 
			json_object_get_string(channel5_object)) ) {

		return 1;
	}

	/* Mqtt_operateWirelessSettings: 0-exeuted succeed; 1-failed */
	if( Mqtt_operateWirelessSettings(json_object_get_string(ssid_object),
			json_object_get_string(en_object), 
			json_object_get_string(key_object),
			json_object_get_string(channel24_object), 
			json_object_get_string(channel5_object)) ) {

		return 1;
	}
	return 0;
}

/*
 * return:	0-		success.
 *			1-		error
*/
int Mqtt_operateRsyslog(json_object *IN_object) {
	json_object *rsyslog_object = NULL;
	char operation[1024] = {0};

	if( json_object_object_get_ex(IN_object, "ip", &rsyslog_object) == 0 ) {
		return 1;
	}

	_mqtt_log_printf(MOSQ_LOG_INFO, "rsyslog server ips length = %d\n", \
		json_object_array_length(rsyslog_object));
	
	char buf_stm_cmd[BUF_STM_CMD_LEN] = {0};
	char buf_stm_result[BUF_STM_RESULT_LEN] = {0};
	int i = 0;
	for( i=0; i<json_object_array_length(rsyslog_object); i++) {
		memset(buf_stm_cmd, 0, sizeof(buf_stm_cmd));
		memset(buf_stm_result, 0, sizeof(buf_stm_result));

		memset(operation, 0, sizeof(operation));
		struct json_object *obj = json_object_array_get_idx(rsyslog_object, i);
		snprintf(operation, sizeof(operation), 
			"uci add_list rsyslog.@rsyslog[0].server_hostname='%s'", 
			json_object_get_string(obj));

		ExecuateShellCMD(operation, buf_stm_result, sizeof(buf_stm_result));
		s_sleep(0, 500000); //0.5s

		// _mqtt_log_printf(MOSQ_LOG_INFO, "sys_task: %s\n", operation);
	}

	memset(buf_stm_cmd, 0, sizeof(buf_stm_cmd));
	memset(buf_stm_result, 0, sizeof(buf_stm_result));
	snprintf(buf_stm_cmd, sizeof(buf_stm_cmd), "%s", "uci commit rsyslog");
	ExecuateShellCMD(buf_stm_cmd, buf_stm_result, sizeof(buf_stm_result));
	s_sleep(0, 500000); //0.5s

	memset(buf_stm_cmd, 0, sizeof(buf_stm_cmd));
	memset(buf_stm_result, 0, sizeof(buf_stm_result));
	snprintf(buf_stm_cmd, sizeof(buf_stm_cmd), "%s", "/etc/init.d/rsyslog stop");
	ExecuateShellCMD(buf_stm_cmd, buf_stm_result, sizeof(buf_stm_result));

	s_sleep(0, 500000); //0.5s

	memset(buf_stm_cmd, 0, sizeof(buf_stm_cmd));
	memset(buf_stm_result, 0, sizeof(buf_stm_result));
	snprintf(buf_stm_cmd, sizeof(buf_stm_cmd), "%s", "/etc/init.d/rsyslog start");
	ExecuateShellCMD(buf_stm_cmd, buf_stm_result, sizeof(buf_stm_result));

	return 0;
}

/*
 * return:	0-		success.
 *			1-		error
*/
int Mqtt_operateMosquitto(json_object *IN_object) {
	json_object *mosquitto_object = NULL;
	char buf[70] = {0};
	char content_out[256] = {0}, operation[256] = {0};

    if( json_object_object_get_ex(IN_object, "ip", &mosquitto_object) == 0 ){
		return 1;
	}

	const char *subjson_obj = json_object_get_string(mosquitto_object);
	if (subjson_obj == NULL) {
		return 1;
	}
    snprintf(operation, sizeof(operation), 
		"uci set mosquitto.@bridge[0].address='%s'", subjson_obj);

	/*this setting operation will never fail*/
    ExecuateShellCMD(operation, content_out, sizeof(content_out));
    ExecuateShellCMD("uci commit mosquitto", buf, sizeof(buf));
    ExecuateShellCMD("/etc/init.d/mosquitto restart", buf, sizeof(buf));

	return 0;
}

/*
 * return:	0-		success.
 *			1-		error
*/
int Mqtt_operateWifidog(json_object *IN_object) {
	json_object *wdhostname_object = NULL, *wdport_object = NULL, *wdpath_object = NULL;

	if( json_object_object_get_ex(IN_object, "hostname", &wdhostname_object) == 0 ){
		_mqtt_log_printf(MOSQ_LOG_INFO, 
			"systask: wifidog key word 'hostname' is not exist.\n");
		return 1;
	}
	if( json_object_object_get_ex(IN_object, "port", &wdport_object) == 0 ){
		_mqtt_log_printf(MOSQ_LOG_INFO, 
			"systask: wifidog key word 'port' is not exist.\n");
		return 1;
	}
	if( json_object_object_get_ex(IN_object, "path", &wdpath_object) == 0 ){
		_mqtt_log_printf(MOSQ_LOG_INFO, 
			"systask: wifidog key word 'path' is not exist.\n");
		return 1;
	}

	const char *tmphostname = json_object_get_string(wdhostname_object);
	const char *tmpport = json_object_get_string(wdport_object);
	const char *tmppath = json_object_get_string(wdpath_object);

	int uci_sub = 0;
	char path[64] = {0};
	char buf[128] = {0};
	char operation[256] = {0};
	char content_out[256] = {0};
	char *p = NULL;
	int len = 0;
	// because tmppath could be B64decode failed to goto OUT, trate it firstly
	if( tmppath != NULL && STRCMP(tmppath, !=, "") ){
		p = base64_decode(tmppath, strlen(tmppath), &len);
		if( p == NULL ) {
			_mqtt_log_printf(MOSQ_LOG_INFO, 
				"systask: wifidog 'path' value B64 decode failed! decode length %d.\n", len);
			return 1;
		}
		
		memcpy(path, p, len);//path is decode from base64
		free(p);

		snprintf(operation, sizeof(operation), 
			"uci set wifidog.@wifidog[0].auth_server_path='%s'", path);
		/*this setting operation will never fail*/
		ExecuateShellCMD(operation, content_out, sizeof(content_out));

		uci_sub = 1;
	}

	if( tmphostname != NULL && STRCMP(tmphostname, !=, "") ){
		snprintf(operation, sizeof(operation), 
			"uci set wifidog.@wifidog[0].auth_server_hostname='%s'", tmphostname);
		ExecuateShellCMD(operation, content_out, sizeof(content_out));
		uci_sub = 1;
	}
	if( tmpport != NULL && STRCMP(tmpport, !=, "") ){
		snprintf(operation, sizeof(operation), 
			"uci set wifidog.@wifidog[0].auth_server_port='%s'", tmpport);
		ExecuateShellCMD(operation, content_out, sizeof(content_out));
		uci_sub = 1;
	}

	if (1 == uci_sub) {
		ExecuateShellCMD("uci commit wifidog", buf, sizeof(buf));
		ExecuateShellCMD("sync", content_out, sizeof(content_out));
		ExecuateShellCMD("/etc/init.d/wifidog reload", buf, sizeof(buf));
	}

	return 0;
}

/*
 * return:	0-		success.
 *			1-		error
*/
int Mqtt_operateWD_wired_pass(json_object *IN_object) {
	json_object *enable_object = NULL;
	char content_out[256] = {0}, operation[256] = {0};

    if( json_object_object_get_ex(IN_object, "enable", &enable_object) == 0 ) {
		return 1;
	}

	const char *enable_stat = json_object_get_string(enable_object);
	if (is_error(enable_stat)) {
		return 1;
	}

	if (!(STRCMP(enable_stat, ==, "0")) && !(STRCMP(enable_stat, ==, "1"))) {
		_mqtt_log_printf(MOSQ_LOG_ERR, "systask: WD_wired_pass field [%s] error\n", enable_stat);
		return 1;
	}

    snprintf(operation, sizeof(operation), 
		"uci set wifidog.@wifidog[0].wired_passed='%s'", enable_stat);

	/*this setting operation will never fail*/
    ExecuateShellCMD(operation, content_out, sizeof(content_out));
    ExecuateShellCMD("uci commit wifidog", content_out, sizeof(content_out));
    ExecuateShellCMD("/etc/init.d/wifidog reload", content_out, sizeof(content_out));

	return 0;
}

/*
 * return:	0-		success.
 *			1-		error
*/
int Mqtt_operateWD_roam_switch(json_object *IN_object) {
	json_object *enable_object = NULL;
	char content_out[256] = {0}, operation[256] = {0};

    if( json_object_object_get_ex(IN_object, "enable", &enable_object) == 0 ){
        return 1;
	}

	const char *enable_stat = json_object_get_string(enable_object);
	if ( enable_stat == NULL) {
		return 1;
	}

	char buf_stm_cmd[BUF_STM_CMD_LEN] = {0};
	char buf_stm_result[BUF_STM_RESULT_LEN] = {0};
	if( STRCMP(enable_stat, ==, "0") ) {
		snprintf(buf_stm_cmd, sizeof(buf_stm_cmd), "%s", "wifidog_roam disable");
		ExecuateShellCMD(buf_stm_cmd, buf_stm_result, sizeof(buf_stm_result));
		s_sleep(0, 500000); //0.5s
	} else if( STRCMP(enable_stat, ==, "1") ) {
		snprintf(buf_stm_cmd, sizeof(buf_stm_cmd), "%s", "wifidog_roam enable");
		ExecuateShellCMD(buf_stm_cmd, buf_stm_result, sizeof(buf_stm_result));
		s_sleep(0, 500000); //0.5s
	} else {
		return 1;
	}

	return 0;
}

/*
 * return:	0-		success.
 *			1-		error
*/
int Mqtt_operateShell(json_object *IN_object, json_object *OUT_object) {
	json_object *shell_json_object = NULL;
	char content_out[SHELL_CMD_BUFFER] = {0};

	if( json_object_object_get_ex( IN_object, "cmd", &shell_json_object) == 0 ) {
		return 1;
	}

	const char* operation = json_object_get_string(shell_json_object);
	if (is_error(operation)) {
		return 1;
	}

	if( ExecuateShellCMD_log(operation, content_out) ){
		return 1;
	}
	json_object_object_add(OUT_object, "log", json_object_new_string(content_out));

	return 0;
}

/*
 * return:	0-		success.
 *			1-		error
*/
int Mqtt_operateShell64(json_object *IN_object, json_object *OUT_object) {
	json_object *shell_object = NULL;
	char content_out[SHELL_CMD_BUFFER] = {0}, 
		content_err[SHELL_CMD_BUFFER] = {0}, 
		operation_cmd[SHELL_CMD_BUFFER] = {0};

	char *encode_out = NULL, *encode_err = NULL;
	int out_len = 0;

	if( json_object_object_get_ex( IN_object, "cmd", &shell_object) == 0 ){
		return 1;
	}

	const char* operation = json_object_get_string(shell_object);
	if (operation == NULL) {
		return 1;
	}

	snprintf(operation_cmd, sizeof(operation_cmd), 
		"%s 1>/tmp/stdout.log 2>/tmp/stderr.log", operation);
	//_mqtt_log_printf(MOSQ_LOG_INFO, "sys_task: Mqtt_operateShell64:%s\n", operation_cmd);
	char buf_stm_result[BUF_STM_RESULT_LEN] = {0};
	ExecuateShellCMD(operation_cmd, buf_stm_result, sizeof(buf_stm_result));
	s_sleep(0, 100000); //0.1s

	if( read_all_file("/tmp/stdout.log", content_out) ){
		return 1;
	}
	encode_out = base64_encode(content_out, strlen(content_out), &out_len);
	json_object_object_add(OUT_object, "logout", json_object_new_string(encode_out));

	out_len = 0;
	if( read_all_file("/tmp/stderr.log", content_err) ){
		return 1;
	}
	encode_err = base64_encode(content_err, strlen(content_err), &out_len);
	json_object_object_add(OUT_object, "logerr", json_object_new_string(encode_err));

	return 0;
}

/*
 * Mqtt_GetFWname4murl
 * return:	0-		success.
 *			1-		error
*/
int Mqtt_GetFWname4murl(char *url, char *FWname) {
	if( url == NULL ){
		return 1;
	}
	int index = strlen(url) -1;
	int step_count = 0;
    char * prt = url;

	while( prt[index] != '/' ){
		index--;
		step_count++;
	}

	memcpy(FWname, &prt[index+1], step_count-1);
	FWname[step_count-1] = '\0';

	return 0;
}

/*
 * return:	0-		success.
 *			1-		error
*/
int 
Mqtt_operationFWupgrade(json_object *IN_object) {
	json_object *sfile_object = NULL, *md5_object = NULL, *reflash_object = NULL, *destver_object = NULL;
	char content_out[1024] = {0}, operation[1024] = {0};
	char firmware_name[FN_LEN] = {0}, url_fmt[F_URL_LEN] = {0};
	char destver_buf[64] = {0};

	if( json_object_object_get_ex(IN_object, "sfile", &sfile_object) == 0 ){
		return 1;
	}
	if( json_object_object_get_ex(IN_object, "md5", &md5_object) == 0 ){
		return 1;
	}
	if( json_object_object_get_ex(IN_object, "reflash", &reflash_object) == 0 ){
		return 1;
	}

	char buf_stm_cmd[BUF_STM_CMD_LEN] = {0};
	char buf_stm_result[BUF_STM_RESULT_LEN] = {0};
	snprintf(buf_stm_cmd, sizeof(buf_stm_cmd), "%s", "rm -f /tmp/*sysupgrade.bin");
	ExecuateShellCMD(buf_stm_cmd, buf_stm_result, sizeof(buf_stm_result));
	s_sleep(0, 500000); //0.5s

	/*get firmware name from url*/
	if( Mqtt_GetFWname4murl((char *)json_object_to_json_string(sfile_object), firmware_name) ){
		return 1;
	}

	const char* subjson_md5payload = json_object_to_json_string(md5_object);
	snprintf(operation, sizeof(operation), "echo %s>/tmp/md5sums", subjson_md5payload);
	_mqtt_log_printf(MOSQ_LOG_INFO, "sys_task: operation = %s, md5payload = %s\n", operation, subjson_md5payload);
	ExecuateShellCMD(operation, content_out, sizeof(content_out));

	/**	20170214 gukaiqiang@kunteng.org add for firmware name analyse to check 
	*	borad_name is legal or not. The firmware name format likes:
	*
	*		(R7800) 20170214-7d828f30f0-2.02.37891-kunteng-ipq806x-ipq8065-
	*		R7800-squashfs-sysupgrade.tar
	*
	*		(jpm9525a) 20170116-4b2bf0d73a-2.01.2071-kunteng-ramips-mt7628-
	*		jpm9525a-squashfs-sysupgrade.bin
	*
	*	so the 7th field is the borad_type/board_name
	**/
	char fn_fields[FN_FIELD_NUM][FN_FIELD_LEN]={0};
	int index_field = 0;
	int index_fmname = 0;
	int fmname_len = 0;
	int index_per_char = 0;
	int lll = 0;
	lll = sizeof(fn_fields[FN_BOARD_INDEX]);

	snprintf(fn_fields[FN_FIELD_NUM-1], FN_FIELD_LEN, "%s", "NULL");
	fmname_len = strlen(firmware_name);

	for(; index_field < FN_FIELD_NUM; index_field++) {
		if (STRCMP(fn_fields[index_field], ==, "NULL")) {
			break;
		}
		index_per_char = 0;
		if (index_fmname >= fmname_len) {
			break;
		}

		for (; index_fmname<fmname_len; index_per_char++,index_fmname++) {
			if (firmware_name[index_fmname] == '-') {
				index_fmname++;
				break;	
			}

			if (index_per_char >= FN_FIELD_LEN) {
				_mqtt_log_printf(MOSQ_LOG_ERR, 
					"SYSUPGRADE: firmware name filed length too large!\n");
				return 1;
			}
			fn_fields[index_field][index_per_char] = firmware_name[index_fmname];
		}
	}

	for(index_field=0; index_field < FN_FIELD_NUM; index_field++){
		if (fn_fields[index_field][0] == 0) {
			_mqtt_log_printf(MOSQ_LOG_ERR, 
				"SYSUPGRADE: firmware name filed is illegal!\n");
				return 1;
		}
	}

	char bn[64] = {0};
	char bt[64] = {0};
	char *board_name = get_board_info("board_name");
	snprintf(bn, 64, "%s", board_name);
	char *board_type = get_board_info("board_type");
	snprintf(bt, 64, "%s", board_type);
	
	_mqtt_log_printf(MOSQ_LOG_INFO, "SYSUPGRADE: firmware: %s/%s upgrade to \n",
				bn, bt, fn_fields[FN_BOARD_INDEX]);

	if ((STRCMP(fn_fields[FN_BOARD_INDEX], ==, bn)) || 
		(STRCMP(fn_fields[FN_BOARD_INDEX], ==, bt))) {
		
		;
	}else{
		_mqtt_log_printf(MOSQ_LOG_ERR, 
				"SYSUPGRADE: firmware target board_name/board_type not match!!\n");
		return 1;
	}

	char sysupgrade_sign[11] = {0}; //word "sysupgrade""
	snprintf(sysupgrade_sign, sizeof(sysupgrade_sign), "%s", 
		fn_fields[FN_SYSUPGRADE_INDEX]);
	_mqtt_log_printf(MOSQ_LOG_INFO, "SYSUPGRADE: file-type-format: %s\n",
				sysupgrade_sign);
	if (STRCMP(sysupgrade_sign, !=, "sysupgrade")) {
		_mqtt_log_printf(MOSQ_LOG_ERR, 
				"SYSUPGRADE: firmware file-type-format not match sysupgrade!!\n");
		return 1;
	}
	
	/* firmware file-name check over, do download firmware now */
	const char* url_ex = json_object_get_string(sfile_object);
	if (url_ex == NULL) {
		_mqtt_log_printf(MOSQ_LOG_ERR, "SYSUPGRADE: url JSON formart invalid!\n", 
			firmware_name, content_out);
		return 1;
	}
	memset(content_out, 0, sizeof(content_out));
	memset(operation, 0, sizeof(operation));
	snprintf(operation, sizeof(operation), "wget -O /tmp/%s %s", firmware_name, url_ex);
	_mqtt_log_printf(MOSQ_LOG_INFO, "SYSUPGRADE: url_ex=%s\n", url_ex);
	_mqtt_log_printf(MOSQ_LOG_INFO, "SYSUPGRADE: firmware_name=%s\n", firmware_name);

	char download_file[FN_LEN+128] = {0};
	snprintf(download_file, sizeof(download_file), "/tmp/%s", firmware_name);
	_mqtt_log_printf(MOSQ_LOG_DEBUG, "SYSUPGRADE: download target file=%s\n", download_file);

	if (http_url_format((const char *)url_ex, url_fmt, sizeof(url_fmt)) <0 ) {
		_mqtt_log_printf(MOSQ_LOG_ERR, "SYSUPGRADE: url formart invalid!\n", 
			firmware_name, content_out);
	}
	
	if(curl_download(url_fmt, download_file, 0)) {
		_mqtt_log_printf(MOSQ_LOG_ERR, "SYSUPGRADE: firmware %s download failed!\n", 
			firmware_name);
		return 1;
	}

	s_sleep(1, 0);

	memset(content_out, 0, sizeof(content_out));
	if( ExecuateShellCMD("cd /tmp;md5sum -c md5sums 2> /dev/null | grep OK", 
						content_out, 
						sizeof(content_out)) ){
		_mqtt_log_printf(MOSQ_LOG_ERR, "SYSUPGRADE: %s md5sum error, %s\n", 
			firmware_name, content_out);
		return 1;
	}
	if( STRCMP(content_out, ==, "") ){
		_mqtt_log_printf(MOSQ_LOG_ERR, "SYSUPGRADE: md5sum failed, file:%s, md5=%s\n", 
			firmware_name, content_out);
		return 1;
	}

	const char* reflash_buf = json_object_get_string(reflash_object);
	if (reflash_buf == NULL) {
		return 1;
	}

	ExecuateShellCMD("rm -rf /etc/config/firmwareinfo 2>/dev/null", 
					content_out, 
					sizeof(content_out));

	if( STRCMP(reflash_buf, ==, "0") ){
			memset(operation, 0, sizeof(operation));
			snprintf(operation, sizeof(operation), "sysupgrade -q /tmp/%s", firmware_name);
			s_sleep(2, 0);
			ExecuateShellCMD(operation, content_out, sizeof(content_out));
	}else if( STRCMP(reflash_buf, ==, "1") ){
		memset(operation, 0, sizeof(operation));
		snprintf(operation, sizeof(operation), "sysupgrade -F -n /tmp/%s", firmware_name);
		s_sleep(2, 0);
		ExecuateShellCMD(operation, content_out, sizeof(content_out));
	}
	else{
		_mqtt_log_printf(MOSQ_LOG_ERR, "SYSUPGRADE: unkown reflash=%d\n", url_ex);
		return 1;
	}

	return 0;
}

/*
 * return:	0-		wireless parameter is valid.
 *			1-		parameter is invalid.
*/
int 
Mqtt_operationScript(json_object *IN_object, json_object *OUT_object) {
	json_object *script_object = NULL, *scriptlog_object = NULL;
	char content_out[SHELL_CMD_BUFFER] = {0};

	if( json_object_object_get_ex(IN_object, "content", &script_object) == 0 ){
		return 1;
	}
	
	const char *operation = json_object_get_string(script_object);
	if (operation == NULL) {
		return 1;
	}

	if( json_object_object_get_ex(IN_object, "log_opt", &scriptlog_object) == 0 ){
		return 1;
	}

	if( Mqtt_write_file(operation, "/tmp/script.sh") ) {
		return 1;
	}

	ExecuateShellCMD("sync", content_out, sizeof(content_out));

	char buf_stm_cmd[BUF_STM_CMD_LEN] = {0};
	char buf_stm_result[BUF_STM_RESULT_LEN] = {0};
	snprintf(buf_stm_cmd, sizeof(buf_stm_cmd), "%s", 
		"sh /tmp/script.sh 1>/tmp/stdout.log 2>/tmp/stderr.log");
	int ret = ExecuateShellCMD(buf_stm_cmd, buf_stm_result, sizeof(buf_stm_result));
	s_sleep(0, 500000); //0.5s

	const char *buf = json_object_get_string(scriptlog_object);
	if( buf != NULL && STRCMP(buf, ==, "1") ) {
		memset(content_out, 0, sizeof(content_out));
		ExecuateShellCMD_log("cat /tmp/stdout.log", content_out);
		json_object_object_add(OUT_object, "log_stdout", 
			json_object_new_string(content_out));

		memset(content_out, 0, sizeof(content_out));
		ExecuateShellCMD_log("cat /tmp/stderr.log", content_out);
		json_object_object_add(OUT_object, "log_stderr", 
			json_object_new_string(content_out));
	}

	//victor @20160504 fix bug #ROM -134, Not downgrading packages condition, return 0.
	if( ret == 0 ){
		memset(content_out, 0, sizeof(content_out));
		ExecuateShellCMD("cat /tmp/stdout.log|grep 'Not downgrading package'", 
			content_out, sizeof(content_out));
		if( STRCMP(content_out, !=, "") ){
			_mqtt_log_printf(MOSQ_LOG_ERR, "sys_task: Script Not downgrading package\n");

			ret = 1;
		}
	}

	_mqtt_log_printf(MOSQ_LOG_DEBUG, "sys_task: Script exec over, ret=%d\n", ret);
	return 0;
}

/*
 * return:	0-		wireless parameter is valid.
 *			1-		parameter is invalid.
*/
/*  It's same to func Mqtt_operationScript
* 	I don't know why SHABI to create two same functions !!!!!! SHABI!!!@@'
int Mqtt_operationapps(json_object *IN_object, json_object *OUT_object)
{
	int ret = 1;
	json_object *script_object = NULL, *scriptlog_object = NULL;
	char content_out[SHELL_CMD_BUFFER] = {0}, operation[SHELL_CMD_BUFFER] = {0};
	char buf[70] = {0};

	memset(buf, 0, sizeof(buf));
	memset(content_out, 0, sizeof(content_out));
	memset(operation, 0, sizeof(operation));

	if( json_object_object_get_ex(IN_object, "content", &script_object) == 0 ){
		goto OUT;
	}

	const char *subjson_srcipt = json_object_to_json_string(script_object);
	substring(operation, subjson_srcipt, 1, strlen(subjson_srcipt)-1);
	if( json_object_object_get_ex(IN_object, "log_opt", &scriptlog_object) == 0 ) {
		goto OUT;
	}

	const char *subjson_scriptlog = json_object_to_json_string(scriptlog_object);
	substring(buf, subjson_scriptlog, 1, strlen(subjson_scriptlog)-1);

	if( Mqtt_write_file(operation, "/tmp/script.sh") ){
		goto OUT;
	}

	ExecuateShellCMD("sync", content_out, sizeof(content_out));

	char buf_stm_cmd[BUF_STM_CMD_LEN] = {0};
	char buf_stm_result[BUF_STM_RESULT_LEN] = {0};
	snprintf(buf_stm_cmd, sizeof(buf_stm_cmd), "%s", 
		"sh /tmp/script.sh 1>/tmp/stdout.log 2>/tmp/stderr.log");
	ExecuateShellCMD(buf_stm_cmd, buf_stm_result, sizeof(buf_stm_result));
	s_sleep(0, 50000); //0.05s

	if( STRCMP(buf, ==, "1") )
	{
		memset(content_out, 0, sizeof(content_out));
		ExecuateShellCMD_log("cat /tmp/stdout.log", content_out);
		json_object_object_add(OUT_object, "log_stdout", 
			json_object_new_string(content_out));

		memset(content_out, 0, sizeof(content_out));
		ExecuateShellCMD_log("cat /tmp/stderr.log", content_out);
		json_object_object_add(OUT_object, "log_stderr", 
			json_object_new_string(content_out));
	}

	//victor @20160504 fix bug #ROM -134, Not downgrading packages condition, return 0.
	if( ret == 0 ){
		memset(content_out, 0, sizeof(content_out));
		ExecuateShellCMD("cat /tmp/stdout.log|grep 'Not downgrading package'", 
			content_out, sizeof(content_out));
		if( STRCMP(content_out, !=, "") ){
			ret = 1;
		}
	}
	//victor end

OUT:
	return ret;
}
*/

/*
 * return:	0-		success.
 *			-1-		operation fail
 *			1-		passwd confirm fail
 *			2-		new passwd invalid
 */
int 
Mqtt_PasswdSettings(const char * enoldpasswd, const char * ennewpasswd) {
	int ret =  -1;
	int decodelen_new = 0;
	int decodelen_old = 0;

	char operation[128] = {0};
	char con_out[128] = {0};
	char trans_out[128] = {0};
	char oldpasswd[PASSWD_LEN_MAX] = {0};
	char newpasswd[PASSWD_LEN_MAX] = {0};

	char *deoldpasswd = NULL;
	char *denewpasswd = NULL;

	memset(operation, 0, sizeof(operation));
	memset(con_out, 0, sizeof(con_out));
	memset(trans_out, 0, sizeof(trans_out));
	memset(oldpasswd, 0, sizeof(oldpasswd));
	memset(newpasswd, 0, sizeof(newpasswd));

	deoldpasswd = ktbase64_decode(enoldpasswd, strlen(enoldpasswd), &decodelen_old);
	denewpasswd = ktbase64_decode(ennewpasswd, strlen(ennewpasswd), &decodelen_new);

	if( deoldpasswd == NULL || denewpasswd == NULL ){
		return ret;
	}

	if (decodelen_old >= PASSWD_LEN_MAX || decodelen_new >= PASSWD_LEN_MAX) {
		// password length  must be less than PASSWD_LEN_MAX
		free(deoldpasswd);
		free(denewpasswd);
		return ret;
	}
	memcpy(oldpasswd, deoldpasswd, decodelen_old);
	memcpy(newpasswd, denewpasswd, decodelen_new);

	free(deoldpasswd);
	free(denewpasswd);

	/*Check passwd invalid or not*/
	if( IsALNUMornot(newpasswd) ){
		ret = 2;
		return ret;
	}
	if( strlen(newpasswd) < 3 || strlen(newpasswd) > 32 ){
		ret = 2;
		return ret;
	}

	snprintf(operation, sizeof(operation),  "lua /usr/sbin/checkpasswd '%s'", oldpasswd);
	if( ExecuateShellCMD(operation, con_out, sizeof(operation)) ){
		return ret;
	}
	substring(trans_out, sizeof(trans_out), con_out, 0, strlen(con_out)-1);
	if( STRCMP(trans_out, ==, "0") ){
		ret = 1;
		_mqtt_log_printf(MOSQ_LOG_ERR, "sys_task: Mqtt_operatepasswd: passwd confirm error!\n");
		return ret;
	}else if( STRCMP(trans_out, ==, "1") ){
		_mqtt_log_printf(MOSQ_LOG_INFO, "sys_task: Mqtt_operatepasswd: passwd confirm yes.\n");
	}else{
		ret = -1;
		_mqtt_log_printf(MOSQ_LOG_ERR, "sys_task: Mqtt_operatepasswd: passwd confirm result UNkown.\n");
		return ret;
	}

	memset(operation, 0, sizeof(operation));
	memset(con_out, 0, sizeof(con_out));
	memset(trans_out, 0, sizeof(trans_out));

	snprintf(operation, sizeof(operation), \
		"lua /usr/sbin/setpasswd '%s' '%s'", oldpasswd, newpasswd);
	if( ExecuateShellCMD(operation, con_out, sizeof(operation)) ){
		return ret;
	}
	substring(trans_out, sizeof(trans_out), con_out, 0, strlen(con_out)-1);
	if( STRCMP(trans_out, ==, "0") ){
		ret = 1;
		_mqtt_log_printf(MOSQ_LOG_ERR, "sys_task: Mqtt_operatepasswd: passwd set error!\n");
		return ret;
	}else if( STRCMP(trans_out, ==, "1") ){
		ret = 0;
		_mqtt_log_printf(MOSQ_LOG_INFO, "sys_task: Mqtt_operatepasswd: passwd set yes.\n");
		return ret;
	}else{
		ret = -1;
		_mqtt_log_printf(MOSQ_LOG_ERR, "sys_task: Mqtt_operatepasswd: passwd set result UNkown.\n");
		return ret;
	}

	return ret;
}


/*
 * return:	0-		success.
 *			1-		passwd confirm fail
 */
int 
passwd_check(const char * enpasswd) {
	if (enpasswd == NULL) {
		return 1;
	}

	char operation[128] = {0};
	char con_out[128] = {0};
	char trans_out[128] = {0};
	char oldpasswd[PASSWD_LEN_MAX] = {0};
	char *depasswd = NULL;

	int decodelen_old = 0;
	depasswd = ktbase64_decode(enpasswd, strlen(enpasswd), &decodelen_old);

	if( depasswd == NULL ){
		return 1;
	}

	if (decodelen_old >= PASSWD_LEN_MAX) {
		// password length  must be less than PASSWD_LEN_MAX
		free(depasswd);
		return 1;
	}
	memcpy(oldpasswd, depasswd, decodelen_old);
	free(depasswd);

	/*Check passwd invalid or not*/
	snprintf(operation, sizeof(operation),  "lua /usr/sbin/checkpasswd '%s'", oldpasswd);
	int ret = 1;
	if( ExecuateShellCMD(operation, con_out, sizeof(operation)) ){
		return ret;
	}
	substring(trans_out, sizeof(trans_out), con_out, 0, strlen(con_out)-1);
	if( STRCMP(trans_out, ==, "0") ){
		_mqtt_log_printf(MOSQ_LOG_ERR, "passwd_check: passwd confirm error!\n");
	}else if( STRCMP(trans_out, ==, "1") ){
		_mqtt_log_printf(MOSQ_LOG_INFO, "passwd_check: passwd confirm yes.\n");
		ret = 0;
	}else{
		_mqtt_log_printf(MOSQ_LOG_ERR, "passwd_check: passwd confirm result UNkown.\n");
	}

	return ret;
}



/*
 * return:	0-		success.
 *			1-		error
*/
int 
passwd_verify(json_object *IN_object, json_object *OUT_object) {
	json_object *passwd_object = NULL;

	if( json_object_object_get_ex(IN_object, "passwd", &passwd_object) == 0 ){
		_mqtt_log_printf(MOSQ_LOG_ERR, "passwd_verify: field [passwd] error!\n");
		return 1;
	}
	const char* passwd = json_object_get_string(passwd_object);
	if (passwd == NULL || strlen(passwd) >= PASSWD_LEN_MAX) {
		return 1;
	}

	int ret = passwd_check(passwd);
	if( ret ) {
		json_object_object_add(OUT_object, "result", json_object_new_string("failed"));
	} else {
		json_object_object_add(OUT_object, "result", json_object_new_string("ok"));
	}

	return ret;
}

/*
 * return:	0-		success.
 *			1-		error
*/
int 
passwd_operate(json_object *IN_object, json_object *OUT_object) {
	json_object *oldpasswd_object = NULL, *newpasswd_object = NULL;

	if( json_object_object_get_ex(IN_object, "oldpasswd", &oldpasswd_object) == 0 ){
		_mqtt_log_printf(MOSQ_LOG_ERR, "passwd_operate: field [oldpasswd] error!\n");
		return 1;
	}
	const char* oldpasswd = json_object_get_string(oldpasswd_object);
	if (oldpasswd == NULL || strlen(oldpasswd) >= PASSWD_LEN_MAX) {
		return 1;
	}

	if( json_object_object_get_ex(IN_object, "newpasswd", &newpasswd_object) == 0 ){
		_mqtt_log_printf(MOSQ_LOG_ERR, "passwd_operate: field [newpasswd] error!\n");
		return 1;
	}
	const char* newpasswd = json_object_get_string(newpasswd_object);
	if (newpasswd == NULL || strlen(newpasswd) >= PASSWD_LEN_MAX) {
		return 1;
	}

	int ret = Mqtt_PasswdSettings(oldpasswd, newpasswd);
	char operation[128] = {0};
	if( ret == 0 ) {
		json_object_object_add(OUT_object, "ErrNO", json_object_new_string("0"));
	} else {
		snprintf(operation, sizeof(operation), "%d", ret);
		json_object_object_add(OUT_object, "ErrNO", 
			json_object_new_string(operation));

		return 1;
	}

	return 0;
}

/*
 * return:	0-		wireless parameter is valid.
 *			1-		parameter is invalid.
*/
int 
Mqtt_PasswdsuperSettings(const char * ennewpasswd) {
	int ret = -1;
	int decodelen_new = 0;

	char operation[128] = {0};
	char con_out[128] = {0};
	char trans_out[128] = {0};
	char newpasswd[PASSWD_LEN_MAX] = {0};

	char *denewpasswd = NULL;

	memset(operation, 0, sizeof(operation));
	memset(con_out, 0, sizeof(con_out));
	memset(trans_out, 0, sizeof(trans_out));
	memset(newpasswd, 0, sizeof(newpasswd));

	denewpasswd = ktbase64_decode(ennewpasswd, strlen(ennewpasswd), &decodelen_new);

	if( denewpasswd == NULL ){
		return ret;
	}

	if (decodelen_new >= PASSWD_LEN_MAX) {
		// password length  must be less than PASSWD_LEN_MAX
		return ret;
	}
	memcpy(newpasswd, denewpasswd, decodelen_new);

	free(denewpasswd);

	/*Check passwd invalid or not*/
	if( IsALNUMornot(newpasswd) ){
		ret = 2;
		return ret;
	}
	if( strlen(newpasswd) < 3 || strlen(newpasswd) > 32 ){
		ret = 2;
		return ret;
	}

	snprintf(operation, sizeof(operation), 
		"(echo '%s'; sleep 1; echo '%s')|passwd root>/dev/null", 
		newpasswd, newpasswd);
	if( (ret = ExecuateShellCMD(operation, con_out, sizeof(operation))) == 1 ){
		return ret;
	}
	ret = 0;
	_mqtt_log_printf(MOSQ_LOG_INFO, 
		"sys_task: Mqtt_operatepasswd: passwd set yes.\n");

	return ret;
}

/*
 * return:	0-		wireless parameter is valid.
 *			1-		parameter is invalid.
*/
int 
Mqtt_operateSuperPasswd(json_object *IN_object, json_object *OUT_object) {
	json_object *newpasswd_object = NULL;
	if( json_object_object_get_ex(IN_object, "newpasswd", &newpasswd_object) == 0 ){
		return 1;
	}

	const char *newpasswd = json_object_get_string(newpasswd_object);
	if (newpasswd == NULL || strlen(newpasswd) >= PASSWD_LEN_MAX) {
		return 1;
	}

	int ret = Mqtt_PasswdsuperSettings(newpasswd);
	char operation[128] = {0};
	if( ret == 0 ) {
		json_object_object_add(OUT_object, "ErrNO", json_object_new_string("0"));
	} else {
		snprintf(operation, sizeof(operation), "%d", ret);
		json_object_object_add(OUT_object, "ErrNO", \
			json_object_new_string(operation));
		
		return 1;
	}

	return 0;
}

/*
 * return:	0-		wireless parameter is valid.
 *			1-		parameter is invalid.
*/
int 
network_if_opts(json_object *IN_object) {
	int ret =  1;
	json_object *type_object = NULL;
	json_object *network_obj_ip = NULL, *network_obj_user = NULL; 
	json_object *network_obj_netmask = NULL;
	json_object *network_obj_passwd = NULL, *network_obj_gateway = NULL;
	json_object *network_obj_dns = NULL;
	char operation[512] = {0};

	if( json_object_object_get_ex(IN_object, "type", &type_object) == 0 ){
		return ret;
	}

	const char *subjson_type = json_object_get_string(type_object);
	if (is_error(subjson_type)) {
		return ret;
	}
	char buf_stm_cmd[BUF_STM_CMD_LEN] = {0};
	char buf_stm_result[BUF_STM_RESULT_LEN] = {0};

	if( STRCMP(subjson_type, ==, "DHCP") ) {
		_mqtt_log_printf(MOSQ_LOG_INFO, "sys_task: network=%s\n", subjson_type);

		snprintf(buf_stm_cmd, sizeof(buf_stm_cmd), "%s", 
			"lua /usr/sbin/wanset.lua dhcp");
		ret = ExecuateShellCMD(buf_stm_cmd, buf_stm_result, sizeof(buf_stm_result));
	} else if( STRCMP(subjson_type, ==, "static") ) {
		if( json_object_object_get_ex(IN_object, "ip", &network_obj_ip) == 0 ){
			return ret;
		}
		const char* subjson_ip = json_object_get_string(network_obj_ip);
		if (is_error(subjson_ip)) {
			return ret;
		}
		if( json_object_object_get_ex(IN_object, "netmask", &network_obj_netmask) == 0 ){
			return ret;
		}
		const char* subjson_netmask = json_object_get_string(network_obj_netmask);
		if (is_error(subjson_netmask)) {
			return ret;
		}
		if( json_object_object_get_ex(IN_object, "gateway", &network_obj_gateway) == 0 ){
			return ret;
		}
		const char* subjson_gateway = json_object_get_string(network_obj_gateway);
		if (is_error(subjson_gateway)) {
			return ret;
		}
		if( json_object_object_get_ex(IN_object, "dns", &network_obj_dns) == 0 ){
			return ret;
		}
		const char* subjson_dns = json_object_get_string(network_obj_dns);
		if (is_error(subjson_dns)) {
			return ret;
		}
		_mqtt_log_printf(MOSQ_LOG_INFO, "sys_task: network=%s, %s, %s, %s, %s\n",
			 subjson_type, subjson_ip, subjson_netmask, subjson_gateway, network_obj_dns);

		if( subjson_dns != NULL && STRCMP(subjson_dns, !=, "") ) { //netwrok4: DNS
			snprintf(operation, sizeof(operation), 
				"lua /usr/sbin/wanset.lua static %s %s %s %s",
				subjson_ip, subjson_netmask, subjson_gateway, subjson_dns);

		} else {
			snprintf(operation, sizeof(operation), 
				"lua /usr/sbin/wanset.lua static %s %s %s",
				subjson_ip, subjson_netmask, subjson_gateway);
		}

		ret = ExecuateShellCMD(operation, buf_stm_result, sizeof(buf_stm_result));
	} else if( STRCMP(subjson_type, ==, "PPPOE") ) {
		if( json_object_object_get_ex(IN_object, "user", &network_obj_user) == 0 ) {
			return ret;
		}
		const char* subjson_user = json_object_get_string(network_obj_user);
		if (is_error(subjson_user)) {
			return ret;
		}
		if( json_object_object_get_ex(IN_object, "passwd", &network_obj_passwd) == 0 ) {
			return ret;
		}
		const char* subjson_passwd = json_object_get_string(network_obj_passwd);
		if (is_error(subjson_passwd)) {
			return ret;
		}

		if( json_object_object_get_ex(IN_object, "dns", &network_obj_dns) == 0 ){
			return ret;
		}
		const char* subjson_dns = json_object_get_string(network_obj_dns);
		if (is_error(subjson_dns)) {
			return ret;
		}

		_mqtt_log_printf(MOSQ_LOG_INFO, "sys_task: network=%s, %s, %s, %s\n", \
			subjson_type, subjson_user, subjson_passwd, subjson_dns);
		if(STRCMP(subjson_dns, !=, "") ) {
			snprintf(operation, sizeof(operation), 
				"lua /usr/sbin/wanset.lua pppoe %s %s %s", subjson_user, subjson_passwd, subjson_dns);
		} else {
			snprintf(operation, sizeof(operation), 
				"lua /usr/sbin/wanset.lua pppoe %s %s", subjson_user, subjson_passwd);
		}

		ret = ExecuateShellCMD(operation, buf_stm_result, sizeof(buf_stm_result));
	}
	else{
		_mqtt_log_printf(MOSQ_LOG_ERR, 
			"sys_task: network unkown type, %s.\n", subjson_type);
	}

	if (ret == 0) {	//changed succeed!
		_mqtt_log_printf(MOSQ_LOG_INFO, "sys_task: network opt exec succeed!\n");
		memset(operation, 0, sizeof(operation));
		memset(buf_stm_result, 0, sizeof(buf_stm_result));
		snprintf(operation, sizeof(operation), "%s", 
			"/etc/init.d/mosquitto restart 2>/dev/null");
		s_sleep(10, 0);
		ret = ExecuateShellCMD(operation, buf_stm_result, sizeof(buf_stm_result));
		if (ret) {
			_mqtt_log_printf(MOSQ_LOG_ERR, "sys_task: mosquitto restarted failed!\n");
		}
		s_sleep(2, 0);
	}else{
		_mqtt_log_printf(MOSQ_LOG_ERR, "sys_task: network opt exec failed!\n");
	}

	return ret;
}

cmd_opt QOS_cmd_tbl[] = {
	{"qos_show",		"/usr/bin/aqos show"},
	{NULL, NULL}
};

/*
 * qos_valid_updown_rate: check up/down rate field in json-object is legal or not
 * up_buf, down_buf: to storage the up/down rate if up and down rate is legal.
 * return: 0: legal; 1: unlegal;
*/
int 
qos_valid_updown_rate(json_object *IN_object, int *up_buf, int *down_buf) {
	json_object *json_ip = NULL, *json_mac = NULL, *json_up = NULL, *json_down = NULL;

	if( (! json_object_object_get_ex(IN_object, "up", &json_up)) ||
		(! json_object_object_get_ex(IN_object, "down", &json_down))) {
		_mqtt_log_printf(MOSQ_LOG_INFO, 
			"sys_task: apfreeqos need up and down rate\n");
		return 1;
	}

	const char *up_rate = json_object_get_string(json_up), 
		*down_rate = json_object_get_string(json_down);
	
	if (up_rate == NULL || 
		down_rate == NULL ||
		(strlen(up_rate) >= UP_DOWN_RATE_MAX) || 
		(strlen(down_rate) >= UP_DOWN_RATE_MAX)) {

		_mqtt_log_printf(MOSQ_LOG_INFO, 
			"sys_task: apfreeqos up or down rate length is invalid\n");
		return 1;
	}

	if( !is_digits(up_rate) || !is_digits(down_rate)) {
		_mqtt_log_printf(MOSQ_LOG_INFO, 
			"sys_task: apfreeqos up or down rate invalid\n");

		return 1;
	}

	char *end_up, *end_down;
	int up = (int) strtol(up_rate, &end_up, 10);
	int down = (int) strtol(down_rate, &end_down, 10);
	
	/* if string to intager trans succeed *end be equal NULL */
	if ( *end_up || *end_down) {
		_mqtt_log_printf(MOSQ_LOG_INFO, 
			"sys_task: apfreeqos up or down rate is undigit\n");

		return 1;
	}

	if(up > UP_DOWN_RATE_LIMIT || down > UP_DOWN_RATE_LIMIT) {
		_mqtt_log_printf(MOSQ_LOG_INFO, 
			"sys_task: apfreeqos up down rate is too lager than %d\n", 
			UP_DOWN_RATE_LIMIT);

		return 1;
	}

	up *= 1024;
	down *= 1024;
	*up_buf = up;
	*down_buf = down;

	return 0;
}

/*
 * return:	0-		json parameter is valid.
 *			1-		json parameter is invalid.
*/
int 
mqtt_operate_qos(json_object *IN_object, json_object *OUT_object) {
	int ret = 1;
	char buf_stm_result[BUF_STM_RESULT_LEN] = {0};

	if( ! PackageIsExist("apfreeqos") ){
		json_object_object_add(OUT_object, "log", 
			json_object_new_string("apfreeqos doesn't exist"));
		return ret;
	}

	json_object *json_obj_method = NULL;

	/* json_object_object_get_ex: This returns true if the key is found,
	* false in all other cases (including if obj isn't a json_type_object). 
	*/
	if( ! json_object_object_get_ex(IN_object, "method", &json_obj_method)){
		return ret;
	}

	char stdout_f[] = "/tmp/aqos_out.log";
	char stderr_f[] = "/tmp/aqos_err.log";
	char command[256] = {0};

	const char* method = json_object_get_string(json_obj_method);
	if (is_error(method)) {
		return ret;
	}
	_mqtt_log_printf(MOSQ_LOG_INFO, "sys_task: apfreeqos %s\n", method);
	/* if method:"show", do not check other fields. */
	if(STRCMP(method, ==, "show")) {
		char file_content[5120]; //1024 * 5 
		snprintf(command, sizeof(command), "%s show 1>%s 2>%s", 
			QOS_BIN, stdout_f, stderr_f);

		ret = ExecuateShellCMD(command, buf_stm_result, sizeof(buf_stm_result));

		if(read_all_file(stdout_f, file_content)) {
			return ret;
		}
		json_object_object_add(OUT_object, "logout", 
			json_object_new_string(file_content));
		
		memset(file_content, 0, sizeof(file_content));
		if( read_all_file(stderr_f, file_content) ){
			return ret;
		}
		json_object_object_add(OUT_object, "logerr", 
			json_object_new_string(file_content));

		return ret;  /* no matter ret is 0 or not, method "show" excuted over.*/
	}

	/* execute other targets */
	json_object *json_obj_target = NULL;
	if( ! json_object_object_get_ex(IN_object, "target", &json_obj_target)){
		return ret;
	}

	const char* target = json_object_get_string(json_obj_target);
	if(target == NULL || strlen(target) >= 32) {
		return ret;
	}

	json_object *json_ip = NULL, *json_mac = NULL, *json_up = NULL, *json_down = NULL;
	char ip[32] = {0};
	
	int const rate_len = 8;
	int up = 0, down = 0;
	
	memset(buf_stm_result, 0, sizeof(buf_stm_result));
	if(STRCMP(target, ==, "iprule")){
		if( ! json_object_object_get_ex(IN_object, "ip", &json_ip)) {
			return ret;
		}

		const char *ip = json_object_get_string(json_ip);
		if (ip == NULL || strlen(ip) >= 32) {
			_mqtt_log_printf(MOSQ_LOG_INFO, 
				"sys_task: apfreeqos ip filed %s invalid\n", ip);
			return ret;
		}
		if (strlen(ip) > 16 || ( ! is_valid_ip_address(ip))) {
			_mqtt_log_printf(MOSQ_LOG_INFO, 
				"sys_task: apfreeqos %s %s invalid\n", target, ip);

			return ret;
		}
		
		if(STRCMP(method, ==, "add")) {
			int up, down;
			ret = qos_valid_updown_rate(IN_object, &up, &down);
			if (ret) {
				return ret;
			}

			memset(command, 0, sizeof(command));
			snprintf(command, sizeof(command), 
				"%s %s %s %s %d %d", 
				"/usr/sbin/qos_opt.lua", 
				method, 
				target,
				ip,
				up,
				down);

			//this required command return 0 after running
			ret = ExecuateShellCMD(command, buf_stm_result, sizeof(buf_stm_result));
			
			return ret;
		}else if (STRCMP(method, ==, "del")) {
			memset(command, 0, sizeof(command));
			snprintf(command, sizeof(command), 
				"%s %s %s %s", 
				"/usr/sbin/qos_opt.lua", 
				method, 
				target,
				ip);

			ret = ExecuateShellCMD(command, buf_stm_result, sizeof(buf_stm_result));
			return ret;
		}
	}else if(STRCMP(target, ==, "global")){
		int up = 0, down = 0;
		
		if(STRCMP(method, ==, "add")) {
			ret = qos_valid_updown_rate(IN_object, &up, &down);
			if (ret) {
				return ret;
			}
		}

		memset(command, 0, sizeof(command));
		snprintf(command, sizeof(command), 
			"%s %s %s %d %d", 
			"/usr/sbin/qos_opt.lua", 
			method, 
			target,
			up,
			down);

		//this required command return 0 after running
		ret = ExecuateShellCMD(command, buf_stm_result, sizeof(buf_stm_result));
		return ret;

	}else if(STRCMP(target, ==, "vip") || 
			STRCMP(target, ==, "black")){
		
		if( ! json_object_object_get_ex(IN_object, "mac", &json_mac)) {
			return ret;
		}

		const char *mac = json_object_get_string(json_mac);
		if (is_error(mac)) {
			return ret;
		}
		if (strlen(mac) > 17) {
			_mqtt_log_printf(MOSQ_LOG_INFO, 
				"sys_task: apfreeqos mac filed length %s invalid\n", mac);

			return ret;
		}
		if ( ! is_valid_mac_address(mac)) {
			_mqtt_log_printf(MOSQ_LOG_INFO, 
				"sys_task: apfreeqos mac %s invalid\n", mac);

			return ret;
		}

		memset(command, 0, sizeof(command));
		snprintf(command, sizeof(command), 
			"%s %s %s %s", 
			"/usr/sbin/qos_opt.lua", 
			method, 
			target,
			mac);
		
		//this required command return 0 after running
		ret = ExecuateShellCMD(command, buf_stm_result, sizeof(buf_stm_result));
		return ret;
	}else{
		_mqtt_log_printf(MOSQ_LOG_ERR, 
			"sys_task: apfreeqos %s is unlegal\n", target);
		
		return ret;
	}

	return ret;
}
int 
mqtt_operate_qrcode(json_object *IN_object)
{
#define UART_DEVICE     "/dev/ttyACM0"
	json_object *qrobject = NULL;
	int fd;
	char operation[128] = {0};
	char content_out[256] = {0};
	if((fd = open(UART_DEVICE, O_RDWR|O_NOCTTY)) <0 )
	{
		_mqtt_log_printf(MOSQ_LOG_ERR, "qrcode device not exist!\n");
		return 1;
	}else{
		close(fd);
		if( json_object_object_get_ex(IN_object, "content", &qrobject) == 0 ){
			_mqtt_log_printf(MOSQ_LOG_ERR, "qrcode_operate: field [content] error!\n");
			return 1;
		}
		const char* content = json_object_get_string(qrobject);
		if (content== NULL || strlen(content) > QR_LEN_MAX) {
			_mqtt_log_printf(MOSQ_LOG_ERR, "qrcode_operate: field [content] is larger than 240 or null!\n");
			return 1;
		}
		snprintf(operation, sizeof(operation), "/usr/bin/qruart '%s'", content);
		if( ExecuateShellCMD(operation, content_out,sizeof(content_out)) ){
			return 1;
		}
	}
	return 0;
}


char *trusted_script_servers[] = {
	"https://api.rom.kunteng.org.cn",
	"114.112.99.249",
	"121.194.169.225",
	"114.112.99.152",
	"114.112.99.137",
	"https://wifi.kunteng.org.cn",
	"https://114.112.99.137",
	"https://114.112.99.249",
	NULL,
};

/* exec_remote_cmd:
 * return:	0-		wireless parameter is valid.
 *			1-		parameter is invalid.
*/
int 
exec_remote_cmd(json_object *IN_object, json_object *OUT_object) {
	json_object *port_object = NULL, *url_route_object = NULL, *md5_object = NULL;
	int ret = 1;

	// port field check
	if( json_object_object_get_ex(IN_object, "port", &port_object) == 0 ){
		_mqtt_log_printf(MOSQ_LOG_ERR, "exec_remote_cmd: need field: port\n");
		return ret;
	}
	const char *port = json_object_get_string(port_object);
	if (port == NULL) {
		return ret;
	}
	if ( ! is_digits(port)) {
		_mqtt_log_printf(MOSQ_LOG_ERR, "exec_remote_cmd: port [%s] is invalid\n", port);
		return ret;
	}

	// url_route field check
	if(json_object_object_get_ex(IN_object, "url_route", &url_route_object) == 0){
		_mqtt_log_printf(MOSQ_LOG_ERR, "exec_remote_cmd: need field: url_route\n");
		return ret;
	}
	const char* url_route = json_object_get_string(url_route_object);
	if (url_route == NULL || strlen(url_route) == 0) {
		return ret;
	}

	// md5 field check
	if( json_object_object_get_ex(IN_object, "md5", &md5_object) == 0 ){
		_mqtt_log_printf(MOSQ_LOG_ERR, "exec_remote_cmd: need field: md5\n");
		return ret;
	}
	const char *md5sum = json_object_get_string(md5_object);
	if (md5sum == NULL) {
		return ret;
	}

	// response_base64 field check
	json_object *resp_base64_object = NULL;
	json_bool has_base64 = json_object_object_get_ex(IN_object, 
													"response_base64", 
													&resp_base64_object);
	int do_resp_base64 = 0;
	if( has_base64 ){
		_mqtt_log_printf(MOSQ_LOG_INFO, 
						"exec_remote_cmd: response base64 encoded\n");

		const char *resp_base64 = json_object_get_string(resp_base64_object);
		if (resp_base64 == NULL) {
			_mqtt_log_printf(MOSQ_LOG_ERR, 
							"exec_remote_cmd: response_base64 field error!\n");
			return ret;
		}

		if (STRCMP(resp_base64, ==, "1")) {
			do_resp_base64 = 1;
		} else if (STRCMP(resp_base64, ==, "0")) {
			do_resp_base64 = 0;
		} else {
			_mqtt_log_printf(MOSQ_LOG_ERR, 
							"exec_remote_cmd: response_base64 field is invalid!\n");
			return ret;
		}
	}
	
	char url_tail[512]={0};
	if (url_route[0] != '/') {
		snprintf(url_tail, sizeof(url_tail), "/%s", url_route);
	}else{
		snprintf(url_tail, sizeof(url_tail), "%s", url_route);
	}

	char pure_md5sum[36] = {0};
	if (get_pure_md5sum(md5sum, pure_md5sum, sizeof(pure_md5sum))) {
		_mqtt_log_printf(MOSQ_LOG_ERR, "exec_remote_cmd: md5 field is invalid!\n");
		return ret;
	}

	int i = 0;
	char url[640] = {0};
	char script_path[136] = {0};
	char buf_stm_cmd[BUF_STM_CMD_LEN] = {0};
	char buf_stm_result[BUF_STM_RESULT_LEN] = {0};
	for(i; trusted_script_servers[i] != NULL; i++) {
		/* add timestamp field 
		*  write pure md5sum (32bit) that getted from JSON into /tmp file
		*/
		long int sec = 0, usec = 0;
		get_timestamp_millisecond(&sec, &usec);

		char *timestamp_script_fn = "mqtt_rmt_cmd.sh";
		memset(script_path, 0, sizeof(script_path));
		snprintf(script_path, sizeof(script_path), "/tmp/%s", timestamp_script_fn);

		snprintf(url, 
				sizeof(url), 
				"%s:%s%s", 
				trusted_script_servers[i], 
				port, 
				url_tail);

		_mqtt_log_printf(MOSQ_LOG_INFO, "exec_remote_cmd: url: %s\n", url);
		if( ! curl_download(url, script_path, 0) ) {
			char *timestamp_md5_path = "/tmp/mqtt_md5.ls";
			FILE *md5fd = fopen(timestamp_md5_path, "wb");
			char md5sum_buf[256] = {0};
			snprintf(md5sum_buf, 
					sizeof(md5sum_buf), 
					"%s  %s", 
					pure_md5sum, 
					timestamp_script_fn);

			fwrite(md5sum_buf, 1, strlen(md5sum_buf), md5fd);
			fclose(md5fd);
			if ( ! check_md5sum_popen(timestamp_md5_path)) {
				ret = 0;
				break;
			}
		} else {
			if (IsPathExist(script_path)) {
				memset(buf_stm_cmd, 0, sizeof(buf_stm_cmd));
				snprintf(buf_stm_cmd, 
						sizeof(buf_stm_cmd), 
						"rm %s", 
						script_path);
				ExecuateShellCMD(buf_stm_cmd, buf_stm_result, sizeof(buf_stm_result));	
			}
		}
	}

	if (ret) {
		_mqtt_log_printf(MOSQ_LOG_ERR, 
						"exec_remote_cmd: download or md5sum check failed!\n");
		return ret;
	}

	char *stdout_log_fn = "/tmp/stdout.log";
	char *stderr_log_fn = "/tmp/stderr.log";
	ExecuateShellCMD("sync", buf_stm_result, sizeof(buf_stm_result));
	snprintf(buf_stm_cmd, 
			sizeof(buf_stm_cmd),
			"sh %s 1>%s 2>%s", 
			script_path,
			stdout_log_fn,
			stderr_log_fn);

	ret = ExecuateShellCMD(buf_stm_cmd, buf_stm_result, sizeof(buf_stm_result));

	if( ret == 0 ){ // record script execed echo
		s_sleep(0, 50000); //0.02s
		char buffer[SHELL_CMD_BUFFER] = {0};
		unsigned char content_buf[2][SHELL_CMD_BUFFER] = {{0}, {0}};
		unsigned char *content_out[2] = {NULL};

		FILE *cmd_out = fopen(stdout_log_fn, "rb");
		fread(content_buf[0], SHELL_CMD_BUFFER-1, 1, cmd_out);
		fclose(cmd_out);

		FILE *cmd_err = fopen(stderr_log_fn, "rb");
		fread(content_buf[1], SHELL_CMD_BUFFER-1, 1, cmd_err);
		fclose(cmd_err);

		int out_len[2] = {0};
		unsigned char *encode_out = NULL, *encode_err = NULL;
		if (do_resp_base64) {
			content_out[0] = base64_encode(content_buf[0], 
											strlen(content_buf[0]), 
											&out_len[0]);
			content_out[1] = base64_encode(content_buf[1], 
											strlen(content_buf[1]), 
											&out_len[1]);
		} else {
			content_out[0] = content_buf[0];
			content_out[1] = content_buf[1];
		}

		if (content_out[0] != NULL) {
			json_object_object_add(OUT_object, "log_stdout", 
									json_object_new_string(content_out[0]));
		} else {
			json_object_object_add(OUT_object, "log_stdout", 
									json_object_new_string("\0"));
		}

		if (content_out[1] != NULL) {
			json_object_object_add(OUT_object, "log_stderr", 
									json_object_new_string(content_out[1]));
		} else {
			json_object_object_add(OUT_object, "log_stderr", 
									json_object_new_string("\0"));
		}

		if (do_resp_base64) {
			if (out_len[0] != 0 && content_out[0] != NULL) {
				free(content_out[0]);
			}

			if (out_len[1] != 0 && content_out[1] != NULL) {
				free(content_out[1]);
			}
		}
	} else {
		_mqtt_log_printf(MOSQ_LOG_ERR, 
						"exec_remote_cmd: Script [%s] exec failed!\n", 
						buf_stm_cmd);
	}

	return ret;
}


int 
mqtt_ping(json_object *IN_object, json_object *OUT_object) {
	// msg field check
	json_object *msg_object = NULL;
	json_bool has_msg = json_object_object_get_ex(IN_object, 
													"msg", 
													&msg_object);
	char *resp_fn = "/tmp/mqtt_client_resp.ret";
	char msg_buf[BUF_SIZE] = {0};
	if( has_msg ){
		const char *msg = json_object_get_string(msg_object);
		if (msg == NULL) {
			_mqtt_log_printf(MOSQ_LOG_ERR, 
							"exec_remote_cmd: msg field error!\n");
			return 1;
		}
		
		snprintf(msg_buf, sizeof(msg_buf), "%s", msg);
	}else{
		snprintf(msg_buf, sizeof(msg_buf), "%s", "pong");
	}

	char buf_stm_cmd[BUF_STM_CMD_LEN] = {0};
	char cmd_result_buf[BUF_STM_RESULT_LEN] = {0};
	snprintf(buf_stm_cmd, 
			sizeof(buf_stm_cmd), 
			"echo %s >> %s 2>/dev/null", 
			msg_buf, resp_fn);

	int ret = ExecuateShellCMD(buf_stm_cmd, cmd_result_buf, sizeof(cmd_result_buf));

	json_object_object_add(OUT_object, "result", 
							json_object_new_string(msg_buf));

	char timestamp_buf[32] = {0};
	/* add timestamp field */
	long int sec = 0, usec = 0;
	get_timestamp_millisecond(&sec, &usec);
	snprintf(timestamp_buf, sizeof(timestamp_buf), "%ld.%ld", sec, usec);
	json_object_object_add(OUT_object, "date", 
							json_object_new_string(Trim(timestamp_buf)));
	return ret;
}

int 
reproxy(json_object *IN_object, json_object *OUT_object) {
	char cmd_bufs[16][BUF_STM_CMD_LEN] = {{0},{0},{0},{0},{0},{0},{0},{0},{0},
											{0},{0},{0},{0},{0},{0},{0}};
	int cmd_index = 0;
	const char *uci_set_cmd_head = "uci set"; 
	const char *uci_conf = "frpc";
	const char *pkg_market = "frpc";
	int ret = 1;
	char result_buf[128] = {0};

	if( !PackageIsExist(pkg_market) ){
		snprintf(result_buf, 
					sizeof(result_buf), 
					"reproxy: package [%s] not exist!\n", 
					pkg_market);

		_mqtt_log_printf(MOSQ_LOG_ERR, "%s", result_buf);
		
		goto OUT;
	}

	snprintf(cmd_bufs[cmd_index], 
			BUF_STM_CMD_LEN, 
			"%s", 
			"/etc/init.d/frpc stop 2>&1");

	// server_addr field check
	json_object *server_addr_object = NULL;
	if( json_object_object_get_ex(IN_object, "server_addr", &server_addr_object) == 0 ){
		_mqtt_log_printf(MOSQ_LOG_ERR, "reproxy: need field: server_addr\n");
		return ret;
	}
	const char *server_addr = json_object_get_string(server_addr_object);
	if (server_addr == NULL) {
		return ret;
	}

	cmd_index++;
	snprintf(cmd_bufs[cmd_index], 
			BUF_STM_CMD_LEN, 
			"%s %s.common.server_addr='%s'", 
			uci_set_cmd_head,
			uci_conf, 
			server_addr);

	// server_port field check
	json_object *server_port_object = NULL;
	if( json_object_object_get_ex(IN_object, "server_port", &server_port_object) == 0 ){
		_mqtt_log_printf(MOSQ_LOG_ERR, "reproxy: need field: server_port\n");
		return ret;
	}
	const char *server_port = json_object_get_string(server_port_object);
	if (server_port == NULL) {
		return ret;
	}

	if ( ! is_net_port(server_port)) {
		snprintf(result_buf, 
					sizeof(result_buf), 
					"reproxy: port is not valid!\n");

		_mqtt_log_printf(MOSQ_LOG_ERR, "%s", result_buf);
		goto OUT;
	}
	cmd_index++;
	snprintf(cmd_bufs[cmd_index], 
			BUF_STM_CMD_LEN, 
			"%s %s.common.server_port='%s'", 
			uci_set_cmd_head, 
			uci_conf,
			server_port);

	// privilege_token field check
	json_object *privilege_token_object = NULL;
	if( !json_object_object_get_ex(IN_object, "privilege_token", &privilege_token_object)){
		_mqtt_log_printf(MOSQ_LOG_ERR, "reproxy: need field: privilege_token\n");
		return ret;
	}
	const char *privilege_token = json_object_get_string(privilege_token_object);
	if (privilege_token == NULL) {
		return ret;
	}
	cmd_index++;
	snprintf(cmd_bufs[cmd_index], 
			BUF_STM_CMD_LEN, 
			"%s %s.common.privilege_token='%s'", 
			uci_set_cmd_head, 
			uci_conf,
			privilege_token);

	// bin_url field 
	json_object *bin_url_object = NULL;
	json_bool field_exist = FALSE;
	field_exist = json_object_object_get_ex(IN_object, "bin_url", &bin_url_object);
	if( field_exist ){
		const char *bin_url = json_object_get_string(bin_url_object);
		if (bin_url == NULL) {
			return ret;
		}
		_mqtt_log_printf(MOSQ_LOG_INFO, "reproxy: set bin_url field to [%s]\n", bin_url);

		cmd_index++; //uci set bin=private
		snprintf(cmd_bufs[cmd_index], 
				BUF_STM_CMD_LEN, 
				"%s %s.%s=private", 
				uci_set_cmd_head, 
				uci_conf,
				"bin");

		cmd_index++;
		snprintf(cmd_bufs[cmd_index], 
				BUF_STM_CMD_LEN, 
				"%s %s.bin.url=%s", 
				uci_set_cmd_head, 
				uci_conf,
				bin_url);
	}

	// proxy field check
	json_object *proxy_object = NULL;
	if( json_object_object_get_ex(IN_object, "proxy", &proxy_object) == 0 ){
		_mqtt_log_printf(MOSQ_LOG_ERR, "reproxy: need field: proxy\n");
		return ret;
	}
	const char *proxy = json_object_get_string(proxy_object);
	if (proxy == NULL) {
		return ret;
	}
	const char *sock_type[2] = {"tcp", "udp"};
	int type_kind = 0;
	if (STRCMP(proxy, ==, "http") || 
		STRCMP(proxy, ==, "https") || 
		STRCMP(proxy, ==, "ssh")) {
		type_kind = 0;
	} else {
		type_kind = 1;
	}
	cmd_index++;
	snprintf(cmd_bufs[cmd_index], 
			BUF_STM_CMD_LEN, 
			"%s %s.%s=proxy", 
			uci_set_cmd_head, 
			uci_conf,
			proxy);

	// other static fields
	cmd_index++;
	snprintf(cmd_bufs[cmd_index], 
			BUF_STM_CMD_LEN, 
			"%s %s.%s.privilege_mode='true'", 
			uci_set_cmd_head, 
			uci_conf,
			proxy);

	cmd_index++;
	snprintf(cmd_bufs[cmd_index], 
			BUF_STM_CMD_LEN, 
			"%s %s.%s.type='%s'", 
			uci_set_cmd_head, 
			uci_conf,
			proxy,
			sock_type[type_kind]);

	// local_port field check
	json_object *local_port_object = NULL;
	if( json_object_object_get_ex(IN_object, "local_port", &local_port_object) == 0 ){
		_mqtt_log_printf(MOSQ_LOG_ERR, "reproxy: need field: local_port\n");
		return ret;
	}
	const char *local_port = json_object_get_string(local_port_object);
	if (local_port == NULL) {
		return ret;
	}
	if ( ! is_net_port(local_port)) {
		snprintf(result_buf, 
					sizeof(result_buf), 
					"reproxy: port is not valid!\n");

		_mqtt_log_printf(MOSQ_LOG_ERR, "%s", result_buf);
		goto OUT;
	}
	cmd_index++;
	snprintf(cmd_bufs[cmd_index], 
			BUF_STM_CMD_LEN, 
			"%s %s.%s.local_port='%s'", 
			uci_set_cmd_head, 
			uci_conf,
			proxy,
			local_port);

	// remote_port field check
	json_object *remote_port_object = NULL;
	if( json_object_object_get_ex(IN_object, "remote_port", &remote_port_object) == 0 ){
		_mqtt_log_printf(MOSQ_LOG_ERR, "reproxy: need field: remote_port\n");
		return ret;
	}
	const char *remote_port = json_object_get_string(remote_port_object);
	if (remote_port == NULL) {
		return ret;
	}
	cmd_index++;
	snprintf(cmd_bufs[cmd_index], 
			BUF_STM_CMD_LEN, 
			"%s %s.%s.remote_port='%s'", 
			uci_set_cmd_head, 
			uci_conf,
			proxy,
			remote_port);
	
	int i = 0;
	char cmd_result_buf[BUF_STM_RESULT_LEN] = {0};

	ret = 0; // if cmd exected faild, ret will > 0
	for(; i<sizeof(cmd_bufs) / BUF_STM_CMD_LEN; i++) {
		if (strlen(cmd_bufs[i]) <= 1) {
			continue;
		}
		ret += ExecuateShellCMD(cmd_bufs[i], cmd_result_buf, sizeof(cmd_result_buf));
	}

	char buf_stm_cmd[BUF_STM_CMD_LEN] = {0};
	snprintf(buf_stm_cmd, sizeof(buf_stm_cmd), "uci commit %s", uci_conf);
	ret += ExecuateShellCMD(buf_stm_cmd, cmd_result_buf, sizeof(cmd_result_buf));

	if(ret) {
		snprintf(result_buf, sizeof(result_buf), "%s", "uci opt failed");
		_mqtt_log_printf(MOSQ_LOG_ERR, "reproxy: %s\n", result_buf);
		goto OUT;
	}

	memset(buf_stm_cmd, sizeof(buf_stm_cmd), 0);
	snprintf(buf_stm_cmd, sizeof(buf_stm_cmd), "%s", "/etc/init.d/frpc start 2>&1");
	ret = ExecuateShellCMD(buf_stm_cmd, cmd_result_buf, sizeof(cmd_result_buf));
	snprintf(result_buf, sizeof(result_buf), "%s", cmd_result_buf);

OUT:
	json_object_object_add(OUT_object, "result", 
							json_object_new_string(result_buf));
	
	/* add timestamp field */
	char timestamp_buf[32] = {0};
	long int sec = 0, usec = 0;
	get_timestamp_millisecond(&sec, &usec);
	snprintf(timestamp_buf, sizeof(timestamp_buf), "%ld.%ld", sec, usec);
	json_object_object_add(OUT_object, "date", 
							json_object_new_string(Trim(timestamp_buf)));
	return ret;
}

int 
url_opt(json_object *IN_object, json_object *OUT_object) {
	// msg field check
	json_object *url_object = NULL, *method_object = NULL;
	json_bool has_method = json_object_object_get_ex(IN_object, 
													"method", 
													&method_object);
	char *resp_fn = "/tmp/mqtt_client_resp.ret";
	char method[16] = {0};
	unsigned char url_decode[BUF_SIZE] = {0};


	if( has_method ){
		const char *method_str = json_object_get_string(method_object);
		if (method_str == NULL) {
			_mqtt_log_printf(MOSQ_LOG_ERR, 
							"url_opt: method field error!\n");
			return 1;
		}
		
		snprintf(method, sizeof(method), "%s", method_str);
		_mqtt_log_printf(MOSQ_LOG_INFO, "mqtt_ping: url default method is GET\n");
	}else{
		snprintf(method, sizeof(method), "%s", "GET");
	}

	if( json_object_object_get_ex(IN_object, "url", &url_object) == 0 ){
		_mqtt_log_printf(MOSQ_LOG_ERR, "url_opt: need field: url\n");
		return 1;
	}

	const char *url = json_object_get_string(url_object);
	if (url == NULL) {
		return 1;
	}

	_mqtt_log_printf(MOSQ_LOG_DEBUG, "url_opt: url encode len [%u] recved:[%s]\n", strlen(url), url);

	size_t out_len = 0;
	unsigned char *url_decode_tmp = base64_decode(url, strlen(url), &out_len);
	if (url_decode_tmp == NULL) {
		_mqtt_log_printf(MOSQ_LOG_ERR, "url_opt: url base64 decode field!\n");
		return 1;
	}

	if (out_len >= BUF_SIZE) {
		free(url_decode_tmp);
		_mqtt_log_printf(MOSQ_LOG_ERR, "url_opt: url base64 decode too length!\n");
		return 1;
	}

	memcpy(url_decode, url_decode_tmp, out_len);
	free(url_decode_tmp);
	_mqtt_log_printf(MOSQ_LOG_DEBUG, "url_opt: url decode 2 len [%u] result:[%s]\n", out_len, url_decode);

	/* start opt */
	int opt_method = GET;
	if (STRCMP(method, ==, "GET")) {
		opt_method = GET;
	} else if (STRCMP(method, ==, "POST")) {
		opt_method = POST;
	} else {
		_mqtt_log_printf(MOSQ_LOG_WARNING, 
						"mqtt_ping: url method wrong, using GET instead\n");
	}

	struct mycurl_string ret_buf;
	if ( ! mycurl_string_init(&ret_buf)) {
		_mqtt_log_printf(MOSQ_LOG_ERR, "url_opt: ret_buf init field!\n");
		if (url_decode) {
			free(url_decode);
		}
		return 1;
	}

	int state_code = 0;
	double down_size = 0;
	int ret = net_visit(url_decode, 
			&ret_buf,
			opt_method,
			NULL,
			60l, 
			&state_code,
			&down_size);
	
	if (ret) {
		_mqtt_log_printf(MOSQ_LOG_ERR, 
						"url_opt: url [%s] visit failed, state code:[%d]\n", 
						url_decode, 
						state_code);
		mycurl_string_free(&ret_buf);
		if (url_decode) {
			free(url_decode);
		}

		return 1;
	}

	unsigned char *ret_encode = base64_encode(ret_buf.ptr, strlen(ret_buf.ptr), &out_len);
	if (ret_encode == NULL) {
		_mqtt_log_printf(MOSQ_LOG_ERR, "url_opt: ret_buf base64 encode field!\n");
		mycurl_string_free(&ret_buf);
		if (url_decode) {
			free(url_decode);
		}

		return 1;
	}

	json_object_object_add(OUT_object, "response", json_object_new_string(ret_encode));
	
	mycurl_string_free(&ret_buf);
	if (url_decode) {
		free(url_decode);
	}
	if (ret_encode) {
		free(ret_encode);
	}
	/* opt end */

	char timestamp_buf[32] = {0};

	/* add timestamp field */
	long int sec = 0, usec = 0;
	get_timestamp_millisecond(&sec, &usec);
	snprintf(timestamp_buf, sizeof(timestamp_buf), "%ld.%ld", sec, usec);
	json_object_object_add(OUT_object, "date", 
							json_object_new_string(Trim(timestamp_buf)));
	return 0;
}

/*
 * return:		0-		success.
				1-		error
*/
int 
Mqtt_parse_INstring_generate_OUTstringEXE(void *reply_buf, char *payload) {
	json_object *IN_object = NULL;
	json_object *OUT_object = json_object_new_object();
	json_object *item_object = NULL, *id_object = NULL;

	int ret = 1;

	char content_out[1024] = {0};
	char desc[DESC_BUFF_LEN] = {0};
	int has_desc = 0;

	IN_object = json_tokener_parse(payload);/*translate string to object*/
	if( !IN_object || json_object_get_type(IN_object) != json_type_object) {
		_mqtt_log_printf(MOSQ_LOG_ERR, "Failed to parse EXE message data=0x%x.\n", payload);
		goto ERROR;
	}
	if( json_object_get_type(IN_object) != json_type_object ){
		_mqtt_log_printf(MOSQ_LOG_ERR, "Failed to parse EXE message data=%s.\n", payload);
		goto ERROR;
	}

	if( !json_object_object_get_ex(IN_object, "id", &id_object) ){
		goto ERROR;
	}
	const char *id = json_object_get_string(id_object);
	if (is_error(id)) {
		goto ERROR;
	}
	json_object_object_add(OUT_object, "id", json_object_new_string(id));

	if( !json_object_object_get_ex(IN_object, "item", &item_object) ){
		goto ERROR;
	}
	const char *item = json_object_get_string(item_object);
	if (is_error(item)) {
		goto ERROR;
	}
	json_object_object_add(OUT_object, "item", json_object_new_string(item));
	
	const char *buf = json_object_get_string(item_object);
	if (is_error(buf)) {
		goto ERROR;
	}
	if( STRCMP(buf, ==, "wireless") ){
		if( Mqtt_operationWireless(IN_object) ){
			goto ERROR;
		}
	}else if( STRCMP(buf, ==, "lan_net_opt")){
		has_desc = 1;
		if( lan_if_opt(IN_object, desc) ){
			goto ERROR;
		}
	}else if( STRCMP(buf, ==, "lan_dhcp_opt")){
		has_desc = 1;
		if( lan_dhcp_opt(IN_object, desc) ){
			goto ERROR;
		}
	}else if( STRCMP(buf, ==, "wireless_if_opt")){
		if( wireless_if_opt(IN_object) ){
			goto ERROR;
		}
	}else if( STRCMP(buf, ==, "wifidog_mode_opt")){
		has_desc = 1;
		if( wifidog_mode_opt(IN_object, desc) ){
			goto ERROR;
		}
	}else if( STRCMP(buf, ==, "rsyslogserverIP")){
		if( Mqtt_operateRsyslog(IN_object) ){
			goto ERROR;
		}
	}else if( STRCMP(buf, ==, "wifidog")){
		if( Mqtt_operateWifidog(IN_object) ){
			goto ERROR;
		}
	}else if( STRCMP(buf, ==, "WD_wired_pass")){
		if( Mqtt_operateWD_wired_pass(IN_object) ){
			goto ERROR;
		}
	}else if( STRCMP(buf, ==, "WD_roam_switch")){
		if( Mqtt_operateWD_roam_switch(IN_object) ){
			goto ERROR;
		}
	}else if( STRCMP(buf, ==, "reboot")){
		ExecuateShellCMD("echo \"REBOOT\" > /dev/console", content_out, 
			sizeof(content_out));
		ExecuateShellCMD("sync", content_out, sizeof(content_out));
		ExecuateShellCMD("reboot", content_out, sizeof(content_out));
	}else if( STRCMP(buf, ==, "remote_cmd") ){
		if( exec_remote_cmd(IN_object, OUT_object) ){
			goto ERROR;
		}
	}else if( STRCMP(buf, ==, "ping") ){
		if( mqtt_ping(IN_object, OUT_object) ){
			goto ERROR;
		}
	}else if( STRCMP(buf, ==, "reproxy") ){
		if( reproxy(IN_object, OUT_object) ){
			goto ERROR;
		}
	}else if( STRCMP(buf, ==, "url_opt") ){
		if( url_opt(IN_object, OUT_object) ){
			goto ERROR;
		}
	}
	
#if EXEC_SHELL  // do not open cmd_shell interface for everybody
	else if( STRCMP(buf, ==, "script") ){
		if( Mqtt_operationScript(IN_object, OUT_object) ){
			goto ERROR;
		}
	}else if( STRCMP(buf, ==, "shell")){
		if( Mqtt_operateShell(IN_object, OUT_object)){
			goto ERROR;
		}
	}else if( STRCMP(buf, ==, "shell64") ){
		if( Mqtt_operateShell64(IN_object, OUT_object)){
			goto ERROR;
		}
	}
#endif

	else if( STRCMP(buf, ==, "firmware") ){
		if( Mqtt_operationFWupgrade(IN_object) ) {
			goto ERROR;
		}
	}else if( STRCMP(buf, ==, "apps") ){
		// if( Mqtt_operationapps(IN_object, OUT_object) ){
		if( Mqtt_operationScript(IN_object, OUT_object) ){
			goto ERROR;
		}
	}else if( STRCMP(buf, ==, "passwd") ){
		if( passwd_operate(IN_object, OUT_object) ){
			goto ERROR;
		}
	}else if( STRCMP(buf, ==, "passwd_verify") ){
		if( passwd_verify(IN_object, OUT_object) ){
			goto ERROR;
		}
	}else if( STRCMP(buf, ==, "superpasswd") ){
		if( Mqtt_operateSuperPasswd(IN_object, OUT_object) ){
			goto ERROR;
		}
	}else if( STRCMP(buf, ==, "qos") ){
		if( mqtt_operate_qos(IN_object, OUT_object) ){
			goto ERROR;
		}
	}else if( STRCMP(buf, ==, "network") ){
		if( network_if_opts(IN_object) ){
			goto ERROR;
		}
	}else if( STRCMP(buf, ==, "qrcode") ){
		if(mqtt_operate_qrcode(IN_object)){
			goto ERROR;
		}
	}else{
		_mqtt_log_printf(MOSQ_LOG_ERR, "systask: EXE unkown item: [%s].\n", buf);
		goto ERROR;
	}

	json_object_object_add(OUT_object, "state", json_object_new_string("0"));
	ret = 0;

	goto OUT;

ERROR:
	json_object_object_add(OUT_object, "state", json_object_new_string("-1"));
OUT:

#if WITH_DESC
	if (has_desc) {	//cmd exec state description
		json_object_object_add(OUT_object, "desc", json_object_new_string(desc));
	}
#endif
	if( !is_error(IN_object) ){
		json_object_put(IN_object);
	}

	strncpy((char *)reply_buf, json_object_to_json_string(OUT_object), BUF_SIZE-1);
	if (!is_error(OUT_object)) {
		json_object_put(OUT_object);
	}else{
		_mqtt_log_printf(MOSQ_LOG_ERR, 
			"sys_task: OUT_object is NULL! it should never be happend!\n");
	}
	
	return ret;
}

void 
*SYS_task(void *argv) {
	int msgid = 0, ret_value = 0;
	struct mosquitto *mosq = NULL;
	char *topic = NULL;
	char *payload = NULL;
	mqtt_c_msq sys_msg;
	char reply_buffer[BUF_SIZE] = {0};
	char newtopic[128] = {0};

	memset(&sys_msg, 0, sizeof(mqtt_c_msq));

	msgid = msgget(SYS_MSGKEY, IPC_EXCL);
	if(msgid < 0){
		_mqtt_log_printf(MOSQ_LOG_ERR, 
			"sys_task: SYS_MSGKEY not existed! errno=%d [%s].\n", errno, strerror(errno));

		return NULL;
	}

	int pub_res = 0;
	int publish_len = 0;
	while( 1 ) {
		publish_len = 0;
		ret_value = msgrcv(msgid, &sys_msg, sizeof(mqtt_c_msq),0, 0);
		//_mqtt_log_printf(MOSQ_LOG_INFO, "%x, topic=%x, payload=%x.\n",
		//	sys_msg.content[0], sys_msg.content[1], sys_msg.content[2]);
		mosq = (struct mosquitto *)sys_msg.content[0];
		topic = sys_msg.content[1];
		payload = sys_msg.content[2];
		_mqtt_log_printf(MOSQ_LOG_INFO, 
						"EXE: topic=%s, payload=%s\n", topic, payload);

		//think again more.
		Mqtt_parse_INstring_generate_OUTstringEXE(reply_buffer, payload);

		if( Mqtt_generate_newTopic(newtopic, sizeof(newtopic), topic)) {
			goto LOOP;
		}

		publish_len = strlen((const char *)reply_buffer);
		if (publish_len >= BUF_SIZE) {
			_mqtt_log_printf(MOSQ_LOG_ERR, 
						"CMD_EXE: publish message too lang!\n");
			goto LOOP;
		}

		pub_res = mosquitto_publish(mosq, 
			NULL, 
			newtopic, 
			publish_len,
			reply_buffer, 
			0, 
			false);

		if (pub_res == MOSQ_ERR_SUCCESS) {
					_mqtt_log_printf(MOSQ_LOG_INFO, 
						"CMD_EXE: publish OK [MOSQ_SUCCESS]\n");
				}else if (pub_res == MOSQ_ERR_INVAL) {
					_mqtt_log_printf(MOSQ_LOG_ERR, 
						"CMD_EXE: publish failed [MOSQ_ERR_INVAL]\n");
				}else if (pub_res == MOSQ_ERR_NOMEM) {
					_mqtt_log_printf(MOSQ_LOG_ERR, 
						"CMD_EXE: publish failed [MOSQ_ERR_NOMEM]\n");
				}else if (pub_res == MOSQ_ERR_NO_CONN) {
					_mqtt_log_printf(MOSQ_LOG_ERR, 
						"CMD_EXE: publish failed [MOSQ_ERR_NO_CONN]\n");
				}else if (pub_res == MOSQ_ERR_PROTOCOL) {
					_mqtt_log_printf(MOSQ_LOG_ERR, 
						"CMD_EXE: publish failed [MOSQ_ERR_PROTOCOL]\n");
				}else if (pub_res == MOSQ_ERR_PAYLOAD_SIZE) {
					_mqtt_log_printf(MOSQ_LOG_ERR, 
						"CMD_EXE: publish failed [MOSQ_ERR_PAYLOAD_SIZE]\n");
				}

		memset(reply_buffer, 0, sizeof(reply_buffer));
		memset(newtopic, 0, sizeof(newtopic));

LOOP:
		if (!is_error(topic)) {
			free(topic);
		}
		topic = NULL;
		
		if (!is_error(payload)) {
			free(payload);
		}
		payload = NULL;
	}

	return NULL;
}
