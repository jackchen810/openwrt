/*
 * wifidog process task 4 mqtt-client
 * Copyright (c) 2016, victortang <tangronghua@kunteng.org>
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */

/*
 * Contributors:
 * Victor Tang @20160712- initial implementation and documentation.
 */
#include <stdio.h>
#include <sys/types.h>
#include <sys/ipc.h>
#include <sys/msg.h>
#include <errno.h>
#include "set_sync_task.h"
#include "common.h"
#include "ktmarket.h"
#include "utils.h"


cmd_opt WifidogCMD_Tbl[] = {
	{"domainlist_set",			"wdctl add_trusted_domains "},
	{"maclist_w_set",			"wdctl add_trusted_mac "},
	{"maclist_b_set",			"wdctl add_untrusted_mac "},
	{"iplist_set",				"wdctl add_trusted_iplist "},
	{"domainlist_clear",		"wdctl clear_trusted_domains"},
	{"domainlist_del",			"wdctl del_trusted_domains "},
	{"pandomain_add",			"wdctl add_trusted_pdomains "},
	{"pandomain_del",			"wdctl del_trusted_pdomains "},
	{"pandomain_clear",			"wdctl clear_trusted_pdomains"},
	{"maclist_w_clear",			"wdctl clear_trusted_mac"},
	{"maclist_w_del",			"wdctl del_trusted_mac "},
	{"maclist_b_clear",			"wdctl clear_untrusted_mac"},
	{"maclist_b_del",			"wdctl del_untrusted_mac "},
	{"iplist_clear",			"wdctl clear_trusted_iplist"},
	{"maclist_reset",			"wdctl reset "},
	{NULL, NULL}
};

cmd_opt CloudCMD_Tbl[] = {
	{"blist_mac_get", 				"/usr/sbin/blist get_mac_list"},
	{"blist_mac_set", 				"/usr/sbin/blist add_mac_list "},
	{"blist_mac_del",		 		"/usr/sbin/blist del_mac_list "},
	{"blist_mac_clear_all", 		"/usr/sbin/blist flush_mac"},
	{"blist_domain_get", 			"/usr/sbin/blist get_domain_list"},
	{"blist_domain_set",			"/usr/sbin/blist set_domain "},
	{"blist_domain_clear_all",		"/usr/sbin/blist flush_domain"},
	{"channelpath_set",				"uci set firmwareinfo.info.channel_path='"},
	{"channelpath_clear",			"uci set firmwareinfo.info.channel_path=''"},
	{NULL, NULL}
};

void Mqtt_parse_INstring_generate_OUTstringSET(void *reply_buf, char *payload) {
	if (reply_buf == NULL) {
		_mqtt_log_printf(MOSQ_LOG_ERR, 
			"CMD_SET: Failed to init reply_buf! pointer=0x%x. It shouldnt be happend!\n",
			reply_buf);
		
		return;
	}
	if (payload == NULL) {
		_mqtt_log_printf(MOSQ_LOG_ERR, 
			"CMD_SET: Failed to parse payload! pointer=0x%x.\n", payload);
		goto ERROR;
	}

	json_object *IN_object = NULL;
	json_object *OUT_object = json_object_new_object();
	json_object *item_object = NULL, *id_object = NULL;
	json_object *content_object = NULL;

	char content[SHELL_CMD_BUFFER] = {0}, content_ex[1100*5] = {0};
	char content_out[1132*5] = {0};

	IN_object = json_tokener_parse(payload);/*translate string to object*/
	if( is_error(IN_object) || json_object_get_type(IN_object) != json_type_object) {
		_mqtt_log_printf(MOSQ_LOG_ERR, 
			"CMD_SET: Failed to parse SET message data=%s.\n", payload);
		goto ERROR;
	}

	if( !json_object_object_get_ex(IN_object, "id", &id_object) ){
		_mqtt_log_printf(MOSQ_LOG_ERR, 
			"CMD_SET: No id field! data=[%s].\n", payload);
		goto ERROR;
	}
	const char *id = json_object_get_string(id_object);
	if (id == NULL) {
		_mqtt_log_printf(MOSQ_LOG_ERR, 
			"CMD_SET: Failed to parse id field! data=[%s].\n", payload);
		goto ERROR;
	}
	json_object_object_add(OUT_object, "id", json_object_new_string(id));

	if( !json_object_object_get_ex(IN_object, "item", &item_object) ){
		_mqtt_log_printf(MOSQ_LOG_ERR, 
			"CMD_SET: Failed to parse item field! data=[%s].\n", payload);
		goto ERROR;
	}
	const char *subjson_item = json_object_get_string(item_object);
	if (subjson_item == NULL) {
		_mqtt_log_printf(MOSQ_LOG_ERR, "CMD_SET: Item parse init failed!\n");
		goto ERROR;
	}
	json_object_object_add(OUT_object, "item", json_object_new_string(subjson_item));

	/*process*/
	int i = 0;
	if( STRCMP(subjson_item, ==, "domainlist_set") || 
		STRCMP(subjson_item, ==, "domainlist_clear") ||
		STRCMP(subjson_item, ==, "domainlist_del") ||
		STRCMP(subjson_item, ==, "pandomain_add") || 
		STRCMP(subjson_item, ==, "pandomain_del") ||
		STRCMP(subjson_item, ==, "pandomain_clear") ||
		STRCMP(subjson_item, ==, "iplist_set") || 
		STRCMP(subjson_item, ==, "iplist_clear") ||
		STRCMP(subjson_item, ==, "maclist_w_set") || 
		STRCMP(subjson_item, ==, "maclist_w_clear") ||
		STRCMP(subjson_item, ==, "maclist_w_del") ||
		STRCMP(subjson_item, ==, "maclist_b_set") || 
		STRCMP(subjson_item, ==, "maclist_b_clear") ||
		STRCMP(subjson_item, ==, "maclist_b_del") ||
		STRCMP(subjson_item, ==, "maclist_reset") ) {
		/* wifidog operactions */
		if( !PackageIsExist("apfree_wifidog") ){
			json_object_object_add(OUT_object, "log", 
				json_object_new_string("wifidog doesn't exit"));
			goto ERROR;
		}

		for( i=0; WifidogCMD_Tbl[i].name != NULL; i++ ) {
			if( STRCMP(subjson_item, ==, WifidogCMD_Tbl[i].name) ) {
				strncpy(content_ex, WifidogCMD_Tbl[i].cmd_shell, sizeof(content_ex));
				break;
			}
		}

		if( STRCMP(subjson_item, ==, "domainlist_set") || 
			STRCMP(subjson_item, ==, "maclist_w_set") ||
			STRCMP(subjson_item, ==, "maclist_b_set") || 
			STRCMP(subjson_item, ==, "iplist_set") ||
			STRCMP(subjson_item, ==, "pandomain_add") || 
			STRCMP(subjson_item, ==, "pandomain_del") ||
			STRCMP(subjson_item, ==, "domainlist_del") || 
			STRCMP(subjson_item, ==, "maclist_w_del") ||
			STRCMP(subjson_item, ==, "maclist_b_del") ||
			STRCMP(subjson_item, ==, "maclist_reset")
		  ) {
			if(json_object_object_get_ex(IN_object, "content", &content_object) == 0){
				_mqtt_log_printf(MOSQ_LOG_ERR, 
					"set_sync_task: %s need content field !\n", subjson_item);
				goto ERROR;
			}

			const char *subjson_content = json_object_get_string(content_object);
			if (content_ex == NULL) {
				_mqtt_log_printf(MOSQ_LOG_ERR, "CMD_SET: content parse init failed!\n");
				goto ERROR;
			}
			int cmd_len = strlen(content_ex);
			snprintf(content_ex+cmd_len, 
				sizeof(content_ex) - cmd_len - 1, "%s", subjson_content);
		}
		if( ExecuateShellCMD(content_ex, content_out, sizeof(content_out)) ){
			goto ERROR;
		}
		json_object_object_add(OUT_object, "log", json_object_new_string(content_out));

		memset(content_out, 0, sizeof(content_out));

		ExecuateShellCMD("wdctl user_cfg_save", content_out, sizeof(content_out));
		json_object_object_add(OUT_object, 
								"user_cfg_save", 
								json_object_new_string(content_out));

	} else if(	STRCMP(subjson_item, ==, "blist_mac_get") || 
				STRCMP(subjson_item, ==, "blist_mac_set") ||
				STRCMP(subjson_item, ==, "blist_mac_del") || 
				STRCMP(subjson_item, ==, "blist_mac_clear_all") ||
				STRCMP(subjson_item, ==, "blist_domain_get") || 
				STRCMP(subjson_item, ==, "blist_domain_set") ||
				STRCMP(subjson_item, ==, "blist_domain_clear_all") ||
				STRCMP(subjson_item, ==, "channelpath_set") || 
				STRCMP(subjson_item, ==, "channelpath_clear") ) {
				/* blist operactions */

		if (content_ex == NULL) {
			goto ERROR;
		}
		for( i=0; CloudCMD_Tbl[i].name != NULL; i++ ) {
			if( STRCMP(subjson_item, ==, CloudCMD_Tbl[i].name) ) {
				strncpy(content_ex, CloudCMD_Tbl[i].cmd_shell, sizeof(content_ex));
				break;
			}
		}

		if( STRCMP(subjson_item, ==, "blist_mac_set") || 
			STRCMP(subjson_item, ==, "blist_mac_del") ||
			STRCMP(subjson_item, ==, "blist_domain_set") ||
			STRCMP(subjson_item, ==, "channelpath_set") ){

			if(json_object_object_get_ex(IN_object, "content", &content_object) == 0){
				_mqtt_log_printf(MOSQ_LOG_ERR, 
					"set_sync_task: %s need content field !\n", subjson_item);
				goto ERROR;
			}

			const char *subjson_content = json_object_get_string(content_object);
			if (is_error(subjson_content)) {
				goto ERROR;
			}

			int cmd_len = strlen(content_ex);
			snprintf(content_ex+cmd_len, 
				sizeof(content_ex) - cmd_len - 1, "%s", subjson_content);

			cmd_len = strlen(content_ex);
			if( STRCMP(subjson_item, ==, "channelpath_set") ) {
				snprintf(content_ex + cmd_len, sizeof(content_ex) - cmd_len - 1, "%s", "'");
			} else {
				snprintf(content_ex + cmd_len, 
						sizeof(content_ex) - cmd_len - 1, 
						"%s", 
						" 1>/tmp/wdout.log 2>/tmp/wderr.log");
			}
		} else if(STRCMP(subjson_item, ==, "blist_mac_get") || 
					STRCMP(subjson_item, ==, "blist_domain_get") ||
					STRCMP(subjson_item, ==, "blist_mac_clear_all") || 
					STRCMP(subjson_item, ==, "blist_domain_clear_all")){

			int cmd_len = strlen(content_ex);
			snprintf(content_ex + cmd_len, 
					sizeof(content_ex) - cmd_len - 1, 
					"%s", 
					" 1>/tmp/wdout.log 2>/tmp/wderr.log");
		}

		char buf_stm_cmd[BUF_STM_CMD_LEN] = {0};
		char buf_stm_result[BUF_STM_RESULT_LEN] = {0};
		if (ExecuateShellCMD(content_ex, buf_stm_result, sizeof(buf_stm_result))) {
			goto ERROR;
		}
		memset(buf_stm_cmd, 0, sizeof(buf_stm_cmd));
		if( STRCMP(subjson_item, ==, "channelpath_set") || 
			STRCMP(subjson_item, ==, "channelpath_clear") ) {

			snprintf(buf_stm_cmd, sizeof(buf_stm_cmd), "%s", 
				"uci commit firmwareinfo");
			ExecuateShellCMD(buf_stm_cmd, buf_stm_result, sizeof(buf_stm_result));
			s_sleep(0, 100000); //0.1s

			memset(buf_stm_cmd, 0, sizeof(buf_stm_cmd));
			snprintf(buf_stm_cmd, sizeof(buf_stm_cmd), "%s", "sync");
			ExecuateShellCMD(buf_stm_cmd, buf_stm_result, sizeof(buf_stm_result));
		}else{
			snprintf(buf_stm_cmd, sizeof(buf_stm_cmd), "%s", "sync");
			ExecuateShellCMD(buf_stm_cmd, buf_stm_result, sizeof(buf_stm_result));

			if( read_all_file("/tmp/wdout.log", content_out) ) {
				goto ERROR;
			}
			json_object_object_add(OUT_object, "logout", 
				json_object_new_string(content_out));

			memset(content_out, 0, sizeof(content_out));
			if( read_all_file("/tmp/wderr.log", content_out) ){
				goto ERROR;
			}
			json_object_object_add(OUT_object, "logerr", 
				json_object_new_string(content_out));
		}
	}else{
		_mqtt_log_printf(MOSQ_LOG_ERR, 
			"set_sync_task: SET unkown item, %s\n", subjson_item);

		goto ERROR;
	}
	json_object_object_add(OUT_object, "state", json_object_new_string("0"));
	goto OUT;

ERROR:
	json_object_object_add(OUT_object, "state", json_object_new_string("-1"));

OUT:
	strncpy((char *)reply_buf, json_object_to_json_string(OUT_object), BUF_SIZE-1);

	if (!is_error(OUT_object)) {
		json_object_put(OUT_object);
	}

	if (!is_error(IN_object)) {
		json_object_put(IN_object);
	}

	return ;
}

void Mqtt_parse_INstring_generate_OUTstringSYNC(void *reply_buf, char *payload) {
	int i = 0, j = 0;
	
	json_object *IN_object = NULL;
	json_object *OUT_object = json_object_new_object();
	json_object *item_object = NULL, *id_object = NULL;
	json_object *tmp_object = NULL;
	
	char *shellcmd[] = {
		"domainlist_set", 
		"maclist_w_set", 
		"maclist_b_set", 
		"pandomain_add"
		};

	IN_object = json_tokener_parse(payload);/*translate string to object*/
	if( ! IN_object || json_object_get_type(IN_object) != json_type_object) {
		_mqtt_log_printf(MOSQ_LOG_ERR, 
			"CMD_SYNC: Failed to parse SYNC message data=0x%x.\n", payload);
		goto ERROR;
	}

	if( !json_object_object_get_ex(IN_object, "id", &id_object) ){
		_mqtt_log_printf(MOSQ_LOG_ERR, 
			"CMD_SYNC: Failed to parse SET message data=%s.\n", payload);
		goto ERROR;
	}
	const char *id = json_object_get_string(id_object);
	if (id == NULL) {
		_mqtt_log_printf(MOSQ_LOG_ERR, 
			"CMD_SYNC: Failed to parse id field! data=[%s].\n", payload);
		goto ERROR;
	}
	json_object_object_add(OUT_object, "id", json_object_new_string(id));

	if( !json_object_object_get_ex(IN_object, "item", &item_object) ){
		goto ERROR;
	}
	const char *item = json_object_get_string(item_object);
	if (item == NULL) {
		_mqtt_log_printf(MOSQ_LOG_ERR, 
			"CMD_SYNC: Failed to parse item field! data=[%s].\n", payload);
		goto ERROR;
	}
	json_object_object_add(OUT_object, "item", json_object_new_string(item));

	const char *subjson_item = json_object_get_string(item_object);
	if( STRCMP(subjson_item, !=, "sysync") ){
		_mqtt_log_printf(MOSQ_LOG_ERR, 
			"CMD_SYNC: item field is not accepted! item=[%s].\n", subjson_item);
		goto ERROR;
	}

	//sync almost only service for apfree_wifidog
	if( !PackageIsExist("apfree_wifidog") ){
		json_object_object_add(OUT_object, 
								"log", 
								json_object_new_string("wifidog doesn't exit"));
								
		_mqtt_log_printf(MOSQ_LOG_INFO, "CMD_SYNC: wifidog doesn't exit.\n");
		goto ERROR;
	}

	/*process*/
	int cmd_len = 0;
	char buf_stm_result[BUF_STM_RESULT_LEN] = {0};
	char content_out[SHELL_CMD_BUFFER] = {0};
	char buf_stm_cmd[BUF_STM_CMD_LEN] = {0};
	char content_ex[SHELL_CMD_BUFFER] = {0};
	for( i=0; i<sizeof(shellcmd)/sizeof(char*); i++ ) {
		tmp_object = NULL;
		if( !json_object_object_get_ex(IN_object, shellcmd[i], &tmp_object) ) {
			continue;
		}

		const char *subjson_tmp = json_object_get_string(tmp_object);
		if (subjson_tmp == NULL) {
			continue;
		}

		if( STRCMP(subjson_tmp, ==, "")){
			continue;
		}
		memset(content_ex, 0, sizeof(content_ex));

		for( j=0;WifidogCMD_Tbl[j].name != NULL;j++ ) {
			if( STRCMP(shellcmd[i], ==, WifidogCMD_Tbl[j].name) ){
				strncpy(content_ex, WifidogCMD_Tbl[j].cmd_shell, sizeof(content_ex));
				break;
			}
		}

		cmd_len = strlen(content_ex);
		if ( 1 >= cmd_len) {
			_mqtt_log_printf(MOSQ_LOG_ERR, "sync: no method %s, it should not happened\n",
				shellcmd[i]);

			goto OUT;
		}
		snprintf(content_ex + cmd_len, sizeof(content_ex) - cmd_len - 1, "%s", subjson_tmp);

		if(ExecuateShellCMD(content_ex, content_out, sizeof(content_out))) {
			snprintf(content_out, sizeof(content_out), "%s", "unknown");
		}
		json_object_object_add(OUT_object, 
								shellcmd[i], 
								json_object_new_string(content_out));
	}

	memset(buf_stm_result, 0, sizeof(buf_stm_result));
	snprintf(buf_stm_cmd, sizeof(buf_stm_cmd), "%s", "wdctl user_cfg_save");

	if ( ExecuateShellCMD(buf_stm_cmd, buf_stm_result, sizeof(buf_stm_result)) ) {
		goto ERROR;
	}

	json_object_object_add(OUT_object, "state", json_object_new_string("0"));
	goto OUT;

ERROR:
	json_object_object_add(OUT_object, "state", json_object_new_string("-1"));

OUT:
	strncpy((char *)reply_buf, json_object_to_json_string(OUT_object), BUF_SIZE-1);

	if(!is_error(OUT_object)) {
		json_object_put(OUT_object);
	}

	if (!is_error(IN_object)) {
		json_object_put(IN_object);
	}

	return ;
}

void *WD_task(void *argv) {
	int msgid = 0, ret_value = 0;
	mqtt_c_msq wd_msg;
	struct mosquitto *mosq = NULL;
	int msg_type = 0;
	char *topic = NULL;
	char *payload = NULL;
	char reply_buffer[BUF_SIZE] = {0};
	char newtopic[128] = {0};

	memset(&wd_msg, 0, sizeof(mqtt_c_msq));
	memset(reply_buffer, 0, sizeof(reply_buffer));
	memset(newtopic, 0, sizeof(newtopic));

	msgid = msgget(WD_MSGKEY, IPC_EXCL);
	if(msgid < 0){
		_mqtt_log_printf(MOSQ_LOG_ERR, 
			"set_sync_task: SYS_MSGKEY not existed! errno=%d [%s].\n", 
			errno, 
			strerror(errno));
			
		return NULL;
	}

	int publish_len = 0;
	while( 1 ) {
		ret_value = msgrcv(msgid, &wd_msg, sizeof(mqtt_c_msq),0, 0);
		mosq = (struct mosquitto *)wd_msg.content[0];
		topic = wd_msg.content[1];
		payload = wd_msg.content[2];

		msg_type = wd_msg.msgtype;
		if( msg_type == CMD_SET ){
			_mqtt_log_printf(MOSQ_LOG_INFO, 
							"CMD_SET: topic=%s, payload=%s.\n", 
							(void *)topic, 
							payload);
			Mqtt_parse_INstring_generate_OUTstringSET((void *)reply_buffer, payload);
		} else if (msg_type == CMD_SYNC ) {
			_mqtt_log_printf(MOSQ_LOG_INFO, 
							"CMD_SYNC: topic=%s, payload=%s.\n", 
							(void *)topic, 
							payload);
			Mqtt_parse_INstring_generate_OUTstringSYNC((void *)reply_buffer, payload);
		} else {
			_mqtt_log_printf(MOSQ_LOG_ERR, 
				"sys_sync_task recv invalid msg type, but assert...\n");
		}

		if( Mqtt_generate_newTopic(newtopic,sizeof(newtopic), topic) ) {
			goto LOOP;
		}

		publish_len = strlen((const char *)reply_buffer);
		if (publish_len >= BUF_SIZE) {
			_mqtt_log_printf(MOSQ_LOG_ERR, 
						"CMD_EXE: publish message too lang!\n");
			goto LOOP;
		}

		int pub_res = mosquitto_publish(mosq, 
			NULL, 
			newtopic, 
			publish_len, 
			reply_buffer, 
			0, 
			false);

		if (pub_res == MOSQ_ERR_SUCCESS) {
			_mqtt_log_printf(MOSQ_LOG_INFO, 
				"CMD_SET: publish OK [MOSQ_SUCCESS]\n");
		}else if (pub_res == MOSQ_ERR_INVAL) {
			_mqtt_log_printf(MOSQ_LOG_ERR, 
				"CMD_SET: publish failed [MOSQ_ERR_INVAL]\n");
		}else if (pub_res == MOSQ_ERR_NOMEM) {
			_mqtt_log_printf(MOSQ_LOG_ERR, 
				"CMD_SET: publish failed [MOSQ_ERR_NOMEM]\n");
		}else if (pub_res == MOSQ_ERR_NO_CONN) {
			_mqtt_log_printf(MOSQ_LOG_ERR, 
				"CMD_SET: publish failed [MOSQ_ERR_NO_CONN]\n");
		}else if (pub_res == MOSQ_ERR_PROTOCOL) {
			_mqtt_log_printf(MOSQ_LOG_ERR, 
				"CMD_SET: publish failed [MOSQ_ERR_PROTOCOL]\n");
		}else if (pub_res == MOSQ_ERR_PAYLOAD_SIZE) {
			_mqtt_log_printf(MOSQ_LOG_ERR, 
				"CMD_SET: publish failed [MOSQ_ERR_PAYLOAD_SIZE]\n");
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