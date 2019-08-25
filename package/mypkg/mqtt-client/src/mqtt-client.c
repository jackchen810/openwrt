/*
Copyright (c) 2009-2014 Roger Light <roger@atchoo.org>

All rights reserved. This program and the accompanying materials
are made available under the terms of the Eclipse Public License v1.0
and Eclipse Distribution License v1.0 which accompany this distribution.

The Eclipse Public License is available at
   http://www.eclipse.org/legal/epl-v10.html
and the Eclipse Distribution License is available at
  http://www.eclipse.org/org/documents/edl-v10.php.
*/

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

extern int ancestor_pid;
bool process_messages = true;
int msg_count = 0;

// auto_cmds_sended if equal 0 whill send ROM_SYNC to YUNAC-server
static int auto_cmds_sended = 0;
static unsigned long long yunac_loop_times = 0;

static struct uci_context *wireless_ctx = NULL;

/*
  * uci flag determs use what kind of uci api
  * channel is different
  */
sys_info WirelessCMD_Tbl[] = {
	{"ssid",				"ssid",				1},
	{"encryption",			"encryption",		1},
	{"key",					"key",				1},
	{"channel_2.4",			"2.4G",				0},
	{"channel_5",			"5G",				0},
	{NULL, NULL},
};

/*
 * Input:	option-	wireless option
 		buf-		target buf
 * return:	0-		success
 *		1-		error
*/
int wireless_iface_read(char *option, char *buf, int buf_len) {
	int ret = 1;
	struct uci_element *e = NULL;
	const char *op_value = NULL;
	struct uci_package *wireless_pkg = NULL;

    //open UCI file
    if( UCI_OK != uci_load(wireless_ctx, "/etc/config/wireless", &wireless_pkg) )
    {
			_mqtt_log_printf(MOSQ_LOG_ERR, "%s: uci_load wireless failed.\n", __FILE__);
			return ret;
    }

	//look through
	uci_foreach_element(&wireless_pkg->sections, e) {
		struct uci_section *s = uci_to_section(e);
		if( STRCMP(s->type, !=, "wifi-iface") ) {
			continue;
		}

		op_value = uci_lookup_option_string(wireless_ctx, s, option);
		if( op_value != NULL ){
			strncpy(buf, op_value, buf_len);
			ret = 0;
			break;
		}
	}
	uci_unload(wireless_ctx, wireless_pkg);

	return ret;
}

/*
 * Input:	channel-	wireless channel option
 		buf-		target buf
 * return:	0-		success
 *		1-		error
*/
int wireless_channel_read(char *channel, char *buf, int buf_len) {
	int ret = 1;
	struct uci_element *e = NULL;
	const char *band_value = NULL;
	const char *channel_value = NULL;

	struct uci_package *wireless_pkg = NULL;

    //open UCI file
    if( UCI_OK != uci_load(wireless_ctx, "/etc/config/wireless", &wireless_pkg) )
    {
			_mqtt_log_printf(MOSQ_LOG_ERR, "%s: uci_load wireless failed.\n", __FILE__);
			return ret;
    }
	//look through
	uci_foreach_element(&wireless_pkg->sections, e) {
		struct uci_section *s = uci_to_section(e);
		if( STRCMP(s->type, !=, "wifi-device") )
			continue;
		band_value = uci_lookup_option_string(wireless_ctx, s, "band");
		if( STRCMP(band_value, ==, channel) )
		{
			ret = 0;
			channel_value = uci_lookup_option_string(wireless_ctx, s, "channel");
			strncpy(buf, channel_value, buf_len);
		}
	}
	uci_unload(wireless_ctx, wireless_pkg);

	return ret;
}

int Sync_generate_newTopic(char *newtopic, int len) {
	char tmpmac[32] = {0};

	if( GetRouterMAC("br-lan", tmpmac, sizeof(tmpmac)) ) {
		_mqtt_log_printf(MOSQ_LOG_ERR, "mqtt-client: br-lan get error: %s\n", tmpmac);
		return 1;
	}

	snprintf(newtopic, len, "%s/%s/CMD_GET/", SNYNC_TARGET, tmpmac);
	return 0;
}

// my_message_callback It will block when haven't handled recent message
void 
my_message_callback(struct mosquitto *mosq, 
					void *obj, 
					const struct mosquitto_message *message) {

	struct mosq_config *cfg;
	int i;
	bool res;
	char subtopic[32] = {0};
	char newtopic[128] = {0};
	char reply_buffer[BUF_SIZE] = {0};

	if(process_messages == false) {
		_mqtt_log_printf(MOSQ_LOG_ERR, 
			"%s: process_messages is false, it should not occurred.\n", __FILE__);
		return;/*whether it is nessesary victor@20160114*/
	}


	if ( ! obj) {
		_mqtt_log_printf(MOSQ_LOG_ERR, 
			"%s: obj is NULLs, it should not occurred.\n", __FILE__);
		return;
	}
	cfg = (struct mosq_config *)obj;

	if(message->retain && cfg->no_retain) return;

	if(cfg->filter_outs){
		for(i=0; i<cfg->filter_out_count; i++){
			mosquitto_topic_matches_sub(cfg->filter_outs[i], message->topic, &res);
			if(res) return;
		}
	}

	if(cfg->verbose){
		if(message->payloadlen){
			printf("%s ", message->topic);
			fwrite(message->payload, 1, message->payloadlen, stdout);
			if(cfg->eol){
				printf("\n");
			}
		}else{
			if(cfg->eol){
				printf("%s (null)\n", message->topic);
			}
		}
		fflush(stdout);
	}else{
		if(message->payloadlen){	//start handle message payload
			/*process IN msg*/
			if( Mqtt_parse_INtopic_OUTsubtopic(subtopic, 32, message->topic) ) {
				_mqtt_log_printf(MOSQ_LOG_ERR, "%s: topic(%s) is in wrong format, %s, %d.\n", __FILE__,
					message->topic, __FUNCTION__, __LINE__);
				goto OUT;
			}

			/*this interface is used when EXE cmd is suspended.*/
			if( STRCMP(subtopic, ==, "REBOOT") ) {
				_mqtt_log_printf(MOSQ_LOG_INFO, "REBOOT:%s: receive=%s do router reboot...\n", 
					__FILE__, subtopic);

				char buf_stm_cmd[BUF_STM_CMD_LEN] = {0};
				char buf_stm_result[BUF_STM_RESULT_LEN] = {0};
				snprintf(buf_stm_cmd, sizeof(buf_stm_cmd), "%s", "reboot -f");
				ExecuateShellCMD(buf_stm_cmd, buf_stm_result, sizeof(buf_stm_result));
				goto OUT;
			}

			int send_ret = 0;
			if( STRCMP(subtopic, ==, "CMD_GET") ) {
				if( cmd_method_get((void *)reply_buffer, message->payload) ) {
					Mqtt_SYSINFO_error((void *)reply_buffer, message->payload);
				}

				Mqtt_generate_newTopic(newtopic, sizeof(newtopic), message->topic);

				int publish_len = strlen((const char *)reply_buffer);
				if (publish_len >= BUF_SIZE) {
					_mqtt_log_printf(MOSQ_LOG_ERR, 
								"CMD_EXE: publish message too lang!\n");
					goto OUT;
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
						"CMD_GET: publish OK [MOSQ_SUCCESS]\n");
				}else if (pub_res == MOSQ_ERR_INVAL) {
					_mqtt_log_printf(MOSQ_LOG_ERR, 
						"CMD_GET: publish failed [MOSQ_ERR_INVAL]\n");
				}else if (pub_res == MOSQ_ERR_NOMEM) {
					_mqtt_log_printf(MOSQ_LOG_ERR, 
						"CMD_GET: publish failed [MOSQ_ERR_NOMEM]\n");
				}else if (pub_res == MOSQ_ERR_NO_CONN) {
					_mqtt_log_printf(MOSQ_LOG_ERR, 
						"CMD_GET: publish failed [MOSQ_ERR_NO_CONN]\n");
				}else if (pub_res == MOSQ_ERR_PROTOCOL) {
					_mqtt_log_printf(MOSQ_LOG_ERR, 
						"CMD_GET: publish failed [MOSQ_ERR_PROTOCOL]\n");
				}else if (pub_res == MOSQ_ERR_PAYLOAD_SIZE) {
					_mqtt_log_printf(MOSQ_LOG_ERR, 
						"CMD_GET: publish failed [MOSQ_ERR_PAYLOAD_SIZE]\n");
				}
			} else if( STRCMP(subtopic, ==, "CMD_EXE") ) {
				send_ret = send_msq(mosq, message->topic, message->payload, subtopic);
			} else if(STRCMP(subtopic, ==, "CMD_SET")||STRCMP(subtopic, ==, "CMD_SYNC")){
				send_ret = send_msq(mosq, message->topic, message->payload, subtopic);
			}
			
			switch (send_ret) {
				case 0:
					break;
				case 1:
					_mqtt_log_printf(MOSQ_LOG_ERR, 
									"com: msgsend payload create failed!\n");
				case EAGAIN:
					_mqtt_log_printf(MOSQ_LOG_WARNING, "com: msgqueue is full already!\n");
					break;
				default:
					_mqtt_log_printf(MOSQ_LOG_DEBUG, "com: msgsend failed! errno = %d\n", send_ret);
			}
		} else {
			_mqtt_log_printf(MOSQ_LOG_WARNING, 
							"%s, %s: MSQ message recved payload length = 0\n", 
							__FILE__, 
							__LINE__);
		}
	}
OUT:
	if(cfg->msg_count>0){
		msg_count++;
		if(cfg->msg_count == msg_count){
			process_messages = false;
			mosquitto_disconnect(mosq);
		}
	}
}

// auto_server_send
void 
auto_server_send(struct mosquitto *mosq) {
	char newtopic[128] = {0};
	char reply_buffer[BUF_SIZE] = {0};

	memset(newtopic, 0, sizeof(newtopic));
	memset(reply_buffer, 0, sizeof(reply_buffer));

	/*this interface is used when EXE cmd is suspended.*/
	_mqtt_log_printf(MOSQ_LOG_INFO, 
		"auto request: auto send %s to server at mqtt_client start\n", SNYNC_ID);

	Mqtt_generate_SYSinfo((void *)reply_buffer, "sysinfo", SNYNC_ID);

	Sync_generate_newTopic(newtopic, sizeof(newtopic));

	int publis_result = 0;
	int publish_len = strlen((const char *)reply_buffer);
	if (publish_len >= BUF_SIZE) {
		_mqtt_log_printf(MOSQ_LOG_ERR, 
					"CMD_EXE: publish message too lang!\n");
		return;
	}
	publis_result = mosquitto_publish(mosq, 
		NULL, 
		newtopic, 
		publish_len,
		reply_buffer, 
		0, 
		false);
	if (publis_result != MOSQ_ERR_SUCCESS) {
		_mqtt_log_printf(MOSQ_LOG_ERR, 
			"auto request: auto send %s to server failed, errno:%d\n", 
			SNYNC_ID, publis_result);
	}else{
		_mqtt_log_printf(MOSQ_LOG_INFO, "auto request: auto send succeed!\n");
	}
}

void my_connect_callback(struct mosquitto *mosq, void *obj, int result)
{
	int i;
	struct mosq_config *cfg;

	if ( ! obj) {
		_mqtt_log_printf(MOSQ_LOG_ERR, 
			"%s: obj is NULLs, it should not occurred.\n", __FILE__);
		return;
	}


	cfg = (struct mosq_config *)obj;

	if(!result){
		for(i=0; i<cfg->topic_count; i++){
			mosquitto_subscribe(mosq, NULL, cfg->topics[i], cfg->qos);
		}
	}else{
		if(result && !cfg->quiet){
			fprintf(stderr, "%s\n", mosquitto_connack_string(result));
		}
	}
}

void 
my_subscribe_callback(struct mosquitto *mosq, 
						void *obj, 
						int mid, 
						int qos_count, 
						const int *granted_qos){

	int i;
	struct mosq_config *cfg;
	char reply_buffer[BUF_SIZE] = {0};
	char newtopic[128] = {0};

	if ( ! obj) {
		_mqtt_log_printf(MOSQ_LOG_ERR, 
			"%s: obj is NULLs, it should not occurred.\n", __FILE__);
		return;
	}
	cfg = (struct mosq_config *)obj;

	Mqtt_generate_SYSinfo((void *)reply_buffer, "sysinfo", SNYNC_ID);
	if (Sync_generate_newTopic(newtopic, 128)) {
		return;
	}
	
	_mqtt_log_printf(MOSQ_LOG_INFO, "Send SYNC to YUN:%s.\n", reply_buffer);

	int publish_len = strlen((const char *)reply_buffer);
	if (publish_len >= BUF_SIZE) {
		_mqtt_log_printf(MOSQ_LOG_ERR, 
					"CMD_EXE: publish message too lang!\n");
		return;
	}

	int mosquitto_publish_restult = mosquitto_publish(mosq, 
			NULL, 
			newtopic, 
			publish_len,
			reply_buffer, 
			1, 
			false);

	if (mosquitto_publish_restult != MOSQ_ERR_SUCCESS) {
		_mqtt_log_printf(MOSQ_LOG_ERR, 
			"Send SYNC to YUN: publish faild, MOSQCODE= %d.\n",
			mosquitto_publish_restult);
	}
}

void init_config(struct mosq_config *cfg) {
	memset(cfg, 0, sizeof(*cfg));
	cfg->port = 1883;
	cfg->max_inflight = 20;//victor@2016.0113 maybe should increse this value
	cfg->keepalive = 60;
	cfg->clean_session = true;
	cfg->eol = true;
	cfg->protocol_version = MQTT_PROTOCOL_V31;
}

int client_config_load(struct mosq_config *cfg, int pub_or_sub, int argc, char *argv[])
{
	int rc;
	FILE *fptr;
	char line[1024];
	int count;
	char *loc = NULL;
	int len;
	char *args[3];

#ifndef WIN32
	char *env;
#else
	char env[1024];
#endif
	args[0] = NULL;

	init_config(cfg);

	/* Default config file */
#ifndef WIN32
	env = getenv("XDG_CONFIG_HOME");
	if(env){
		len = strlen(env) + strlen("/mosquitto_pub") + 1;
		loc = malloc(len);
		if(pub_or_sub == CLIENT_PUB){
			snprintf(loc, len, "%s/mosquitto_pub", env);
		}else{
			snprintf(loc, len, "%s/mosquitto_sub", env);
		}
		loc[len-1] = '\0';
	}else{
		env = getenv("HOME");
		if(env){
			len = strlen(env) + strlen("/.config/mosquitto_pub") + 1;
			loc = malloc(len);
			if(pub_or_sub == CLIENT_PUB){
				snprintf(loc, len, "%s/.config/mosquitto_pub", env);
			}else{
				snprintf(loc, len, "%s/.config/mosquitto_sub", env);
			}
			loc[len-1] = '\0';
		}else{
			fprintf(stderr, "Warning: Unable to locate configuration directory, default config not loaded.\n");
		}
	}

#else
	rc = GetEnvironmentVariable("USERPROFILE", env, 1024);
	if(rc > 0 && rc < 1024){
		len = strlen(env) + strlen("\\mosquitto_pub.conf") + 1;
		loc = malloc(len);
		if(pub_or_sub == CLIENT_PUB){
			snprintf(loc, len, "%s\\mosquitto_pub.conf", env);
		}else{
			snprintf(loc, len, "%s\\mosquitto_sub.conf", env);
		}
		loc[len-1] = '\0';
	}else{
		fprintf(stderr, "Warning: Unable to locate configuration directory, default config not loaded.\n");
	}
#endif

	if(loc){
		fptr = fopen(loc, "rt");
		if(fptr){
			while(fgets(line, 1024, fptr)){
				if(line[0] == '#') continue; /* Comments */

				while(line[strlen(line)-1] == 10 || line[strlen(line)-1] == 13){
					line[strlen(line)-1] = 0;
				}
				/* All offset by one "args" here, because real argc/argv has
				 * program name as the first entry. */
				args[1] = strtok(line, " ");
				if(args[1]){
					args[2] = strtok(NULL, " ");
					if(args[2]){
						count = 3;
					}else{
						count = 2;
					}
					rc = client_config_line_proc(cfg, pub_or_sub, count, args);
					if(rc){
						fclose(fptr);
						free(loc);
						return rc;
					}
				}
			}
			fclose(fptr);
		}
		free(loc);
	}

	/* Deal with real argc/argv */
	rc = client_config_line_proc(cfg, pub_or_sub, argc, argv);
	if(rc) return rc;

	if(cfg->will_payload && !cfg->will_topic){
		fprintf(stderr, "Error: Will payload given, but no will topic given.\n");
		return 1;
	}
	if(cfg->will_retain && !cfg->will_topic){
		fprintf(stderr, "Error: Will retain given, but no will topic given.\n");
		return 1;
	}
	if(cfg->password && !cfg->username){
		if(!cfg->quiet) fprintf(stderr, "Warning: Not using password since username not set.\n");
	}
#ifdef WITH_TLS
	if((cfg->certfile && !cfg->keyfile) || (cfg->keyfile && !cfg->certfile)){
		fprintf(stderr, "Error: Both certfile and keyfile must be provided if one of them is.\n");
		return 1;
	}
#endif
#ifdef WITH_TLS_PSK
	if((cfg->cafile || cfg->capath) && cfg->psk){
		if(!cfg->quiet) fprintf(stderr, "Error: Only one of --psk or --cafile/--capath may be used at once.\n");
		return 1;
	}
	if(cfg->psk && !cfg->psk_identity){
		if(!cfg->quiet) fprintf(stderr, "Error: --psk-identity required if --psk used.\n");
		return 1;
	}
#endif

	if(pub_or_sub == CLIENT_SUB){
		if(cfg->clean_session == false && (cfg->id_prefix || !cfg->id)){
			if(!cfg->quiet) fprintf(stderr, "Error: You must provide a client id if you are using the -c option.\n");
			return 1;
		}
		if(cfg->topic_count == 0){
			if(!cfg->quiet) fprintf(stderr, "Error: You must specify a topic to subscribe to.\n");
			return 1;
		}
	}

	if(!cfg->host){
		cfg->host = "localhost";
	}
	return MOSQ_ERR_SUCCESS;
}

/* Process a tokenised single line from a file or set of real argc/argv */
int client_config_line_proc(struct mosq_config *cfg, int pub_or_sub, int argc, char *argv[])
{
	int i;

	for(i=1; i<argc; i++){
		if(!strcmp(argv[i], "-p") || !strcmp(argv[i], "--port")){
			if(i==argc-1){
				fprintf(stderr, "Error: -p argument given but no port specified.\n\n");
				return 1;
			}else{
				cfg->port = atoi(argv[i+1]);
				if(cfg->port<1 || cfg->port>65535){
					fprintf(stderr, "Error: Invalid port given: %d\n", cfg->port);
					return 1;
				}
			}
			i++;
		}else if(!strcmp(argv[i], "-A")){
			if(i==argc-1){
				fprintf(stderr, "Error: -A argument given but no address specified.\n\n");
				return 1;
			}else{
				cfg->bind_address = strdup(argv[i+1]);
			}
			i++;
#ifdef WITH_TLS
		}else if(!strcmp(argv[i], "--cafile")){
			if(i==argc-1){
				fprintf(stderr, "Error: --cafile argument given but no file specified.\n\n");
				return 1;
			}else{
				cfg->cafile = strdup(argv[i+1]);
			}
			i++;
		}else if(!strcmp(argv[i], "--capath")){
			if(i==argc-1){
				fprintf(stderr, "Error: --capath argument given but no directory specified.\n\n");
				return 1;
			}else{
				cfg->capath = strdup(argv[i+1]);
			}
			i++;
		}else if(!strcmp(argv[i], "--cert")){
			if(i==argc-1){
				fprintf(stderr, "Error: --cert argument given but no file specified.\n\n");
				return 1;
			}else{
				cfg->certfile = strdup(argv[i+1]);
			}
			i++;
		}else if(!strcmp(argv[i], "--ciphers")){
			if(i==argc-1){
				fprintf(stderr, "Error: --ciphers argument given but no ciphers specified.\n\n");
				return 1;
			}else{
				cfg->ciphers = strdup(argv[i+1]);
			}
			i++;
#endif
		}else if(!strcmp(argv[i], "-C")){
			if(pub_or_sub == CLIENT_PUB){
				goto unknown_option;
			}else{
				if(i==argc-1){
					fprintf(stderr, "Error: -C argument given but no count specified.\n\n");
					return 1;
				}else{
					cfg->msg_count = atoi(argv[i+1]);
					if(cfg->msg_count < 1){
						fprintf(stderr, "Error: Invalid message count \"%d\".\n\n", cfg->msg_count);
						return 1;
					}
				}
				i++;
			}
		}else if(!strcmp(argv[i], "-d") || !strcmp(argv[i], "--debug")){
			cfg->debug = true;
		}else if(!strcmp(argv[i], "-f") || !strcmp(argv[i], "--file")){
			if(pub_or_sub == CLIENT_SUB){
				goto unknown_option;
			}
			if(cfg->pub_mode != MSGMODE_NONE){
				fprintf(stderr, "Error: Only one type of message can be sent at once.\n\n");
				return 1;
			}else if(i==argc-1){
				fprintf(stderr, "Error: -f argument given but no file specified.\n\n");
				return 1;
			}else{
				cfg->pub_mode = MSGMODE_FILE;
				cfg->file_input = strdup(argv[i+1]);
			}
			i++;
		}else if(!strcmp(argv[i], "--help")){
			return 2;
		}else if(!strcmp(argv[i], "-h") || !strcmp(argv[i], "--host")){
			if(i==argc-1){
				fprintf(stderr, "Error: -h argument given but no host specified.\n\n");
				return 1;
			}else{
				cfg->host = strdup(argv[i+1]);
			}
			i++;
#ifdef WITH_TLS
		}else if(!strcmp(argv[i], "--insecure")){
			cfg->insecure = true;
#endif
		}else if(!strcmp(argv[i], "-i") || !strcmp(argv[i], "--id")){
			if(cfg->id_prefix){
				fprintf(stderr, "Error: -i and -I argument cannot be used together.\n\n");
				return 1;
			}
			if(i==argc-1){
				fprintf(stderr, "Error: -i argument given but no id specified.\n\n");
				return 1;
			}else{
				cfg->id = strdup(argv[i+1]);
			}
			i++;
		}else if(!strcmp(argv[i], "-I") || !strcmp(argv[i], "--id-prefix")){
			if(cfg->id){
				fprintf(stderr, "Error: -i and -I argument cannot be used together.\n\n");
				return 1;
			}
			if(i==argc-1){
				fprintf(stderr, "Error: -I argument given but no id prefix specified.\n\n");
				return 1;
			}else{
				cfg->id_prefix = strdup(argv[i+1]);
			}
			i++;
		}else if(!strcmp(argv[i], "-k") || !strcmp(argv[i], "--keepalive")){
			if(i==argc-1){
				fprintf(stderr, "Error: -k argument given but no keepalive specified.\n\n");
				return 1;
			}else{
				cfg->keepalive = atoi(argv[i+1]);
				if(cfg->keepalive>65535){
					fprintf(stderr, "Error: Invalid keepalive given: %d\n", cfg->keepalive);
					return 1;
				}
			}
			i++;
#ifdef WITH_TLS
		}else if(!strcmp(argv[i], "--key")){
			if(i==argc-1){
				fprintf(stderr, "Error: --key argument given but no file specified.\n\n");
				return 1;
			}else{
				cfg->keyfile = strdup(argv[i+1]);
			}
			i++;
#endif
		}else if(!strcmp(argv[i], "-l") || !strcmp(argv[i], "--stdin-line")){
			if(pub_or_sub == CLIENT_SUB){
				goto unknown_option;
			}
			if(cfg->pub_mode != MSGMODE_NONE){
				fprintf(stderr, "Error: Only one type of message can be sent at once.\n\n");
				return 1;
			}else{
				cfg->pub_mode = MSGMODE_STDIN_LINE;
			}
		}else if(!strcmp(argv[i], "-m") || !strcmp(argv[i], "--message")){
			if(pub_or_sub == CLIENT_SUB){
				goto unknown_option;
			}
			if(cfg->pub_mode != MSGMODE_NONE){
				fprintf(stderr, "Error: Only one type of message can be sent at once.\n\n");
				return 1;
			}else if(i==argc-1){
				fprintf(stderr, "Error: -m argument given but no message specified.\n\n");
				return 1;
			}else{
				cfg->message = strdup(argv[i+1]);
				cfg->msglen = strlen(cfg->message);
				cfg->pub_mode = MSGMODE_CMD;
			}
			i++;
		}else if(!strcmp(argv[i], "-M")){
			if(i==argc-1){
				fprintf(stderr, "Error: -M argument given but max_inflight not specified.\n\n");
				return 1;
			}else{
				cfg->max_inflight = atoi(argv[i+1]);
			}
			i++;
		}else if(!strcmp(argv[i], "-n") || !strcmp(argv[i], "--null-message")){
			if(pub_or_sub == CLIENT_SUB){
				goto unknown_option;
			}
			if(cfg->pub_mode != MSGMODE_NONE){
				fprintf(stderr, "Error: Only one type of message can be sent at once.\n\n");
				return 1;
			}else{
				cfg->pub_mode = MSGMODE_NULL;
			}
		}else if(!strcmp(argv[i], "-V") || !strcmp(argv[i], "--protocol-version")){
			if(i==argc-1){
				fprintf(stderr, "Error: --protocol-version argument given but no version specified.\n\n");
				return 1;
			}else{
				if(!strcmp(argv[i+1], "mqttv31")){
					cfg->protocol_version = MQTT_PROTOCOL_V31;
				}else if(!strcmp(argv[i+1], "mqttv311")){
					cfg->protocol_version = MQTT_PROTOCOL_V311;
				}else{
					fprintf(stderr, "Error: Invalid protocol version argument given.\n\n");
					return 1;
				}
				i++;
			}
#ifdef WITH_SOCKS
		}else if(!strcmp(argv[i], "--proxy")){
			if(i==argc-1){
				fprintf(stderr, "Error: --proxy argument given but no proxy url specified.\n\n");
				return 1;
			}else{
				if(mosquitto__parse_socks_url(cfg, argv[i+1])){
					return 1;
				}
				i++;
			}
#endif
#ifdef WITH_TLS_PSK
		}else if(!strcmp(argv[i], "--psk")){
			if(i==argc-1){
				fprintf(stderr, "Error: --psk argument given but no key specified.\n\n");
				return 1;
			}else{
				cfg->psk = strdup(argv[i+1]);
			}
			i++;
		}else if(!strcmp(argv[i], "--psk-identity")){
			if(i==argc-1){
				fprintf(stderr, "Error: --psk-identity argument given but no identity specified.\n\n");
				return 1;
			}else{
				cfg->psk_identity = strdup(argv[i+1]);
			}
			i++;
#endif
		}else if(!strcmp(argv[i], "-q") || !strcmp(argv[i], "--qos")){
			if(i==argc-1){
				fprintf(stderr, "Error: -q argument given but no QoS specified.\n\n");
				return 1;
			}else{
				cfg->qos = atoi(argv[i+1]);
				if(cfg->qos<0 || cfg->qos>2){
					fprintf(stderr, "Error: Invalid QoS given: %d\n", cfg->qos);
					return 1;
				}
			}
			i++;
		}else if(!strcmp(argv[i], "--quiet")){
			cfg->quiet = true;
		}else if(!strcmp(argv[i], "-r") || !strcmp(argv[i], "--retain")){
			if(pub_or_sub == CLIENT_SUB){
				goto unknown_option;
			}
			cfg->retain = 1;
		}else if(!strcmp(argv[i], "-s") || !strcmp(argv[i], "--stdin-file")){
			if(pub_or_sub == CLIENT_SUB){
				goto unknown_option;
			}
			if(cfg->pub_mode != MSGMODE_NONE){
				fprintf(stderr, "Error: Only one type of message can be sent at once.\n\n");
				return 1;
			}else{ 
				cfg->pub_mode = MSGMODE_STDIN_FILE;
			}
#ifdef WITH_SRV
		}else if(!strcmp(argv[i], "-S")){
			cfg->use_srv = true;
#endif
		}else if(!strcmp(argv[i], "-t") || !strcmp(argv[i], "--topic")){
			if(i==argc-1){
				fprintf(stderr, "Error: -t argument given but no topic specified.\n\n");
				return 1;
			}else{
				if(pub_or_sub == CLIENT_PUB){
					if(mosquitto_pub_topic_check(argv[i+1]) == MOSQ_ERR_INVAL){
						fprintf(stderr, "Error: Invalid publish topic '%s', does it contain '+' or '#'?\n", argv[i+1]);
						return 1;
					}
					cfg->topic = strdup(argv[i+1]);
				}else{
					if(mosquitto_sub_topic_check(argv[i+1]) == MOSQ_ERR_INVAL){
						fprintf(stderr, "Error: Invalid subscription topic '%s', are all '+' and '#' wildcards correct?\n", argv[i+1]);
						return 1;
					}
					cfg->topic_count++;
					cfg->topics = realloc(cfg->topics, cfg->topic_count*sizeof(char *));
					cfg->topics[cfg->topic_count-1] = strdup(argv[i+1]);
				}
				i++;
			}
		}else if(!strcmp(argv[i], "-T") || !strcmp(argv[i], "--filter-out")){
			if(pub_or_sub == CLIENT_PUB){
				goto unknown_option;
			}
			if(i==argc-1){
				fprintf(stderr, "Error: -T argument given but no topic filter specified.\n\n");
				return 1;
			}else{
				if(mosquitto_sub_topic_check(argv[i+1]) == MOSQ_ERR_INVAL){
					fprintf(stderr, "Error: Invalid filter topic '%s', are all '+' and '#' wildcards correct?\n", argv[i+1]);
					return 1;
				}
				cfg->filter_out_count++;
				cfg->filter_outs = realloc(cfg->filter_outs, cfg->filter_out_count*sizeof(char *));
				cfg->filter_outs[cfg->filter_out_count-1] = strdup(argv[i+1]);
			}
			i++;
#ifdef WITH_TLS
		}else if(!strcmp(argv[i], "--tls-version")){
			if(i==argc-1){
				fprintf(stderr, "Error: --tls-version argument given but no version specified.\n\n");
				return 1;
			}else{
				cfg->tls_version = strdup(argv[i+1]);
			}
			i++;
#endif
		}else if(!strcmp(argv[i], "-u") || !strcmp(argv[i], "--username")){
			if(i==argc-1){
				fprintf(stderr, "Error: -u argument given but no username specified.\n\n");
				return 1;
			}else{
				cfg->username = strdup(argv[i+1]);
			}
			i++;
		}else if(!strcmp(argv[i], "-P") || !strcmp(argv[i], "--pw")){
			if(i==argc-1){
				fprintf(stderr, "Error: -P argument given but no password specified.\n\n");
				return 1;
			}else{
				cfg->password = strdup(argv[i+1]);
			}
			i++;
		}else if(!strcmp(argv[i], "--will-payload")){
			if(i==argc-1){
				fprintf(stderr, "Error: --will-payload argument given but no will payload specified.\n\n");
				return 1;
			}else{
				cfg->will_payload = strdup(argv[i+1]);
				cfg->will_payloadlen = strlen(cfg->will_payload);
			}
			i++;
		}else if(!strcmp(argv[i], "--will-qos")){
			if(i==argc-1){
				fprintf(stderr, "Error: --will-qos argument given but no will QoS specified.\n\n");
				return 1;
			}else{
				cfg->will_qos = atoi(argv[i+1]);
				if(cfg->will_qos < 0 || cfg->will_qos > 2){
					fprintf(stderr, "Error: Invalid will QoS %d.\n\n", cfg->will_qos);
					return 1;
				}
			}
			i++;
		}else if(!strcmp(argv[i], "--will-retain")){
			cfg->will_retain = true;
		}else if(!strcmp(argv[i], "--will-topic")){
			if(i==argc-1){
				fprintf(stderr, "Error: --will-topic argument given but no will topic specified.\n\n");
				return 1;
			}else{
				if(mosquitto_pub_topic_check(argv[i+1]) == MOSQ_ERR_INVAL){
					fprintf(stderr, "Error: Invalid will topic '%s', does it contain '+' or '#'?\n", argv[i+1]);
					return 1;
				}
				cfg->will_topic = strdup(argv[i+1]);
			}
			i++;
		}else if(!strcmp(argv[i], "-c") || !strcmp(argv[i], "--disable-clean-session")){
			if(pub_or_sub == CLIENT_PUB){
				goto unknown_option;
			}
			cfg->clean_session = false;
		}else if(!strcmp(argv[i], "-N")){
			if(pub_or_sub == CLIENT_PUB){
				goto unknown_option;
			}
			cfg->eol = false;
		}else if(!strcmp(argv[i], "-R")){
			if(pub_or_sub == CLIENT_PUB){
				goto unknown_option;
			}
			cfg->no_retain = true;
		}else if(!strcmp(argv[i], "-v") || !strcmp(argv[i], "--verbose")){
			if(pub_or_sub == CLIENT_PUB){
				goto unknown_option;
			}
			cfg->verbose = 1;
		}else{
			goto unknown_option;
		}
	}

	return MOSQ_ERR_SUCCESS;

unknown_option:
	fprintf(stderr, "Error: Unknown option '%s'.\n",argv[i]);
	return 1;
}

void client_config_cleanup(struct mosq_config *cfg) {
	int i;
	free(cfg->id);
	free(cfg->id_prefix);
	free(cfg->host);
	free(cfg->file_input);
	free(cfg->message);
	free(cfg->topic);
	free(cfg->bind_address);
	free(cfg->username);
	free(cfg->password);
	free(cfg->will_topic);
	free(cfg->will_payload);
#ifdef WITH_TLS
	free(cfg->cafile);
	free(cfg->capath);
	free(cfg->certfile);
	free(cfg->keyfile);
	free(cfg->ciphers);
	free(cfg->tls_version);
#  ifdef WITH_TLS_PSK
	free(cfg->psk);
	free(cfg->psk_identity);
#  endif
#endif
	if(cfg->topics){
		for(i=0; i<cfg->topic_count; i++){
			free(cfg->topics[i]);
		}
		free(cfg->topics);
	}
	if(cfg->filter_outs){
		for(i=0; i<cfg->filter_out_count; i++){
			free(cfg->filter_outs[i]);
		}
		free(cfg->filter_outs);
	}
#ifdef WITH_SOCKS
	free(cfg->socks5_host);
	free(cfg->socks5_username);
	free(cfg->socks5_password);
#endif
}

void 
my_log_callback(struct mosquitto *mosq, void *obj, int level, const char *str) {
	printf("%s\n", str);
	//if( level & MOSQ_LOG_ALL )
	//	_mqtt_client_log_printf(level, str);
}


void print_usage(void) {
	int major, minor, revision;
	mosquitto_lib_version(&major, &minor, &revision);

	printf("mqtt-client is a simple mqtt client that will subscribe to a single local topic.\n");
	//printf("mqtt-client version %s running on libmosquitto %d.%d.%d.\n\n", VERSION, major, minor, revision);
	printf("mqtt-client -t $MAC_ADDR/+/#");
}

int client_opts_set(struct mosquitto *mosq, struct mosq_config *cfg) {
	int rc;

	if(cfg->will_topic && mosquitto_will_set(mosq, cfg->will_topic,
				cfg->will_payloadlen, cfg->will_payload, cfg->will_qos,
				cfg->will_retain)){

		if(!cfg->quiet) fprintf(stderr, "Error: Problem setting will.\n");
		mosquitto_lib_cleanup();
		return 1;
	}
	if(cfg->username && mosquitto_username_pw_set(mosq, cfg->username, cfg->password)){
		if(!cfg->quiet) fprintf(stderr, "Error: Problem setting username and password.\n");
		mosquitto_lib_cleanup();
		return 1;
	}
#ifdef WITH_TLS
	if((cfg->cafile || cfg->capath)
			&& mosquitto_tls_set(mosq, cfg->cafile, cfg->capath, cfg->certfile, cfg->keyfile, NULL)){

		if(!cfg->quiet) fprintf(stderr, "Error: Problem setting TLS options.\n");
		mosquitto_lib_cleanup();
		return 1;
	}
	if(cfg->insecure && mosquitto_tls_insecure_set(mosq, true)){
		if(!cfg->quiet) fprintf(stderr, "Error: Problem setting TLS insecure option.\n");
		mosquitto_lib_cleanup();
		return 1;
	}
#  ifdef WITH_TLS_PSK
	if(cfg->psk && mosquitto_tls_psk_set(mosq, cfg->psk, cfg->psk_identity, NULL)){
		if(!cfg->quiet) fprintf(stderr, "Error: Problem setting TLS-PSK options.\n");
		mosquitto_lib_cleanup();
		return 1;
	}
#  endif
	if(cfg->tls_version && mosquitto_tls_opts_set(mosq, 1, cfg->tls_version, cfg->ciphers)){
		if(!cfg->quiet) fprintf(stderr, "Error: Problem setting TLS options.\n");
		mosquitto_lib_cleanup();
		return 1;
	}
#endif
	mosquitto_max_inflight_messages_set(mosq, cfg->max_inflight);
#ifdef WITH_SOCKS
	if(cfg->socks5_host){
		rc = mosquitto_socks5_set(mosq, cfg->socks5_host, cfg->socks5_port, cfg->socks5_username, cfg->socks5_password);
		if(rc){
			mosquitto_lib_cleanup();
			return rc;
		}
	}
#endif
	mosquitto_opts_set(mosq, MOSQ_OPT_PROTOCOL_VERSION, &(cfg->protocol_version));
	return MOSQ_ERR_SUCCESS;
}

int client_id_generate(struct mosq_config *cfg, const char *id_base) {
	int len;
	char hostname[256];

	if(cfg->id_prefix){
		cfg->id = malloc(strlen(cfg->id_prefix)+10);
		if(!cfg->id){
			if(!cfg->quiet) fprintf(stderr, "Error: Out of memory.\n");
			mosquitto_lib_cleanup();
			return 1;
		}
		snprintf(cfg->id, strlen(cfg->id_prefix)+10, "%s%d", cfg->id_prefix, getpid());
	}else if(!cfg->id){
		hostname[0] = '\0';
		gethostname(hostname, 256);
		hostname[255] = '\0';
		len = strlen(id_base) + strlen("/-") + 6 + strlen(hostname);
		cfg->id = malloc(len);
		if(!cfg->id){
			if(!cfg->quiet) fprintf(stderr, "Error: Out of memory.\n");
			mosquitto_lib_cleanup();
			return 1;
		}
		snprintf(cfg->id, len, "%s/%d-%s", id_base, getpid(), hostname);
		if(strlen(cfg->id) > MOSQ_MQTT_ID_MAX_LENGTH){
			/* Enforce maximum client id length of 23 characters */
			cfg->id[MOSQ_MQTT_ID_MAX_LENGTH] = '\0';
		}
	}
	return MOSQ_ERR_SUCCESS;
}

int client_connect(struct mosquitto *mosq, struct mosq_config *cfg) {
	char err[1024];
	int rc;

#ifdef WITH_SRV
	if(cfg->use_srv){
		rc = mosquitto_connect_srv(mosq, cfg->host, cfg->keepalive, cfg->bind_address);
	}else{
		rc = mosquitto_connect_bind(mosq, cfg->host, cfg->port, cfg->keepalive, cfg->bind_address);
	}
#else
	rc = mosquitto_connect_bind(mosq, cfg->host, cfg->port, cfg->keepalive, cfg->bind_address);
#endif
	if(rc>0){
		if(!cfg->quiet){
			if(rc == MOSQ_ERR_ERRNO){
#ifndef WIN32
				strerror_r(errno, err, 1024);
#else
				FormatMessage(FORMAT_MESSAGE_FROM_SYSTEM, NULL, errno, 0, (LPTSTR)&err, 1024, NULL);
#endif
				fprintf(stderr, "Error: %s\n", err);
				_mqtt_log_printf(MOSQ_LOG_ERR, "%s: ERROR: %s. %d\n", __FILE__, err, __LINE__);
			}else{
				fprintf(stderr, "Unable to connect (%s).\n", mosquitto_strerror(rc));
			}
		}
		mosquitto_lib_cleanup();
//victor @20160802 delete MSQ
		destory_message_queues();
//victor end
		return rc;
	}
	return MOSQ_ERR_SUCCESS;
}

/*
 * return:		0-		same, do not need to send sync msg to YUN.
				1-		diff, do need to send sync msg to YUN
*/
int SyncWirelesseSettings(char *oldwlan_param, int step_len, int step_num) {
	char *old_prt = oldwlan_param;
	if (old_prt == NULL) {
		return 1;
	}
	
	int ret = 0;
	char newwlan_param[5][128] = {0};
	char buffer[128] = {0}/*ues to store shell CMD result*/;

	int i = 0;
	for(; WirelessCMD_Tbl[i].cmd_name != NULL && i < step_num; i++ ) {
		if( WirelessCMD_Tbl[i].uciflag ) {
			if(wireless_iface_read(WirelessCMD_Tbl[i].cmd_shell, buffer, sizeof(buffer))){
				strncpy(buffer, "unkown", sizeof(buffer));
			}
		} else {
			if(wireless_channel_read(WirelessCMD_Tbl[i].cmd_shell, 
									buffer, 
									sizeof(buffer))){

				strncpy(buffer, "unkown", sizeof(buffer));
			}
		}
		memcpy(&newwlan_param[i][0], buffer, sizeof(buffer));

		//printf("diff=%s, %s\n", &newwlan_param[i][0], old_prt);
		if( STRCMP(&newwlan_param[i][0], !=, old_prt) ) {
			strncpy(old_prt, &newwlan_param[i][0], step_len);
			ret  = 1;
		}
		old_prt += step_len;
	}

	return ret;
}

void *SyncYUN_task(void *argv) {
	struct mosquitto *mosq = NULL;
	char oldwireless_param[5][128] = {0};
	char buffer[128] = {0}/*ues to store shell CMD result*/;
	char reply_buffer[BUF_SIZE] = {0};
	char newtopic[128] = {0};

	mosq = (struct mosquitto *)argv;

    //malloc UCI context
    wireless_ctx = uci_alloc_context();

	int i = 0;
	for(; WirelessCMD_Tbl[i].cmd_name != NULL; i++ ) {
		if( WirelessCMD_Tbl[i].uciflag ) {
			if(wireless_iface_read(WirelessCMD_Tbl[i].cmd_shell, 
									buffer, 
									sizeof(buffer))){

				strncpy(buffer, "unkown", sizeof(buffer));
			}
		}else{
			if(wireless_channel_read(WirelessCMD_Tbl[i].cmd_shell, 
									buffer, 
									sizeof(buffer))){

				strncpy(buffer, "unkown", sizeof(buffer));
			}
		}
		memcpy(&oldwireless_param[i][0], buffer, sizeof(buffer));
		s_sleep(1, 0);
	}

	_mqtt_log_printf(MOSQ_LOG_INFO, "start sysinfo and ROM_SYNC heartbeat loop...");
	
	int publish_len = 0;
	while(1) {
		if(SyncWirelesseSettings((char *)oldwireless_param, 128, 5)) {
			//user modify router's info loacally, send sync to YUNAC
			Mqtt_generate_SYSinfo((void *)reply_buffer, "sysinfo", SNYNC_MODIFY);
			Sync_generate_newTopic(newtopic, sizeof(newtopic));
			_mqtt_log_printf(MOSQ_LOG_INFO, 
							"%s: SyncYUN_task, wifi config diff=%s.\n", 
							__FILE__, newtopic);

			publish_len = strlen((const char *)reply_buffer);
			if (publish_len >= BUF_SIZE) {
				_mqtt_log_printf(MOSQ_LOG_ERR, 
							"CMD_EXE: publish message too lang!\n");
				continue;
			}

			mosquitto_publish(mosq, 
								NULL, 
								newtopic, 
								publish_len,
								reply_buffer, 
								1, 
								false);

			_mqtt_log_printf(MOSQ_LOG_INFO, 
				"%s: SyncYUN_task SNYNC_MODIFY=%s.\n", __FILE__, reply_buffer);

			memset(reply_buffer, 0, sizeof(reply_buffer));
		}

		yunac_loop_times++;
		s_sleep(3, 0);

		if (1 != auto_cmds_sended) {
			auto_server_send(mosq);
			auto_cmds_sended = 1;
		}

		_mqtt_log_printf(MOSQ_LOG_INFO, "heartbeat record: %llu\n", yunac_loop_times);
		s_sleep(57, 0);
		// clean_dead_pids(NULL);
	}

	return NULL;
}

int main(int argc, char *argv[]) {
	struct mosq_config cfg; /*memset operation is in function init_config*/
	struct mosquitto *mosq = NULL;
	int rc = 0;

	pthread_t thread_sync, thread_sys, thread_wd;

	memset(&thread_sync, 0, sizeof(thread_sync));
	memset(&thread_sys, 0, sizeof(thread_sys));
	memset(&thread_wd, 0, sizeof(thread_wd));

	rc = client_config_load(&cfg, CLIENT_SUB, argc, argv);
	if(rc){
		client_config_cleanup(&cfg);
		if(rc == 2){
			/* --help */
			print_usage();
		}else{
			fprintf(stderr, "\nUse 'mosquitto_sub --help' to see usage.\n");
		}
		return 1;
	}
	mosquitto_lib_init();

	if(client_id_generate(&cfg, "mosqsub")){
		return 1;
	}

	if (cfg.clean_session) {
		_mqtt_log_printf(MOSQ_LOG_INFO, "init mosquitto by session clean ...\n");
	}
	
	mosq = mosquitto_new(cfg.id, cfg.clean_session, &cfg);
	if(!mosq) {
		switch(errno){
			case ENOMEM:
				if(!cfg.quiet) fprintf(stderr, "Error: Out of memory.\n");
				break;
			case EINVAL:
				if(!cfg.quiet) fprintf(stderr, "Error: Invalid id and/or clean_session.\n");
				break;
		}
		mosquitto_lib_cleanup();
		return 1;
	}

	if(client_opts_set(mosq, &cfg)){
		return 1;
	}

	ancestor_pid = get_ancestor_pid(MQTT_CLINET_PROC_MAME, getpid());
	_mqtt_log_printf(MOSQ_LOG_INFO, 
					"MAIN: pid=%d ppid=%d ancestor_pid=%d waiting msq_init ...\n", 
					getpid(),
					getppid(),
					ancestor_pid);
	
	if (ancestor_pid < 0) {
		_mqtt_log_printf(MOSQ_LOG_ERR, 
					"MAIN: ancestor_pid init faild!");
		return 1;
	}
	rc = local_message_queues_init();
	if( rc ){
		_mqtt_log_printf(MOSQ_LOG_ERR, "%s: MSQ init error!\n", __FILE__);
		return 1;
	}

	s_sleep(1, 0);

	if(cfg.debug){
		mosquitto_log_callback_set(mosq, my_log_callback);
	}

	mosquitto_subscribe_callback_set(mosq, my_subscribe_callback);
	_mqtt_log_printf(MOSQ_LOG_INFO, "%s: SYNC-callback inited.\n", __FILE__);

	mosquitto_connect_callback_set(mosq, my_connect_callback);
	mosquitto_message_callback_set(mosq, my_message_callback);
	_mqtt_log_printf(MOSQ_LOG_INFO, "%s: MQTT-client inited.\n", __FILE__);

	rc = client_connect(mosq, &cfg);
	if(rc) {
		destory_message_queues();
		return rc;
	}

	_mqtt_log_printf(MOSQ_LOG_INFO, 
					"%s: start client_connect ... %s, %d.\n", 
					__FILE__, 
					__FUNCTION__,
					__LINE__);

	//victor add this thread to sync router info
	_mqtt_log_printf(MOSQ_LOG_INFO, "Creating sync/sys/wd task thread.\n");
	rc = pthread_create(&thread_sync, NULL, SyncYUN_task, (void *)mosq);
	if(rc) {
		_mqtt_log_printf(MOSQ_LOG_ERR, "%s: ERROR: return code is %d. %s, %d.\n",
			__FILE__, rc, __FUNCTION__, __LINE__);
		destory_message_queues();
		return EXIT_FAILURE;
	}

	rc = pthread_create(&thread_sys, NULL, SYS_task, NULL);
	if(rc) {
		_mqtt_log_printf(MOSQ_LOG_ERR, "%s: ERROR: return code is %d. %s, %d.\n",
			__FILE__, rc, __FUNCTION__, __LINE__);
		destory_message_queues();
		return EXIT_FAILURE;
	}
	s_sleep(1, 0);
	
	rc = pthread_create(&thread_sys, NULL, WD_task, NULL);
	if(rc) {
		_mqtt_log_printf(MOSQ_LOG_ERR, "%s: ERROR: return code is %d. %s, %d.\n",
			__FILE__, rc, __FUNCTION__, __LINE__);
		destory_message_queues();
		return EXIT_FAILURE;
	}
	s_sleep(1, 0);

	rc = mosquitto_loop_forever(mosq, -1, 1);

	mosquitto_destroy(mosq);
	mosquitto_lib_cleanup();
	destory_message_queues();

	if(cfg.msg_count>0 && rc == MOSQ_ERR_NO_CONN){
		rc = 0;
	}
	if(rc){
		fprintf(stderr, "Error: %s\n", mosquitto_strerror(rc));
		_mqtt_log_printf(MOSQ_LOG_ERR, "%s, %d: Error: %s\n", __FILE__, __LINE__, mosquitto_strerror(rc));
	}
	return rc;
}

