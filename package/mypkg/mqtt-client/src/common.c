/*
 * Common providing some basic function 4 mqtt-client
 * Copyright (c) 2016, victortang <tangronghua@kunteng.org>
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */

/*
 * Contributors:
 * Victor Tang @20160712- 201611 implementation and documentation.
 * gukaiqiang@kunteng.org @201611-today
 */
#include "common.h"
#include "ktmarket.h"
#include <sys/time.h>
#include <errno.h>
#include <unistd.h> 
#include <sys/types.h> 
#include <sys/wait.h> 
#include <fcntl.h>
#include <alloca.h>
#include <err.h>
#include <libgen.h>
#include "utils.h"

// #include "popen_noshell.h"

#define EXEC_TIMEOUT 240

#define DUP2_FAILED 2
#define DOWNLOAD_TRYTIMES 1
#define MESSAGE_Q_TRY_TIMES 8
#define PID_KILL_BUF_LEN 100

int ancestor_pid = -1;
static pthread_mutex_t cmd_mutex = PTHREAD_MUTEX_INITIALIZER;

sys_info ShellCMD_Tbl[] =
{
	{"hostname", 			"uci get system.@system[0].hostname 2>/tmp/uci_err.log", 0},
	{"boardname", 			"cat /tmp/sysinfo/board_name", 0},
	{"boardtype", 			"cat /tmp/sysinfo/board_type", 0},
	{"fwversion", 			"uci get firmwareinfo.info.firmware_version 2>/tmp/uci_err.log", 0},
	{"rsyslogversion", 		"cat /usr/lib/opkg/info/rsyslog.control | grep Version | awk '{print $2}' 2>/dev/null", 0},
//	{"macscanversion", 		"cat /usr/lib/opkg/info/macscan.control | grep Version | awk '{print $2}'",			0},
//	{"wdpiversion",			"cat /usr/lib/opkg/info/kmod-wdpi_kernel.control | grep Version | awk '{print $2}'",0},
//	{"wifidogversion",		"cat /usr/lib/opkg/info/apfree_wifidog.control | grep Version | awk '{print $2}'", 	0},
//	{"mosquittoversion",	"cat /usr/lib/opkg/info/mosquitto.control | grep Version | awk '{print $2}'",	 	0},
	{"mqtt-clientversion",	"cat /usr/lib/opkg/info/mqtt-client.control | grep Version | awk '{print $2}'", 0},
	{"luciversion",			"cat /usr/lib/opkg/info/luci.control | grep Version | awk '{print $2}'", 0},
	{"mode",				"uci get network.lan.proto 2>/tmp/uci_err.log", 0},
	{"ssid", 				"uci get wireless.@wifi-iface[%c].ssid 2>/tmp/uci_err.log", 0},
	{"encryption", 			"uci get wireless.@wifi-iface[%c].encryption 2>/tmp/uci_err.log", 0},
	{"key", 				"uci get wireless.@wifi-iface[%c].key 2>/tmp/uci_err.log",	0},
	// liudf changed 20160215
	// add kt_wireless_op shell to be compatible with different device type
	{"channel_2.4", 		"/usr/sbin/kt_wireless_op.lua chan get 2", 0},
	{"channel_5", 			"/usr/sbin/kt_wireless_op.lua chan get 5", 0},
	{"rsyslogserverIP", 	"uci get rsyslog.@rsyslog[0].server_hostname 2>/tmp/uci_err.log", 0},
//	{"wifidogserverIP",		"uci show wifidog.@wifidog[0].auth_server_hostname | cut -d'=' -f 2", 1},
	{"mosquittoserverIP",	"uci get mosquitto.@bridge[0].address 2>/tmp/uci_err.log", 0},
	{"channel_path",	"uci get firmwareinfo.info.channel_path 2>/tmp/uci_err.log", 0},
	{NULL, NULL},
};

int 
ExecuateShellCMD_log(const char * shellCMD, char * r_buffer){
	return ExecuateShellCMD(shellCMD, r_buffer, SHELL_CMD_BUFFER-1);
}

// ExecuateShellCMD_desc do ExecuateShellCMD func and add desc of exec result
int 
ExecuateShellCMD_desc(char * shellCMD, char *r_buffer, int len, char *desc) {
	if (desc == NULL) {
		return 1;
	}
	int exec_res = 0;
	exec_res = ExecuateShellCMD(shellCMD, r_buffer, SHELL_CMD_BUFFER);

	if(exec_res) {
		snprintf(desc, DESC_BUFF_LEN, "CMD exected failed!");
	}

	return exec_res;
}

// get_cmd_timeout read the timeout env from mqtt_config file
// return: 0: faild, >0 get the timeout secounds
// int get_cmd_timeout() {
// 	int ret = 0;
// 	FILE *fp;
// 	char time_str[8] = {0};
// 	fp = fopen(CMD_TIMEOUT_PATH, "r");
// 	if (fp == NULL) {
// 		_mqtt_log_printf(MOSQ_LOG_ERR, "timeout read failed\n");
// 		return ret;
// 	}

// 	int i = 0;
// 	for (;i<strlen(time_str); i++) {
// 		if (time_str[i] < '0' || time_str[i] > '9') {
// 			_mqtt_log_printf(MOSQ_LOG_ERR, "timeout number format illegal:%s\n", time_str);
// 			fclose(fp);
// 			return ret;
// 		}
// 	}

// 	fread(time_str, sizeof(time_str), 1, fp);
// 	time_str[7] = 0;
// 	Trim(time_str);
// 	fclose(fp);

// 	int time_int = 0;
// 	time_int = atoi(time_str);
// 	return time_int;
// }

// ExecuateShellCMD argument len is the length of r_buffer
// return :
// 		1: error 0: succeed
int 
ExecuateShellCMD(const char *shellCMD, char *r_buffer, int len) {
	if (shellCMD == NULL || r_buffer == NULL) {
		return 1;
	}
	pthread_mutex_lock(&cmd_mutex);
	char tmp[1024]={0};
	FILE *fstream = popen(shellCMD, "r");
	if (NULL == fstream) {
		perror("ExecuateShellCMD popen");
		_mqtt_log_printf(MOSQ_LOG_INFO, "CMD:EXEC:[%s] popen init faild\n", shellCMD);
		pthread_mutex_unlock(&cmd_mutex);
		return 1;
	}

	fd_set readfd;
	time_t startTime = time(NULL);
	struct timeval tv;
	int sele_ret = 0;
	unsigned int script_tmout = EXEC_TIMEOUT;

	int fcntl_ret  = fcntl(fileno(fstream), F_SETFD, FD_CLOEXEC);
	if (fcntl_ret == -1) {
		_mqtt_log_printf(MOSQ_LOG_ERR, "com: fcntl to FD_CLOEXEC faild");
		printf("com: fcntl to FD_CLOEXEC failed\n");
		pclose(fstream);
		pthread_mutex_unlock(&cmd_mutex);
		return 1;
	}

	int ret = 0;
	int surplus_len = len;
	int tmp_buf_len = 0, i = 0;

	while(1) {
		FD_ZERO(&readfd);
		FD_SET(fileno(fstream), &readfd);

		/** Select Timeout **/
		tv.tv_sec = EXEC_TIMEOUT;
		tv.tv_usec = 0;
		sele_ret = select(fileno(fstream)+1, &readfd, NULL, NULL, &tv);
		if (sele_ret < 0) {
			_mqtt_log_printf(MOSQ_LOG_ERR, "com: [%s] select failed!\n", shellCMD);
			ret = 1;
			break;
		} else if (sele_ret == 0) {
			_mqtt_log_printf(MOSQ_LOG_ERR, "com: [%s] select Time out!\n", shellCMD);
			ret = 1;
			break;
		} else { // read command exec result to r_buffer
			if(FD_ISSET(fileno(fstream), &readfd)) {
				if(fgets(tmp, sizeof(tmp), fstream) != NULL ) {
					if (surplus_len > 1) {
						snprintf(r_buffer + i, surplus_len - 1, "%s", tmp);
						tmp_buf_len = strlen(tmp);
						i += tmp_buf_len;
						surplus_len = surplus_len - tmp_buf_len;
					}else{
						ret = 1;
						break;
					}
				}else{
					break;
				}
			} else {
				ret = 1;
				break;
			}
		}

		if ((startTime + script_tmout) < time(NULL)) {
			_mqtt_log_printf(MOSQ_LOG_ERR, "com: script Time out!: %s.\n", shellCMD);
			ret = 1;
			break;
		}
	}

	if ( 0 == ret ) {
		pclose(fstream);
	} else {
		fclose(fstream);

		int proc_ancestor_pid = 0;
		char cmd_exec_head[64] = {0};
		char others[4] = {0};
		sscanf(shellCMD, "%64s %1s", cmd_exec_head, others);

#ifdef STARTED_BY_SERVICE
		proc_ancestor_pid = ancestor_pid;
#else
		proc_ancestor_pid = getpid(); 
#endif
		int cleaned_count = clean_dead_pids(cmd_exec_head, proc_ancestor_pid);
		_mqtt_log_printf(MOSQ_LOG_ERR, 
						"com: script cleaned_count=%d, proc_ancestor_pid=%d\n",
						cleaned_count, 
						proc_ancestor_pid);
	}

	_mqtt_log_printf(MOSQ_LOG_INFO, "CMD:[%s] result = %d\n", shellCMD, ret);
	pthread_mutex_unlock(&cmd_mutex);
	return ret;
}

// return: the pid count cleaned
int 
clean_dead_pids(char *cmd_head, int proc_ancestor_pid) {
	int pids_buf[PID_KILL_BUF_LEN] = {0};
	int parent_pid = proc_ancestor_pid;
	int Allpidnum = 0;
	if (cmd_head != NULL) {
		Allpidnum = get_child_pids(parent_pid, 
								cmd_head, 
								pids_buf, 
								sizeof(pids_buf), 
								0);

		if (Allpidnum < 0) {
			Allpidnum = 0;
		}
	}

	int Zpidnum = get_child_pids(parent_pid, 
								NULL, 
								pids_buf + Allpidnum, 
								sizeof(pids_buf) - Allpidnum, 
								'Z');

	// int Spidnum = get_child_pids()
	if (Zpidnum < 0) {
		Zpidnum = 0;
	}

	_mqtt_log_printf(MOSQ_LOG_INFO, 
		"pid_clean: Zpidnum = %d\t Allpidnum=%d\n", Zpidnum, Allpidnum);

	int i=0;
	for(; i<Allpidnum + Zpidnum; i++) {
		kill(pids_buf[i], SIGKILL);
		waitpid(pids_buf[i], NULL, WNOHANG);
	}

	return Zpidnum+Allpidnum;
}

/*
 * Input:		buf-		network interface
 * 			src-		target buffer to store mac
 * return:		0-		success.
				1-		error
*/
int 
GetRouterMAC(char *buf, char *mac, int mac_len) {
	int ret = 1;
	int i = 0;
	int sock = 0;

	if (mac_len < 12 || buf == NULL) {
		return 1;
	}
	struct ifreq ifreq;

	sock = socket(AF_INET, SOCK_STREAM, 0);
	if( sock < 0 ) {
		perror("error sock");
		goto OUT;
	}

	strncpy(ifreq.ifr_name, buf, IFNAMSIZ);
	if( ioctl(sock, SIOCGIFHWADDR,&ifreq) < 0 ) {
		perror("error ioctl");
		goto OUT;
	}

	for( i = 0; i < 6; i++ ){
		snprintf(mac+2*i, mac_len - 2*i, "%02X", 
			(unsigned char)ifreq.ifr_hwaddr.sa_data[i]);
	}
	mac[strlen(mac)] = 0;
	ret =  0;

OUT:
	close(sock);
	return ret;
}

/*
 * Mqtt_parse_INtopic_OUTsubtopic()
 * victortang@20160114 Obtain 'subtopic CMD'
 * enum subtopic CMD 'CMD_GET, CMD_EXE, CMD_SET'
 * Input:	INtopic-	input topic
 * 		opertation-	output CMD
 * return:	0-		meet CMD requirements
		1-		error
*/
int 
Mqtt_parse_INtopic_OUTsubtopic(char *subtopic, int olen, char *INtopic) {
	int ret = 1; /*if ret = 1, subtopic value is useless*/

	if( INtopic == NULL || subtopic == NULL ){
		return ret;
	}

	int index = strlen(INtopic) -1;
	int step_count = 0;
	char * prt = INtopic;

	if( prt[index] != '/'){
		/*return means that topic is in wrong format*/
		return ret;
	}

	do{
		index--;
		step_count++;
	}while( prt[index] != '/' );

	if (step_count > olen)
		return ret;

	memcpy(subtopic, &prt[index+1], step_count-1);
	subtopic[step_count-1] = '\0';
	_mqtt_log_printf(MOSQ_LOG_INFO, "com: subtopic = %s.\n", subtopic);

	if( STRCMP(subtopic, ==, "CMD_GET" ) || STRCMP(subtopic, ==, "CMD_EXE")
		|| STRCMP(subtopic, ==, "CMD_SET") || STRCMP(subtopic, ==, "CMD_SYNC") ||
		STRCMP(subtopic, ==, "REBOOT") ) {

		ret = 0;
	}

	return ret;
}

/*
 * Mqtt_generate_newTopic()
 * victortang@20160115 generate publish newtopic
 * Input:	newtopic-	new topic
 * 		oldtopic-		old topic
 * return:	0-		meet CMD requirements
		1-		error
*/
int 
Mqtt_generate_newTopic(char *newtopic, int new_topic_len, char *oldtopic) {
	if( oldtopic == NULL ) {
		_mqtt_log_printf(MOSQ_LOG_ERR, "com: old topic NULL\n");
		return 1;
	}

	if (new_topic_len < strlen(oldtopic) + 1) {
		_mqtt_log_printf(MOSQ_LOG_ERR, "com: new topic buffer is not enougth\n");
		return 1;
	}
	
	int index = strlen(oldtopic) -1;
	int step_count = 0, step2 = 0;
    char * prt = oldtopic, *p = NULL;
	char str2[20] = {0}, str3[20] = {0};

	memset(str2, 0, sizeof(str2));
	memset(str3, 0, sizeof(str3));


	if( prt[index] != '/'){
		/*return means that topic is in wrong format*/
		_mqtt_log_printf(MOSQ_LOG_INFO, "com: topic format wrong:%s\n", prt);
		return 1;
	}

	while( prt[step_count] != '/' )
		step_count++;
	p = &prt[step_count+1];
	while( prt[step_count+1] != '/' ){
		step2++;
		step_count++;
	}

	memcpy(newtopic, p, step2);
	newtopic[step_count] = '\0';

	if( GetRouterMAC("br-lan", str2, sizeof(str2)) ){
		_mqtt_log_printf(MOSQ_LOG_INFO, "com: getrouter_brlan failed! str2=%s.\n", str2);
		return 1;
	}

	step_count = 0;
	do{
		index--;
		step_count++;
	}while( prt[index] != '/' );
	memcpy(str3, &prt[index+1], step_count);

	strcat(newtopic, "/");
	strcat(newtopic, str2);
	strcat(newtopic, "/");
	strcat(newtopic, str3);

	return 0;
}

void destory_message_queues(void) {
	int destory_result = 0;
	int try_times = 0;
	if(sys_msqid >= 0){
		do {
			try_times++;
			destory_result = msgctl(sys_msqid, IPC_RMID,0);
			_mqtt_log_printf(MOSQ_LOG_INFO, "MSQ: clear MSQ_ID %d, try times %d... \n",
				sys_msqid, try_times);

			s_sleep(0, 200000); //0.2s
		} while (destory_result < 0 && try_times < MESSAGE_Q_TRY_TIMES);
	}

	try_times = 0;
	if(wd_msqid >= 0){
		do {
			try_times++;
			destory_result = msgctl(wd_msqid, IPC_RMID,0);
			_mqtt_log_printf(MOSQ_LOG_INFO, "MSQ: clear MSQ_ID %d, try times %d... \n", 
				wd_msqid, try_times);

			s_sleep(0, 200000); //0.2s
		} while (destory_result < 0 && try_times < MESSAGE_Q_TRY_TIMES);
	}
	return;
}

/*
 * return:	0-		success
 *			1-		fail to init msq of sys_msq and wd_msq
*/
int 
local_message_queues_init(void) {
	sys_msqid = msgget(SYS_MSGKEY, IPC_EXCL);
	_mqtt_log_printf(MOSQ_LOG_INFO, "com: init sys_msqid: %d.\n", sys_msqid);

	int clean_times = 0;
	while( sys_msqid >= 0 && clean_times < MESSAGE_Q_TRY_TIMES){ //only try 8 times
		clean_times++;
		msgctl(sys_msqid, IPC_RMID, 0);
		sys_msqid = msgget(SYS_MSGKEY, IPC_EXCL);
		if (sys_msqid >= 0) {
			_mqtt_log_printf(MOSQ_LOG_INFO, 
				"com: MID [%d] [%d]s clear field, clean again... %d\n", SYS_MSGKEY, 
				clean_times, sys_msqid);
			
			s_sleep(0, 200000); //0.2s
		}
	}
	
	sys_msqid = msgget(SYS_MSGKEY, IPC_CREAT|0666);
	if( sys_msqid <0 ){
		_mqtt_log_printf(MOSQ_LOG_ERR, 
			"com: failed to create sys_msqid | ERR-%d: [%s]\n", errno, strerror(errno));
		return 1;
	}

	wd_msqid = msgget(WD_MSGKEY, IPC_EXCL);
	_mqtt_log_printf(MOSQ_LOG_INFO, "com: wd_msqid init=%d.\n", wd_msqid);

	clean_times = 0;
	while( wd_msqid >= 0 && clean_times < MESSAGE_Q_TRY_TIMES){
		clean_times++;
		msgctl(wd_msqid, IPC_RMID, 0);
		wd_msqid = msgget(WD_MSGKEY, IPC_EXCL);
		if (wd_msqid >= 0) {
			_mqtt_log_printf(MOSQ_LOG_INFO, 
				"com: MID [%d] [%d]s clear field, clean again... %d\n", WD_MSGKEY, clean_times, wd_msqid);

			s_sleep(0, 200000); //0.2s
		}
	}
	
	wd_msqid = msgget(WD_MSGKEY, IPC_CREAT|0666);
	if( wd_msqid <0 ){
		_mqtt_log_printf(MOSQ_LOG_ERR, 
			"com: failed to create wd_msqid | ERR-%d: [%s]\n", errno, strerror(errno));
		return 1;
	}

	_mqtt_log_printf(MOSQ_LOG_INFO, 
		"com: Init SYS and WD MSQ success, sysqid = 0x%x, wdqid = 0x%x.\n", 
		sys_msqid, wd_msqid);

	return 0;
}

/*
 * return:		0-		success
				1-		fail to init msq of sys_msq and wd_msq
				msg_ret errno in errno_base.h 
*/
int 
send_msq(void *mosq, char *topic, char *payload, char *subtopic) {
	if (topic == NULL || payload == NULL || subtopic == NULL) {
		return 1;
	}

	mqtt_c_msq msq;

	memset(&msq, 0, sizeof(mqtt_c_msq));
	char *s_topic = (char *)os_malloc(strlen(topic)+1);
	if( s_topic == NULL ){
		return 1;
	}
	strncpy(s_topic, topic, strlen(topic)+1);
	
	char *s_payload = (char *)os_malloc(strlen(payload)+1);
	if( s_payload == NULL ){
		return 1;
	}
	strncpy(s_payload, payload, strlen(payload)+1);

	int msq_target_id = wd_msqid;
	if( STRCMP(subtopic, ==, "CMD_SET") ) {
		msq.msgtype = CMD_SET;
	}else if( STRCMP(subtopic, ==, "CMD_SYNC") ){
		msq.msgtype = CMD_SYNC;
	}else if( STRCMP(subtopic, ==, "CMD_EXE") ){
		msq.msgtype = CMD_EXE;
		msq_target_id = sys_msqid;
	}else{
		_mqtt_log_printf(MOSQ_LOG_ERR, 
			"com: subtopic:%s un recognise, it should not occurred\n", subtopic);
		return 1;
	}

	msq.content[0] = mosq;
	msq.content[1] = s_topic;
	msq.content[2] = s_payload;

	int msg_ret = msgsnd(msq_target_id, &msq, sizeof(mqtt_c_msq), IPC_NOWAIT);
	if (msg_ret) {
		msg_ret = errno;
		free(s_topic);
		free(s_payload);
	}
	return msg_ret;
}

// read_all_file: read file with SEEK_LOCK
// return: 0:success; 1:error
int 
read_all_file(char * fname, char *content) {
	if (fname == NULL) {
		return 1;
	}
	FILE *fp;
	int ret = 1;
	fp = fopen(fname, "r");
	if( fp == NULL ) {
		return 1;
	}

	fseek(fp, 0, SEEK_END);
	int fsize = ftell(fp);
	//_mqtt_log_printf(MOSQ_LOG_INFO, "com: read_file, fsize=%d.\n", fsize);
	if( fsize == 0 ){
		ret = 0;
		goto OUT;
	}
	fseek(fp, 0, SEEK_SET);
	fread(content, fsize, 1, fp);
	//_mqtt_log_printf(MOSQ_LOG_INFO, "com: read_file, content=%s.\n", content);

	ret = 0;
OUT:
	fclose(fp);
	return ret;
}

int 
is_file_notexist(const char *file_path) {
	if( file_path == NULL )
		return 1;
	if( access(file_path, F_OK) ==  0 )
		return 0;
	return 1;
}

int 
CollectionOfAPPName(char *table, int *num) {
    DIR *dir = NULL;
    struct dirent *ptr = NULL;
	int counter = 0;
	char market_path[] = KTMARKET_PATH;

    if( (dir=opendir(market_path)) == NULL ) {
        perror("Open dir error...");
        return 1;
    }

    while( (ptr=readdir(dir)) != NULL && counter < 64 )
    {
        if( STRCMP(ptr->d_name, ==, ".") || STRCMP(ptr->d_name, ==, "..") )//current dir OR parrent dir
            continue;
        else if( ptr->d_type == 4 ){ //dir
            strncpy(table, ptr->d_name, 63); //STRNCPY
			table += 64;
			counter++;
        }
    }

	closedir(dir);
	*num = counter;
    return 0;
}

// return: 0: succeed, 1: failed
int 
CollectionOfAPPVersion(char *name, char *content, int content_len) {
	if (name == NULL) {
		return 1;
	}

	char control_file[256] = {0}, content_out[64] = {0}, content_cut[64] = {0};

	snprintf(control_file, sizeof(control_file), 
		"cat /usr/lib/opkg/info/%s.control | grep Version | awk '{print $2}' 2>/dev/null", 
		name);

	if( ExecuateShellCMD(control_file, content_out, sizeof(content_out)) ){
		strncpy(content, "unkown", content_len);
	}else{
		substring(content_cut, sizeof(content_cut), content_out, 0, strlen(content_out)-1);
		strncpy(content, content_cut, content_len-1);
	}

	return 0;
}

// get_wireless_iface_id_with_band support 2.4G and 5G
// org: band_type, `2` is 2.4G and '5' is 5G
// return: 1 cannot get iface id; 0: get succeed
int 
get_wireless_iface_id_with_band(const char band_type, char *iface_id_buff) {
	if ( '2' != band_type && '5' != band_type ) {
		_mqtt_log_printf(MOSQ_LOG_ERR, 
			"com: band type error, it should not happend! type=%c.\n", band_type);

		return 1;
	}

	char command[64] = {0};
	char result_buf[16] = {0};
	snprintf(command, sizeof(command), 
		"/usr/sbin/kt_wireless_op.lua iface %c", band_type);

	if( ExecuateShellCMD(command, result_buf, sizeof(result_buf)) ){
		return 1;
	} else {
		if (strlen(result_buf) >= 1){
			if (result_buf[0] >= '0' && result_buf[0] <= '9'){
				*iface_id_buff = result_buf[0];
				_mqtt_log_printf(MOSQ_LOG_INFO, 
					"wireless: band type[%c]'s devNUM:%c.\n", band_type, *iface_id_buff);
				return 0;
			} else {
				_mqtt_log_printf(MOSQ_LOG_ERR, 
					"wireless: band type[%c]'s devNUM is not digit.\n", band_type);
				return 1;
			}
		}else{
			_mqtt_log_printf(MOSQ_LOG_WARNING, 
				"com: sysinfo: cmd %s executed but no return.\n", command);
			return 1;
		}
	}

	return 0;
}

void 
Mqtt_generate_SYSinfo(void *reply_buf, char *sysinfo, char *id) {
	int i = 0;
	char ROM_MAC[32] = {0};
	char buffer[128] = {0};			/*ues to store shell CMD result*/ 
	char buf[128] = {0};			/*use to cut prefix " and suffix "*/
	char timestamp_buf[32] = {0};

	/*Creating a json array for apps*/
	json_object *OUT_object = json_object_new_object();

	/* add timestamp field */
	long int sec = 0, usec = 0;
	get_timestamp_millisecond(&sec, &usec);
	snprintf(timestamp_buf, sizeof(timestamp_buf), "%ld.%ld", sec, usec);
	json_object_object_add(OUT_object, "date", json_object_new_string(Trim(timestamp_buf)));

	json_object_object_add(OUT_object, "item", json_object_new_string(sysinfo));
	json_object_object_add(OUT_object, "id", json_object_new_string(id));

	if( GetRouterMAC("br-lan", ROM_MAC, sizeof(ROM_MAC)) == 0 ){
		json_object_object_add(OUT_object, "mac", json_object_new_string(ROM_MAC));
	}

	char iface_id = '0';
	const char iface_by_band = '2';

	int get_iface_rest = get_wireless_iface_id_with_band(iface_by_band, &iface_id);
	if ( 1 == get_iface_rest) {
		_mqtt_log_printf(MOSQ_LOG_WARNING, 
			"com: sysinfo: router maybe no band %sG, instead of iface[%c].\n",
			iface_by_band=='2'?"2.4":"5", iface_id);
	}

	char *shell_cmd = NULL;
	int exe_rest = 0;
	char shell_cmd_buffer[64] = {0};
	for( i=0;ShellCMD_Tbl[i].cmd_name != NULL;i++ ) {
		exe_rest = 0;
		memset(shell_cmd_buffer, 0, sizeof(shell_cmd_buffer));

		if(STRCMP(ShellCMD_Tbl[i].cmd_name, ==, "ssid") || 
			STRCMP(ShellCMD_Tbl[i].cmd_name, ==, "encryption") ||
			STRCMP(ShellCMD_Tbl[i].cmd_name, ==, "key")) {
				
			/* now the ShellCMD_Tbl[i].cmd_shell is the fmt with %c */
			snprintf(shell_cmd_buffer, 
				sizeof(shell_cmd_buffer), 
				ShellCMD_Tbl[i].cmd_shell, 
				iface_id);

			exe_rest = ExecuateShellCMD(shell_cmd_buffer, buffer, sizeof(buffer));
		}else{
			exe_rest = ExecuateShellCMD(ShellCMD_Tbl[i].cmd_shell, buffer, sizeof(buffer));
		}
			
		if( exe_rest ) {
			_mqtt_log_printf(MOSQ_LOG_ERR, 
				"com: syncYUNinfo: SYSINFO error, i=%d.\n", i);
			json_object_object_add(OUT_object, ShellCMD_Tbl[i].cmd_name, 
				json_object_new_string("unkown"));

			continue;
		}

		if ( 0 == ShellCMD_Tbl[i].uciflag ) {
			substring(buf, sizeof(buf), buffer, 0, strlen(buffer)-1);	/* cut suffix \n */
		} else if( 1 == ShellCMD_Tbl[i].uciflag ){	/* uci prefix ' and suffix '\n */
			substring(buf, sizeof(buf), buffer, 1, strlen(buffer)-2);
		} 

		json_object_object_add(OUT_object, ShellCMD_Tbl[i].cmd_name, 
			json_object_new_string(buf));

		memset(buf, 0, sizeof(buf));
		memset(buffer, 0, sizeof(buffer));
	}

	if( is_file_notexist(KTMARKET_PATH) ){
		goto OUT;
	}

	char app_table[64][64] = {0};	//default max apps is 64.
	int Anum = 0;
	if( CollectionOfAPPName((char *)app_table, &Anum) ) {
		goto OUT;
	}
	if( Anum == 0 ){
		goto OUT;
	}

	char app_version[64] = {0};
	int appversin_len = sizeof(app_version);
	json_object *app_object[APPS_COUTN_MAX];	//max app num
	json_object *jarray = json_object_new_array();

	for( i=0; i < Anum && i < APPS_COUTN_MAX; i++ ) {
		app_object[i] = json_object_new_object();
		if (CollectionOfAPPVersion(app_table[i], app_version, appversin_len)) {
			continue;
		}

		json_object_object_add(app_object[i], app_table[i], 
								json_object_new_string(app_version));

		json_object_array_add(jarray, app_object[i]);
		memset(app_version, 0, appversin_len);
	}

	json_object_object_add(OUT_object, "apps", jarray);

OUT:
	strncpy((char *)reply_buf, json_object_to_json_string(OUT_object), BUF_SIZE-1);

	//json_object_put(jarray); //don't free again!
	if (!is_error(OUT_object)) {
		json_object_put(OUT_object);
	}
	return;
}

/*
 * return:		0-		success.
			1-		error
*/
void 
Mqtt_SYSINFO_error(void *reply_buf, char *payload) {
	json_object *IN_object = NULL;
	json_object *OUT_object = json_object_new_object();
	json_object *item_object = NULL, *id_object = NULL;
	char buf[70] = {0}/*use 4 cut prefix " and suffix "*/;
	int ret = 1;

	memset(buf, 0, sizeof(buf));

	IN_object = json_tokener_parse(payload);/*translate string to object*/
	if( !IN_object || json_object_get_type(IN_object) != json_type_object ) {
		_mqtt_log_printf(MOSQ_LOG_ERR, "Failed to parse error message data.\n");
		goto ERROR;
	}

	_mqtt_log_printf(MOSQ_LOG_ERR, 
		"Mqtt_SYSINFO_error: payload=%s.\n", json_object_get_string(IN_object));

	if( !json_object_object_get_ex(IN_object, "item", &item_object) ){
		/*whether or not the key exists*/
		_mqtt_log_printf(MOSQ_LOG_ERR, "com: sysinfo_error itme is missing.\n");
		goto ERROR;
	}

	const char *item_json = json_object_get_string(item_object);
	if(item_json == NULL) {
		goto ERROR;
	}
	//generate OUT object
	json_object_object_add(OUT_object, "item", json_object_new_string(item_json));

	if( !json_object_object_get_ex(IN_object, "id", &id_object) ){
		/*whether or not the key exists*/
		_mqtt_log_printf(MOSQ_LOG_ERR, "com: sysinfo_error id is missing.\n");
		goto ERROR;
	}

	const char *id_json = json_object_get_string(id_object);
	if(id_json == NULL) {
		goto ERROR;
	}
	json_object_object_add(OUT_object, "id", json_object_new_string(id_json));

ERROR:
	json_object_object_add(OUT_object, "state", json_object_new_string("-1"));

	strncpy((char *)reply_buf, json_object_to_json_string(OUT_object), BUF_SIZE-1);

	if (!is_error(OUT_object)){
		json_object_put(OUT_object);
	}
	if (!is_error(IN_object)){
		json_object_put(IN_object);
	}

	return;
}

// get_board_info get the board_name or board_type of router
// if get failed, router_board_info[0] == 0
char 
*get_board_info(const char *board_info) {
	static char router_board_info[64] = {0};
	char cmd_res_buf[64] = {0};
	int exe_rest = 0;
	// char router_board_type[64] = {0};
	char board_info_get_cmd[64] = {0};

	memset(router_board_info, 0, sizeof(router_board_info));
	if ((STRCMP(board_info, !=, "board_name")) && 
		(STRCMP(board_info, !=, "board_type"))) {
		goto OUT;
	}

	snprintf(board_info_get_cmd, sizeof(board_info_get_cmd), 
		"cat /tmp/sysinfo/%s", board_info);
	exe_rest = ExecuateShellCMD(board_info_get_cmd, cmd_res_buf, sizeof(cmd_res_buf));
	if (exe_rest) {
		goto OUT;
	}

	/* cut suffix \n */
	substring(router_board_info, 
		sizeof(router_board_info), 
		cmd_res_buf, 
		0, 
		strlen(cmd_res_buf)-1);

OUT:
	return router_board_info;
}


/*
 * return:		0-		channel is valid.
			1-		channel is invalid.
*/
int 
IsInvalidchannel24(const char *channel) {
	if (channel == NULL) {
		return 1;
	}

	if( STRCMP(channel, ==, "") ){
		return 0;
	}

	int i = 0;
	for( i=0; i<strlen(channel); i++ ){
		if( !isdigit(channel[i]) ){
			return 1;
		}
	}

	int intchannel = atoi(channel);
	if( intchannel<0 || intchannel>13 ){
		return 1;
	}

	return 0;
}

/*
 * return:	0-wireless parameter is valid.
 *			1-parameter is invalid.
*/
int 
wireless_ssid_check(const char *ssid) {
	if (ssid == NULL) {
		return 1;
	}
	
	if( strlen(ssid) > LEN_SSID ){
		_mqtt_log_printf(MOSQ_LOG_ERR, "wireless check: invalid ssid:%s.\n", ssid);
		return 1;
	}

	return 0;
}

// return : 1 failed, 0: OK
int 
wireless_encryption_check(const char *encryption, const char *key) {
	if (encryption == NULL || key == NULL) {
		return 1;
	}

	int ret = 1;
	int do_encrypt = 0;
	int key_len = 0;
	char exchangebuf[64]={0};

	if (strlen(encryption) > sizeof(exchangebuf)) {
		return ret;
	}

	snprintf(exchangebuf, sizeof(exchangebuf), "%s", encryption);

	key_len = strlen(key);
	if( STRCMP(exchangebuf, ==, "none") || 
			STRCMP(exchangebuf, ==, "psk-mixed+tkip+ccmp") || 
			STRCMP(exchangebuf, ==, "") || 
			STRCMP(exchangebuf, ==, "1") || 
			STRCMP(exchangebuf, ==, "0")) {

		if (STRCMP(exchangebuf, ==, "psk-mixed+tkip+ccmp") || 
			STRCMP(exchangebuf, ==, "1")) {
			do_encrypt = 1;
			if (key_len == 0) {
				_mqtt_log_printf(MOSQ_LOG_ERR, 
					"wireless check: invalid key (void) with wifi encrypt.\n",
					key);
				return ret;
			}
		}
	}else{
		_mqtt_log_printf(MOSQ_LOG_ERR, 
			"wireless check: invalid encryption method:%s.\n", exchangebuf);
		return ret;
	}

	if (do_encrypt) {
		if (key_len >= 8 && key_len < WIRELESS_KEY_LEN) {
			memset(exchangebuf, 0, sizeof(exchangebuf));
			snprintf(exchangebuf, sizeof(exchangebuf), "%s", key);
			if( IsALNUMornot((const char *)exchangebuf) ){
				return ret;
			}
		}else{
			_mqtt_log_printf(MOSQ_LOG_ERR, 
				"wireless check: invalid wireless-key:%s\n", exchangebuf);
			return ret;
		}
	}
	

	ret = 0;
	return ret;
}

// return: 1: failed, 0:OK
int 
wireless_channel_check(const char *band_type, const char *channel) {
	if (band_type == NULL || channel == NULL) {
		return 1;
	}

	int ret = 1;
	char exchangebuf[64]={0};
	char band_type_buf[WIRELESS_BAND_TYPE_LEN] = {0};

	if (strlen(band_type) > 10 || strlen(channel) > 10) {
		_mqtt_log_printf(MOSQ_LOG_ERR, 
			"wireless check: invalid wireless arguments!\n");

		return ret;
	}

	snprintf(band_type_buf, WIRELESS_BAND_TYPE_LEN, "%s", band_type);

	if (STRCMP(band_type_buf, ==, "2.4G") || STRCMP(band_type_buf, ==, "5G")) {
		snprintf(exchangebuf, sizeof(exchangebuf), "%s", channel);
		if (STRCMP(band_type_buf, ==, "2.4G")) {
			if( IsInvalidchannel24(exchangebuf) ){
				_mqtt_log_printf(MOSQ_LOG_ERR, 
					"wireless check: invalid 2.4G channel:%s\n", exchangebuf);
				return ret;
			}
		} else {
			if( STRCMP(exchangebuf, ==, "0") || STRCMP(exchangebuf, ==, "149") ||
				STRCMP(exchangebuf, ==, "153") || STRCMP(exchangebuf, ==, "157") ||
				STRCMP(exchangebuf, ==, "161") || STRCMP(exchangebuf, ==, "165") || 
				STRCMP(exchangebuf, ==, "")){
				;
			} else {
				_mqtt_log_printf(MOSQ_LOG_ERR, 
					"sys_task: invalid 5G channel:%s\n", exchangebuf);
				return ret;
			}
		}
	} else {
		_mqtt_log_printf(MOSQ_LOG_ERR, 
			"wireless check: invalid band_type:%s\n", band_type);

		return ret;
	}

	ret = 0;
	return ret;
}

/*
 * return:		0-success; 1-error
*/
int 
wireless_opts(const char *band_type, 
				const char *ssid, 
				const char *encryption, 
				const char *key, 
				const char *channel,
				const char *disabled){
	int ret = 0;
	char buf[32] = {0}, cmd_buf[128] = {0};

	//check howmany ssid in this router
	ret = ExecuateShellCMD("uci show wireless | grep channel | wc -l 2>/tmp/uci_err.log",
		buf, sizeof(buf));

	if (ret) {
		_mqtt_log_printf(MOSQ_LOG_ERR, "wireless opts: wireless device get failed!\n");
		return ret;
	}

	int band_target = 0;
	if ( STRCMP(band_type, ==, "2.4G") ) {
		band_target = 2;
	}else{ //band_type=="5G"
		band_target = 5;
	}

	snprintf(cmd_buf, sizeof(cmd_buf), 
		"/usr/sbin/kt_wireless_op.lua iface %d", band_target);

	ret = ExecuateShellCMD(cmd_buf, buf, sizeof(buf));
	if (STRCMP(buf, ==, "")) {
		_mqtt_log_printf(MOSQ_LOG_ERR, 
			"wireless opts:band_type [%s] cannot be found in wireless config\n",
			band_type);
		return ret;
	}

	int opt_band_target = buf[0] - '0';
	_mqtt_log_printf(MOSQ_LOG_INFO, 
		"wireless opts:opt band_type target [%d]\n", opt_band_target);
	
	memset(buf, 0, sizeof(buf));
	memset(cmd_buf, 0, sizeof(cmd_buf));

	if( STRCMP(ssid, !=, "") ){
		snprintf(cmd_buf, sizeof(cmd_buf), 
			"uci set wireless.@wifi-iface[%d].ssid='%s' 2>/tmp/uci_err.log", 
			opt_band_target, ssid);

		ret = ExecuateShellCMD(cmd_buf, buf, sizeof(buf));
		if(ret) {
			_mqtt_log_printf(MOSQ_LOG_ERR, 
				"wireless opts: wifi-iface %d ssid set failed!\n", opt_band_target);
			return ret;
		}
	}

	memset(buf, 0, sizeof(buf));
	memset(cmd_buf, 0, sizeof(cmd_buf));

	snprintf(cmd_buf, 100, 
		"uci set wireless.@wifi-iface[%d].encryption='%s' 2>/tmp/uci_err.log", 
		opt_band_target, encryption);
	ret = ExecuateShellCMD(cmd_buf, buf, sizeof(buf));
	if(ret) {
		_mqtt_log_printf(MOSQ_LOG_ERR, 
			"wireless opts: wifi-iface %d encryption set failed!\n", opt_band_target);
		return ret;
	}
	memset(buf, 0, sizeof(buf));
	memset(cmd_buf, 0, sizeof(cmd_buf));
	snprintf(cmd_buf, 100, "uci set wireless.@wifi-iface[%d].key='%s'",
		opt_band_target, key);
	ret = ExecuateShellCMD(cmd_buf, buf, sizeof(buf));
	if(ret) {
		_mqtt_log_printf(MOSQ_LOG_ERR, 
			"wireless opts: wifi-iface %d key set failed!\n", opt_band_target);
		return ret;
	}

	memset(buf, 0, sizeof(buf));
	memset(cmd_buf, 0, sizeof(cmd_buf));
	if( channel != NULL && STRCMP(channel, !=, "" ) ){
		snprintf(cmd_buf, sizeof(cmd_buf),  
			"/usr/sbin/kt_wireless_op.lua chan set %d '%s'", band_target, channel);
		ret = ExecuateShellCMD(cmd_buf, buf, sizeof(buf));
		if(ret) {
			_mqtt_log_printf(MOSQ_LOG_ERR, 
				"wireless opts: wifi-iface %d channel set failed!\n", 
				opt_band_target);
			return ret;
		}
	}

	memset(buf, 0, sizeof(buf));
	memset(cmd_buf, 0, sizeof(cmd_buf));
	if(disabled != NULL && STRCMP(disabled, !=, "" ) ){
		snprintf(cmd_buf, 100, "uci set wireless.@wifi-iface[%d].disabled='%s'",
			opt_band_target, disabled);
		ret = ExecuateShellCMD(cmd_buf, buf, sizeof(buf));
		if(ret) {
			_mqtt_log_printf(MOSQ_LOG_ERR, 
				"wireless opts: wifi-iface %d wifi disabled set failed!\n", 
				opt_band_target);
			return ret;
		}
		
		memset(buf, 0, sizeof(buf));
	}

	if( ExecuateShellCMD("uci commit wireless 2>/tmp/uci_err.log", buf, sizeof(buf)) ){
		_mqtt_log_printf(MOSQ_LOG_ERR, 
			"wireless opts: wireless config commit failed!\n");
		return ret;
	}

	s_sleep(0, 5000);
	memset(buf, 0, sizeof(buf));
	if( ExecuateShellCMD("sync", buf, sizeof(buf)) ){
		_mqtt_log_printf(MOSQ_LOG_ERR, 
			"wireless opts: wireless config sync failed!\n");
		return ret;
	}

	if (ExecuateShellCMD("wifi reload 2>/tmp/wifi_err.log", buf, sizeof(buf))) {
		_mqtt_log_printf(MOSQ_LOG_ERR, 
			"wireless opts: wifi reload failed!\n");
		return ret;
	}

	return 0;
}

// curl_download download from url, and saved into target_filename
// 0:succeed
// 1: failed
int 
curl_download(char *url, char *target_filename, int resume_enable) {
	if (target_filename == NULL || strlen(target_filename) == 0) {
		return 1;
	}

	long timeout = 600;
	int looptimes = 0;
	int ret = 0;
	int state_code = 0;
	double download_size = 0;

	while (ret = download(url, 
		target_filename, 
		resume_enable, 
		timeout, 
		&state_code, 
		&download_size)) {

		looptimes++;

		_mqtt_log_printf(MOSQ_LOG_DEBUG, 
			"curl download interrupt! statecode = %d, size = %f, trytime = %d\n", 
			state_code, download_size, looptimes);
		
		if ((state_code == CURL_TIMEOUT_SET_ERR || 
			state_code == CURL_HTTP_OTHER) && 
			(download_size == 0)) {
			_mqtt_log_printf(MOSQ_LOG_ERR, "curl download failed !\n");
			break;
		} else if (state_code == CURL_HTTP_404) {
			_mqtt_log_printf(MOSQ_LOG_ERR, "curl download 404 not found!\n");
			break;
		}

        s_sleep(0, 5000);

		if (looptimes >= DOWNLOAD_TRYTIMES) {
			_mqtt_log_printf(MOSQ_LOG_ERR, 
				"curl download trytime = %d, timeout!\n", 
				looptimes);
			break;
		}
    }

    return ret; 
}

// 	check_md5sum_popen using popen(CMDEXEC) to check file's md5sum
//	md5list_file: md5sum result list file's absolute path, as "/root/a_sum.list"
//	return: 0: ok, 1:faild
int 
check_md5sum_popen(const char *md5list_file) {
	if (md5list_file == NULL || strlen(md5list_file) == 0) {
		return 1;
	}

	if ( ! IsPathExist(md5list_file)) {
		_mqtt_log_printf(MOSQ_LOG_ERR, "path [%s] is not exist !\n", md5list_file);
		return 1;
	}

	/* warning: dirname and basename funcs will change the argument, so using 
	*  tmp-buffer which coppied the target file-name to be used as argument
	*/ 
	char fn_tmp_bufs[2][128] = {{0}, {0}};
	int i=0;
	for(i; i<2; i++) {
		snprintf(fn_tmp_bufs[i], 128, "%s", md5list_file);
	}
	char *dir = dirname(fn_tmp_bufs[0]);
	char *basefn = basename(fn_tmp_bufs[1]);

	char cmd_buf[512] = {0};
	char content_out[64] = {0};
	snprintf(cmd_buf, 
			sizeof(cmd_buf), 
			"cd %s;md5sum -c %s 2> /dev/null | grep OK", 
			dir, 
			basefn);

	if( ExecuateShellCMD(cmd_buf, 
						content_out,
						sizeof(content_out)) ){
		_mqtt_log_printf(MOSQ_LOG_ERR, "check_md5sum_popen: %s md5sum error, %s\n", 
			md5list_file, content_out);
		return 1;
	}
	if( STRCMP(content_out, ==, "") ){
		_mqtt_log_printf(MOSQ_LOG_ERR, 
						"check_md5sum_popen: md5sum failed, file:%s, md5=%s\n", 
			md5list_file, content_out);
		return 1;
	}

	return 0;
}