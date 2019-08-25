#include "common.h"

static int Logpriority = MOSQ_LOG_NONE;
static char log_dst1[] = "/var/log/mqtt.log.1";
static char log_dst2[] = "/var/log/mqtt.log.2";

static int log_flag = 1;

static pthread_mutex_t log_callback_mutex = PTHREAD_MUTEX_INITIALIZER;

/*
 * victor add
 * print log to serial
 * with serial, you can see all mqtt-client payload
*/
void WriteLog2Serial(const char *string) {
	char log[SHELL_CMD_BUFFER] = {0};
	char buf[32] = {0};

	memset(log, 0, sizeof(log));
	memset(buf, 0, sizeof(buf));

	if( log_flag == 0 )
		return;

	snprintf(log, sizeof(log), "echo '%s'>/dev/ttyS0", string);
	//ExecuateShellCMD(log, buf, sizeof(buf));
	//victor @20160526 fix sync 3 times Aborted issue.
	//popen is a serious fucction, use will cause memory issue.

	char buf_stm_result[BUF_STM_RESULT_LEN] = {0};
	ExecuateShellCMD(log, buf_stm_result, sizeof(log));
}

void GetTime(UINT8 *pszTimeStr, int str_len) {
    struct tm      tSysTime     = {0};
    struct timeval tTimeVal     = {0};
    time_t         tCurrentTime = {0};

    UINT8  szUsec[20] = {0};
    UINT8  szMsec[20] = {0};

    if (pszTimeStr == NULL)
    {
        return;
    }

	tCurrentTime = time(NULL);
	localtime_r(&tCurrentTime, &tSysTime);

	gettimeofday(&tTimeVal, NULL);
	snprintf(szUsec, sizeof(szUsec), "%06ld", tTimeVal.tv_usec);
	strncpy(szMsec, szUsec, 3);

	snprintf(pszTimeStr, str_len, "[%04d.%02d.%02d %02d:%02d:%02d.%3.3s]",
			tSysTime.tm_year+1900, tSysTime.tm_mon+1, tSysTime.tm_mday,
			tSysTime.tm_hour, tSysTime.tm_min, tSysTime.tm_sec, szMsec);
}

UINT8 *LogLevel(UINT32 Level) {
	switch( Level&MOSQ_LOG_ALL )
	{
		case MOSQ_LOG_INFO:
			return "INFO";

		case MOSQ_LOG_NOTICE:   
            return "NOTICE";

        case MOSQ_LOG_WARNING :
            return "WARN";

        case MOSQ_LOG_ERR :
            return "ERR";

        case MOSQ_LOG_DEBUG:   
            return "DEBUG";

        case MOSQ_LOG_SUBSCRIBE:   
            return "SUBSCRIBE";

        case MOSQ_LOG_UNSUBSCRIBE:   
            return "UNSUBSCRIBE";

        case MOSQ_LOG_WEBSOCKETS:   
            return "WEBSOCKETS";

        case MOSQ_LOG_ALL:   
            return "ALL";

        default: 
            return "OTHER";
    }
}

/**
*@Description: write log pure
*@Input: string of input
*@Return: void: void
*/
void mqtt_log_write_file(char *level, char * string) {
	FILE * file_fd = NULL;
	char timestamp[64] = {0};

	GetTime(timestamp, sizeof(timestamp));
	file_fd = fopen(log_dst1, "a+");
	
	if( NULL != file_fd ) {
		fprintf(file_fd, "%s [%s] %s", timestamp, level, string);
		if( ftell(file_fd) > MAXLOGSIZE ) {
			fclose(file_fd);
			if (rename(log_dst1, log_dst2))
			{
				remove(log_dst2);
				rename(log_dst1, log_dst2);
			}
		}else{
			fclose(file_fd);
		}
	} else {
		perror("open mqtt_log file failed");
	}
	return;
}

int _mqtt_log_printf(int priority, const char *fmt, ...) {
	va_list va;
	char *s;
	int len;

	pthread_mutex_lock(&log_callback_mutex);
	//len = strlen(fmt) + 500;
	//victor @20160804 according to rsyslog debug buffer size.
	len = 32*1024;
	s = (char *)os_malloc(len*sizeof(char));
	if(!s){
		pthread_mutex_unlock(&log_callback_mutex);
		return MOSQ_ERR_NOMEM;
	}

	va_start(va, fmt);
	vsnprintf(s, len, fmt, va);
	va_end(va);
	s[len-1] = '\0'; /* Ensure string is null terminated. */

	mqtt_log_write_file(LogLevel(priority), s);

	os_free(s);
	pthread_mutex_unlock(&log_callback_mutex);
	return MOSQ_ERR_SUCCESS;
}
