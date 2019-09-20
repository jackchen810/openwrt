/*
 * Copyright (C) 2011-2014  <chenzejun@kunteng.org>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License version 2.1
 * as published by the Free Software Foundation
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */
#ifndef __LIBWL_PUB_H_
#define __LIBWL_PUB_H_


#define FUNCTION_DESC(str)        1
#define MACROSTR(X)   #X
#define MACROSTR_VALUE(X)   #X, (X)
#define GET_VALID_ARG(did, dargc, dargv)   ((did) < dargc ? dargv[did] : NULL)



typedef int (* PF_LIBWL_SHOW)(char *, int);
typedef struct LIBWL_CMD_LIST_ST
{
        char                   cmd_name[64];    //command name
        PF_LIBWL_SHOW  pf_function;
}LIBWL_CMD_LIST;





/* 0-100, ouput to screen */
/* 100-..., ouput to log*/
enum {
        LIBWL_INFO  = 1,
        LIBWL_ERROR  = 2,
        LIBWL_LOG_TRACE  = 3,
        LIBWL_CMD_TRACE  = 4,
        LIBWL_API_TRACE  = 5,
        LIBWL_SWITCH_MAX  = 6,
};



/* debug pointer, support log or screen to output info */
typedef int (* PF_LIBWL_PRINT)(const char *, ...);
extern PF_LIBWL_PRINT pf_debug_function;
#define LIBWL_DBG_PRINTF(Category, fmt, args...)  \
do{                                   \
        if (pf_debug_function) \
        {\
                if (libwl_debug_get_switch(Category))     pf_debug_function(fmt, ##args);  \
        }\
}while(0)



void libwl_printf_currtime(void);
int libwl_log(const char *name, const char *format, ...);
int libwl_debug_get_switch(int category);
int libwl_cmd_service_create(char *name);
int libwl_cmd_service_destroy(void);
void libwl_cmd_service_callback(int sock_fd, LIBWL_CMD_LIST ast_list[], int size);
int libwl_cmd_client_create(char *name);
int libwl_cmd_client_show(int sock_fd, char *arg1, char *arg2, char *arg3);
int libwl_cmd_client_debug(int sock_fd);
int libwl_cmd_client_addr_len(void);

void libwl_cmd_client_timeout(int sig);
void libwl_cmd_output_log(int num);
void libwl_cmd_output_printf(int num);
int libwl_cmd_service_init(LIBWL_CMD_LIST *pst_cmdlist, int list_size);
bool libwl_inst_is_running(char *lock_file);


#endif
