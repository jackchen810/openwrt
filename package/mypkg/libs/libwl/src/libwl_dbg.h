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
#ifndef __LIBWL_DBG_H_
#define __LIBWL_DBG_H_


#define LIBWL_SERVICE                     1
#define LIBWL_CLIENT_SHOW            2
#define LIBWL_CLIENT_DEBUG           3

#define MAX_LOGSIZE (400*1024)


struct  LIBWL_GLOBAL_DEBUG
{

        unsigned short debug_flag;
        unsigned char  dbg_switch[BUF_LEN_64];
        pthread_mutex_t log_printf_mutex;
        pthread_mutex_t log_file_mutex;
        char logfilename[BUF_LEN_128];
        char logstr[LOG_BUFFER_1024 + BUF_LEN_32];
};

 static inline void libwl_printf_hexdump(const char *str, const unsigned char *pbuf, unsigned int len);



#endif
