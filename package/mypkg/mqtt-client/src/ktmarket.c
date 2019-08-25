/*
 * ktmarket for kunteng-router-market management
 * Copyright (c) 2016, gukq <tangronghua@kunteng.org>
 *
 */

#include <stdio.h>
#include <dirent.h>
#include <stdlib.h>
#include <string.h>
#include "ktmarket.h"

#define         STRCMP(a, R, b)         (strcmp(a, b) R 0)
// 0: not exist
// 1: package exist
int 
PackageIsExist(const char *package_name) {
	if (package_name == NULL) {
		return 0;
	}
	
	DIR *dir = NULL;
	struct dirent *ptr = NULL;
	int counter = 0;
	char market_path[] = KTMARKET_PATH;
	int ret = 0;

	if( (dir=opendir(market_path)) == NULL ){
		perror("Open dir error...");
		return 0;
	}

	while( (ptr=readdir(dir)) != NULL )
	{
 		//_mqtt_log_printf(MOSQ_LOG_INFO, "wd_task: dname=%s.\n", ptr->d_name);
		if( STRCMP(ptr->d_name, ==, ".") || STRCMP(ptr->d_name, ==, "..") ){
		//current dir OR parrent dir
			continue;
		}else if( STRCMP(ptr->d_name, ==, package_name) ){//dir
			ret = 1;
			break;
		}
	}

	closedir(dir);
	return ret;
}