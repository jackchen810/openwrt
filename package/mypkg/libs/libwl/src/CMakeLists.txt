cmake_minimum_required(VERSION 2.6)

PROJECT(libwl C)
##ADD_DEFINITIONS(-Os -Wall -Werror --std=gnu99)

SET(CMAKE_SHARED_LIBRARY_LINK_C_FLAGS "")

##添加头文件目录
INCLUDE_DIRECTORIES(../include)

SET(APP_SRC  libwl_alist.c libwl_api.c libwl_dbg.c)
SET(LIBS ubox uci)

##TIMESTAMP
execute_process(COMMAND date "+%F %T%z" OUTPUT_VARIABLE TIMESTAMP OUTPUT_STRIP_TRAILING_WHITESPACE)
execute_process(COMMAND basename ${CMAKE_SOURCE_DIR} OUTPUT_VARIABLE PKG_RELEASE OUTPUT_STRIP_TRAILING_WHITESPACE)

add_definitions (-DTIMESTAMP=\"${TIMESTAMP}\")
add_definitions (-DPKG_RELEASE=\"${PKG_RELEASE}\")


#添加动态库  
ADD_LIBRARY(wl SHARED ${APP_SRC})  
#添加静态库  
ADD_LIBRARY(wl_static STATIC ${APP_SRC})  



#生成动态库的版本号  
SET_TARGET_PROPERTIES(wl PROPERTIES VERSION 1.2 SOVERSION 1) 

#将静态库重新命名为libwl, 在构建libwl.a时，就会清理掉libwl.so. 
SET_TARGET_PROPERTIES(wl_static PROPERTIES OUTPUT_NAME "wl")  
  
#安装静态库和动态库  
INSTALL(TARGETS wl   wl_static   
    LIBRARY DESTINATION /usr/lib   
    ARCHIVE DESTINATION /usr/lib)  


#安装libwl.h  
#INSTALL(FILES libwl.h DESTINATION include/libwl)  



