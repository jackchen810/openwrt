cmake_minimum_required(VERSION 2.6)

PROJECT(gateway-gset C)
##ADD_DEFINITIONS(-Os -Wall -Werror --std=gnu99)

SET(CMAKE_SHARED_LIBRARY_LINK_C_FLAGS "")


SET(APP_SRC  gateway-gset.c cJSON.c)
SET(LIBS ubox uci libwl.a m)

##TIMESTAMP
execute_process(COMMAND date "+%F %T%z" OUTPUT_VARIABLE TIMESTAMP OUTPUT_STRIP_TRAILING_WHITESPACE)
execute_process(COMMAND basename ${CMAKE_SOURCE_DIR} OUTPUT_VARIABLE PKG_RELEASE OUTPUT_STRIP_TRAILING_WHITESPACE)

add_definitions (-DTIMESTAMP=\"${TIMESTAMP}\")
add_definitions (-DPKG_RELEASE=\"${PKG_RELEASE}\")

ADD_EXECUTABLE(gateway-gset ${APP_SRC})

TARGET_LINK_LIBRARIES(gateway-gset ${LIBS})

INSTALL(TARGETS gateway-gset	RUNTIME DESTINATION /usr/bin)
