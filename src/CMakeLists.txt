cmake_minimum_required(VERSION 2.6)
PROJECT(dawn)

ADD_DEFINITIONS(-Os -Wall -Werror --std=gnu99 -Wmissing-declarations -Wno-unknown-warning-option -Wno-format-truncation)

SET(CMAKE_SHARED_LIBRARY_LINK_C_FLAGS "")

SET(SOURCES
	main.c datastorage.c datastorage.h networksocket.c networksocket.h ubus.c ubus.h utils.h runopts.c runopts.h)

SET(LIBS
	ubox ubus json-c blobmsg_json config)

ADD_EXECUTABLE(dawn ${SOURCES})

TARGET_LINK_LIBRARIES(dawn ${LIBS})

INSTALL(TARGETS dawn
	RUNTIME DESTINATION /usr/bin/
)