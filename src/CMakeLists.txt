cmake_minimum_required(VERSION 2.6)
PROJECT(dawn)

INCLUDE_DIRECTORIES(include)

ADD_DEFINITIONS(-Os -Wall -Werror --std=gnu99 -Wmissing-declarations -Wno-unknown-warning-option -Wno-format-truncation)

SET(CMAKE_SHARED_LIBRARY_LINK_C_FLAGS "")

SET(SOURCES
        main.c

        storage/datastorage.c
        include/datastorage.h

        storage/uface.c
        include/uface.h

        network/networksocket.c
        include/networksocket.h

        network/broadcastsocket.c
        include/broadcastsocket.h

        network/multicastsocket.c
        include/multicastsocket.h

        utils/ubus.c
        include/ubus.h

        utils/dawn_uci.c
        include/dawn_uci.h

        crypto/crypto.c
        include/crypto.h

        include/utils.h
        utils/utils.c

        include/tcpsocket.h
        network/tcpsocket.c

        include/dawn_iwinfo.h
        utils/dawn_iwinfo.c

        utils/ieee80211_utils.c
        include/ieee80211_utils.h)

SET(SOURCES_TEST_STORAGE
        test/test_storage.c

        include/uface.h

        utils/utils.c
        include/utils.h

        storage/datastorage.c
        include/datastorage.h

        utils/ieee80211_utils.c
        include/ieee80211_utils.h)

SET(LIBS
        ubox ubus json-c blobmsg_json uci gcrypt iwinfo)

ADD_EXECUTABLE(dawn ${SOURCES})
ADD_EXECUTABLE(test_storage ${SOURCES_TEST_STORAGE})

TARGET_LINK_LIBRARIES(dawn ${LIBS})

INSTALL(TARGETS dawn
        RUNTIME DESTINATION /usr/sbin/)
