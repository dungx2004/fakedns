cmake_minimum_required(VERSION 3.10)
project(fakedns C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

# libpcap
find_path(PCAP_INCLUDE_DIR pcap.h
	HINTS /usr/include /usr/local/include /opt/local/include
	DOC "Path to pcap.h"
)
find_library(PCAP_LIBRARY pcap
	HINTS /usr/lib /usr/local/lib /opt/local/lib
	DOC "Path to libpcap library"
)
if (NOT PCAP_INCLUDE_DIR OR NOT PCAP_LIBRARY)
	message(FATAL_ERROR "Error: Could not find libpcap headers or library.")
endif()

# libnet
find_path(LIBNET_INCLUDE_DIR libnet.h
	HINTS /usr/include /usr/local/include /opt/local/include
	DOC "Path to libnet.h"
)
find_library(LIBNET_LIBRARY net
	HINTS /usr/lib /usr/local/lib /opt/local/lib
	DOC "Path to libnet library"
)
if (NOT LIBNET_INCLUDE_DIR OR NOT LIBNET_LIBRARY)
	message(FATAL_ERROR "Error: Could not find libnet headers or library.")
endif()

# yaml
find_path(YAML_INCLUDE_DIR yaml.h
	HINTS /usr/include /usr/local/include /opt/local/include
	DOC "Path to yaml.h"
)
find_library(YAML_LIBRARY yaml
	HINTS /usr/lib /usr/local/lib /opt/local/lib
	DOC "Path to libnet library"
)
if (NOT YAML_INCLUDE_DIR OR NOT YAML_LIBRARY)
	message(FATAL_ERROR "Error: Could not find libnet headers or library.")
endif()


include_directories(src ${PCAP_INCLUDE_DIR} ${LIBNET_INCLUDE_DIR})
file(GLOB SOURCE_FILES "src/*.c")

add_executable(fakedns ${SOURCE_FILES})

target_link_libraries(fakedns
	${PCAP_LIBRARY}
	${LIBNET_LIBRARY}
	${YAML_LIBRARY}
	pthread
)

target_compile_options(fakedns PRIVATE -g -Wall)
