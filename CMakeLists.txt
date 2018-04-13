# CMakeLists files in this project can refer to the root source directory of
# the project as ${FLEA_SOURCE_DIR} and to the root binary directory of
# the project as ${FLEA_BINARY_DIR}.
cmake_minimum_required(VERSION 2.8)

#note: use correct gcc version /usr/bin/gcc
PROJECT(FLEA)

# include standard cmake modules
INCLUDE(FindThreads)
#INCLUDE(FindQt4)

# Allow empty ELSE() and ENDIF() constructs
SET(CMAKE_ALLOW_LOOSE_LOOP_CONSTRUCTS true)
# gnu-compiler flags

SET(CMAKE_C_FLAGS "-std=c99 -pedantic")
SET(CMAKE_CXX_FLAGS "-std=c++11 ")


ADD_DEFINITIONS( 
  #-finline-functions -O3  -fomit-frame-pointer  -momit-leaf-frame-pointer 
      -fstrict-aliasing
      -W -Wall -Wextra -Wno-long-long -Wmissing-declarations
     -Wno-sign-compare -Wno-unused-parameter -Wno-unused-label -Wno-cast-qual
     -Wno-char-subscripts 
     -Wunused-function   -Wunused-value -Wunused-variable
  -Wpointer-arith  -Wcast-align -Wwrite-strings
  #out: -Wconversion 
  )

ADD_DEFINITIONS(-D__FLEA_HAVE_LINUX_FILESYSTEM)

IF(NOT CMAKE_BUILD_TYPE)
  SET(CMAKE_BUILD_TYPE Release CACHE STRING
      "Choose the type of build, options are: 'Debug' and 'Release'."
      FORCE)
ENDIF(NOT CMAKE_BUILD_TYPE)

SET(afl "false" CACHE STRING "wether to compile with afl-gcc")
IF(${afl} STREQUAL "true")
  SET($ENV{AFL_USE_ASAN} "1")  
  SET(CMAKE_C_COMPILER afl-gcc)
  SET(CMAKE_CXX_COMPILER afl-g++)
ENDIF()

SET(build_cfg "default" CACHE STRING "which build_cfg to use")

#SET(mudflap "false" CACHE STRING "wether to compile in mudflap for gcc")
#IF(${mudflap} STREQUAL "true")
#	ADD_DEFINITIONS(-fmudflap )
#	SET(MUDFLAP_LIB mudflap)
SET(ASAN_STR -asan)
#ELSEIF(${mudflap} STREQUAL "false")
	
#ELSE()
#	MESSAGE(FATAL_ERROR "mudflap must be either 'true' or 'false'")
#ENDIF()

IF(CMAKE_BUILD_TYPE STREQUAL "Debug" OR CMAKE_BUILD_TYPE STREQUAL "DEBUG" OR CMAKE_BUILD_TYPE STREQUAL "debug")
  ADD_DEFINITIONS(-g)
  #SET(DEBUG_STRING -d)
ELSE()
  ADD_DEFINITIONS( -O3 )
  #-fomit-frame-pointer  -momit-leaf-frame-pointer 
ENDIF()


SET(BUILD_STATIC false CACHE STRING
      "Whether to build also a static version of the library or not: true/false"
      )
IF(BUILD_STATIC STREQUAL true)
    SET(DO_BUILD_STATIC 1)
ENDIF()

SET(asan false CACHE STRING
      "Whether to build an additional version of the library and the tests using asan: true/false"
      )
IF(asan STREQUAL true)
    SET(DO_USE_ASAN 1)
ENDIF()


SET(BUILD_SHARED true CACHE STRING
      "Whether to build also a common (dynamic) version of the library or not: true/false"
      )
IF(BUILD_SHARED STREQUAL true)
    SET(DO_BUILD_SHARED 1)
ENDIF()

SET(VERSION_STRING ${DEBUG_STRING})
SET(LIB_NAME_STRING flea)
SET(FULL_LIB_STRING ${LIB_NAME_STRING}${VERSION_STRING})
SET(FULL_LIB_STRING_ASAN ${LIB_NAME_STRING}${VERSION_STRING}${ASAN_STR})
SET(FULL_LIB_STRING_STATIC${LIB_NAME_STRING}_static${VERSION_STRING})
SET(FULL_LIB_STRING_STATIC_ASAN ${LIB_NAME_STRING}_static${VERSION_STRING}${ASAN_STR})

SET(TEST_LIB_NAME_STRING flea_test_lib)
SET(TEST_LIB_STRING ${TEST_LIB_NAME_STRING}${VERSION_STRING})
SET(TEST_LIB_STRING_ASAN ${TEST_LIB_NAME_STRING}${VERSION_STRING}${ASAN_STR})
SET(TEST_LIB_STRING_STATIC${TEST_LIB_NAME_STRING}_static${VERSION_STRING})
SET(TEST_LIB_STRING_STATIC_ASAN ${TEST_LIB_NAME_STRING}_static${VERSION_STRING}${ASAN_STR})

SET(PROJECT_BINARY_DIR build)
SET(LIBRARY_OUTPUT_PATH ${PROJECT_BINARY_DIR})
SET(EXECUTABLE_OUTPUT_PATH ${PROJECT_BINARY_DIR})


# Directories
SET(INCLUDE_DIR include include/api test/include test/include/api build_cfg/general/${build_cfg}
  build_cfg/pltf_spec/32bit_default )

SET(SRC_DIR src )



# List of source files
FILE(GLOB FLEA_SRCS ${SRC_DIR}/x86/*.c ${SRC_DIR}/common/*.c ${SRC_DIR}/user/*.c
  ${SRC_DIR}/common/hash/*.c ${SRC_DIR}/common/math/*.c ${SRC_DIR}/common/pk_enc/*.c 
  ${SRC_DIR}/common/asn1/*.c ${SRC_DIR}/common/streams/*.c
  ${SRC_DIR}/common/file_io/*.c
  ${SRC_DIR}/pc/*.c ${SRC_DIR}/pc/*.cpp
   ${SRC_DIR}/common/tls/*.c pltf_support/linux/src/*.c)

FILE(GLOB TEST_SRCS test/src/pc/*.cpp test/src/pc/*.c test/src/common/*.c)
FILE(GLOB TEST_LIB_SRCS test/src/test_lib/*.cpp test/src/test_lib/*.c )

# include folder with header files
INCLUDE_DIRECTORIES(${INCLUDE_DIR} )



IF(DO_BUILD_SHARED)
    ADD_LIBRARY(${FULL_LIB_STRING} SHARED ${FLEA_SRCS})
    TARGET_LINK_LIBRARIES(${FULL_LIB_STRING} pthread )

    ADD_LIBRARY(${TEST_LIB_STRING} SHARED ${TEST_LIB_SRCS})
    TARGET_LINK_LIBRARIES(${TEST_LIB_STRING} pthread )
ENDIF()

IF(DO_BUILD_STATIC)
    ADD_LIBRARY(${FULL_LIB_STRING_STATIC} STATIC ${FLEA_SRCS})
    ADD_LIBRARY(${TEST_LIB_STRING_STATIC} STATIC ${TEST_LIB_SRCS})
ENDIF()


ADD_EXECUTABLE(flea-test test/src/pc/unit_test_main.cpp ${TEST_SRCS})
TARGET_LINK_LIBRARIES(flea-test ${FULL_LIB_STRING} ${TEST_LIB_STRING})


#    set (CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS}  -static-libasan -fno-omit-frame-pointer -fsanitize=address")
#    set (CMAKE_C_FLAGS "${CMAKE_C_FLAGS}  -static-libasan -fno-omit-frame-pointer -fsanitize=address")

SET(ASAN_FLAGS "-fno-omit-frame-pointer -fsanitize=address")

#IF(DO_BUILD_SHARED)
#ADD_LIBRARY(${FULL_LIB_STRING_ASAN} SHARED ${FLEA_SRCS})
#TARGET_LINK_LIBRARIES(${FULL_LIB_STRING_ASAN} asan pthread )
#    target_compile_options(${FULL_LIB_STRING_ASAN} PUBLIC -fno-omit-frame-pointer -fsanitize=address)
#ENDIF()

IF(DO_USE_ASAN)
  ADD_LIBRARY(${FULL_LIB_STRING_STATIC_ASAN} STATIC ${FLEA_SRCS})
  ADD_LIBRARY(${TEST_LIB_STRING_STATIC_ASAN} STATIC ${TEST_LIB_SRCS})
  TARGET_LINK_LIBRARIES(${FULL_LIB_STRING_STATIC_ASAN} ${TEST_LIB_STRING_STATIC_ASAN}  asan pthread )
  #set_target_properties(${FULL_LIB_STRING_STATIC_ASAN} PROPERTIES COMPILE_FLAGS ${ASAN_FLAGS})
  target_compile_options(${FULL_LIB_STRING_STATIC_ASAN} PUBLIC -m32 -fno-omit-frame-pointer -fsanitize=address)
  target_compile_options(${TEST_LIB_STRING_STATIC_ASAN} PUBLIC -m32 -fno-omit-frame-pointer -fsanitize=address)

  ADD_EXECUTABLE(flea-test-asan test/src/pc/unit_test_main.cpp ${TEST_SRCS})
  target_compile_options(flea-test-asan PUBLIC -m32 -fno-omit-frame-pointer -fsanitize=address)
  TARGET_LINK_LIBRARIES(flea-test-asan asan ${FULL_LIB_STRING_STATIC_ASAN}
    ${TEST_LIB_STRING_STATIC_ASAN} "-m32" )
ENDIF()
