# Original liblsl code: Copyright (C) 2012 Christian A. Kothe, MIT License
# Modifications: Copyright (C) 2025-2026 The Regents of the University of California.
# All Rights Reserved. Author: Seyed Yahya Shirazi, SCCN, INC, UCSD
# See LICENSE in the repository root for terms.

cmake_minimum_required (VERSION 3.12)
project (liblsl
	VERSION 1.16.1
	LANGUAGES C CXX
	DESCRIPTION "Labstreaminglayer C/C++ library"
	HOMEPAGE_URL "https://github.com/sccn/liblsl"
	)

# API version, to be incremented on backwards-incompatible ABI changes
set(LSL_ABI_VERSION 2)

# Security layer version (independent of base liblsl version)
# Major: Breaking changes (API, protocol, config format)
# Minor: New features (new API functions, new config options)
# Patch: Bug fixes, security patches
set(LSL_SECURITY_VERSION_MAJOR 1)
set(LSL_SECURITY_VERSION_MINOR 0)
set(LSL_SECURITY_VERSION_PATCH 0)
set(LSL_SECURITY_STAGE "alpha")  # "alpha", "beta", "rc.N", or "" for stable

# Compute security version string
set(LSL_SECURITY_VERSION
	"${LSL_SECURITY_VERSION_MAJOR}.${LSL_SECURITY_VERSION_MINOR}.${LSL_SECURITY_VERSION_PATCH}")

# Compute full version string (base-secure.security[-stage])
if(LSL_SECURITY_STAGE)
	set(LSL_FULL_VERSION
		"${PROJECT_VERSION}-secure.${LSL_SECURITY_VERSION}-${LSL_SECURITY_STAGE}")
else()
	set(LSL_FULL_VERSION
		"${PROJECT_VERSION}-secure.${LSL_SECURITY_VERSION}")
endif()

set(CMAKE_CXX_VISIBILITY_PRESET hidden)
set(CMAKE_VISIBILITY_INLINES_HIDDEN ON)
if(NOT MSVC_VERSION VERSION_LESS 1700)
	set(CMAKE_CXX_STANDARD 14)
endif()
# generate a compilation database (compile_commands.json) for clang tooling
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

option(LSL_DEBUGLOG "Enable (lots of) additional debug messages" OFF)
option(LSL_UNIXFOLDERS "Use the unix folder layout for install targets" On)
option(LSL_FORCE_FANCY_LIBNAME "Add library name decorations (32/64/-debug)" OFF)
option(LSL_BUILD_EXAMPLES "Build example programs in examples/" OFF)
option(LSL_BUILD_STATIC "Build LSL as static library." OFF)
option(LSL_LEGACY_CPP_ABI "Build legacy C++ ABI into lsl-static" OFF)
option(LSL_OPTIMIZATIONS "Enable some more compiler optimizations" ON)
option(LSL_UNITTESTS "Build LSL library unit tests" OFF)
option(LSL_BUNDLED_BOOST "Use the bundled Boost by default" ON)
option(LSL_BUNDLED_PUGIXML "Use the bundled pugixml by default" ON)
option(LSL_SLIMARCHIVE "Use experimental but smaller serialization code" OFF)
option(LSL_TOOLS "Build some experimental tools for in-depth tests" OFF)
option(LSL_SECURITY "Enable security layer (requires libsodium)" ON)
option(LSL_SECURITY_TOOLS "Build security tools (lsl-keygen, lsl-config)" ON)

mark_as_advanced(LSL_SLIMARCHIVE LSL_FORCE_FANCY_LIBNAME)

set(LSL_WINVER "0x0601" CACHE STRING
	"Windows version (_WIN32_WINNT) to target (defaults to 0x0601 for Windows 7)")

if(LSL_BUILD_STATIC)
	set(LSL_LIB_TYPE STATIC)
else()
	set(LSL_LIB_TYPE SHARED)
	# shared libraries require relocatable symbols so we enable them by default
	set(CMAKE_POSITION_INDEPENDENT_CODE ON)
endif()

# Add an object library so all files are only compiled once
add_library(lslobj OBJECT
	src/api_config.cpp
	src/api_config.h
	src/api_types.hpp
	src/cancellable_streambuf.h
	src/cancellation.h
	src/cancellation.cpp
	src/common.cpp
	src/common.h
	src/consumer_queue.cpp
	src/consumer_queue.h
	src/data_receiver.cpp
	src/data_receiver.h
	src/forward.h
	src/info_receiver.cpp
	src/info_receiver.h
	src/inlet_connection.cpp
	src/inlet_connection.h
	src/lsl_resolver_c.cpp
	src/lsl_inlet_c.cpp
	src/lsl_outlet_c.cpp
	src/lsl_streaminfo_c.cpp
	src/lsl_xml_element_c.cpp
	src/netinterfaces.h
	src/netinterfaces.cpp
	src/portable_archive/portable_archive_exception.hpp
	src/portable_archive/portable_archive_includes.hpp
	src/portable_archive/portable_iarchive.hpp
	src/portable_archive/portable_oarchive.hpp
	src/resolver_impl.cpp
	src/resolver_impl.h
	src/resolve_attempt_udp.cpp
	src/resolve_attempt_udp.h
	src/sample.cpp
	src/sample.h
	src/send_buffer.cpp
	src/send_buffer.h
	src/socket_utils.cpp
	src/socket_utils.h
	src/stream_info_impl.cpp
	src/stream_info_impl.h
	src/stream_inlet_impl.h
	src/stream_outlet_impl.cpp
	src/stream_outlet_impl.h
	src/tcp_server.cpp
	src/tcp_server.h
	src/time_postprocessor.cpp
	src/time_postprocessor.h
	src/time_receiver.cpp
	src/time_receiver.h
	src/udp_server.cpp
	src/udp_server.h
	src/util/cast.hpp
	src/util/cast.cpp
	src/util/endian.cpp
	src/util/endian.hpp
	src/util/inireader.hpp
	src/util/inireader.cpp
	src/util/strfuns.hpp
	src/util/strfuns.cpp
	src/util/uuid.hpp
	thirdparty/loguru/loguru.cpp
	$<$<BOOL:${LSL_LEGACY_CPP_ABI}>:src/legacy/legacy_abi.cpp src/legacy/legacy_abi.h>
	# security layer
	$<$<BOOL:${LSL_SECURITY}>:src/lsl_security.cpp src/lsl_security.h>
	# headers
	include/lsl_c.h
	$<$<BOOL:${LSL_SECURITY}>:include/lsl_security.h>
	include/lsl_cpp.h
	include/lsl/common.h
	include/lsl/inlet.h
	include/lsl/outlet.h
	include/lsl/resolver.h
	include/lsl/streaminfo.h
	include/lsl/types.h
	include/lsl/xml.h
)

if(LSL_BUNDLED_PUGIXML)
	message(STATUS "Using bundled pugixml")
	target_sources(lslobj PRIVATE thirdparty/pugixml/pugixml.cpp)
	target_include_directories(lslobj SYSTEM PUBLIC
		$<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/thirdparty/pugixml>)
else()
	message(STATUS "Using system pugixml")
	find_package(pugixml REQUIRED)
	if(NOT TARGET pugixml::pugixml)
		add_library(pugixml::pugixml ALIAS pugixml)
	endif()
	target_link_libraries(lslobj PUBLIC pugixml::pugixml)
endif()

# try to find out which revision is currently checked out
find_package(Git)
if(lslgitrevision AND lslgitbranch)
	message(STATUS "Got git information ${lslgitrevision}/${lslgitbranch} from the command line")
elseif(GIT_FOUND)
	execute_process(
		COMMAND ${GIT_EXECUTABLE} describe --tags HEAD
		WORKING_DIRECTORY "${CMAKE_CURRENT_LIST_DIR}"
		OUTPUT_VARIABLE lslgitrevision
		OUTPUT_STRIP_TRAILING_WHITESPACE
	)
	execute_process(
		COMMAND ${GIT_EXECUTABLE} rev-parse --symbolic-full-name --abbrev-ref @
		WORKING_DIRECTORY "${CMAKE_CURRENT_LIST_DIR}"
		OUTPUT_VARIABLE lslgitbranch
		OUTPUT_STRIP_TRAILING_WHITESPACE
	)
	message(STATUS "Git version information: ${lslgitbranch}/${lslgitrevision}")
else()
	set(lslgitrevision "unknown")
	set(lslgitbranch "unknown")
endif()

# generate a version information string that can be retrieved with the exported
# lsl_library_info() function
set(LSL_VERSION_INFO "git:${lslgitrevision}/branch:${lslgitbranch}/build:${CMAKE_BUILD_TYPE}/compiler:${CMAKE_CXX_COMPILER_ID}-${CMAKE_CXX_COMPILER_VERSION}")

# Pass version definitions to buildinfo.cpp
if(LSL_SECURITY)
	set_source_files_properties("src/buildinfo.cpp"
		PROPERTIES COMPILE_DEFINITIONS
		"LSL_LIBRARY_INFO_STR=\"${LSL_VERSION_INFO}/link:${LSL_LIB_TYPE}/security:${LSL_SECURITY_VERSION}\";LSL_BASE_VERSION=\"${PROJECT_VERSION}\";LSL_SECURITY_VERSION_STR=\"${LSL_SECURITY_VERSION}\";LSL_FULL_VERSION_STR=\"${LSL_FULL_VERSION}\";LSL_SECURITY_STAGE_STR=\"${LSL_SECURITY_STAGE}\";LSL_IS_SECURE_BUILD=1"
	)
else()
	set_source_files_properties("src/buildinfo.cpp"
		PROPERTIES COMPILE_DEFINITIONS
		"LSL_LIBRARY_INFO_STR=\"${LSL_VERSION_INFO}/link:${LSL_LIB_TYPE}\";LSL_BASE_VERSION=\"${PROJECT_VERSION}\";LSL_IS_SECURE_BUILD=0"
	)
endif()
set_source_files_properties("thirdparty/loguru/loguru.cpp"
	PROPERTIES COMPILE_DEFINITIONS LOGURU_STACKTRACES=$<BOOL:${LSL_DEBUGLOG}>)

find_package(Threads REQUIRED)

# libsodium for security layer
if(LSL_SECURITY)
	find_package(PkgConfig)
	if(PkgConfig_FOUND)
		pkg_check_modules(SODIUM IMPORTED_TARGET libsodium>=1.0.18)
	endif()

	if(SODIUM_FOUND)
		message(STATUS "Found libsodium ${SODIUM_VERSION} via pkg-config")
	else()
		# Fallback: try to find libsodium manually
		find_path(SODIUM_INCLUDE_DIR sodium.h
			HINTS
				ENV SODIUM_ROOT
				${SODIUM_ROOT}
			PATH_SUFFIXES include
		)
		find_library(SODIUM_LIBRARY
			NAMES sodium libsodium
			HINTS
				ENV SODIUM_ROOT
				${SODIUM_ROOT}
			PATH_SUFFIXES lib lib64
		)
		if(SODIUM_INCLUDE_DIR AND SODIUM_LIBRARY)
			set(SODIUM_FOUND TRUE)
			message(STATUS "Found libsodium via manual search: ${SODIUM_LIBRARY}")
		else()
			message(FATAL_ERROR "libsodium not found. Install libsodium 1.0.18+ or set SODIUM_ROOT.\n"
				"  Ubuntu/Debian: apt install libsodium-dev\n"
				"  macOS: brew install libsodium\n"
				"  Windows: vcpkg install libsodium")
		endif()
	endif()
endif()

# create the lslboost target
add_library(lslboost INTERFACE)
if(LSL_BUNDLED_BOOST)
	message(STATUS "Using bundled Boost")
	target_include_directories(lslboost SYSTEM INTERFACE
		$<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/lslboost>)
else()
	message(STATUS "Using system Boost")
	find_package(Boost REQUIRED)
	target_compile_definitions(lslboost
		INTERFACE
			lslboost=boost # allows the LSL code base to work with the original Boost namespace/headers
	)
	target_link_libraries(lslboost INTERFACE Boost::boost Boost::disable_autolinking)
endif()

if(LSL_SLIMARCHIVE OR NOT LSL_BUNDLED_BOOST)
	message(STATUS "Using shim instead of full Boost.Archive")
	target_compile_definitions(lslboost INTERFACE SLIMARCHIVE)
elseif(LSL_BUNDLED_BOOST)
	# compile Boost.Serialization objects as part of lslobj
	target_sources(lslobj PRIVATE lslboost/serialization_objects.cpp)
endif()
target_compile_definitions(lslboost INTERFACE BOOST_ALL_NO_LIB)

# target configuration for the internal lslobj target
target_link_libraries(lslobj PRIVATE lslboost Threads::Threads)

# libsodium linking for security layer
if(LSL_SECURITY)
	target_compile_definitions(lslobj PUBLIC LSL_SECURITY_ENABLED)
	if(TARGET PkgConfig::SODIUM)
		target_link_libraries(lslobj PRIVATE PkgConfig::SODIUM)
	else()
		target_include_directories(lslobj PRIVATE ${SODIUM_INCLUDE_DIR})
		target_link_libraries(lslobj PRIVATE ${SODIUM_LIBRARY})
	endif()
	# macOS frameworks for device ID computation (IOKit for hardware serial, CoreFoundation for strings)
	if(APPLE)
		find_library(IOKIT_FRAMEWORK IOKit REQUIRED)
		find_library(COREFOUNDATION_FRAMEWORK CoreFoundation REQUIRED)
		target_link_libraries(lslobj PRIVATE ${IOKIT_FRAMEWORK} ${COREFOUNDATION_FRAMEWORK})
	endif()
	message(STATUS "LSL security layer enabled")
endif()

target_compile_features(lslobj PUBLIC cxx_std_11 cxx_lambda_init_captures)
target_include_directories(lslobj
	PUBLIC
		$<BUILD_INTERFACE:${CMAKE_CURRENT_LIST_DIR}/include>
		$<INSTALL_INTERFACE:include>
	INTERFACE # for unit tests
		$<BUILD_INTERFACE:${CMAKE_CURRENT_LIST_DIR}/src>
	)
target_include_directories(lslobj
	SYSTEM PUBLIC
		$<BUILD_INTERFACE:${CMAKE_CURRENT_LIST_DIR}/thirdparty/loguru>
		$<BUILD_INTERFACE:${CMAKE_CURRENT_LIST_DIR}/thirdparty/asio>
)
target_compile_definitions(lslobj PRIVATE
	LIBLSL_EXPORTS
	LOGURU_DEBUG_LOGGING=$<BOOL:${LSL_DEBUGLOG}>
	PUBLIC ASIO_NO_DEPRECATED
)

# platform specific configuration
if(UNIX AND NOT APPLE)
	include(CheckSymbolExists)
	# check that clock_gettime is present in the stdlib, link against librt otherwise
	check_symbol_exists(clock_gettime time.h HAS_GETTIME)
	if(NOT HAS_GETTIME)
		target_link_libraries(lslobj PRIVATE rt)
	endif()
	if(LSL_DEBUGLOG)
		target_link_libraries(lslobj PRIVATE dl)
	endif()
elseif(WIN32)
	target_link_libraries(lslobj PRIVATE iphlpapi winmm mswsock ws2_32)
	target_compile_definitions(lslobj
		PRIVATE _CRT_SECURE_NO_WARNINGS
		PUBLIC LSLNOAUTOLINK # don't use #pragma(lib) in CMake builds
		_WIN32_WINNT=${LSL_WINVER}
		)
endif()

# the "real" liblsl library. It contains one source with the version info
# string because some generators require it. The remaining source code is
# built in the lslobj target and later linked into this library
add_library(lsl ${LSL_LIB_TYPE} src/buildinfo.cpp)

# defines for LSL_CPP_API export header (shared: dllimport/dllexport)
target_compile_definitions(lsl PUBLIC
	$<IF:$<BOOL:${LSL_BUILD_STATIC}>,LIBLSL_STATIC,LIBLSL_EXPORTS>
	$<$<CXX_COMPILER_ID:MSVC>:LSLNOAUTOLINK> # don't use #pragma(lib) in CMake builds
)
target_link_libraries(lsl PRIVATE lslobj lslboost)
target_include_directories(lsl INTERFACE
	$<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
	$<INSTALL_INTERFACE:include>
)
# Set library version and soversion
set_target_properties(lsl PROPERTIES
	VERSION ${liblsl_VERSION_MAJOR}.${liblsl_VERSION_MINOR}.${liblsl_VERSION_PATCH}
	SOVERSION ${LSL_ABI_VERSION}
)

# Rename binary to lsl-secure when security is enabled
if(LSL_SECURITY)
	set_target_properties(lsl PROPERTIES
		OUTPUT_NAME "lsl-secure"
	)
	message(STATUS "Library will be named: liblsl-secure (security version: ${LSL_FULL_VERSION})")
endif()

# enable some additional expensive compiler optimizations
if(LSL_OPTIMIZATIONS)
	# enable LTO (https://en.wikipedia.org/wiki/Interprocedural_optimization
	set(CMAKE_INTERPROCEDURAL_OPTIMIZATION ON)
else()
	# build one object file for Asio instead of once every time an Asio function is called. See
	# https://think-async.com/Asio/asio-1.18.2/doc/asio/using.html#asio.using.optional_separate_compilation
	target_sources(lslobj PRIVATE thirdparty/asio_objects.cpp)
	target_compile_definitions(lslobj PUBLIC ASIO_SEPARATE_COMPILATION)
endif()



if(LSL_FORCE_FANCY_LIBNAME)
	math(EXPR lslplatform "8 * ${CMAKE_SIZEOF_VOID_P}")
	set_target_properties(lsl PROPERTIES
		PREFIX ""
		OUTPUT_NAME "liblsl${lslplatform}"
		DEBUG_POSTFIX "-debug"
	)
endif()

if(LSL_UNIXFOLDERS)
	include(GNUInstallDirs)
else()
	set(CMAKE_INSTALL_BINDIR LSL)
	set(CMAKE_INSTALL_LIBDIR LSL)
	set(CMAKE_INSTALL_INCLUDEDIR LSL/include)
endif()

include(CMakePackageConfigHelpers)
write_basic_package_version_file(
	"${CMAKE_CURRENT_BINARY_DIR}/LSLConfigVersion.cmake"
	VERSION "${liblsl_VERSION_MAJOR}.${liblsl_VERSION_MINOR}.${liblsl_VERSION_PATCH}"
	COMPATIBILITY AnyNewerVersion
)

set(LSLTargets lsl)
if(LSL_BUILD_STATIC)
	list(APPEND LSLTargets lslobj lslboost)
endif()

install(TARGETS ${LSLTargets}
	EXPORT LSLTargets
	COMPONENT liblsl
	RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
	LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
	ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
	INCLUDES DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
)

export(EXPORT LSLTargets
	FILE "${CMAKE_CURRENT_BINARY_DIR}/LSLTargets.cmake"
	NAMESPACE LSL::
)

install(EXPORT LSLTargets
	FILE LSLTargets.cmake
	COMPONENT liblsl
	NAMESPACE "LSL::"
	DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/LSL
)
configure_file(cmake/LSLConfig.cmake "${CMAKE_CURRENT_BINARY_DIR}/LSLConfig.cmake" COPYONLY)
configure_file(cmake/LSLCMake.cmake "${CMAKE_CURRENT_BINARY_DIR}/LSLCMake.cmake" COPYONLY)


# install headers
install(DIRECTORY include/
	DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
	COMPONENT liblsl
)

install(FILES
	cmake/LSLCMake.cmake
	${CMAKE_CURRENT_BINARY_DIR}/LSLConfig.cmake
	${CMAKE_CURRENT_BINARY_DIR}/LSLConfigVersion.cmake
	COMPONENT liblsl
	DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/LSL
)

include(cmake/LSLCMake.cmake)

add_executable(lslver testing/lslver.c)
target_link_libraries(lslver PRIVATE lsl)
installLSLApp(lslver)

if(NOT WIN32 AND LSL_TOOLS)
	add_executable(blackhole testing/blackhole.cpp)
	target_link_libraries(blackhole PRIVATE Threads::Threads)
	target_include_directories(blackhole PRIVATE "thirdparty/asio/")
	installLSLApp(blackhole)
endif()

set(LSL_INSTALL_ROOT ${CMAKE_CURRENT_BINARY_DIR})
if(LSL_UNITTESTS)
	add_subdirectory(testing)
endif()

if(LSL_BUILD_EXAMPLES)
	add_subdirectory(examples)
endif()

# Security tools
if(LSL_SECURITY AND LSL_SECURITY_TOOLS)
	add_executable(lsl-keygen tools/lsl-keygen.cpp)
	target_link_libraries(lsl-keygen PRIVATE lsl)
	target_compile_definitions(lsl-keygen PRIVATE LSL_SECURITY_ENABLED)
	# Link libsodium for base64 functions
	if(TARGET PkgConfig::SODIUM)
		target_link_libraries(lsl-keygen PRIVATE PkgConfig::SODIUM)
	else()
		target_include_directories(lsl-keygen PRIVATE ${SODIUM_INCLUDE_DIR})
		target_link_libraries(lsl-keygen PRIVATE ${SODIUM_LIBRARY})
	endif()
	installLSLApp(lsl-keygen)

	add_executable(lsl-config tools/lsl-config.cpp)
	target_link_libraries(lsl-config PRIVATE lsl)
	target_compile_definitions(lsl-config PRIVATE LSL_SECURITY_ENABLED)
	if(TARGET PkgConfig::SODIUM)
		target_link_libraries(lsl-config PRIVATE PkgConfig::SODIUM)
	else()
		target_include_directories(lsl-config PRIVATE ${SODIUM_INCLUDE_DIR})
		target_link_libraries(lsl-config PRIVATE ${SODIUM_LIBRARY})
	endif()
	installLSLApp(lsl-config)

	# Interop test binaries for cross-language testing
	add_executable(cpp_secure_outlet tools/cpp_secure_outlet.cpp)
	target_link_libraries(cpp_secure_outlet PRIVATE lsl)
	installLSLApp(cpp_secure_outlet)

	add_executable(cpp_secure_inlet tools/cpp_secure_inlet.cpp)
	target_link_libraries(cpp_secure_inlet PRIVATE lsl)
	installLSLApp(cpp_secure_inlet)

	message(STATUS "Security tools will be built: lsl-keygen, lsl-config, cpp_secure_outlet, cpp_secure_inlet")
endif()

LSLGenerateCPackConfig()
