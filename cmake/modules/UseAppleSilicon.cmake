#
# - Handle Apple Silicon

execute_process(
	COMMAND uname -m
	OUTPUT_VARIABLE UNAME_ARCHITECTURE
)
string(STRIP "${UNAME_ARCHITECTURE}" UNAME_ARCHITECTURE)

execute_process(
	COMMAND sysctl hw.optional.arm64
	OUTPUT_VARIABLE SYSCTL_IS_ARM
	ERROR_QUIET
)
string(REGEX MATCH "hw\\.optional\\.arm64: 1" APPLE_HARDWARE "${SYSCTL_IS_ARM}")

set(APPLE_ARCHITECTURE "${UNAME_ARCHITECTURE}")
if (${UNAME_ARCHITECTURE} STREQUAL "x86_64" AND "${APPLE_HARDWARE}")
	# this is a build running on a translated system
	message(STATUS "Building with Rosetta 2 for ${APPLE_ARCHITECTURE}")
else()
	# this is a native build on either arm64 or x86{_64}
	message(STATUS "Building native for ${APPLE_ARCHITECTURE}")

	# cmake 3.18.0 is the first version cappable of building
	# on Apple Silicon
	if (${UNAME_ARCHITECTURE} STREQUAL "arm64")
		if (${CMAKE_VERSION} VERSION_LESS "3.18.0")
			message(FATAL_ERROR "Compiling for Apple Silicon requires at least CMake 3.18 or higher.")
		endif()
	endif()

endif()

set(CMAKE_OSX_ARCHITECTURES "${APPLE_ARCHITECTURE}")
