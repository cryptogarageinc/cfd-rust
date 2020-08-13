if(CMAKE_JS_INC)
option(ENABLE_SHARED "enable shared library (ON or OFF. default:ON)" ON)
else()
option(ENABLE_SHARED "enable shared library (ON or OFF. default:OFF)" OFF)
endif()
option(ENABLE_ELEMENTS "enable elements code (ON or OFF. default:ON)" ON)
option(ENABLE_TESTS "enable code tests (ON or OFF. default:ON)" ON)
option(ENABLE_EMSCRIPTEN "enable EMSCRIPTEN (ON or OFF. default:OFF)" OFF)

# use "cmake -DCMAKE_BUILD_TYPE=Debug" or "cmake-js -D"
# option(ENABLE_DEBUG "enable debugging (ON or OFF. default:OFF)" OFF)

if(NOT WIN32)
#option(TARGET_RPATH "target rpath list (separator is ';') (default:)" "")
set(TARGET_RPATH "" CACHE STRING "target rpath list (separator is ';') (default:)")
option(ENABLE_COVERAGE "enable code coverage (ON or OFF. default:OFF)" OFF)
option(ENABLE_RPATH "enable rpath (ON or OFF. default:ON)" ON)
else()
set(TARGET_RPATH "")
set(ENABLE_COVERAGE FALSE)
set(ENABLE_RPATH off)
endif()

if("${CMAKE_BUILD_TYPE}" STREQUAL "Debug")
set(ENABLE_DEBUG  TRUE)
set_property(DIRECTORY APPEND PROPERTY COMPILE_DEFINITIONS $<$<CONFIG:Debug>:DEBUGBUILD>)
if(ENABLE_COVERAGE AND ${ENABLE_COVERAGE})
set(STACK_PROTECTOR_OPT  "")
else()
set(STACK_PROTECTOR_OPT  $<IF:$<CXX_COMPILER_ID:MSVC>,/GS,-fstack-check -fstack-protector>)
endif()
else()
set(ENABLE_DEBUG  FALSE)
set(STACK_PROTECTOR_OPT  "")
endif() # CMAKE_BUILD_TYPE

if(NOT WIN32)
if(ENABLE_RPATH)
set(CMAKE_SKIP_BUILD_RPATH  FALSE)
if(APPLE)
set(CMAKE_MACOSX_RPATH 1)
else()
set(CMAKE_BUILD_RPATH_USE_ORIGIN TRUE)
endif()
set(CMAKE_BUILD_WITH_INSTALL_RPATH TRUE)
set(CMAKE_INSTALL_RPATH_USE_LINK_PATH TRUE)

if(TARGET_RPATH)
if(APPLE)
string(REPLACE "\$\$ORIGIN" "." TEMP_RPATH1 "${TARGET_RPATH}")
string(REPLACE "\$ORIGIN" "." TEMP_RPATH2 "${TEMP_RPATH1}")
string(REPLACE "\$\${ORIGIN}" "." TEMP_RPATH3 "${TEMP_RPATH2}")
string(REPLACE "\${ORIGIN}" "." MODIFIED_RPATH "${TEMP_RPATH3}")
set(CMAKE_INSTALL_RPATH "${MODIFIED_RPATH};./;./build/${RPATH_TARGET};@rpath")
else()
string(REPLACE "\$\${ORIGIN}" "$$ORIGIN" TEMP_RPATH1 "${TARGET_RPATH}")
string(REPLACE "\${ORIGIN}" "$ORIGIN" MODIFIED_RPATH "${TEMP_RPATH1}")
set(CMAKE_INSTALL_RPATH "${MODIFIED_RPATH};$ORIGIN/;./;./build/${RPATH_TARGET};@rpath")
endif()
else(TARGET_RPATH)
if(APPLE)
set(CMAKE_INSTALL_RPATH "./;./build/${RPATH_TARGET};@rpath")
else()
set(CMAKE_INSTALL_RPATH "$ORIGIN/;./;./build/${RPATH_TARGET};@rpath")
endif()
endif(TARGET_RPATH) 
# message(STATUS "CMAKE_INSTALL_RPATH is => ${CMAKE_INSTALL_RPATH}")
else()
set(CMAKE_SKIP_BUILD_RPATH  TRUE)
endif()
endif()

if(NOT ENABLE_ELEMENTS)
set(ELEMENTS_COMP_OPT "")
set(CFD_ELEMENTS_USE   CFD_DISABLE_ELEMENTS)
else()
set(ELEMENTS_COMP_OPT  BUILD_ELEMENTS)
set(CFD_ELEMENTS_USE   "")
endif()

if(NOT ENABLE_EMSCRIPTEN)
set(USE_EMSCRIPTEN  FALSE)
set(EMSCRIPTEN_OPT  "")
else()
set(USE_EMSCRIPTEN  TRUE)
set(EMSCRIPTEN_OPT  "")
#set(EMSCRIPTEN_OPT  "-fwasm-exceptions")
endif()