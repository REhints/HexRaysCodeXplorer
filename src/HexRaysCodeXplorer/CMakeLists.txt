cmake_minimum_required(VERSION 3.7)

project(HexRaysCodeXplorer CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

if(APPLE)
  set(CMAKE_CXX_FLAGS ${CMAKE_CXX_FLAGS} "-fPIC -arch x86_64")
else()
  set(CMAKE_CXX_FLAGS ${CMAKE_CXX_FLAGS} "-fPIC")
endif()

list(APPEND CMAKE_MODULE_PATH ${PROJECT_SOURCE_DIR}/../cmake)

find_package(IdaSdk REQUIRED)

set(HexRaysSdk_INCLUDE_DIRS ${HexRaysSdk_ROOT_DIR}/include)

include_directories(${HexRaysSdk_INCLUDE_DIRS})
include_directories(${PROJECT_SOURCE_DIR})

set(src
    "CodeXplorer.cpp"
    "Common.h"
    "CtreeExtractor.cpp"
    "CtreeExtractor.h"
    "CtreeGraphBuilder.cpp"
    "CtreeGraphBuilder.h"
    "Debug.cpp"
    "Debug.h"
    "GCCObjectFormatParser.cpp"
    "GCCObjectFormatParser.h"
    "GCCTypeInfo.cpp"
    "GCCTypeInfo.h"
    "GCCVtableInfo.cpp"
    "GCCVtableInfo.h"
    "IObjectFormatParser.cpp"
    "IObjectFormatParser.h"
    "Linux.h"
    "MSVCObjectFormatParser.cpp"
    "MSVCObjectFormatParser.h"
    "MicrocodeExtractor.cpp"
    "MicrocodeExtractor.h"
    "ObjectExplorer.cpp"
    "ObjectExplorer.h"
    "ReconstructableType.cpp"
    "ReconstructableType.h"
    "TypeExtractor.cpp"
    "TypeExtractor.h"
    "TypeReconstructor.cpp"
    "TypeReconstructor.h"
    "Utility.cpp"
    "Utility.h"
    "gcc_rtti_til.h"
    "reconstructed_place_t.cpp"
    "reconstructed_place_t.h")

add_ida_plugin(HexRaysCodeXplorer ${PROJECT_SOURCE_DIR}/CodeXplorer.cpp)

set_ida_target_properties(HexRaysCodeXplorer PROPERTIES CXX_STANDARD 17)
ida_target_include_directories(HexRaysCodeXplorer PRIVATE
                               ${IdaSdk_INCLUDE_DIRS})

add_ida_library(HexRaysCodeXplorerLib ${src})
ida_target_link_libraries(HexRaysCodeXplorer HexRaysCodeXplorerLib)
