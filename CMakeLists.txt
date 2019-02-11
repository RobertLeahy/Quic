cmake_minimum_required(VERSION 3.8 FATAL_ERROR)
project(quic LANGUAGES CXX)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED 1)
set(CMAKE_WINDOWS_EXPORT_ALL_SYMBOLS ON)
add_definitions(-DBOOST_ALL_NO_LIB)
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)
set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "${CMAKE_CURRENT_LIST_DIR}/cmake/modules")
include(cmake/QuicFind.cmake)
find_package(Catch2)
find_package(Doxygen)
include(GNUInstallDirs)
if(Catch2_FOUND)
  enable_testing()
endif()
include(cmake/Functions.cmake)
include(cmake/Doxygen.cmake)
add_subdirectory(src)
install(EXPORT QuicTargets
        DESTINATION share/Quic/cmake
        NAMESPACE Quic::)
install(FILES cmake/QuicFind.cmake
              cmake/QuicConfig.cmake
              cmake/modules/FindBoost.cmake
              cmake/modules/FindSockets.cmake
        DESTINATION share/Quic/cmake)
