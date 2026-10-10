cmake_minimum_required(VERSION 3.16)
project(SFUnpacker LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
  set(CMAKE_BUILD_TYPE Release)
endif()

add_library(lzma STATIC
  7zip/C/Alloc.c
  7zip/C/LzmaDec.c
  7zip/C/Lzma2Dec.c
)
target_include_directories(lzma PUBLIC 7zip/C)

add_library(blast STATIC third_party/blast/blast.c)
target_include_directories(blast PUBLIC third_party/blast)

add_executable(sfunpacker
  src/main.cpp
  src/io.cpp
  src/pe.cpp
  src/codec.cpp
  src/installer.cpp
  src/sf7.cpp
  src/sf8.cpp
)
target_link_libraries(sfunpacker PRIVATE lzma blast)

if(MSVC)
  target_compile_options(sfunpacker PRIVATE /W4 /utf-8)
  target_compile_definitions(sfunpacker PRIVATE _CRT_SECURE_NO_WARNINGS)
else()
  target_compile_options(sfunpacker PRIVATE -Wall -Wextra)
endif()
