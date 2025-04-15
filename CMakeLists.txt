cmake_minimum_required(VERSION 3.19)

file(READ "${CMAKE_SOURCE_DIR}/VERSION" VER_RAW)
string(STRIP ${VER_RAW} VER)

project(
    checkpoint
    DESCRIPTION "Tiny reverse proxy that attempts to block AI scrapers"
    VERSION ${VER}
)

set(CHECKPOINT_VERSION ${VER})
set(PISTACHE_BUILD_TESTS OFF)
set(PISTACHE_BUILD_FUZZ OFF)

add_subdirectory(subprojects/pistache)
add_subdirectory(subprojects/fmt)
add_subdirectory(subprojects/tinylates)
add_subdirectory(subprojects/glaze)

file(GLOB_RECURSE SRCFILES CONFIGURE_DEPENDS "src/*.cpp")

set(CMAKE_CXX_STANDARD 23)

add_executable(checkpoint ${SRCFILES})

add_compile_options(-Wno-deprecated-declarations -Wno-deprecated)
add_compile_definitions(CHECKPOINT_VERSION="${CHECKPOINT_VERSION}")

find_package(PkgConfig REQUIRED)

pkg_check_modules(deps IMPORTED_TARGET openssl)

target_include_directories(checkpoint
PRIVATE
   "./subprojects/pistache/include"
   "./subprojects/glaze/include"
   "./subprojects/re2/include"
   "./subprojects/tinylates/include"
   "./subprojects/pistache/subprojects/cpp-httplib"
   "./subprojects/pistache/subprojects/hinnant-date/include"
)
target_link_libraries(checkpoint
    PkgConfig::deps
    pistache
    fmt
    re2
    tinylates
)
