cmake_minimum_required(VERSION 3.16)
project(swm_sdk LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

include(FetchContent)
FetchContent_Declare(
  cpr
  GIT_REPOSITORY https://github.com/libcpr/cpr.git
  GIT_TAG 1.11.0
)
FetchContent_Declare(
  nlohmann_json
  GIT_REPOSITORY https://github.com/nlohmann/json.git
  GIT_TAG v3.11.3
)
FetchContent_MakeAvailable(cpr nlohmann_json)

add_library(swm_sdk src/client.cpp)

target_include_directories(swm_sdk PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)

target_link_libraries(swm_sdk PUBLIC cpr::cpr nlohmann_json::nlohmann_json)
