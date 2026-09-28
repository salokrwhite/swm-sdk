cmake_minimum_required(VERSION 3.24)

project(swm_sdk VERSION 2.0.0 LANGUAGES C CXX)

option(SWM_SDK_BUILD_TESTS "Build SwmSdk C++ tests" ON)
option(SWM_SDK_INSTALL "Install SwmSdk C++ package" ON)

add_library(swm_monocypher STATIC
    third_party/monocypher/monocypher.c
    third_party/monocypher/monocypher-ed25519.c
)
target_include_directories(swm_monocypher PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/third_party/monocypher>
)
target_compile_definitions(swm_monocypher PRIVATE
    _CRT_SECURE_NO_WARNINGS
)

add_library(swm_sdk STATIC
    src/client.cpp
    src/error.cpp
    src/internal/common.cpp
    src/internal/crypto.cpp
    src/internal/device_identity.cpp
    src/internal/hardware_evidence.cpp
    src/internal/host_integrity.cpp
    src/internal/http_client.cpp
    src/internal/multipart.cpp
    src/internal/operation.cpp
    src/internal/request_pipeline.cpp
    src/internal/rim2.cpp
    src/internal/state_store.cpp
    src/internal/trusted_clock.cpp
)
add_library(swm::sdk ALIAS swm_sdk)
set_target_properties(swm_sdk PROPERTIES EXPORT_NAME sdk)

target_compile_features(swm_sdk PUBLIC cxx_std_20)
target_compile_definitions(swm_sdk PUBLIC
    NOMINMAX
    WIN32_LEAN_AND_MEAN
    _WIN32_WINNT=0x0601
)
target_compile_options(swm_sdk PRIVATE
    $<$<CXX_COMPILER_ID:MSVC>:/W4 /permissive- /Zc:__cplusplus>
)
target_include_directories(swm_sdk PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/third_party>
    $<INSTALL_INTERFACE:include>
)
target_include_directories(swm_sdk PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/src
    ${CMAKE_CURRENT_SOURCE_DIR}/third_party/nlohmann
)
target_link_libraries(swm_sdk
    PUBLIC swm_monocypher
    PRIVATE bcrypt crypt32 ncrypt winhttp iphlpapi ws2_32)

if (MSVC)
    target_compile_options(swm_sdk PRIVATE /utf-8)
endif()

if (SWM_SDK_BUILD_TESTS)
    enable_testing()
    add_subdirectory(tests)
endif()

if (SWM_SDK_INSTALL)
    include(GNUInstallDirs)
    include(CMakePackageConfigHelpers)

    install(TARGETS swm_sdk swm_monocypher
        EXPORT swm_sdkTargets
        ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
        PUBLIC_HEADER DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})
    install(DIRECTORY include/ DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})
    install(FILES third_party/nlohmann/json.hpp
        DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/nlohmann)

    write_basic_package_version_file(
        "${CMAKE_CURRENT_BINARY_DIR}/swm_sdkConfigVersion.cmake"
        VERSION ${PROJECT_VERSION}
        COMPATIBILITY SameMajorVersion)
    configure_package_config_file(
        cmake/swm_sdkConfig.cmake.in
        "${CMAKE_CURRENT_BINARY_DIR}/swm_sdkConfig.cmake"
        INSTALL_DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/swm_sdk)

    install(EXPORT swm_sdkTargets
        FILE swm_sdkTargets.cmake
        NAMESPACE swm::
        DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/swm_sdk)
    install(FILES
        "${CMAKE_CURRENT_BINARY_DIR}/swm_sdkConfig.cmake"
        "${CMAKE_CURRENT_BINARY_DIR}/swm_sdkConfigVersion.cmake"
        DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/swm_sdk)
    install(FILES README.md THIRD_PARTY_NOTICES.md DESTINATION share/swm_sdk)
    install(FILES third_party/monocypher/LICENCE.md
        DESTINATION share/swm_sdk/licenses/monocypher)
    install(FILES third_party/nlohmann/LICENSE.MIT
        DESTINATION share/swm_sdk/licenses/nlohmann)
endif()
