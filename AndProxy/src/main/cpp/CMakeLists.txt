cmake_minimum_required(VERSION 3.22.1)

project(proxy)

add_library(${CMAKE_PROJECT_NAME} SHARED
        SvcInterceptor.cpp
        seccomp_hook.cpp
        binder_proxy.cpp
        BinderHook.cpp
        BinderProxy.cpp
        elf_utils.cpp
)

target_link_libraries(${CMAKE_PROJECT_NAME}
        android
        log
        dl
)