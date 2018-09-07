# CMakeLists.txt for TlsDecorator
#
# © 2018 by Richard Walters

cmake_minimum_required(VERSION 3.8)
set(This TlsDecorator)

set(Headers
    include/TlsDecorator/TlsDecorator.hpp
    include/TlsDecorator/TlsShim.hpp
)

set(Sources
    src/TlsDecorator.cpp
    src/TlsShim.cpp
)

add_library(${This} STATIC ${Sources} ${Headers})
set_target_properties(${This} PROPERTIES
    FOLDER Libraries
)

target_include_directories(${This} PUBLIC include)

target_link_libraries(${This} PUBLIC
    SystemAbstractions
    tls ssl crypto
)
if (WIN32)
    target_link_libraries(${This} PUBLIC
        Ws2_32.lib
    )
endif (WIN32)

add_subdirectory(test)
