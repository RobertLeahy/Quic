quic_add_library(core
                 SOURCES packet.cpp
                 LIBRARIES Boost::boost
                           Boost::system)
add_subdirectory(tests)
