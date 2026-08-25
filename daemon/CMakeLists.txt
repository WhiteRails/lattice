cmake_minimum_required(VERSION 3.20)
project(latticed VERSION 0.1.0 LANGUAGES C)

include(GNUInstallDirs)

set(CMAKE_C_STANDARD 17)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)

add_executable(latticed src/latticed.c)
find_package(OpenSSL 3 REQUIRED COMPONENTS Crypto)
target_include_directories(latticed PRIVATE include)
target_compile_options(latticed PRIVATE -Wall -Wextra -Wpedantic -Werror)
target_link_libraries(latticed PRIVATE OpenSSL::Crypto)
target_compile_definitions(latticed PRIVATE LATTICE_VERSION="${PROJECT_VERSION}")

install(TARGETS latticed RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
install(FILES latticed.conf.example DESTINATION ${CMAKE_INSTALL_SYSCONFDIR}/lattice)
install(FILES systemd/latticed.service DESTINATION ${CMAKE_INSTALL_LIBDIR}/systemd/system)
