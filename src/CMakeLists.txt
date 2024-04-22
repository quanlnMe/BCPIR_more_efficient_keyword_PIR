SET(CMAKE_PREFIX_PATH "~/myseal")
find_package(SEAL 4.1 REQUIRED)

add_library(NEWKEYWORDPIR utils.h pir.h pir.cpp client.h client.cpp server.h server.cpp)
target_link_libraries(NEWKEYWORDPIR SEAL::seal)

add_executable(main main.cpp)

target_link_libraries(main NEWKEYWORDPIR)
