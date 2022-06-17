cmake_minimum_required(VERSION 3.20.0)
project(MFRC522)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_library(MFRC522
  "include/mfrc522/MFRC522.hpp"
  "src/MFRC522.cpp"

  "include/mfrc522/SimpleMFRC522.hpp"
  "src/SimpleMFRC522.cpp"
)

target_include_directories(MFRC522 PUBLIC "include")

target_link_libraries(MFRC522 wiringPi)
