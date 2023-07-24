cmake_minimum_required(VERSION 3.13)

project(IDASH23)


set(CMAKE_CXX_FLAGS "-Wall")
set(CMAKE_CXX_STANDARD 17)

# Import Microsoft SEAL

find_package(SEAL 4.1.1 EXACT REQUIRED
              PATHS /usr/local # for Linux
              PATHS /opt/homebrew/Cellar # for Mac OS
            ) 


set(IDASH_SOURCE_DIR ${PROJECT_SOURCE_DIR}/larc_v2)

add_executable(IDASH23 
                ${IDASH_SOURCE_DIR}/main.cpp
                ${IDASH_SOURCE_DIR}/utils.cpp)
                
                    
if(TARGET SEAL::seal)
    target_link_libraries(IDASH23 SEAL::seal)
elseif(TARGET SEAL::seal_shared)
    target_link_libraries(IDASH23 SEAL::seal_shared)
else()
    message(FATAL_ERROR "Cannot find target SEAL::seal or SEAL::seal_shared")
endif()
