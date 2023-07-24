cmake_minimum_required(VERSION 3.13)

# We must specify the C and C++ compilers before the project command
set(CMAKE_C_COMPILER "/usr/bin/clang")
set(CMAKE_CXX_COMPILER "/usr/bin/clang++")
set(CMAKE_CXX_FLAGS "-Wall")
set(CMAKE_CXX_STANDARD 17)

project(IDASH23)


# Import OpenMP
FIND_PACKAGE( OpenMP REQUIRED)
if(OPENMP_FOUND)
    message("OPENMP FOUND")
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${OpenMP_C_FLAGS}")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${OpenMP_CXX_FLAGS}")
    set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} ${OpenMP_EXE_LINKER_FLAGS}")
endif()

# Import Microsoft SEAL
find_package(SEAL 4.1.1 EXACT REQUIRED
             PATHS /usr/local # for Linux
            ) 


set(IDASH_SOURCE_DIR ${PROJECT_SOURCE_DIR})


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
