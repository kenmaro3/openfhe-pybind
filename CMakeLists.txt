cmake_minimum_required (VERSION 3.5.1)
set(pybind11_DIR /home/kmihara/.pyenv/versions/3.7.4/envs/myenv/lib/python3.7/site-packages/pybind11)


project(demo CXX)
set(CMAKE_CXX_STANDARD 17)
option( BUILD_STATIC "Set to ON to include static versions of the library" OFF)

find_package(OpenFHE)

set( CMAKE_CXX_FLAGS ${OpenFHE_CXX_FLAGS} )

add_subdirectory(pybind11)

include_directories( ${OPENMP_INCLUDES} )
include_directories( ${OpenFHE_INCLUDE} )
include_directories( ${OpenFHE_INCLUDE}/third-party/include )
include_directories( ${OpenFHE_INCLUDE}/core )
include_directories( ${OpenFHE_INCLUDE}/pke )
### add directories for other OpenFHE modules as needed for your project

link_directories( ${OpenFHE_LIBDIR} )
link_directories( ${OPENMP_LIBRARIES} )
if(BUILD_STATIC)
    set( CMAKE_EXE_LINKER_FLAGS "${OpenFHE_EXE_LINKER_FLAGS} -static")
    link_libraries( ${OpenFHE_STATIC_LIBRARIES} )
else()
    set( CMAKE_EXE_LINKER_FLAGS ${OpenFHE_EXE_LINKER_FLAGS} )
    link_libraries( ${OpenFHE_SHARED_LIBRARIES} )
endif()

pybind11_add_module(openfhe_pybind
	src/test.cpp
	)

target_include_directories(openfhe_pybind
	PUBLIC ${PROJECT_SOURCE_DIR}
  #${OpenFHE_INCLUDE}
  #${OpenFHE_INCLUDE}/third-party/include
  #${OpenFHE_INCLUDE}/core
  #${OpenFHE_INCLUDE}/pke
)
#target_link_libraries(openfhe_pybind ${OpenFHE_SHARED_LIBRARIES})



#add_subdirectory(thirdparties)

### ADD YOUR EXECUTABLE(s) HERE
### add_executable( EXECUTABLE-NAME SOURCES )
###
### EXAMPLE:
#add_executable( test src/test.cpp )
