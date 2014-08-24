
add_custom_command(
    OUTPUT psykoosi_wrap.cxx
    COMMAND ${PROJECT_BINARY_DIR}/depends/swig/swig -c++ -lua -o ${PROJECT_BINARY_DIR}/psylua/psykoosi_wrap.cxx ${PROJECT_SOURCE_DIR}/psykoosi_lib/psykoosi.i
    DEPENDS ${PROJECT_SOURCE_DIR}/psykoosi_lib/psykoosi.i)

add_executable (psylua
                        main.cpp
                        psykoosi_wrap.cxx)

add_dependencies(psylua swig)

target_link_libraries(psylua psykoosi_lib lua)
