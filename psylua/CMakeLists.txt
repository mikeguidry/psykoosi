
add_custom_command(
    OUTPUT psy_wrap.cxx
    COMMAND ${PROJECT_BINARY_DIR}/depends/swig/swig -c++ -lua -o ${PROJECT_BINARY_DIR}/psylua/psy_wrap.cxx ${PROJECT_SOURCE_DIR}/psykoosi_lib/psy.i
    DEPENDS ${PROJECT_SOURCE_DIR}/psykoosi_lib/psy.i)

add_executable (psylua
                        main.cpp
                        psy_wrap.cxx)

add_dependencies(psylua swig)

target_link_libraries(psylua psykoosi_lib lua)
