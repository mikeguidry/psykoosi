
add_executable (psykoosi
                        analysis.cpp
                        disassemble.cpp
                        fileformats.cpp
                        loading.cpp
                        logging.cpp
                        main.cpp
                        modules.cpp
                        rebuild.cpp
                        utilities.cpp
                        virtualmemory.cpp
                        )

target_link_libraries(psykoosi pe_bliss capstone-static udis86)
