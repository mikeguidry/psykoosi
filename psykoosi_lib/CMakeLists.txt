
add_library (psykoosi_lib
                        analysis.cpp
                        disassemble.cpp
                        fileformats.cpp
                        loading.cpp
                        logging.cpp
                        modules.cpp
                        rebuild.cpp
                        utilities.cpp
                        virtualmemory.cpp
                        psykoosi.cpp
                        emulation.cpp
                        xen/x86_emulate.c
                        )

target_link_libraries(psykoosi_lib pe_bliss capstone-static udis86)
