
add_executable (psykoosi
                        analysis.cpp
                        disassemble.cpp
			polymorph.cpp
                        fileformats.cpp
                        loading.cpp
                        logging.cpp
                        main.cpp
                        modules.cpp
                        rebuild.cpp
                        utilities.cpp
                        virtualmemory.cpp
			emulation.cpp
			xen/x86_emulate.c
			apiproxy_client.cpp
                        )
target_link_libraries(psykoosi pe_bliss capstone-static udis86)

add_executable (fuzz
                        analysis.cpp
                        disassemble.cpp
                        polymorph.cpp
                        fileformats.cpp
                        emu_hooks.cpp
                        loading.cpp
                        logging.cpp
                        fuzz.cpp
                        modules.cpp
                        rebuild.cpp
                        utilities.cpp
                        virtualmemory.cpp
                        emulation.cpp
                        xen/x86_emulate.c
			apiproxy_client.cpp
                        )

target_link_libraries(fuzz pe_bliss capstone-static udis86)
