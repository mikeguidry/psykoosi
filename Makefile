all:
	g++ -o Debug/psy analysis.cpp disassemble.cpp fileformats.cpp loading.cpp main.cpp modification.cpp rebuild.cpp utilities.cpp virtualmemory.cpp -I/Users/mike/win/portable-executable-library-read-only -I/Users/mike/psykoosi/capstone/include libs/libcapstone.a libs/libpebliss.a -liconv -ludis86 -ggdb
