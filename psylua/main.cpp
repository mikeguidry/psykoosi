/* DO NOT DISTRIBUTE - PRIVATE SOURCE CODE OF MIKE GUIDRY GROUP / UNIFIED DEFENSE TECHNOLOGIES, INC.
 * YOU WILL BE PROSECUTED TO THE FULL EXTENT OF THE LAW IF YOU DISTRIBUTE OR DO NOT DELETE IMMEDIATELY,
 * UNLESS GIVEN PRIOR WRITTEN CONSENT BY MICHAEL GUIDRY, OR BOARD OF UNIFIED DEFENSE TECHNOLOGIES.
 *
 *
 * README CONTAINS INFORMATION
 */
#include <iostream>
#include <string>
#include <stdint.h>
#include <cstring>

#include <psykoosi_lib/psykoosi.h>

#include <unistd.h>

#include <depends/lua/lua.hpp>
#include <depends/lua/lualib.h>
#include <depends/lua/lauxlib.h>

extern "C" {
    int luaopen_psy(lua_State* L); // declare the wrapped module
}
#define LUA_EXTRALIBS {"psy",luaopen_building_construction},

using namespace psykoosi;
using namespace std;

int main(int argc, char *argv[]) {
    if (argc != 2) {
        cerr << "Usage: " << argv[0] << " script.lua\n";
        return 42;
	}

    lua_State *L = luaL_newstate();
    luaopen_base(L);  // load basic libs (eg. print)
    luaL_openlibs(L); // load all the lua libs (gives us math string functions etc.)
    luaopen_psy(L);   // load the wrapped module
    if (luaL_loadfile(L,argv[1])==0) // load and run the file
        lua_pcall(L,0,0,0);
    else
        printf("unable to load %s\n",argv[1]);
    lua_close(L);
    return 0;
}
