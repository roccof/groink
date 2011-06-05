/*
 * Copyright (c) Denatured Ethyl Crew
 *
 * This file is part of GroinK.
 *
 * GroinK is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * GroinK is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with GroinK.  If not, see <http://www.gnu.org/licenses/>.
 */
#include <stdlib.h>
#include <lua.h>
#include <lualib.h>
#include <lauxlib.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>

#include "script_engine.h"
#include "base.h"
#include "debug.h"
#include "globals.h"
#include "hook.h"
#include "selib.h"
#include "packet.h"

#define INIT_SCRIPT GROINK_DATADIR"/selib/script_engine.lua"
#define DEFAULT_SCRIPT "default"

static int se_panic(lua_State *L)
{
  se_fatal("%s", (char *)lua_tostring(gbls->L, -1));
  return 0;
}

static void open_clib(lua_State *L)
{
  se_open_packet(L);
  se_open_header(L);
  se_open_core(L);
  se_open_bit(L);
  se_open_netutil(L);
  se_open_constants(L);
}

char *append_script_dir(char *script_name)
{
  if (gbls->scripts_dir == NULL) {
    
    return str_concat(GROINK_DATADIR"/"SCRIPT_DIR"/", script_name, SCRIPT_EXT, NULL);
    
  } else {
    
    if (gbls->scripts_dir[0] == '/') {
      
      if ((gbls->scripts_dir)[strlen(gbls->scripts_dir) - 1] == '/')
	return str_concat(gbls->scripts_dir, script_name, SCRIPT_EXT, NULL);
      else
	return str_concat(gbls->scripts_dir, "/", script_name, SCRIPT_EXT, NULL);
      
    } else if (gbls->scripts_dir[0] == '.' && gbls->scripts_dir[1] == '/') {
      
      char *cwd = getcwd(NULL, 0);
      char *path = NULL;
      
      if ((gbls->scripts_dir)[strlen(gbls->scripts_dir) - 1] == '/')
	path = str_concat(cwd, "/", (gbls->scripts_dir + 2), script_name, 
			  SCRIPT_EXT, NULL);
      else
	path = str_concat(cwd, "/", (gbls->scripts_dir + 2), "/", script_name, 
			  SCRIPT_EXT, NULL);
      
      free(cwd);
      return path;
      
    } else {
      
      char *cwd = getcwd(NULL, 0);
      char *path = NULL;
      
      if ((gbls->scripts_dir)[strlen(gbls->scripts_dir) - 1] == '/')
	path = str_concat(cwd, "/", gbls->scripts_dir, script_name, 
			  SCRIPT_EXT, NULL);
      else
	path = str_concat(cwd, "/", gbls->scripts_dir, "/", script_name, 
			  SCRIPT_EXT, NULL);
      
      free(cwd);
      return path;
    }
  }
}

static void se_pushargs(lua_State *L)
{
  int i = 0;
  char *saveptr = NULL;

  lua_newtable(L);

  while (i < gbls->script_argc) {
    char *arg_tok = NULL;
    char *dup = strdup(gbls->script_argv[i++]);
    
    /* Arg name */
    arg_tok = strtok_r(dup, "=", &saveptr);
    lua_pushstring(L, arg_tok);
    
    /* Arg value */
    arg_tok = strtok_r(NULL, "=", &saveptr);
    lua_pushstring(L, arg_tok);

    lua_settable(L, -3);
    
    free(dup);
  }
}

static int se_init(lua_State *L)
{
  char *script = NULL;

  script = (char *)luaL_checkstring(L, 1);

  lua_settop(L, 0); /* Clear the stack */

  /* Push the script args into the registry */
  se_pushargs(L);
  lua_setfield(L, LUA_REGISTRYINDEX, SE_ARGV);
  lua_pushnumber(L, gbls->script_argc);
  lua_setfield(L, LUA_REGISTRYINDEX, SE_ARGC);

  lua_getglobal(L, "debug");
  myassert(!lua_isnil(L, -1));
  lua_getfield(L, -1, "traceback");
  myassert(!lua_isnil(L, -1));
  lua_replace(L, 1);  /* Stack pos 1: traceback function */

  /* Save a copy of traceback function into the registry */
  lua_pushvalue(L, 1);
  lua_setfield(L, LUA_REGISTRYINDEX, SE_TRACEBACK);

  /* Stack pos 2: script_engine.lua code */
  if (luaL_loadfile(L, INIT_SCRIPT) != 0) {
    luaL_error(L, "could not load script_engine.lua: %s", lua_tostring(L, -1));
  }

  /* Stack pos 3: script that will be executed */
  lua_pushstring(L, script);

  /* Stack pos 4: selib path */
  lua_pushstring(L, GROINK_DATADIR"/selib/");

  /* 
   * Run main script that initialize the engine and 
   * execute the selected script
   */
  if(lua_pcall(L, 2, 0, 1) != 0)
    lua_error(L);

  return 0;
}

static void proc_pkt_cb(hookdata_t *data)
{
  myassert(gbls->L != NULL);
  myassert(data != NULL && data->type == HOOKDATA_PACKET);

  /* Stack pos 1: traceback function */
  lua_getfield(gbls->L, LUA_REGISTRYINDEX, SE_TRACEBACK);

  /* Stack pos 2: proc_pkt function in the script */
  lua_getfield(gbls->L, LUA_REGISTRYINDEX, SE_PROC_PKT);

  se_pushobject(gbls->L, (packet_t *)data->data, SE_OBJ_TYPE_PACKET, 
		SE_OBJ_NAME_PACKET);

  if (lua_pcall(gbls->L, 1, 0, 1) != 0)
      lua_error(gbls->L);
  
  lua_settop(gbls->L, 0); /* Clear the stack */
}

static void se_run()
{
  myassert(gbls->L != NULL);

  se_debug("running script '%s'", gbls->script);

  /* Stack pos 1: traceback function */
  lua_getfield(gbls->L, LUA_REGISTRYINDEX, SE_TRACEBACK);

  /* Stack pos 2: init function in the script */
  lua_getfield(gbls->L, LUA_REGISTRYINDEX, SE_INIT);

  if (!lua_isnil(gbls->L, 2))
    if (lua_pcall(gbls->L, 0, 0, 1) != 0)
      lua_error(gbls->L);
  
  lua_settop(gbls->L, 0); /* Clear the stack */

  /* Register hook for SE_PROC_PKT */
  hook_register(HOOK_RECEIVED, proc_pkt_cb);
}

void se_open()
{
  myassert(gbls->L == NULL);

  debug("starting script engine...");

  /* Start lua */
  gbls->L = luaL_newstate();

  /* Set panic callback function */
  lua_atpanic(gbls->L, &se_panic);

  /* Open lua libraries */
  luaL_openlibs(gbls->L);
  debug("loaded lua libraries");

  /* Open C libraries */
  open_clib(gbls->L);
  debug("loaded C libraries");  

 /* If not setted, set default script */
  if(gbls->script == NULL)
      gbls->script = append_script_dir(DEFAULT_SCRIPT);

  /**** Start the engine ****/

  lua_pushcfunction(gbls->L, &se_init);
  lua_pushstring(gbls->L, gbls->script);

  if(lua_pcall(gbls->L, 1, 0, 0) != 0)
    se_fatal("%s", lua_tostring(gbls->L, -1));

  lua_settop(gbls->L, 0); /* Clear the stack */

  /* Run the script */
  se_run();
}

void se_close()
{
  if(gbls->L == NULL)
    return;

  /* Unregister hook for SE_PROC_PKT */
  hook_unregister(HOOK_RECEIVED, proc_pkt_cb);

  lua_settop(gbls->L, 0); /* Clear the stack */

  /*** Call cleanup script function ***/

  /* Stack pos 1: traceback function */
  lua_getfield(gbls->L, LUA_REGISTRYINDEX, SE_TRACEBACK);

  /* Stack pos 2: callback function */
  lua_getfield(gbls->L, LUA_REGISTRYINDEX, SE_CLEANUP);

  if(!lua_isnil(gbls->L, 2))
    if(lua_pcall(gbls->L, 0, 0, 1) != 0)
	se_fatal("%s", lua_tostring(gbls->L, -1));

  /* Performs a full garbage-collection cycle */
  lua_getglobal(gbls->L, "collectgarbage");
  myassert(!lua_isnil(gbls->L, -1));
  lua_pushstring(gbls->L, "collect");
  lua_pcall(gbls->L, 1, 0, 1);

  /* Close lua */
  lua_close(gbls->L);
  gbls->L = NULL;

  debug("script engine closed");
}
