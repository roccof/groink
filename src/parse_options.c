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
#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "config.h"
#include "base.h"
#include "debug.h"
#include "globals.h"
/* #include "netutil.h" */
#include "parse_options.h"
/* #include "script_engine.h" */

static const struct option long_options[] = {
  {"help", no_argument, NULL, 'h'},
  {"version", no_argument, NULL, 'v'},
  {"iface", required_argument, NULL, 'i'},
  {"daemon", no_argument, NULL, 'D'},
  {"mitm", required_argument, NULL, 'M'},
  {"no-promisc", no_argument, NULL, 0},
  {"rfmon", no_argument, NULL, 0},
  {"no-scan", no_argument, NULL, 0},
  {"show-scripts", no_argument, NULL, 0},
  {"scripts-dir", required_argument, NULL, 0},
  {"debug-mode", no_argument, NULL, 0},
  {"cap-timeout", required_argument, NULL, 0},
  {"cap-snaplen", required_argument, NULL, 0},
  {NULL, 0, NULL, 0}
};

static const char *short_options = "hvi:DM:";

static void print_usage(int status)
{
  printf("\nUsage: groink [OPTIONS] [SCRIPT_NAME [ARG1[=VAL1] [ARG2[=VAL2] ...]]]\n");
  printf("OPTIONS:\n");
  printf("  -h, --help                              print this help\n");
  printf("  -v, --version                           print version\n");
  printf("  -i, --iface <iface>                     network interface\n");
  printf("  -D, --daemon                            demonize desniff\n");
  printf("  -M, --mitm <method:options>             perform MiTM attack\n");
  printf("  --rfmon                                 enable monitor mode\n");
  printf("  --no-promisc                            don't set iface in promisc mode\n");
  printf("  --no-scan                               disable host scanning\n");
  printf("  --show-scripts                          show all scripts\n");
  printf("  --scripts-dir                           alternative scripts directory\n");
  printf("  --debug-mode                            enable debug symbol in the script execution\n");
  printf("  --cap-timeout                           packet capture timeout, the default is 0 ms\n");
  printf("  --cap-snaplen                           bytes of data of captured packet, the default is 65535 bytes\n");
  printf("EXAMPLE:\n");
  printf("  groink -i eth0\n");
  printf("  groink -i eth0 dump type=hex\n");
  printf("  groink -M arpp:192.168.0.1 packet_analyzer\n");
  printf("SEE MAN PAGE FOR MORE INFO\n\n");

  exit(status);
}

static void print_version()
{
  printf("%s %s\n", PACKAGE_NAME, VERSION);
  printf("Powered by "COLOR_BOLD"DECrew"COLOR_NORMAL" <http://decrew.indivia.net>\n");
  printf("Please send problems, bugs, questions, desirable enhancements, etc. to: %s\n", PACKAGE_BUGREPORT);
  
  exit(EXIT_SUCCESS);
}

void parse_options(int argc, char **argv)
{
  int next_opt = 0, opt_index = 0;
  char *mitm_tok = NULL;
  char *dup = NULL;
  char *saveptr = NULL;

  /* Option ARGV elements */
  while ((next_opt = getopt_long(argc, argv, short_options, long_options, &opt_index)) != -1) {
    switch (next_opt) {
    case 0:
      if (strcmp(long_options[opt_index].name, "no-promisc") == 0)
	gbls->promisc = 0;
      else if (strcmp(long_options[opt_index].name, "show-scripts") == 0)
	bug("parse_options", "--show-scripts option not implemented yet");
      else if (strcmp(long_options[opt_index].name, "debug-mode") == 0)
	gbls->script_debug_mode = 1;
      else if (strcmp(long_options[opt_index].name, "rfmon") == 0)
	gbls->rfmon = 1;
      else if (strcmp(long_options[opt_index].name, "no-scan") == 0)
	gbls->scan = 0;
      else if (strcmp(long_options[opt_index].name, "scripts-dir") == 0)
	gbls->scripts_dir = (char *)optarg;
      else if (strcmp(long_options[opt_index].name, "cap-timeout") == 0)
	gbls->cap_timeout = atoi(optarg);
      else if (strcmp(long_options[opt_index].name, "cap-snaplen") == 0)
	gbls->snaplen = atoi(optarg);
      else
	fatal(__func__, "'%s' is an invalid option", long_options[opt_index].name);
      break;
	
    case 'h':
      print_usage(0);
      break;
      
    case 'v':
      print_version();
      break;
      
    case 'i':
      gbls->iface = (char *)optarg;
      break;

    case 'M':
      
      /* dup = strdup(optarg); */
      
      /* /\* Get MiTM type attack *\/ */
      /* mitm_tok = strtok_r(dup, ":", &saveptr); */
      /* if (mitm_tok == NULL || !is_valid_mitm_attack(mitm_tok)) { */
      /* 	free(dup); */
      /* 	fatal(__func__, "invalid MiTM attack"); */
      /* } */
      /* gbls->mitm = strdup(mitm_tok); */

      /* /\* Get options *\/ */
      /* mitm_tok = strchr(optarg, ':'); */
      /* if (mitm_tok == NULL) { */
      /* 	free(dup); */
      /* 	fatal(__func__, "you must specify the required options for the MiTM attack"); */
      /* } */
      /* gbls->mitm_options = (mitm_tok + 1); */

      /* free(dup); */
      break;
	
    default:
      print_usage(EXIT_FAILURE);
      break;
    }
  }

  /* Non option ARGV elements */
  /* if(optind < argc) { */
  /*   /\* Get script *\/ */
  /*   char *script = (char *)argv[optind++]; */
    
  /*   if(script[0] == '/') { */
  /*     /\* Absolute path *\/ */
  /*     gbls->script = strdup(script); */
  /*   } else if (script[0] == '.' || index(script, '/') != NULL) { */
  /*     /\* Non-absolute path *\/ */
  /*     char *cwd = getcwd(NULL, 0); */
      
  /*     if (script[0] == '.' && script[1] == '/') */
  /* 	gbls->script = str_concat(cwd, "/", (script + 2), NULL); */
  /*     else */
  /* 	gbls->script = str_concat(cwd, "/", script, NULL); */
      
  /*     free(cwd); */
  /*   } else { */
  /*     /\* Only script name *\/ */
  /*     gbls->script = append_script_dir(script); */
  /*   } */

  /*   if (strlen(gbls->script) > MAX_SCRIPT_NAME) */
  /*     fatal(__func__, "the script name is too big, max %d character", MAX_SCRIPT_NAME); */
    
  /*   opt_index = 0; */

  /*   /\* Get possible script args *\/ */
  /*   while (opt_index < MAX_SCRIPT_ARGS && optind < argc) */
  /*     gbls->script_argv[opt_index++] = (char *)argv[optind++]; */

  /*   gbls->script_argc = opt_index; */
  /* } */
}
