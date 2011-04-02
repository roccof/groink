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
#include <execinfo.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <termios.h>
#include <unistd.h>

#include "config.h"
#include "base.h"
#include "debug.h"
#include "globals.h"
#include "threads.h"
#include "rp_queue.h"
#include "capture.h"
#include "parse_options.h"
#include "hook.h"
#include "protos.h"
#include "rp_processor.h"

static struct termios saved_term;

static void cleanup()
{
  debug("cleaning up...");

  /* Restore terminal settings */
  tcsetattr(STDIN_FILENO, TCSANOW, &saved_term);
  debug("terminal restored");

  stop_sniffing();
  stop_rp_processor();

  protos_destroy();
  cleanup_rp_queue();
  capture_engine_destroy();
  threads_manager_destroy();
  hook_cleanup();
  globals_destroy();
}

static void signal_handler_cb(int signal)
{
  if(signal == SIGSEGV) {
#ifdef GROINK_DEBUG    /* Print backtrace */
    void *buffer[10];
    size_t size;
    char **strings;
    int i;
    
    size = backtrace(buffer, 10);
    strings = backtrace_symbols(buffer, size);
    
    printf("[!!] Segmentation fault, please report this to %s\n", PACKAGE_BUGREPORT);    
    printf("Backtrace:\n");
    for(i=0; i<size; i++)
      printf("\t%s\n", strings[i]);
    printf("\n");
    free(strings);
#else
    printf("[!!] Segmentation fault, please report this to %s\n", PACKAGE_BUGREPORT);
#endif /* GROINK_DEBUG */
    
    exit(EXIT_FAILURE);
  } else {
    exit(EXIT_SUCCESS);
  }
}

static void groink_main()
{
  /* Initialization phase */
  threads_manager_init();
  capture_engine_init();
  load_iface_info();
  protos_init();

  /* Start raw packet processor */
  start_rp_processor();

  message(COLOR_BOLD"%s %s"COLOR_NORMAL" started, type "COLOR_BOLD"Q"
	  COLOR_NORMAL" or "COLOR_BOLD"q"COLOR_NORMAL" to quit...", PACKAGE_NAME, VERSION);

  /* Start capturing process */
  start_sniffing();
}

int main(int argc, char **argv)
{
  struct termios term;

  globals_init();

  atexit(&cleanup);

  /* 
   * Set up a terminal device to read single 
   * characters in noncanonical input mode
   */

  tcgetattr(STDIN_FILENO, &saved_term);
  term = saved_term;

  /* Clear ICANON and ECHO. */
  term.c_lflag &= ~(ICANON | ECHO);
  term.c_cc[VMIN] = 1;
  term.c_cc[VTIME] = 0;
 
  tcsetattr(STDIN_FILENO, TCSANOW, &term);

  parse_options(argc, argv);
  
  /* Register signals */
  signal(SIGINT, &signal_handler_cb);
  signal(SIGTERM, &signal_handler_cb);
  signal(SIGSEGV, &signal_handler_cb);

  groink_main();

  while(1) {
    char c = getchar();
    
    switch(c) {
    case 'q':   /* Quit GroinK */
    case 'Q':
      goto end;
      break;
    }
  }
  
 end: 
  return EXIT_SUCCESS;
}
