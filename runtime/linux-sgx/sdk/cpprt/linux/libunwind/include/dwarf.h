/* libunwind - a platform-independent unwind library
   Copyright (c) 2003-2005 Hewlett-Packard Development Company, L.P.
        Contributed by David Mosberger-Tang <davidm@hpl.hp.com>

This file is part of libunwind.

Permission is hereby granted, free of charge, to any person obtaining
a copy of this software and associated documentation files (the
"Software"), to deal in the Software without restriction, including
without limitation the rights to use, copy, modify, merge, publish,
distribute, sublicense, and/or sell copies of the Software, and to
permit persons to whom the Software is furnished to do so, subject to
the following conditions:

The above copyright notice and this permission notice shall be
included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.  */

#ifndef dwarf_h
#define dwarf_h

#include <libunwind.h>

struct dwarf_cursor;    /* forward-declaration */

#include "dwarf-config.h"

typedef struct dwarf_cursor
  {
    void *as_arg;               /* argument to address-space callbacks */
    void * /* unw_addr_space_t */ as;        /* reference to per-address-space info */

    unw_word_t cfa;     /* canonical frame address; aka frame-/stack-pointer */
    unw_word_t ip;              /* instruction pointer */
    unw_word_t args_size;       /* size of arguments */
    unw_word_t eh_args[UNW_TDEP_NUM_EH_REGS];
    unsigned int eh_valid_mask;

    dwarf_loc_t loc[DWARF_NUM_PRESERVED_REGS];

    unsigned int stash_frames :1; /* stash frames for fast lookup */
    unsigned int use_prev_instr :1; /* use previous (= call) or current (= signal) instruction? */
    unsigned int pi_valid :1;   /* is proc_info valid? */
    unsigned int pi_is_dynamic :1; /* proc_info found via dynamic proc info? */
    unw_proc_info_t pi;         /* info about current procedure */

    short hint; /* faster lookup of the rs cache */
    short prev_rs;
  }
dwarf_cursor_t;

#endif /* dwarf_h */
