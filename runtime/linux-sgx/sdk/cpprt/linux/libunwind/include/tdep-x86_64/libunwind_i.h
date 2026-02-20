/* libunwind - a platform-independent unwind library
   Copyright (C) 2002-2005 Hewlett-Packard Co
        Contributed by David Mosberger-Tang <davidm@hpl.hp.com>

   Modified for x86_64 by Max Asbock <masbock@us.ibm.com>

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

#ifndef X86_64_LIBUNWIND_I_H
#define X86_64_LIBUNWIND_I_H

/* Target-dependent definitions that are internal to libunwind but need
   to be shared with target-independent code.  */

#include <stdlib.h>
#include <libunwind.h>

#include "dwarf.h"

typedef struct
  {
    uint64_t virtual_address;
    int64_t frame_type     : 3;  /* unw_tdep_frame_type_t classification */
    int64_t last_frame     : 1;  /* non-zero if last frame in chain */
    int64_t cfa_reg_rsp    : 1;  /* cfa dwarf base register is rsp vs. rbp */
    int64_t cfa_reg_offset : 29; /* cfa is at this offset from base register value */
    int64_t rbp_cfa_offset : 15; /* rbp saved at this offset from cfa (-1 = not saved) */
    int64_t rsp_cfa_offset : 15; /* rsp saved at this offset from cfa (-1 = not saved) */
  }
unw_tdep_frame_t;

struct cursor
  {
    struct dwarf_cursor dwarf;          /* must be first */

    unw_tdep_frame_t frame_info;        /* quick tracing assist info */

    /* Format of sigcontext structure and address at which it is
       stored: */
    enum
      {
        X86_64_SCF_NONE,                /* no signal frame encountered */
        X86_64_SCF_LINUX_RT_SIGFRAME,   /* Linux ucontext_t */
        X86_64_SCF_FREEBSD_SIGFRAME,    /* FreeBSD signal frame */
        X86_64_SCF_FREEBSD_SYSCALL,     /* FreeBSD syscall */
      }
    sigcontext_format;
    unw_word_t sigcontext_addr;
    int validate;
    ucontext_t *uc;
  };

#endif /* X86_64_LIBUNWIND_I_H */
