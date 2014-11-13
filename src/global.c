/***********************************************************************\
*
* $Revision: 925 $
* $Date: 2012-04-28 12:48:49 +0200 (Sat, 28 Apr 2012) $
* $Author: torsten $
* Contents: global definitions
* Systems: Linux
*
\***********************************************************************/

/****************************** Includes *******************************/
#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <assert.h>

#include "global.h"

/****************** Conditional compilation switches *******************/

/***************************** Constants *******************************/

/**************************** Datatypes ********************************/

/**************************** Variables ********************************/

/****************************** Macros *********************************/

/**************************** Functions ********************************/

#ifdef __cplusplus
extern "C" {
#endif

void __halt(const char   *filename,
            unsigned int lineNb,
            int          exitcode,
            const char   *format,
            ...
           )
{
  va_list arguments;

  assert(filename != NULL);
  assert(format != NULL);

  va_start(arguments,format);
  vfprintf(stderr,format,arguments);
  va_end(arguments);
  fprintf(stderr," - halt in file %s, line %d\n", filename, lineNb);
  exit(exitcode);
}

void __abort(const char   *filename,
             unsigned int lineNb,
             const char   *prefix,
             const char   *format,
             ...
            )
{
  va_list arguments;

  assert(filename != NULL);
  assert(format != NULL);

  if (prefix != NULL) fprintf(stderr,"%s", prefix);
  va_start(arguments,format);
  vfprintf(stderr,format,arguments);
  va_end(arguments);
  fprintf(stderr," - program aborted in file %s, line %d\n", filename, lineNb);
  abort();
}

#ifndef NDEBUG
void dumpMemory(const void *address, uint length)
{
  const byte *p;
  uint       z,i;

  z = 0;
  while (z < length)
  {
    p = (const byte*)address+z;
    printf("%08lx:%08lx  ",(unsigned long)p,(unsigned long)(p-(byte*)address));

    for (i = 0; i < 16; i++)
    {
      if ((z+i) < length)
      {
        p = (const byte*)address+z+i;
        printf("%02x ",((uint)(*p)) & 0xFF);
      }
      else
      {
        printf("   ");
      }
    }
    printf("  ");

    for (i = 0; i < 16; i++)
    {
      if ((z+i) < length)
      {
        p = (const byte*)address+z+i;
        printf("%c",isprint((int)(*p))?(*p):'.');
      }
      else
      {
      }
    }
    printf("\n");

    z += 16;
  }
}
#endif /* NDEBUG */

#ifdef __cplusplus
}
#endif

/* end of file */
