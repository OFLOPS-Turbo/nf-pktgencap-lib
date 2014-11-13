/***********************************************************************\
*
* $Revision: 928 $
* $Date: 2012-04-28 12:50:09 +0200 (Sat, 28 Apr 2012) $
* $Author: torsten $
* Contents: ring buffer functions
* Systems: all
*
\***********************************************************************/

#ifndef __RINGBUFFERS__
#define __RINGBUFFERS__

/****************************** Includes *******************************/
#include <stdlib.h>
#include <stdio.h>
#include <assert.h>

#include "global.h"

/****************** Conditional compilation switches *******************/

/***************************** Constants *******************************/

/***************************** Datatypes *******************************/

// ring buffer handle
typedef struct
{
  uint  elementSize;                 // size of element
  ulong size;                        // size of ring buffer (max. number of elements+1)
  ulong nextIn;                      // index of next in-element
  ulong nextOut;                     // index of next out-element
  byte *data;                        // ring buffer data
} RingBuffer;

// delete ring bufferelement function
typedef void(*RingBufferElementFreeFunction)(void *data, void *userData);

// comparison, iteration functions
typedef int(*RingBufferElementCompareFunction)(void *userData, void *data1, void *data2);
typedef char(*RingBufferElementIterateFunction)(void *userData, void *data);

/***************************** Variables *******************************/

/****************************** Macros *********************************/

#ifndef NDEBUG
  #define RingBuffer_init(ringBuffer,elementSize,size) __RingBuffer_init(__FILE__,__LINE__,ringBuffer,elementSize,size)
  #define RingBuffer_done(ringBuffer,ringBufferElementFreeFunction,ringBufferElementFreeUserData) __RingBuffer_done(__FILE__,__LINE__,ringBuffer,ringBufferElementFreeFunction,ringBufferElementFreeUserData)
  #define RingBuffer_new(elementSize,size) __RingBuffer_new(__FILE__,__LINE__,elementSize,size)
  #define RingBuffer_delete(ringBuffer,ringBufferElementFreeFunction,ringBufferElementFreeUserData) __RingBuffer_delete(__FILE__,__LINE__,ringBuffer,ringBufferElementFreeFunction,ringBufferElementFreeUserData)
#endif /* not NDEBUG */

/***********************************************************************\
* Name   : RINGBUFFER_INIT
* Purpose: init new ring buffer with specific data type
* Input  : type - data type
*          size - size of ring buffer
* Output : -
* Return : ring buffer or NULL
* Notes  : -
\***********************************************************************/

#define RINGBUFFER_INIT(ringBuffer,type,size) RingBuffer_init(&ringBuffer,sizeof(type),size)

/***********************************************************************\
* Name   : RINGBUFFER_DONE
* Purpose: simple done ring buffer
* Input  : ringBuffer - ring buffer
* Output : -
* Return : -
* Notes  : -
\***********************************************************************/

#define RINGBUFFER_DONE(ringBuffer) RingBuffer_done(&ringBuffer,NULL,NULL)

/***********************************************************************\
* Name   : RINGBUFFER_NEW
* Purpose: allocate new ring buffer with specific data type
* Input  : type - data type
*          size - size of ring buffer
* Output : -
* Return : ring buffer or NULL
* Notes  : -
\***********************************************************************/

#define RINGBUFFER_NEW(type,size) RingBuffer_new(sizeof(type),size)

/***********************************************************************\
* Name   : RINGBUFFER_DELETE
* Purpose: simple delete ring buffer
* Input  : ringBuffer - ring buffer
* Output : -
* Return : -
* Notes  : -
\***********************************************************************/

#define RINGBUFFER_DELETE(ringBuffer) RingBuffer_delete(ringBuffer,NULL,NULL)

/***********************************************************************\
* Name   : RINGBUFFER_CLEAR
* Purpose: simgple clear ring buffer
* Input  : ringBuffer - ring buffer
* Output : -
* Return : -
* Notes  : -
\***********************************************************************/

#define RINGBUFFER_CLEAR(ringBuffer) RingBuffer_clear(ringBuffer,NULL,NULL)

/***********************************************************************\
* Name   : RINGBUFFER_ITERATE
* Purpose: iterated over ring buffer elements and execute block
* Input  : ringBuffer - ring buffer
*          variable   - iteration variable
* Output : -
* Return : -
* Notes  : variable point to all entries in ring buffer
*          usage:
*            ringBuffer(ringBuffer,variable)
*            {
*              ... = variable->...
*            }
\***********************************************************************/

#define RINGBUFFER_ITERATE(ringBuffer,variable) \
  for ((variable) =  (typeof(variable))((ringBuffer)->data+(ulong)ringBuffer->nextOut*(ulong)ringBuffer->elementSize); \
       (variable) != (typeof(variable))((ringBuffer)->data+(ulong)ringBuffer->nextIn *(ulong)ringBuffer->elementSize); \
       (variable) =  (typeof(variable))((ringBuffer)->data+(((((byte*)variable)-(ringBuffer)->data)+(ulong)ringBuffer->elementSize)%((ulong)ringBuffer->elementSize*(ulong)ringBuffer->size))) \
      )

// check if ring buffer is valid (debug only)
#ifndef NDEBUG
  #define RINGBUFFER_CHECK_VALID(ringBuffer) \
    do \
    { \
   } \
    while (0)
#else /* NDEBUG */
  #define RINGBUFFER_CHECK_VALID(ringBuffer) \
    do \
    { \
      UNUSED_VARIABLE(ringBuffer); \
    } \
    while (0)
#endif /* not NDEBUG */

/***************************** Forwards ********************************/

/***************************** Functions *******************************/

#ifdef __cplusplus
  extern "C" {
#endif

/***********************************************************************\
* Name   : RingBuffer_init
* Purpose: init ring buffer
* Input  : elementSize - element size (in bytes)
*          size        - size of ring buffer
* Output : -
* Return : TRUE if ring buffer initialized, FALSE otherwise
* Notes  : -
\***********************************************************************/

#ifdef NDEBUG
bool RingBuffer_init(RingBuffer *ringBuffer, uint elementSize, ulong size);
#else /* not NDEBUG */
bool __RingBuffer_init(const char *__fileName__, ulong __lineNb__, RingBuffer *ringBuffer, uint elementSize, ulong size);
#endif /* NDEBUG */

/***********************************************************************\
* Name   : RingBuffer_done
* Purpose: done ring buffer
* Input  : ringBuffer                    - ring buffer to delete
*          ringBufferElementFreeFunction - ring buffer element free function or NULL
*          ringBufferElementFreeUserData - free function user data or NULL
* Output : -
* Return : -
* Notes  : -
\***********************************************************************/

#ifdef NDEBUG
void RingBuffer_done(RingBuffer *ringBuffer, RingBufferElementFreeFunction ringBufferElementFreeFunction, void *ringBufferElementFreeUserData);
#else /* not NDEBUG */
void __RingBuffer_done(const char *__fileName__, ulong __lineNb__, RingBuffer *ringBuffer, RingBufferElementFreeFunction ringBufferElementFreeFunction, void *ringBufferElementFreeUserData);
#endif /* NDEBUG */

/***********************************************************************\
* Name   : RingBuffer_new
* Purpose: create new ring buffer
* Input  : elementSize - element size (in bytes)
*          size        - size of ring buffer
* Output : -
* Return : ring buffer or NULL
* Notes  : -
\***********************************************************************/

#ifdef NDEBUG
RingBuffer* RingBuffer_new(uint elementSize, ulong size);
#else /* not NDEBUG */
RingBuffer* __RingBuffer_new(const char *__fileName__, ulong __lineNb__, uint elementSize, ulong size);
#endif /* NDEBUG */

/***********************************************************************\
* Name   : RingBuffer_delete
* Purpose: delete ring buffer
* Input  : ringBuffer                    - ring buffer to delete
*          ringBufferElementFreeFunction - ring buffer element free function or NULL
*          ringBufferElementFreeUserData - free function user data or NULL
* Output : -
* Return : -
* Notes  : -
\***********************************************************************/

#ifdef NDEBUG
void RingBuffer_delete(RingBuffer *ringBuffer, RingBufferElementFreeFunction ringBufferElementFreeFunction, void *ringBufferElementFreeUserData);
#else /* not NDEBUG */
void __RingBuffer_delete(const char *__fileName__, ulong __lineNb__, RingBuffer *ringBuffer, RingBufferElementFreeFunction ringBufferElementFreeFunction, void *ringBufferElementFreeUserData);
#endif /* NDEBUG */

/***********************************************************************\
* Name   : RingBuffer_getSize
* Purpose: get max. number of free elements in ring buffer
* Input  : ringBuffer - ring buffer
* Output : -
* Return : max. number of elements (size) in ring buffer
* Notes  : -
\***********************************************************************/

INLINE ulong RingBuffer_getSize(const RingBuffer *ringBuffer);
#if defined(NDEBUG) || defined(__RINGBUFFER_IMPLEMENATION__)
INLINE ulong RingBuffer_getSize(const RingBuffer *ringBuffer)
{
  RINGBUFFER_CHECK_VALID(ringBuffer);

  return (ringBuffer != NULL) ? ringBuffer->size-1 : 0L;
}
#endif /* NDEBUG || __RINGBUFFER_IMPLEMENATION__ */

/***********************************************************************\
* Name   : RingBuffer_resize
* Purpose: set new ring buffer size (resize)
* Input  : newSize - new size of ring buffer
* Output : -
* Return : TRUE if ring buffer resized, FALSE otherwise
* Notes  : -
\***********************************************************************/

bool RingBuffer_resize(RingBuffer *ringBuffer, ulong newSize);

/***********************************************************************\
* Name   : RingBuffer_clear
* Purpose: clear ring buffer
* Input  : ringBuffer                    - ring buffer to clear
*          ringBufferElementFreeFunction - ring buffer element free function or NULL
*          ringBufferElementFreeUserData - free function user data or NULL
* Output : -
* Return : -
* Notes  : -
\***********************************************************************/

void RingBuffer_clear(RingBuffer *ringBuffer, RingBufferElementFreeFunction ringBufferElementFreeFunction, void *ringBufferElementFreeUserData);

/***********************************************************************\
* Name   : RingBuffer_getFree
* Purpose: get number of free elements in ring buffer
* Input  : ringBuffer - ring buffer
* Output : -
* Return : number of free elements in ring buffer
* Notes  : -
\***********************************************************************/

INLINE ulong RingBuffer_getFree(const RingBuffer *ringBuffer);
#if defined(NDEBUG) || defined(__RINGBUFFER_IMPLEMENATION__)
INLINE ulong RingBuffer_getFree(const RingBuffer *ringBuffer)
{
  RINGBUFFER_CHECK_VALID(ringBuffer);

  if (ringBuffer != NULL) { 
	   if ((ringBuffer)->nextIn >= (ringBuffer)->nextOut) 
		   return ringBuffer->size - 1 - (ringBuffer)->nextIn + (ringBuffer)->nextOut;
	   else 
		   return ringBuffer->nextOut - (ringBuffer)->nextIn - 1;
  } else 
	  return 0L;
}
#endif /* NDEBUG || __RINGBUFFER_IMPLEMENATION__ */

/***********************************************************************\
* Name   : RingBuffer_getAvailable
* Purpose: get available elements in ring buffer
* Input  : ringBuffer - ring buffer
* Output : -
* Return : number of available elements in ring buffer
* Notes  : -
\***********************************************************************/

INLINE ulong RingBuffer_getAvailable(const RingBuffer *ringBuffer);
#if defined(NDEBUG) || defined(__RINGBUFFER_IMPLEMENATION__)
INLINE ulong RingBuffer_getAvailable(const RingBuffer *ringBuffer)
{
  RINGBUFFER_CHECK_VALID(ringBuffer);
  if (ringBuffer != NULL) { 
	   if ((ringBuffer)->nextIn >= (ringBuffer)->nextOut) 
		   return (ringBuffer)->nextIn-(ringBuffer)->nextOut;
	   else 
		   return (ringBuffer)->size-ringBuffer->nextOut+(ringBuffer)->nextIn;
  } else 
	  return 0L;

}
#endif /* NDEBUG || __RINGBUFFER_IMPLEMENATION__ */

/***********************************************************************\
* Name   : RingBuffer_isEmpty
* Purpose: check if ring buffer is empty
* Input  : ringBuffer - ring buffer
* Output : -
* Return : TRUE iff ring buffer is empty, FALSE otherwise
* Notes  : -
\***********************************************************************/

INLINE bool RingBuffer_isEmpty(const RingBuffer *ringBuffer);
#if defined(NDEBUG) || defined(__RINGBUFFER_IMPLEMENATION__)
INLINE bool RingBuffer_isEmpty(const RingBuffer *ringBuffer)
{
  RINGBUFFER_CHECK_VALID(ringBuffer);

//  return (ringBuffer == NULL) || (ringBuffer->nextIn == ringBuffer->nextOut);
  return (ringBuffer == NULL) || (RingBuffer_getAvailable(ringBuffer) == 0);
}
#endif /* NDEBUG || __RINGBUFFER_IMPLEMENATION__ */

/***********************************************************************\
* Name   : RingBuffer_isFull
* Purpose: check if ring buffer is full
* Input  : ringBuffer - ring buffer
* Output : -
* Return : TRUE iff ring buffer is empty, FALSE otherwise
* Notes  : -
\***********************************************************************/

INLINE bool RingBuffer_isFull(const RingBuffer *ringBuffer);
#if defined(NDEBUG) || defined(__RINGBUFFER_IMPLEMENATION__)
INLINE bool RingBuffer_isFull(const RingBuffer *ringBuffer)
{
  RINGBUFFER_CHECK_VALID(ringBuffer);

  return (ringBuffer == NULL) || (RingBuffer_getFree(ringBuffer) == 0);
}
#endif /* NDEBUG || __RINGBUFFER_IMPLEMENATION__ */

/***********************************************************************\
* Name   : RingBuffer_put
* Purpose: put elements into ring buffer
* Input  : ringBuffer - ring buffer
*          data       - data
*          n          - number of elements
* Output : -
* Return : TRUE if elements are stored in ring buffer, FALSE otherwise
* Notes  : -
\***********************************************************************/

bool RingBuffer_put(RingBuffer *ringBuffer, const void *data, ulong n);

/***********************************************************************\
* Name   : RingBuffer_get
* Purpose: get elements from ring buffer
* Input  : ringBuffer - ring buffer
*          data       - variable for data (can be NULL)
*          n          - number of elements
* Output : data - data
* Return : -
* Notes  : if no data variable is supplied (NULL) a pointer to the
*          data element in the ring buffer is returned
\***********************************************************************/

void *RingBuffer_get(RingBuffer *ringBuffer, void *data, ulong n);

/***********************************************************************\
* Name   : RingBuffer_move
* Purpose: move elements from ring buffer to ring buffer
* Input  : sourceRingBuffer      - source ring buffer
*          destinationRingBuffer - destination ring buffer
*          n                     - number of elements
* Output : data - data
* Return : TRUE if element moved, FALSE otherwise
* Notes  : -
\***********************************************************************/

bool RingBuffer_move(RingBuffer *sourceRingBuffer, RingBuffer *destinationRingBuffer, ulong n);

/***********************************************************************\
* Name   : RingBuffer_cArrayIn
* Purpose: get C-array data pointer to next in-element
* Input  : ringBuffer - ring buffer
* Output : -
* Return : data pointer to next in-element in ring buffer
* Notes  : -
\***********************************************************************/

void *RingBuffer_cArrayIn(RingBuffer *ringBuffer);

/***********************************************************************\
* Name   : RingBuffer_cArrayOut
* Purpose: get C-array data pointer to next out-element
* Input  : ringBuffer - ring buffer
* Output : -
* Return : data pointer to next out-element in ring buffer
* Notes  : -
\***********************************************************************/

const void *RingBuffer_cArrayOut(RingBuffer *ringBuffer);

/***********************************************************************\
* Name   : RingBuffer_increment
* Purpose: increment number of elements in ring buffer
* Input  : ringBuffer - ring buffer
*          n          - number of elements (<= free space!)
* Output : -
* Return : -
* Notes  : used to directly put elements into ring buffer via C-array
\***********************************************************************/

void RingBuffer_increment(RingBuffer *ringBuffer, ulong n);

/***********************************************************************\
* Name   : RingBuffer_decrement
* Purpose: decrement number of elements in ring buffer
* Input  : ringBuffer - ring buffer
*          n          - number of elements (>= available elements!)
* Output : -
* Return : -
* Notes  : used to directly get elements from ring buffer via C-array
\***********************************************************************/

void RingBuffer_decrement(RingBuffer *ringBuffer, ulong n);

/***********************************************************************\
* Name   : RingBuffer_toCArray
* Purpose: get C-array data pointer
* Input  : ringBuffer - ring buffer
* Output : -
* Return : C-array with data of ring buffer
* Notes  : -
\***********************************************************************/

INLINE const void *RingBuffer_cArray(RingBuffer *ringBuffer);
#if defined(NDEBUG) || defined(__RINGBUFFER_IMPLEMENATION__)
INLINE const void *RingBuffer_cArray(RingBuffer *ringBuffer)
{
  RINGBUFFER_CHECK_VALID(ringBuffer);

  return RingBuffer_cArrayOut(ringBuffer);
}
#endif /* NDEBUG || __RINGBUFFER_IMPLEMENATION__ */

#ifndef NDEBUG
/***********************************************************************\
* Name   : RingBuffer_debugDone
* Purpose: done ring buffer debug functions
* Input  : -
* Output : -
* Return : -
* Notes  : -
\***********************************************************************/

void RingBuffer_debugDone(void);

/***********************************************************************\
* Name   : RingBuffer_debugDumpInfo, RingBuffer_debugPrintInfo
* Purpose: ring buffer debug function: output allocated ring buffers
* Input  : handle - output channel
* Output : -
* Return : -
* Notes  : -
\***********************************************************************/

void RingBuffer_debugDumpInfo(FILE *handle);
void RingBuffer_debugPrintInfo(void);

/***********************************************************************\
* Name   : RingBuffer_debugPrintStatistics
* Purpose: ring buffer debug function: output ring buffers statistics
* Input  : -
* Output : -
* Return : -
* Notes  : -
\***********************************************************************/

void RingBuffer_debugPrintStatistics(void);

/***********************************************************************\
* Name   : RingBuffer_debugCheck
* Purpose: ring buffer debug function: output allocated ring buffers and
*          statistics, check for lost resources
* Input  : -
* Output : -
* Return : -
* Notes  : -
\***********************************************************************/

void RingBuffer_debugCheck(void);

#endif /* not NDEBUG */

#ifdef __cplusplus
  }
#endif

#endif /* __RINGBUFFERS__ */


/* end of file */
