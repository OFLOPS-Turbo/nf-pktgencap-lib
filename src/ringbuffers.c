/***********************************************************************\
*
* $Revision: 936 $
* $Date: 2012-05-06 13:32:16 +0200 (Sun, 06 May 2012) $
* $Author: torsten $
* Contents: ring buffer functions
* Systems: all
*
\***********************************************************************/

#define __RINGBUFFER_IMPLEMENATION__

/****************************** Includes *******************************/
#include <stdlib.h>
#include <stdio.h>
#include <assert.h>

#include "global.h"
#ifndef NDEBUG
  #include <pthread.h>
  #include "lists.h"
#endif /* not NDEBUG */

#include "ringbuffers.h"

/****************** Conditional compilation switches *******************/
#define HALT_ON_INSUFFICIENT_MEMORY

/***************************** Constants *******************************/

/***************************** Datatypes *******************************/

#ifndef NDEBUG
  typedef struct DebugRingBufferNode
  {
    LIST_NODE_HEADER(struct DebugRingBufferNode);

    const char       *fileName;
    ulong            lineNb;
    const RingBuffer *ringBuffer;
  } DebugRingBufferNode;

  typedef struct
  {
    LIST_HEADER(DebugRingBufferNode);
    ulong allocatedMemory;
  } DebugRingBufferList;
#endif /* not NDEBUG */

/***************************** Variables *******************************/
#ifndef NDEBUG
  LOCAL pthread_once_t      debugRingBufferInitFlag = PTHREAD_ONCE_INIT;
  LOCAL pthread_mutex_t     debugRingBufferLock;
  LOCAL DebugRingBufferList debugRingBufferList;
#endif /* not NDEBUG */

/****************************** Macros *********************************/

/***************************** Forwards ********************************/

/***************************** Functions *******************************/
#ifdef __cplusplus
  extern "C" {
#endif

/*
+--+--+--+--+--+--+--+--+--+--+
|  |  |  |  |  |  |  |  |  |  |
+--+--+--+--+--+--+--+--+--+--+
*/

/***********************************************************************\
* Name   : debugRingBufferInit
* Purpose: initialize debug functions
* Input  : -
* Output : -
* Return : -
* Notes  : -
\***********************************************************************/

#ifndef NDEBUG
LOCAL void debugRingBufferInit(void)
{
  pthread_mutex_init(&debugRingBufferLock,NULL);
  List_init(&debugRingBufferList);
  debugRingBufferList.allocatedMemory = 0L;
}
#endif /* not NDEBUG */

/***********************************************************************\
* Name   : inIsContiguous
* Purpose: check if input elements can be stored contiguous
* Input  : ringBuffer - ring buffer
*          n          - number of elements
* Output : -
* Return : TRUE if input elements can be stored contiguous, FALSE
*          otherwise
* Notes  : -
\***********************************************************************/

LOCAL_INLINE bool inIsContiguous(const RingBuffer *ringBuffer, ulong n)
{
  assert(ringBuffer != NULL);

  RINGBUFFER_CHECK_VALID(ringBuffer);

  return ringBuffer->nextIn+n <= ringBuffer->size;
}

/***********************************************************************\
* Name   : outIsContiguous
* Purpose: check if output elements are stored contiguous
* Input  : ringBuffer - ring buffer
*          n          - number of elements
* Output : -
* Return : TRUE if output elements are stored contiguous, FALSE
*          otherwise
* Notes  : -
\***********************************************************************/

LOCAL_INLINE bool outIsContiguous(const RingBuffer *ringBuffer, ulong n)
{
  assert(ringBuffer != NULL);

  RINGBUFFER_CHECK_VALID(ringBuffer);

  return ringBuffer->nextOut+n <= ringBuffer->size;
}

/***********************************************************************\
* Name   : normalizeIn
* Purpose: normalize ring buffer input: shift ring buffer elements to
*          beginning and make input contiguous
* Input  : ringBuffer - ring buffer
* Output : -
* Return : -
* Notes  : -
\***********************************************************************/

LOCAL void normalizeIn(RingBuffer *ringBuffer)
{
  ulong n;

  assert(ringBuffer != NULL);
  assert(ringBuffer->data != NULL);

  RINGBUFFER_CHECK_VALID(ringBuffer);

  if (   (ringBuffer->nextOut > 0L)
      && (ringBuffer->nextIn > ringBuffer->nextOut)
     )
  {
//fprintf(stderr,"%s, %d: normalizeIn\n",__FILE__,__LINE__);
    /* non-contigous -> rearrange

       before:

             <-------n------>
       +--+--+--+--+--+--+--+--+--+--+
       |  |  |aa|bb|cc|dd|ee|  |  |  |
       +--+--+--+--+--+--+--+--+--+--+
              ^next out      ^next in

       after:

       <-------n------>
       +--+--+--+--+--+--+--+--+--+--+
       |aa|bb|cc|dd|ee|  |  |  |  |  |
       +--+--+--+--+--+--+--+--+--+--+
        ^next out      ^next in

    */
    n = ringBuffer->nextIn-ringBuffer->nextOut;

    // move output data to beginning
//fprintf(stderr,"%s, %d: \n",__FILE__,__LINE__);
//dumpMemory(ringBuffer->data,ringBuffer->size*ringBuffer->elementSize);
    memmove(ringBuffer->data,
            ringBuffer->data+(ulong)ringBuffer->nextOut*(ulong)ringBuffer->elementSize,
            n
           );
//fprintf(stderr,"%s, %d: \n",__FILE__,__LINE__);
//dumpMemory(ringBuffer->data,ringBuffer->size*ringBuffer->elementSize);

    // adjust indizes
    ringBuffer->nextOut = 0L;
    ringBuffer->nextIn  = n;
  }
}

/***********************************************************************\
* Name   : normalizeOut
* Purpose: normalize ring buffer output: make output contiguous
* Input  : ringBuffer - ring buffer
* Output : -
* Return : -
* Notes  : -
\***********************************************************************/

LOCAL void normalizeOut(RingBuffer *ringBuffer)
{
  ulong n0,n1;

  assert(ringBuffer != NULL);
  assert(ringBuffer->data != NULL);

  RINGBUFFER_CHECK_VALID(ringBuffer);

  if (   (ringBuffer->nextIn > 0L)
      && (ringBuffer->nextIn < ringBuffer->nextOut)
     )
  {
//fprintf(stderr,"%s, %d: normalizeOut\n",__FILE__,__LINE__);
    /* non-contigous -> rearrange

       before:

       <--n0->              <---n1--->
       +--+--+--+--+--+--+--+--+--+--+
       |dd|ee|  |  |  |  |  |aa|bb|cc|
       +--+--+--+--+--+--+--+--+--+--+
              ^next in       ^next out

       after:

       <---n1---|--n0->
       +--+--+--+--+--+--+--+--+--+--+
       |aa|bb|cc|dd|ee|  |  |  |  |  |
       +--+--+--+--+--+--+--+--+--+--+
        ^next out      ^next in

    */
    n0 = ringBuffer->nextIn;
    n1 = ringBuffer->size-ringBuffer->nextOut;

    // move lower part up
//fprintf(stderr,"%s, %d: \n",__FILE__,__LINE__);
//dumpMemory(ringBuffer->data,ringBuffer->size*ringBuffer->elementSize);
    memmove(ringBuffer->data+(ulong)n1*(ulong)ringBuffer->elementSize,
            ringBuffer->data,
            n0
           );
//fprintf(stderr,"%s, %d: \n",__FILE__,__LINE__);
//dumpMemory(ringBuffer->data,ringBuffer->size*ringBuffer->elementSize);

    // copy upper part down
    memcpy(ringBuffer->data,
           ringBuffer->data+(ulong)ringBuffer->nextOut*(ulong)ringBuffer->elementSize,
           n1
          );
//fprintf(stderr,"%s, %d: \n",__FILE__,__LINE__);
//dumpMemory(ringBuffer->data,ringBuffer->size*ringBuffer->elementSize);

    // adjust indizes
    ringBuffer->nextOut = 0L;
    ringBuffer->nextIn  = n1+n0;
  }
}

// ----------------------------------------------------------------------

#ifdef NDEBUG
bool RingBuffer_init(RingBuffer *ringBuffer, uint elementSize, ulong size)
#else /* not NDEBUG */
bool __RingBuffer_init(const char *__fileName__, ulong __lineNb__, RingBuffer *ringBuffer, uint elementSize, ulong size)
#endif /* NDEBUG */
{
  #ifndef NDEBUG
    DebugRingBufferNode *debugRingBufferNode;
  #endif /* not NDEBUG */

  assert(elementSize > 0);
  assert(size > 0);

  /* initialize ring buffer structure. Note: size
     is n+1 elements to be able to store n elements.
  */
  ringBuffer->elementSize = elementSize;
  ringBuffer->size        = size+1;
  ringBuffer->nextIn      = 0L;
  ringBuffer->nextOut     = 0L;

  // allocate ring buffer data
  ringBuffer->data = (byte*)malloc((size+1)*(ulong)elementSize);
  if (ringBuffer->data == NULL)
  {
    #ifdef HALT_ON_INSUFFICIENT_MEMORY
      HALT_INSUFFICIENT_MEMORY();
    #else /* not HALT_ON_INSUFFICIENT_MEMORY */
      return FALSE;
    #endif /* HALT_ON_INSUFFICIENT_MEMORY */
  }

  #ifndef NDEBUG
    pthread_once(&debugRingBufferInitFlag,debugRingBufferInit);

    pthread_mutex_lock(&debugRingBufferLock);
    {
      debugRingBufferNode = LIST_NEW_NODE(DebugRingBufferNode);
      if (debugRingBufferNode == NULL)
      {
        HALT_INSUFFICIENT_MEMORY();
      }
      debugRingBufferNode->fileName   = __fileName__;
      debugRingBufferNode->lineNb     = __lineNb__;
      debugRingBufferNode->ringBuffer = ringBuffer;
      List_append(&debugRingBufferList,debugRingBufferNode);
      debugRingBufferList.allocatedMemory += sizeof(DebugRingBufferNode)+sizeof(RingBuffer)+(ulong)ringBuffer->size*(ulong)ringBuffer->elementSize;
    }
    pthread_mutex_unlock(&debugRingBufferLock);
  #endif /* not NDEBUG */

  return TRUE;
}

#ifdef NDEBUG
void RingBuffer_done(RingBuffer *ringBuffer, RingBufferElementFreeFunction ringBufferElementFreeFunction, void *ringBufferElementFreeUserData)
#else /* not NDEBUG */
void __RingBuffer_done(const char *__fileName__, ulong __lineNb__, RingBuffer *ringBuffer, RingBufferElementFreeFunction ringBufferElementFreeFunction, void *ringBufferElementFreeUserData)
#endif /* NDEBUG */
{
  void *p;
  #ifndef NDEBUG
    DebugRingBufferNode *debugRingBufferNode;
  #endif /* not NDEBUG */

  if (ringBuffer != NULL)
  {
    assert(ringBuffer->data != NULL);

    if (ringBufferElementFreeFunction != NULL)
    {
      RINGBUFFER_ITERATE(ringBuffer,p)
      {
        ringBufferElementFreeFunction(p,ringBufferElementFreeUserData);
      }
    }

    #ifndef NDEBUG
      pthread_once(&debugRingBufferInitFlag,debugRingBufferInit);

      pthread_mutex_lock(&debugRingBufferLock);
      {
        debugRingBufferNode = debugRingBufferList.head;
        while ((debugRingBufferNode != NULL) && (debugRingBufferNode->ringBuffer != ringBuffer))
        {
          debugRingBufferNode = debugRingBufferNode->next;
        }
        if (debugRingBufferNode != NULL)
        {
          List_remove(&debugRingBufferList,debugRingBufferNode);
          assert(debugRingBufferList.allocatedMemory >= sizeof(DebugRingBufferNode)+sizeof(RingBuffer)+(ulong)ringBuffer->size*(ulong)ringBuffer->elementSize);
          debugRingBufferList.allocatedMemory -= sizeof(DebugRingBufferNode)+sizeof(RingBuffer)+(ulong)ringBuffer->size*(ulong)ringBuffer->elementSize;
          LIST_DELETE_NODE(debugRingBufferNode);
        }
        else
        {
          fprintf(stderr,"DEBUG WARNING: ring buffer %p not found in debug list at %s, line %lu\n",
                  ringBuffer,
                  __fileName__,
                  __lineNb__
                 );
        }
      }
      pthread_mutex_unlock(&debugRingBufferLock);
    #endif /* not NDEBUG */

    free(ringBuffer->data);
  }
}

#ifdef NDEBUG
RingBuffer* RingBuffer_new(uint elementSize, ulong size)
#else /* not NDEBUG */
RingBuffer* __RingBuffer_new(const char *__fileName__, ulong __lineNb__, uint elementSize, ulong size)
#endif /* NDEBUG */
{
  RingBuffer *ringBuffer;

  assert(elementSize > 0);
  assert(size > 0);

  // allocate ring buffer structure
  ringBuffer = (RingBuffer*)malloc(sizeof(RingBuffer));
  if (ringBuffer == NULL)
  {
    #ifdef HALT_ON_INSUFFICIENT_MEMORY
      HALT_INSUFFICIENT_MEMORY();
    #else /* not HALT_ON_INSUFFICIENT_MEMORY */
      return NULL;
    #endif /* HALT_ON_INSUFFICIENT_MEMORY */
  }

  // init ring buffer
  #ifndef NDEBUG
    if (!__RingBuffer_init(__fileName__,__lineNb__,ringBuffer,elementSize,size))
    {
      #ifdef HALT_ON_INSUFFICIENT_MEMORY
        HALT_INSUFFICIENT_MEMORY();
      #else /* not HALT_ON_INSUFFICIENT_MEMORY */
        free(ringBuffer);
        return NULL;
      #endif /* HALT_ON_INSUFFICIENT_MEMORY */
    }
  #else  /* NDEBUG */
    if (!RingBuffer_init(ringBuffer,elementSize,size))
    {
      #ifdef HALT_ON_INSUFFICIENT_MEMORY
        HALT_INSUFFICIENT_MEMORY();
      #else /* not HALT_ON_INSUFFICIENT_MEMORY */
        free(ringBuffer);
        return NULL;
      #endif /* HALT_ON_INSUFFICIENT_MEMORY */
    }
  #endif /* not NDEBUG */

  return ringBuffer;
}

#ifdef NDEBUG
void RingBuffer_delete(RingBuffer *ringBuffer, RingBufferElementFreeFunction ringBufferElementFreeFunction, void *ringBufferElementFreeUserData)
#else /* not NDEBUG */
void __RingBuffer_delete(const char *__fileName__, ulong __lineNb__, RingBuffer *ringBuffer, RingBufferElementFreeFunction ringBufferElementFreeFunction, void *ringBufferElementFreeUserData)
#endif /* NDEBUG */
{
  if (ringBuffer != NULL)
  {
    assert(ringBuffer->data != NULL);

    // done ring buffer
    #ifndef NDEBUG
      __RingBuffer_done(__fileName__,__lineNb__,ringBuffer,ringBufferElementFreeFunction,ringBufferElementFreeUserData);
    #else  /* NDEBUG */
      RingBuffer_done(ringBuffer,ringBufferElementFreeFunction,ringBufferElementFreeUserData);
    #endif /* not NDEBUG */

    free(ringBuffer);
  }
}

bool RingBuffer_resize(RingBuffer *ringBuffer, ulong newSize)
{
  void  *newData;
  ulong n;

  assert(newSize > 0);
//fprintf(stderr,"%s, %d: RingBuffer_resize %ld %ld\n",__FILE__,__LINE__,ringBuffer->size,newSize);

  RINGBUFFER_CHECK_VALID(ringBuffer);

  // allocate new ring buffer data memory
  newData = (byte*)malloc((newSize+1)*(ulong)ringBuffer->elementSize);
  if (newData == NULL)
  {
    #ifdef HALT_ON_INSUFFICIENT_MEMORY
      HALT_INSUFFICIENT_MEMORY();
    #else /* not HALT_ON_INSUFFICIENT_MEMORY */
      return FALSE;
    #endif /* HALT_ON_INSUFFICIENT_MEMORY */
  }
  #ifndef NDEBUG
    debugRingBufferList.allocatedMemory += (ulong)((newSize+1)-ringBuffer->size)*(ulong)ringBuffer->elementSize;
  #endif /* not NDEBUG */

  // normalize ring buffer output
  normalizeOut(ringBuffer);

  // move data
  n = MIN(RingBuffer_getAvailable(ringBuffer),newSize);
  memcpy(newData,
         ringBuffer->data+(ulong)ringBuffer->nextOut*(ulong)ringBuffer->elementSize,
         n*(ulong)ringBuffer->elementSize
        );

  // set new data, adjust size/length
  free(ringBuffer->data);
  ringBuffer->size    = newSize+1;
  ringBuffer->nextOut = 0L;
  ringBuffer->nextIn  = n;
  ringBuffer->data    = newData;

  return TRUE;
}

void RingBuffer_clear(RingBuffer *ringBuffer, RingBufferElementFreeFunction ringBufferElementFreeFunction, void *ringBufferElementFreeUserData)
{
  void *p;

  RINGBUFFER_CHECK_VALID(ringBuffer);

  if (ringBuffer != NULL)
  {
    assert(ringBuffer->data != NULL);

    if (ringBufferElementFreeFunction != NULL)
    {
      RINGBUFFER_ITERATE(ringBuffer,p)
      {
        ringBufferElementFreeFunction(p,ringBufferElementFreeUserData);
      }
    }
    ringBuffer->nextIn  = 0L;
    ringBuffer->nextOut = 0L;
  }
}

bool RingBuffer_put(RingBuffer *ringBuffer, const void *data, ulong n)
{
  ulong n0,n1;

  assert(data != NULL);

  RINGBUFFER_CHECK_VALID(ringBuffer);

  if (   (ringBuffer != NULL)
      && (RingBuffer_getFree(ringBuffer) >= n)
     )
  {
    assert(ringBuffer->data != NULL);

    if (n > 0)
    {
      if (inIsContiguous(ringBuffer,n))
      {
        /* continous space -> copy to nextIn..nextIn+n0

                 <-- n0 -->
           +--+--+--+--+--+--+--+--+--+--+
           |aa|bb|  |  |  |  |  |xx|yy|zz|
           +--+--+--+--+--+--+--+--+--+--+
                  ^next in       ^next out
        */
        n0 = n;
        n1 = 0L;
      }
      else
      {
        /* non-continous space -> copy to nextIn..nextIn+n0, 0..n1

           <- n1->              <-- n0 -->
           +--+--+--+--+--+--+--+--+--+--+
           |  |  |  |aa|bb|xx|yy|  |  |  |
           +--+--+--+--+--+--+--+--+--+--+
                  ^next out      ^next in
        */
        n0 = ringBuffer->size-ringBuffer->nextIn;
        n1 = n-n0;
      }

      // copy data into ring buffer
//fprintf(stderr,"%s, %d: \n",__FILE__,__LINE__);
//dumpMemory(ringBuffer->data,ringBuffer->size*ringBuffer->elementSize);
      assert(n0 > 0);
      memcpy(ringBuffer->data+(ulong)ringBuffer->nextIn*(ulong)ringBuffer->elementSize,
             (byte*)data+(ulong)0,
             (ulong)n0*(ulong)ringBuffer->elementSize
            );
//fprintf(stderr,"%s, %d: \n",__FILE__,__LINE__);
//dumpMemory(ringBuffer->data,ringBuffer->size*ringBuffer->elementSize);
      if (n1 > 0)
      {
        memcpy(ringBuffer->data,
               (byte*)data+(ulong)n0*(ulong)ringBuffer->elementSize,
               (ulong)n1*(ulong)ringBuffer->elementSize
              );
//fprintf(stderr,"%s, %d: \n",__FILE__,__LINE__);
//dumpMemory(ringBuffer->data,ringBuffer->size*ringBuffer->elementSize);
      }
//fprintf(stderr,"%s, %d: \n",__FILE__,__LINE__);
//dumpMemory(ringBuffer->data,ringBuffer->size*ringBuffer->elementSize);

      // add elements to ring buffer
      ringBuffer->nextIn = (ringBuffer->nextIn+n)%ringBuffer->size;
    }

    return TRUE;
  }
  else
  {
    return FALSE;
  }
}

void *RingBuffer_get(RingBuffer *ringBuffer, void *data, ulong n)
{
  ulong n0,n1;

  RINGBUFFER_CHECK_VALID(ringBuffer);

  if (   (ringBuffer != NULL)
      && (RingBuffer_getAvailable(ringBuffer) >= n)
     )
  {
    assert(ringBuffer->data != NULL);

    if (n > 0)
    {
      if (data != NULL)
      {
        // copy data from ring buffer
        if (outIsContiguous(ringBuffer,n))
        {
          /* continous space -> copy from nextOut..nextOut+n0

                      <-- n0 -->
             +--+--+--+--+--+--+--+--+--+--+
             |  |  |  |aa|bb|xx|yy|  |  |  |
             +--+--+--+--+--+--+--+--+--+--+
                       ^next out   ^next in
          */
          // continous space -> copy to n0..n0+n
          n0 = n;
          n1 = 0L;
        }
        else
        {
          /* non-continous space -> copy from nextOut..nextOut+n0, 0..n1

             <- n1->              <-- n0 -->
             +--+--+--+--+--+--+--+--+--+--+
             |aa|bb|  |  |  |  |  |xx|yy|zz|
             +--+--+--+--+--+--+--+--+--+--+
                    ^next in       ^next out
          */
          // non-continous space -> copy to nextIn..nextIn+n0, 0..n1
          n0 = ringBuffer->size-ringBuffer->nextOut;
          n1 = n-n0;
        }

//fprintf(stderr,"%s, %d: \n",__FILE__,__LINE__);
//dumpMemory(ringBuffer->data,ringBuffer->size*ringBuffer->elementSize);
        assert(n0 > 0);
        memcpy((byte*)data+0,
               ringBuffer->data+(ulong)ringBuffer->nextOut*(ulong)ringBuffer->elementSize,
               (ulong)n0*(ulong)ringBuffer->elementSize
              );
//fprintf(stderr,"%s, %d: \n",__FILE__,__LINE__);
//dumpMemory(ringBuffer->data,ringBuffer->size*ringBuffer->elementSize);
        if (n1 > 0)
        {
          memcpy((byte*)data+(ulong)n0*(ulong)ringBuffer->elementSize,
                 ringBuffer->data+0,
                 (ulong)n1*(ulong)ringBuffer->elementSize
                );
//fprintf(stderr,"%s, %d: \n",__FILE__,__LINE__);
//dumpMemory(ringBuffer->data,ringBuffer->size*ringBuffer->elementSize);
        }
//fprintf(stderr,"%s, %d: \n",__FILE__,__LINE__);
//dumpMemory(ringBuffer->data,ringBuffer->size*ringBuffer->elementSize);
      }
      else
      {
        // normalize ring buffer
        normalizeOut(ringBuffer);

        // get pointer to data
        data = ringBuffer->data+(ulong)ringBuffer->nextOut*(ulong)ringBuffer->elementSize;
      }

      // remove elements from ring buffer
      ringBuffer->nextOut = (ringBuffer->nextOut+n)%ringBuffer->size;

      // reset indizes if empty (optimization)
      if (ringBuffer->nextOut == ringBuffer->nextIn)
      {
        ringBuffer->nextOut = 0L;
        ringBuffer->nextIn  = 0L;
      }
    }
  }
  else
  {
    data = NULL;
  }

  return data;
}

bool RingBuffer_move(RingBuffer *sourceRingBuffer, RingBuffer *destinationRingBuffer, ulong n)
{
  ulong n0,n1;

  RINGBUFFER_CHECK_VALID(sourceRingBuffer);
  RINGBUFFER_CHECK_VALID(destinationRingBuffer);

  if (   (sourceRingBuffer != NULL)
      && (destinationRingBuffer != NULL)
      && (RingBuffer_getAvailable(sourceRingBuffer) >= n)
      && (RingBuffer_getFree(destinationRingBuffer) >= n)
     )
  {
    if (n > 0L)
    {
      // copy data into ring buffer
      if (outIsContiguous(sourceRingBuffer,n))
      {
        /* continous space -> copy from nextOut..nextOut+n0

                    <-- n0 -->
           +--+--+--+--+--+--+--+--+--+--+
           |  |  |  |aa|bb|xx|yy|  |  |  |
           +--+--+--+--+--+--+--+--+--+--+
                     ^next out   ^next in
        */
        // continous space -> copy to n0..n0+n
        n0 = n;
        n1 = 0L;
      }
      else
      {
        /* non-continous space -> copy from nextOut..nextOut+n0, 0..n1

           <- n1->              <-- n0 -->
           +--+--+--+--+--+--+--+--+--+--+
           |aa|bb|  |  |  |  |  |xx|yy|zz|
           +--+--+--+--+--+--+--+--+--+--+
                  ^next in       ^next out
        */
        // non-continous space -> copy to nextIn..nextIn+n0, 0..n1
        n0 = sourceRingBuffer->size-sourceRingBuffer->nextOut;
        n1 = n-n0;
      }

      // copy to destination ring buffer
//fprintf(stderr,"%s, %d: \n",__FILE__,__LINE__);
//dumpMemory(ringBuffer->data,ringBuffer->size*ringBuffer->elementSize);
      assert(n0 > 0);
      RingBuffer_put(destinationRingBuffer,
                     sourceRingBuffer->data+(ulong)sourceRingBuffer->nextOut*(ulong)sourceRingBuffer->elementSize,
                     (ulong)n0*(ulong)sourceRingBuffer->elementSize
                    );
//fprintf(stderr,"%s, %d: \n",__FILE__,__LINE__);
//dumpMemory(ringBuffer->data,ringBuffer->size*ringBuffer->elementSize);
      if (n1 > 0)
      {
        RingBuffer_put(destinationRingBuffer,
                       sourceRingBuffer->data+0,
                       (ulong)n1*(ulong)sourceRingBuffer->elementSize
                      );
//fprintf(stderr,"%s, %d: \n",__FILE__,__LINE__);
//dumpMemory(ringBuffer->data,ringBuffer->size*ringBuffer->elementSize);
      }

      // remove elements from ring buffer
      sourceRingBuffer->nextOut = (sourceRingBuffer->nextOut+n)%sourceRingBuffer->size;

      // reset indizes if empty (optimization)
      if (sourceRingBuffer->nextOut == sourceRingBuffer->nextIn)
      {
        sourceRingBuffer->nextOut = 0L;
        sourceRingBuffer->nextIn  = 0L;
      }
    }

    return TRUE;
  }
  else
  {
    return FALSE;
  }
}

void *RingBuffer_cArrayIn(RingBuffer *ringBuffer)
{
  assert(ringBuffer != NULL);
  assert(ringBuffer->data != NULL);

  RINGBUFFER_CHECK_VALID(ringBuffer);

  // normalize ring buffer input
  normalizeIn(ringBuffer);

  // get pointer to data
  return (ringBuffer != NULL)
    ? ringBuffer->data+(ulong)ringBuffer->nextIn*(ulong)ringBuffer->elementSize
    : NULL;
}

const void *RingBuffer_cArrayOut(RingBuffer *ringBuffer)
{
  assert(ringBuffer != NULL);
  assert(ringBuffer->data != NULL);

  RINGBUFFER_CHECK_VALID(ringBuffer);

  // normalize ring buffer output
  normalizeOut(ringBuffer);

  // get pointer to data
  return (ringBuffer != NULL)
    ? ringBuffer->data+(ulong)ringBuffer->nextOut*(ulong)ringBuffer->elementSize
    : NULL;
}

void RingBuffer_increment(RingBuffer *ringBuffer, ulong n)
{
  RINGBUFFER_CHECK_VALID(ringBuffer);

  if (ringBuffer != NULL)
  {
    assert(RingBuffer_getFree(ringBuffer) >= n);

    // check if ring buffer content is contiguous
    assert(ringBuffer->nextIn >= ringBuffer->nextOut);
    assert(ringBuffer->nextIn+n <= ringBuffer->size-1);

    // add elements to ring buffer
    ringBuffer->nextIn += n;
  }
}

void RingBuffer_decrement(RingBuffer *ringBuffer, ulong n)
{
  RINGBUFFER_CHECK_VALID(ringBuffer);

  if (ringBuffer != NULL)
  {
    assert(RingBuffer_getAvailable(ringBuffer) >= n);

    // check if ring buffer content is contiguous
    assert(ringBuffer->nextIn >= ringBuffer->nextOut);
    assert(ringBuffer->nextOut+n <= ringBuffer->nextIn);

    // remove elements from ring buffer
    ringBuffer->nextOut += n;

    // reset indizes if empty (optimization)
    if (ringBuffer->nextOut == ringBuffer->nextIn)
    {
      ringBuffer->nextOut = 0L;
      ringBuffer->nextIn  = 0L;
    }
  }
}

#ifndef NDEBUG
void RingBuffer_debugDone(void)
{
  pthread_once(&debugRingBufferInitFlag,debugRingBufferInit);

  RingBuffer_debugCheck();

  pthread_mutex_lock(&debugRingBufferLock);
  {
    List_done(&debugRingBufferList,NULL,NULL);
  }
  pthread_mutex_unlock(&debugRingBufferLock);
}

void RingBuffer_debugDumpInfo(FILE *handle)
{
  DebugRingBufferNode *debugRingBufferNode;

  pthread_once(&debugRingBufferInitFlag,debugRingBufferInit);

  pthread_mutex_lock(&debugRingBufferLock);
  {
    LIST_ITERATE(&debugRingBufferList,debugRingBufferNode)
    {
      fprintf(handle,"DEBUG: RingBuffer %p[%lu] allocated at %s, line %ld\n",
              debugRingBufferNode->ringBuffer->data,
              debugRingBufferNode->ringBuffer->size-1,
              debugRingBufferNode->fileName,
              debugRingBufferNode->lineNb
             );
    }
  }
  pthread_mutex_unlock(&debugRingBufferLock);
}

void RingBuffer_debugPrintInfo(void)
{
  RingBuffer_debugDumpInfo(stderr);
}

void RingBuffer_debugPrintStatistics(void)
{
  pthread_once(&debugRingBufferInitFlag,debugRingBufferInit);

  pthread_mutex_lock(&debugRingBufferLock);
  {
    fprintf(stderr,"DEBUG: %lu RingBuffer(s) allocated, total %lu bytes\n",
            List_count(&debugRingBufferList),
            debugRingBufferList.allocatedMemory
           );
  }
  pthread_mutex_unlock(&debugRingBufferLock);
}

void RingBuffer_debugCheck(void)
{
  pthread_once(&debugRingBufferInitFlag,debugRingBufferInit);

  RingBuffer_debugPrintInfo();
  RingBuffer_debugPrintStatistics();

  pthread_mutex_lock(&debugRingBufferLock);
  {
    if (!List_isEmpty(&debugRingBufferList))
    {
      HALT_INTERNAL_ERROR_LOST_RESOURCE();
    }
  }
  pthread_mutex_unlock(&debugRingBufferLock);
}
#endif /* not NDEBUG */
#ifdef __cplusplus
  }
#endif

/* end of file */
