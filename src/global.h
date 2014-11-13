/***********************************************************************\
*
* $Revision: 934 $
* $Date: 2012-05-06 13:31:25 +0200 (Sun, 06 May 2012) $
* $Author: torsten $
* Contents: global definitions
* Systems: Linux
*
\***********************************************************************/

#ifndef __GLOBAL__
#define __GLOBAL__

 #if (defined DEBUG)
  #warning DEBUG option set - no LOCAL and no -O2 (optimizer) will be used!
 #endif

/****************************** Includes *******************************/
#include <stdlib.h>
#include <stdint.h>
#ifdef HAVE_STDBOOL_H
  #include <stdbool.h>
#endif
#include <limits.h>
#include <float.h>
#include <ctype.h>
#include <string.h>
#include <math.h>
#include <assert.h>

/****************** Conditional compilation switches *******************/

/***************************** Constants *******************************/
#define DEBUG_LEVEL 8                          // debug level

// definition of boolean values
#if defined(__cplusplus) || defined(HAVE_STDBOOL_H)
  #ifndef FALSE
    #define FALSE false
  #endif
  #ifndef TRUE
    #define TRUE true
  #endif
#else
  #ifndef FALSE
    #define FALSE 0
  #endif
  #ifndef TRUE
    #define TRUE  1
  #endif
#endif
#define NO  FALSE
#define YES TRUE
#define OFF FALSE
#define ON  TRUE

// math constants
#ifndef PI
  #define PI 3.14159265358979323846
#endif

// time constants
#define MILLI_PER_SECOND 1000

// minimal and maximal values for some scalar data types
#define MIN_CHAR           CHAR_MIN
#define MAX_CHAR           CHAR_MAX
#define MIN_SHORTINT       SHRT_MIN
#define MAX_SHORTINT       SHRT_MAX
#define MIN_INT            INT_MIN
#define MAX_INT            INT_MAX
#define MIN_LONG           LONG_MIN
#define MAX_LONG           LONG_MAX
#ifdef HAVE_LLONG_MIN
  #define MIN_LONG_LONG    LLONG_MIN
#else
  #define MIN_LONG_LONG    -9223372036854775808LL
#endif
#ifdef HAVE_LLONG_MAX
  #define MAX_LONG_LONG    LLONG_MAX
#else
  #define MAX_LONG_LONG    9223372036854775807LL
#endif

#define MIN_UCHAR          0
#define MAX_UCHAR          UCHAR_MAX
#define MIN_USHORT         0
#define MAX_USHORT         USHRT_MAX
#define MIN_UINT           0
#define MAX_UINT           UINT_MAX
#define MIN_ULONG          0
#define MAX_ULONG          ULONG_MAX
#define MIN_ULONG_LONG     0
#ifdef HAVE_ULLONG_MAX
  #define MAX_ULONG_LONG   ULLONG_MAX
#else
  #define MAX_ULONG_LONG   18446744073709551615LL
#endif

#define MIN_FLOAT          FLT_MIN
#define MAX_FLOAT          FLT_MAX
#define EPSILON_FLOAT      FLT_EPSILON
#define MIN_DOUBLE         DBL_MIN
#define MAX_DOUBLE         DBL_MAX
#define EPSILON_DOUBLE     DBL_EPSILON
#define MIN_LONGDOUBLE     LDBL_MIN
#define MAX_LONGDOUBLE     LDBL_MAX
#define EPSILON_LONGDOUBLE LDBL_EPSILON

// special constants
#define NO_WAIT      0
#define WAIT_FOREVER (-1)

// exit codes
#define EXITCODE_INTERNAL_ERROR 128

/**************************** Datatypes ********************************/
#ifndef HAVE_STDBOOL_H
  #ifndef __cplusplus
    typedef uint8_t          bool;
  #endif
#endif

typedef unsigned char      uchar;
typedef short int          shortint;
typedef unsigned short int ushortint;

typedef enum
{
  CMP_LOWER=-1,
  CMP_EQUAL=0,
  CMP_GREATER=+1
} TCmpResults;

typedef uint8_t             byte;

typedef unsigned char       bool8;
typedef unsigned int        bool32;
typedef char                char8;
typedef unsigned char       uchar8;
typedef char                int8;
typedef short int           int16;
typedef int                 int32;
typedef long long int       int64;
typedef unsigned char       uint8;
typedef unsigned short int  uint16;
typedef unsigned int        uint32;
typedef unsigned long long  uint64;
typedef void                void32;

/**************************** Variables ********************************/

/****************************** Macros *********************************/
#define GLOBAL extern
#define LOCAL static

#ifdef NDEBUG
  #define INLINE static inline
  #define LOCAL_INLINE static inline
#else
  #define INLINE
  #define LOCAL_INLINE static
#endif

#ifdef __GNUC__
  #define ATTRIBUTE_PACKED             __attribute__ ((__packed__))
  #define ATTRIBUTE_WARN_UNUSED_RESULT __attribute__ ((__warn_unused_result__))
#else
  #define ATTRIBUTE_PACKED
  #define ATTRIBUTE_WARN_UNUSED_RESULT
#endif

/***********************************************************************\
* Name   : UNUSED_VARIABLE
* Purpose: avoid compiler warning for unused variables/parameters
* Input  : variable - variable
* Output : -
* Return : -
* Notes  : -
\***********************************************************************/

#define UNUSED_VARIABLE(variable) (void)variable

/***********************************************************************\
* Name   : SIZE_OF_ARRAY
* Purpose: get size of array
* Input  : array - array
* Output : -
* Return : -
* Notes  : -
\***********************************************************************/

#define SIZE_OF_ARRAY(array) (sizeof(array)/sizeof(array[0]))

/***********************************************************************\
* Name   : ALIGN
* Purpose: align value to boundary
* Input  : n         - address
*          alignment - alignment
* Output : -
* Return : -
* Notes  : -
\***********************************************************************/

#define ALIGN(n,alignment) (((alignment)>0)?(((n)+(alignment)-1) & ~((alignment)-1)):(n))

/***********************************************************************\
* Name   : SET_CLEAR, SET_VALUE, SET_ADD, SET_REM
* Purpose: set macros
* Input  : set     - set (integer)
*          element - element
* Output : -
* Return : TRUE if value is in set, FALSE otherwise
* Notes  : -
\***********************************************************************/

#define SET_CLEAR(set) \
  do \
  { \
    (set) = 0; \
  } \
  while (0)

#define SET_VALUE(element) \
  (1 << (element))

#define SET_ADD(set,element) \
  do \
  { \
    (set) |= SET_VALUE(element); \
  } \
  while (0)

#define SET_REM(set,element) \
  do \
  { \
    (set) &= ~(SET_VALUE(element)); \
  } \
  while (0)

#define IN_SET(set,element) (((set) & SET_VALUE(element)) == SET_VALUE(element))

/***********************************************************************\
* Name   : BITSET_SET, BITSET_CLEAR, BITSET_IS_SET, SET_REM, IN_SET
* Purpose: set macros
* Input  : set     - set (array)
*          element - element
* Output : -
* Return : TRUE if value is in bitset, FALSE otherwise
* Notes  : -
\***********************************************************************/

#define BITSET_SET(set,bit) \
  do \
  { \
    ((byte*)(set))[bit/8] |= (1 << (bit%8)); \
  } \
  while (0)

#define BITSET_CLEAR(set,bit) \
  do \
  { \
    ((byte*)(set))[bit/8] &= ~(1 << (bit%8)); \
  } \
  while (0)

#define BITSET_IS_SET(set,bit) \
  ((((byte*)(set))[bit/8] & (1 << (bit%8))) != 0)

/***********************************************************************\
* Name   : IS_NAN, IS_INF
* Purpose: check is NaN, infinite
* Input  : d - number
* Output : -
* Return : TRUE iff NaN/infinite
* Notes  : -
\***********************************************************************/

#ifndef __cplusplus
  #define IS_NAN(d) (!((d)==(d)))                        // check if Not-A-Number (NaN)
  #define IS_INF(d) ((d<-MAX_DOUBLE) || (d>MAX_DOUBLE))  // check if infinit-number
#endif

/***********************************************************************\
* Name   : MIN, MAX, IN_RANGE
* Purpose: get min./max.
* Input  : x,y - numbers
* Output : -
* Return : min./max. of x,y
* Notes  : -
\***********************************************************************/

#ifdef __GNUG__
  #define MIN(x,y) ((x)<?(y))
  #define MAX(x,y) ((x)>?(y))
#else
  #define MIN(x,y) (((x)<(y)) ? (x) : (y))
  #define MAX(x,y) (((x)>(y)) ? (x) : (y))
#endif

/***********************************************************************\
* Name   : IN_RANGE
* Purpose: get value in range
* Input  : l,h - lower/upper bound
*          x   - number
* Output : -
* Return : x iff l<x<h,
*          l iff x <= l,
*          h iff x >= h
* Notes  : -
\***********************************************************************/

#ifdef __GNUG__
  #define IN_RANGE(l,x,h) (( ((x)<?(h) )>?(l))
#else
  #define IN_RANGE(l,x,h) ((x)<(l) ? (l) : ((x)>(h) ? (h) : (x)))
#endif

/***********************************************************************\
* Name   : FLOOR
* Purpose: round number down by factor
* Input  : x - number
*          n - factor (n=y^2)
* Output : -
* Return : x' rounded down with x' <= x && x' mod n == 0
* Notes  : -
\***********************************************************************/

#define FLOOR(x,n) ((x) & ~((n)-1))

/***********************************************************************\
* Name   : CEIL
* Purpose: round number up by factor
* Input  : x - number
*          n - factor (n=y^2)
* Output : -
* Return : x' rounded up with x' >= x && x' mod n == 0
* Notes  : -
\***********************************************************************/

#define CEIL(x,n) (((x)+(n)-1) & ~((n)-1))

/***********************************************************************\
* Name   : SQUARE
* Purpose: calculate square
* Input  : x - number
* Output : -
* Return : x*x
* Notes  : -
\***********************************************************************/

#define SQUARE(x) ((x)*(x))

/***********************************************************************\
* Name   : CHECK_RANGE
* Purpose: check if number is in range
* Input  : l,h - lower/upper bound
*          x   - number
* Output : -
* Return : TRUE iff l<x<h, FALSE otherwise
* Notes  : -
\***********************************************************************/

#define CHECK_RANGE(l,x,u) (( ((l)<=(x)) && ((x)<=(u)) ) || \
                            ( ((u)<=(x)) && ((x)<=(l)) )    \
                           )

/***********************************************************************\
* Name   : CHECK_ANGLE_RANGE
* Purpose: check if number/angle is in range
* Input  : l,h - lower/upper bound [rad]
*          a   - angle [rad]
* Output : -
* Return : TRUE iff l<a<h, FALSE otherwise
* Notes  : -
\***********************************************************************/

#define CHECK_ANGLE_RANGE(l,a,u) (((NormRad(l))<=(NormRad(u)))?CHECK_RANGE(NormRad(l),NormRad(a),NormRad(u)):(CHECK_RANGE(l,a,2*PI) || CHECK_RANGE(0,NormRad(a),NormRad(u))))
#ifndef __cplusplus
 #define IndexMod(l,i,u) ( l+(((i)<0)?( ((u)-(l)+1)-((-(i)%((u)-(l)+1)))%((u)-(l)+1) ):( ((i)>((u)-(l)+1))?( (i)%((u)-(l)+1) ):( (i) ) )) )
#endif

/***********************************************************************\
* Name   : RAD_TO_DEGREE, DEGREE_TO_RAD
* Purpose: convert rad to degree/degree to rad
* Input  : n - rad/degree
* Output : -
* Return : degree/rad value
* Notes  : -
\***********************************************************************/

#define RAD_TO_DEGREE(n) ((n)>=0?\
                          (((n)<=2*PI)?\
                           (n)*180.0/PI:\
                           ((n)-2*PI)*180.0/PI\
                          ):\
                          (((n)+2*PI)*180.0/PI)\
                         )

#define DEGREE_TO_RAD(n) ((n)>=0?\
                          (((n)<=360)?\
                           (n)*PI/180.0:\
                           ((n)-360)*PI/180.0\
                          ):\
                          (((n)+360)*PI/180.0)\
                         )

#ifndef __cplusplus
  #define RadToDegree(n) RAD_TO_DEGREE(n)
  #define DegreeToRad(n) DEGREE_TO_RAD(n)
#endif

/***********************************************************************\
* Name   : NORM_RAD360, NORM_RAD180, NORM_RAD90, NORM_RAD
* Purpose: normalize rad value
* Input  : n - value
* Output : -
* Return : normalized value
* Notes  : -
\***********************************************************************/

#define NORM_RAD360(n)    (fmod(n,2*PI))

#define NORM_RAD180(n)    (((n)>PI)\
                           ?((n)-2*PI)\
                           :(((n)<-PI)\
                             ?((n)+2*PI)\
                             :(n)\
                            )\
                          )

#define NORM_RAD90(n)     (((n)>3*PI/2)\
                           ?((n)-2*PI)\
                           :(((n)>PI/2)\
                             ?((n)-PI)\
                             :(((n)<-3*PI/2)\
                               ?((n)+2*PI)\
                               :(((n)<-PI/2)\
                                 ?((n)+PI)\
                                 :(n)\
                                )\
                              )\
                            )\
                          )
#define NORM_RAD(n)       (((n)<0)\
                           ?((n)+2*PI)\
                           :(((n)>(2*PI))\
                             ?((n)-2*PI)\
                             :(n)\
                            )\
                          )

/***********************************************************************\
* Name   : NORM_DEGREE360, NORM_DEGREE180, NORM_DEGREE90, NORM_DEGREE
* Purpose: normalize degree value
* Input  : n - value
* Output : -
* Return : normalized value
* Notes  : -
\***********************************************************************/

#define NORM_DEGREE360(n) (fmod(n,360))

#define NORM_DEGREE180(n) (((n)>180)\
                           ?((n)-360)\
                           :(((n)<-180)\
                             ?((n)+360):\
                             (n)\
                            )\
                          )
#define NORM_DEGREE90(n)  (((n)>270)\
                            ?((n)-180)\
                            :(((n)>180)\
                              ?((n)-90)\
                              :(((n)<-270)\
                                ?((n)+180)\
                                :(((n)<-180)\
                                  ?((n)+90)\
                                  :(n)\
                                 )\
                               )\
                             )\
                          )

#define NORM_DEGREE(n)    (((n)<0)\
                           ?((n)+360)\
                           :(((n)>360)\
                             ?((n)-360):\
                             (n)\
                            )\
                          )
/* used in code */
#ifndef __cplusplus
  #define SwapWORD(n) ( ((n & 0xFF00) >> 8) | \
                        ((n & 0x00FF) << 8)   \
                      )
  #define SwapLONG(n) ( ((n & 0xFF000000) >> 24) | \
                        ((n & 0x00FF0000) >>  8) | \
                        ((n & 0x0000FF00) <<  8) | \
                        ((n & 0x000000FF) << 24)   \
                      )
#endif

/***********************************************************************\
* Name   : HALT, HALT_INSUFFICIENT_MEMORY, HALT_FATAL_ERROR,
*          HALT_INTERNAL_ERROR, HALT_INTERNAL_ERROR_AT,
*          HALT_INTERNAL_ERROR_STILL_NOT_IMPLEMENTED,
*          HALT_INTERNAL_ERROR_UNHANDLED_SWITCH_CASE,
*          HALT_INTERNAL_ERROR_UNREACHABLE,
*          HALT_INTERNAL_ERROR_LOST_RESOURCE
* Purpose: halt macros
* Input  : errorLevel - error level
*          format     - format string
*          args       - optional arguments
* Output : -
* Return : -
* Notes  : -
\***********************************************************************/

// prefixes
#define HALT_PREFIX_FATAL_ERROR    "FATAL ERROR: "
#define HALT_PREFIX_INTERNAL_ERROR "INTERNAL ERROR: "

// 2 macros necessary, because of "string"-construction
#define _HALT_STRING1(z) _HALT_STRING2(z)
#define _HALT_STRING2(z) #z
#undef HALT
#define HALT(errorLevel, format, args...) \
  do \
  { \
    __halt(__FILE__,__LINE__,errorLevel,format, ## args); \
  } \
  while (0)

#define HALT_INSUFFICIENT_MEMORY(args...) \
  do \
  { \
     __abort(__FILE__,__LINE__,HALT_PREFIX_FATAL_ERROR,"insufficient memory", ## args); \
  } \
 while (0)

#define HALT_FATAL_ERROR(format, args...) \
  do \
  { \
     __abort(__FILE__,__LINE__,HALT_PREFIX_FATAL_ERROR,format, ## args); \
  } \
 while (0)

#define HALT_INTERNAL_ERROR(format, args...) \
  do \
  { \
     __abort(__FILE__,__LINE__,HALT_PREFIX_INTERNAL_ERROR, format, ## args); \
  } \
  while (0)
#define HALT_INTERNAL_ERROR_AT(file, line, format, args...) \
  do \
  { \
     __abort(file,line,HALT_PREFIX_INTERNAL_ERROR,format, ## args); \
  } \
  while (0)
#define HALT_INTERNAL_ERROR_STILL_NOT_IMPLEMENTED() \
  do \
  { \
     HALT_INTERNAL_ERROR("still not implemented"); \
  } \
  while (0)
#define HALT_INTERNAL_ERROR_UNHANDLED_SWITCH_CASE() \
  do \
  { \
     HALT_INTERNAL_ERROR("unhandled switch case"); \
  } \
  while (0)
#define HALT_INTERNAL_ERROR_UNREACHABLE() \
  do \
  { \
     HALT_INTERNAL_ERROR("unreachable code"); \
  } \
  while (0)
#define HALT_INTERNAL_ERROR_LOST_RESOURCE() \
  do \
  { \
     HALT_INTERNAL_ERROR("lost resource"); \
  } \
  while (0)

/***********************************************************************\
* Name   : FAIL
* Purpose: fail macros
* Input  : errorLevel - error level
*          format     - format string
*          args       - optional arguments
* Output : -
* Return : -
* Notes  : -
\***********************************************************************/

/* 2 macros necessary, because of "string"-construction */
#define _FAIL_STRING1(z) _FAIL_STRING2(z)
#define _FAIL_STRING2(z) #z
#define FAIL(errorLevel, format, args...) \
  do \
  { \
   fprintf(stderr, format " - fail in file " __FILE__ ", line " _FAIL_STRING1(__LINE__) "\n" , ## args); \
   exit(errorLevel);\
  } \
  while (0)

/***********************************************************************\
* Name   : MEMSET, MEMCLEAR
* Purpose: set/clear memory macros
* Input  : p     - pointer
*          value - value
*          size  - size (in bytes)
* Output : -
* Return : -
* Notes  : -
\***********************************************************************/

#define MEMSET(p,value,size) memset(p,value,size)

#define MEMCLEAR(p,size) memset(p,0,size)

/**************************** Functions ********************************/

#ifdef __cplusplus
extern "C" {
#endif

#ifndef NDEBUG
/***********************************************************************\
* Name   : __dprintf
* Purpose: debug printf
* Input  : filename - filename
*          lineNb   - line number
*          format   - format string (like printf)
*          ...      - optional arguments
* Output : -
* Return : -
* Notes  : -
\***********************************************************************/

void __dprintf(const char *filename, unsigned int lineNb, const char *format, ...);
#endif /* NDEBUG */

#ifdef __cplusplus

/***********************************************************************\
* Name   : isNaN
* Purpose: check if not-a-number (NaN)
* Input  : n - numer
* Output : -
* Return : TRUE if n is NaN, FALSE otherwise
* Notes  : -
\***********************************************************************/

inline bool isNaN(double n)
{
  return(n!=n);
}

/***********************************************************************\
* Name   : isInf
* Purpose: check if number is infinit
* Input  : n - number
* Output : -
* Return : TRUE if n is infinit, FALSE otherwise
* Notes  : -
\***********************************************************************/

inline bool isInf(double n)
{
  return((n<-MAX_DOUBLE) || (n>MAX_DOUBLE));
}

#endif

#ifdef __cplusplus

/***********************************************************************\
* Name   : radToDegree
* Purpose: convert rad to degree
* Input  : n - angle in rad
* Output : -
* Return : angle in degree
* Notes  : -
\***********************************************************************/

inline double radToDegree(double n)
{
//???  ASSERT_NaN(n);
//  n=fmod(n,2*PI);
//  if (n<0) n+=2*PI;
  return(n*180/PI);
}

/***********************************************************************\
* Name   : degreeToRad
* Purpose: convert degree to rad
* Input  : n - angle in degree
* Output : -
* Return : angle in rad
* Notes  : -
\***********************************************************************/

inline double degreeToRad(double n)
{
//???  ASSERT_NaN(n);
//  n=fmod(n,360);
//  if (n<0) n+=360;
  return(n*PI/180);
}

#endif

#ifdef __cplusplus

/***********************************************************************\
* Name   : normRad
* Purpose: normalize angle in rad (0..2PI)
* Input  : n - angle in rad
* Output : -
* Return : normalized angle (0..2PI)
* Notes  : -
\***********************************************************************/

inline double normRad(double n)
{
//???  ASSERT(!IsNaN(n));
  n=fmod(n,2*PI);
  if (n<0) n+=2*PI;
  return(n);
}

/***********************************************************************\
* Name   : normDegree
* Purpose: normalize angle in degree (0..360)
* Input  : n - angle in degree
* Output : -
* Return : normalize angle (0..360)
* Notes  : -
\***********************************************************************/

inline double normDegree(double n)
{
//???  ASSERT(!IsNaN(n));
  n=fmod(n,360);
  if (n<0) n+=360;
  return(n);
}

/***********************************************************************\
* Name   : normRad90
* Purpose: normalize angle in rad (-PI/2..PI/2)
* Input  : n - angle in rad
* Output : -
* Return : normalized angle (-PI/2..PI/2)
* Notes  : PI/2..3PI/2   = -PI/2..PI/2
*          3PI/2..2PI    = -PI/2..0
*          -PI/2..-3PI/2 = PI/2..-PI/2
*          -3PI/2..-2PI  = PI/2..0
\***********************************************************************/

inline double normRad90(double n)
{
//???  ASSERT(!IsNaN(n));
  if (n> 3*PI/2) n-=2*PI;
  if (n<-3*PI/2) n+=2*PI;
  if (n>   PI/2) n-=PI;
  if (n<  -PI/2) n+=PI;
  return(n);
}

/***********************************************************************\
* Name   : normRad180
* Purpose: normalize angle in rad (-PI..PI)
* Input  : n - angle in rad
* Output : -
* Return : normalized angle (-PI..PI)
* Notes  : -
\***********************************************************************/

inline double normRad180(double n)
{
//???  ASSERT(!IsNaN(n));
  return(n>PI?(n-2*PI):n<-PI?(n+2*PI):n);
}

/***********************************************************************\
* Name   : normDegree90
* Purpose: normalize angle in rad (-90..90)
* Input  : n - angle in degree
* Output : -
* Return : normalized angle (-90..90)
* Notes  : 90..270    = -90..
*          270..360   = -90..0
*          -90..-270  = 90..-90
*          -270..-360 = 90..0
\***********************************************************************/

inline double normDegree90(double n)
{
//???  ASSERT(!IsNaN(n));
  if (n> 270) n-=360;
  if (n<-270) n+=360;
  if (n>  90) n-=180;
  if (n< -90) n+=180;
  return(n);
}

/***********************************************************************\
* Name   : normDegree180
* Purpose: normalize angle in degree (-180..180)
* Input  : n - angle in degree
* Output : -
* Return : normalize angle (-180..180)
* Notes  : -
\***********************************************************************/

inline double normDegree180(double n)
{
//???  ASSERT(!IsNaN(n));
  return(n>180?(n-360):n<-180?(n+360):n);
}

/***********************************************************************\
* Name   : normRad360
* Purpose: normalize angle in rad (-2PI...2PI)
* Input  : n - angle in rad
* Output : -
* Return : normalized angle (-2PI..2PI)
* Notes  : -
\***********************************************************************/

inline double normRad360(double n)
{
//???  ASSERT(!IsNaN(n));
  return(fmod(n,2*PI));
}

/***********************************************************************\
* Name   : normDegree360
* Purpose: normalize angle in degree (-360..360)
* Input  : n - angle in degree
* Output : -
* Return : normalize angle (-360..360)
* Notes  : -
\***********************************************************************/

inline double normDegree360(double n)
{
//???  ASSERT(!IsNaN(n));
  return(fmod(n,360));
}

#endif

/*---------------------------------------------------------------------*/

#ifdef __cplusplus

/***********************************************************************\
* Name   : swapWORD
* Purpose: swap low/high byte of word (2 bytes)
* Input  : n - word (a:b)
* Output : -
* Return : swapped word (b:a)
* Notes  : -
\***********************************************************************/

inline ushort swapWORD(ushort n)
{
  return( ((n & 0xFF00) >> 8) |
          ((n & 0x00FF) << 8)
        );
}

/***********************************************************************\
* Name   : swapLONG
* Purpose: swap bytes of long (4 bytes)
* Input  : n - long (a:b:c:d)
* Output : -
* Return : swapped long (d:c:b:a)
* Notes  : -
\***********************************************************************/

inline ulong swapLONG(ulong n)
{
  return( ((n & 0xFF000000) >> 24) |
          ((n & 0x00FF0000) >>  8) |
          ((n & 0x0000FF00) <<  8) |
          ((n & 0x000000FF) << 24)
        );
}

#endif

/***********************************************************************\
* Name   : __halt
* Purpose: halt program
* Input  : filename - filename
*          lineNb   - line number
*          exitcode - exitcode
*          format   - format string (like printf)
*          ...      - optional arguments
* Output : -
* Return : -
* Notes  : -
\***********************************************************************/

void __halt(const char   *filename,
            unsigned int lineNb,
            int          exitcode,
            const char   *format,
            ...
           );

/***********************************************************************\
* Name   : __abort
* Purpose: abort program
* Input  : filename - filename
*          lineNb   - line number
*          prefix   - prefix text
*          format   - format string (like printf)
*          ...      - optional arguments
* Output : -
* Return : -
* Notes  : -
\***********************************************************************/

void __abort(const char   *filename,
             unsigned int lineNb,
             const char   *prefix,
             const char   *format,
             ...
            );

/***********************************************************************\
* Name   : dumpMemory
* Purpose: dump memory content (hex dump)
* Input  : address - start address
*          length  - length
* Output : -
* Return : -
* Notes  : -
\***********************************************************************/

#ifndef NDEBUG
void dumpMemory(const void *address, uint length);
#endif /* NDEBUG */

#ifdef __cplusplus
}
#endif

#endif /* __GLOBAL__ */

/* end of file */
