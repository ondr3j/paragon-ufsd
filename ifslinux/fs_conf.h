/*++

Module Name:

    fs_conf.h

Abstract:

    This module is a forced include file
    for entire UFSD-based project.

Author:

    Ahdrey Shedel

Revision History:

    27/12/2002 - Andrey Shedel - Created

    Since 29/07/2005 - Alexander Mamaev

--*/


#ifdef __llvm__
#define goto(x...) ("")
#endif


#ifndef __linux__
#define __linux__
#endif

//
// Tune the UFSD library.
//
//#define UFSD_ALLOW_MUL_WRITE_BEGIN

//
// This defines allows to exclude part of library not used in driver
//
#define UFSD_DRIVER_LINUX
#define UFSD_DRIVER_LINUX2

//
// Emulate "." and ".."
//
//#define UFSD_EMULATE_DOTS

//
// Force to use additional thread for periodically volume flush
//
//#define UFSD_USE_FLUSH_THREAD

//
// Just to test compilation
//
//#define UFSD_BIGENDIAN

//
// Activate journal for NTFS
//
#define UFSD_NTFS_JNL

//
// Do not include extended I/O code
// Some of the utilities (e.g. fsutil) uses
// this I/O codes to get usefull information
//
//#define UFSD_NO_USE_IOCTL

//
// Library never allocates a lot of memory
// This defines turns off checking of malloc
//
//#define UFSD_MALLOC_CANT_FAIL

//
// Activate this define if you want to use the only global Memory manager for your project
//
#define UFSD_USE_GLOBAL_MM

//
// Include code that supports User/Group/Mode emulation in NTFS
//
//#define UFSD_ENABLE_UGM     "Turn on $UGM"


//
// Activate this define to check media every write operation
//
//#define UFSD_CHECK_BDI

//
// NTFS uses 64 bit cluster (Win7.x64 still uses 32bit clusters)
//
#ifdef __LP64__
//#define UFSD_NTFS_64BIT_CLUSTER
#endif

//
// Exclude annoying messages while tests
//
//#define UFSD_TRACE_SILENT

//
// Do not keep nodes in library
//
//#define UFSD_FULL_TRUST_NODES   "Vfs keeps nodes itself"

//
// Force to activate trace
//
//#define UFSD_TRACE

//
// Disable library printk
//
//#define UFSD_NO_PRINTK

//
// Do not trace if special define is used
//
#ifdef UFSD_NO_TRACE
  #undef UFSD_TRACE
#endif

#if !defined UFSD_DEBUG && !defined NDEBUG
  #define UFSD_DEBUG 1
#endif

#if defined UFSD_DEBUG && !defined UFSD_TRACE
  #define UFSD_TRACE
#endif

#if defined __i386__
  #define UFSDAPI_CALL  __attribute__((regparm(3)))
  #define UFSDAPI_CALLv __attribute__((cdecl)) __attribute__((regparm(0)))
  #define UFSD_API      __attribute__((regparm(3)))
#else
  #define UFSDAPI_CALL
  #define UFSDAPI_CALLv
  #define UFSD_API
#endif

#ifdef __cplusplus
  extern "C" {
#endif

#define ARRSIZE(x)  ( sizeof(x) / sizeof(x[0]) )

#ifdef UFSD_TRACE

  //
  // _UFSDTrace is used to trace messages from UFSD
  // UFSDError is called when error occurs
  //
  void UFSDAPI_CALL UFSDError( int Err, const char* FileName, int Line );
  void UFSDAPI_CALLv _UFSDTrace( const char* fmt, ... ) __attribute__ ((format (printf, 1, 2)));
  extern char ufsd_trace_file[128];
  extern char ufsd_trace_level_[16];
  extern unsigned long ufsd_trace_level;
  extern unsigned long ufsd_cycle_mb;

  #define UFSD_TRACE_NTFS_RW      // trace read/write operation (Used by UFSD_SDK).
  #define UFSD_TRACE_NTFS_DIR     // trace directory enumeration (Used by UFSD_SDK).
//  #define UFSD_TRACE_NTFS_CMPR
  #define UFSD_TRACE_HFS_RW
  #define UFSD_TRACE_HFS_DIR
  #define UFSD_TRACE_FAT_DIR
  #define UFSD_TRACE_EXFAT_RW
  #define UFSD_TRACE_EXFAT_DIR
  #define UFSD_TRACE_REFS_DIR
  #define UFSD_TRACE_REFS_RW

  #ifdef UFSD_DEBUG
    #define UFSD_NTFS_EXTRA_LOG
    #define UFSD_EXFAT_EXTRA_LOG
    #define UFSD_TRACE_NTFS_JOURNAL
    #define UFSD_TRACE_HFS_JOURNAL
    #define UFSD_TRACE_ERROR
//    #define UFSD_PROFILE          // Profiler puts results into trace
    #define UFSD_USE_GET_MEMORY_USAGE
  #ifndef UFSD_NO_USE_IOCTL
    //
    // /proc/fs/ufsd/<volume> contains NTFS read/write statistics
    //
//    #define UFSD_NTFS_STAT
  #endif
  #endif

  #define UFSD_LEVEL_ALWAYS         0x00000000
  #define UFSD_LEVEL_ERROR          0x00000001
  #define UFSD_LEVEL_DEBUG_HOOKS    0x00000002
  #define UFSD_LEVEL_UFSD           0x00000010
  #define UFSD_LEVEL_UFSDAPI        0x00000080
  #define UFSD_LEVEL_VFS            0x00002000
  #define UFSD_LEVEL_WBWE           0x00004000
  #define UFSD_LEVEL_BIO            0x00008000
  #define UFSD_LEVEL_PAGE_RW        0x00010000
//  #define UFSD_LEVEL_WB             0x10000000
  #define UFSD_LEVEL_IO             0x20000000
  #define UFSD_LEVEL_SEMA           0x40000000
  #define UFSD_LEVEL_MEMMNGR        0x80000000

  // "all"
  #define UFSD_LEVEL_STR_ALL        ~(UFSD_LEVEL_WBWE|UFSD_LEVEL_MEMMNGR|UFSD_LEVEL_IO|UFSD_LEVEL_UFSDAPI|UFSD_LEVEL_BIO|UFSD_LEVEL_PAGE_RW)
  // "vfs"
  #define UFSD_LEVEL_STR_VFS        (UFSD_LEVEL_SEMA|UFSD_LEVEL_VFS|UFSD_LEVEL_BIO|UFSD_LEVEL_ERROR)
  // "lib"
  #define UFSD_LEVEL_STR_LIB        (UFSD_LEVEL_UFSD|UFSD_LEVEL_ERROR)
  // "mid"
  #define UFSD_LEVEL_STR_MID        (UFSD_LEVEL_VFS|UFSD_LEVEL_UFSD|UFSD_LEVEL_ERROR)
  // "tst"
  #define UFSD_LEVEL_STR_TST        (UFSD_LEVEL_ERROR)
  // "default"
  #define UFSD_LEVEL_STR_DEFAULT    (UFSD_LEVEL_DEFAULT)

  #define UFSD_LEVEL_DEFAULT        0x0000000f

  #ifdef __KERNEL__
    #include <linux/types.h>
    extern atomic_t ufsd_trace_indent;
    #define ufsd_trace_inc( indent )  atomic_add( indent, &ufsd_trace_indent );
  #else
    #define ufsd_trace_inc( indent )  ufsd_trace_inc_dbg( indent );
    void UFSDAPI_CALL ufsd_trace_inc_dbg( int Indent );
  #endif

  #define UFSDTrace(a)                          \
    do {                                        \
      if ( ufsd_trace_level & UFSD_LEVEL_UFSD ) \
        _UFSDTrace a;                           \
    } while((void)0,0)

  #define UFSDTrace2(a)                         \
    do {                                        \
      if ( ufsd_trace_level & UFSD_LEVEL_ERROR )\
        _UFSDTrace a;                           \
    } while((void)0,0)

  #ifdef UFSD_DEBUG
  #define DebugTrace(INDENT,LEVEL,X)                        \
    do {                                                    \
      if ( 0 != (LEVEL) && !( ufsd_trace_level & (LEVEL) ) ) \
        break;                                              \
      if ( (INDENT) < 0 )                                   \
        ufsd_trace_inc( (INDENT) );                          \
      _UFSDTrace X;                                         \
      if ( (INDENT) > 0 )                                   \
        ufsd_trace_inc( (INDENT) );                          \
    } while((void)0,0)
  #else
    #define DebugTrace(i, l, x) do{}while((void)0,0)
  #endif
  #define VfsTrace(INDENT,LEVEL,X)                          \
    do {                                                    \
      if ( 0 != (LEVEL) && !( ufsd_trace_level & (LEVEL) ) ) \
        break;                                              \
      if ( (INDENT) < 0 )                                   \
        ufsd_trace_inc( (INDENT) );                          \
      _UFSDTrace X;                                         \
      if ( (INDENT) > 0 )                                   \
        ufsd_trace_inc( (INDENT) );                          \
    } while((void)0,0)
  #define TRACE_ONLY(e) e
#else
  #define UFSDTrace(a) do{}while((void)0,0)
  #define DebugTrace(i, l, x) do{}while((void)0,0)
  #define VfsTrace(i, l, x) do{}while((void)0,0)
  #define TRACE_ONLY(e)
#endif


#ifdef UFSD_SMART_TRACE
  #define SMART_TRACE_ONLY(x) x
#else
  #define SMART_TRACE_ONLY(x)
#endif


#ifdef UFSD_DEBUG

  // ==============================================
  //      The set of debug functions UFSD_SDK can use
  // ==============================================
  void UFSDAPI_CALL               ufsd_dump_stack( void );
  void UFSDAPI_CALL               ufsd_turn_on_trace_level( void );
  void UFSDAPI_CALL               ufsd_revert_trace_level( void );
  #define UFSD_DumpStack          ufsd_dump_stack
  #define UFSD_TurnOnTraceLevel   ufsd_turn_on_trace_level
  #define UFSD_RevertTraceLevel   ufsd_revert_trace_level

   #ifndef ufsd_stringify
     #define ufsd_stringify_1(x...)     #x
     #define ufsd_stringify(x...)       ufsd_stringify_1(x)
   #endif

#if 1
  // The output is replaced by the assert to usfd_assert.  For details see bug 76848.
  // DO NOT CHANGE ufsd_assert without approval of the UFSD CI team.
  #define assert(cond)                                      \
  do { if (!(cond)) {                                       \
      _UFSDTrace( "***** ufsd_assert " __FILE__ ", " ufsd_stringify(__LINE__) "\n" );    \
  }} while((void)0,0)
#else
  // The output is replaced by the assert to usfd_assert.  For details see bug 76848.
  // DO NOT CHANGE ufsd_assert without approval of the UFSD CI team.
  #define assert(cond)                                      \
  do { if (!(cond)) {                                       \
      _UFSDTrace( "***** ufsd_assert " __FILE__ ", " ufsd_stringify(__LINE__) ": %s\n", #cond );    \
   }} while((void)0,0)
#endif

  #define verify(cond) assert(cond)

  #define DEBUG_ONLY(e) e
#else
  #define assert(cond)
  #define verify(cond) {(void)(cond);}
  #define DEBUG_ONLY(e)
#endif


struct inode;
struct super_block;
struct buffer_head;

#if defined UFSD_HFS || (defined UFSD_NTFS && defined UFSD_NTFS_JNL)
  struct buffer_head;
  struct page;

  typedef unsigned long long UINT64;
  #include <stddef.h> // size_t
  #include "jnl.h"
#endif

#ifndef Add2Ptr
  #define Add2Ptr(P,I)   ((unsigned char*)(P) + (I))
  #define PtrOffset(B,O) ((size_t)((size_t)(O) - (size_t)(B)))
#endif

//
// static assert in gcc since 4.3, requires -std=c++0x
//
#if defined __cplusplus
  #if __cplusplus >= 201103L
    #define C_ASSERT(e) static_assert( e, #e )
  #else
    #define C_ASSERT(e) typedef char _C_ASSERT_[(e)?1:-1]
  #endif
#elif (__GNUC__ == 4 && __GNUC_MINOR__ >= 6) || __GNUC__ >= 5
  #define C_ASSERT(e) _Static_assert( e, #e )
#else
  #define C_ASSERT(e) typedef char _C_ASSERT_[(e)?1:-1]
#endif

#ifndef UNREFERENCED_PARAMETER
  #define UNREFERENCED_PARAMETER(P)         {(void)(P);}
#endif

#define UFSD_ERROR_DEFINED // UFSDError is already declared
#define _VERSIONS_H_       // Exclude configuration part of file versions.h

// ==============================================
//            The set of functions UFSD_SDK can use
// ==============================================

void* UFSDAPI_CALL ufsd_set_shared( void* ptr, unsigned bytes );
void* UFSDAPI_CALL ufsd_put_shared( void* ptr );
void* UFSDAPI_CALL ufsd_cache_create( const char*  Name, unsigned size, unsigned align );
void  UFSDAPI_CALL ufsd_cache_destroy( void*  Cache );
void* UFSDAPI_CALL ufsd_cache_alloc( void*  Cache, int bZero );
void  UFSDAPI_CALL ufsd_cache_free( void*  Cache, void*  p );
const char* UFSDAPI_CALL ufsd_bd_name( struct super_block *sb );
void  UFSDAPI_CALL ufsd_bd_set_blocksize( struct super_block *sb, unsigned int BytesPerBlock );
void  UFSDAPI_CALL ufsd_bd_invalidate( struct super_block *sb );
unsigned long UFSDAPI_CALL ufsd_bd_read_ahead( struct super_block *sb, unsigned long long, unsigned long );
void  UFSDAPI_CALL ufsd_bd_unmap_meta( struct super_block *sb, unsigned long long, unsigned long long );
void  UFSDAPI_CALLv ufsd_printk( struct super_block *sb, const char* fmt, ... ) __attribute__ ((format (printf, 2, 3)));
unsigned UFSDAPI_CALL ufsd_get_page0( void *inode, void* data, unsigned int bytes );
unsigned UFSDAPI_CALL ufsd_bd_flush( struct super_block *sb, unsigned wait );

// use unsigned long instead of size_t 'cause size_t is not known here
void* UFSDAPI_CALL ufsd_heap_alloc( unsigned long Size, int Zero )
#if defined __GNUC__ && ((__GNUC__ == 4 && __GNUC_MINOR__ >= 6) || __GNUC__ >= 5)
    __attribute__((alloc_size(1)))
#endif
    ;
void UFSDAPI_CALL ufsd_heap_free( void* p );

//
// UFSD_NO_PRINTK - external define to off from library
//
#ifdef UFSD_NO_PRINTK
  #define UFSDTracek(a)
#else
  #define UFSDTracek(a) ufsd_printk a
  #define UFSD_TRACEK
#endif

#if defined UFSD_TRACE_SILENT || defined UFSD_NO_PRINTK
  #define UFSDTracekS(a)
#else
  #define UFSDTracekS(a)  ufsd_printk a
#endif

#define UFSD_SetShared        ufsd_set_shared
#define UFSD_PutShared        ufsd_put_shared
#define UFSD_CacheCreate      ufsd_cache_create
#define UFSD_CacheDestroy     ufsd_cache_destroy
#define UFSD_CacheAlloc       ufsd_cache_alloc
#define UFSD_CacheFree        ufsd_cache_free
#define UFSD_BdGetName        ufsd_bd_name
#define UFSD_BdSetBlockSize   ufsd_bd_set_blocksize
#define UFSD_BdInvalidate     ufsd_bd_invalidate
#define UFSD_BdUnMapMeta      ufsd_bd_unmap_meta
#ifndef UFSD_TURN_OFF_READAHEAD
  #define UFSD_BdReadAhead      ufsd_bd_read_ahead
#endif
#define UFSD_HeapAlloc        ufsd_heap_alloc
#define UFSD_HeapFree         ufsd_heap_free
// To activate nonresident -> resident activate define ufsd_get_page0
#define ufsd_get_page0         ufsd_get_page0
#define ufsd_bd_flush         ufsd_bd_flush

#ifdef __cplusplus
} // extern "C"{
#endif
