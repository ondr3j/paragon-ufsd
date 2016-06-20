/*++


Module Name:

    vfsdebug.c

Abstract:

    This module implements UFSD debug subsystem

Author:

    Ahdrey Shedel

Revision History:

    18/09/2000 - Andrey Shedel - Created
    Since 29/07/2005 - Alexander Mamaev

--*/

#include <linux/version.h>
#include <linux/kernel.h>
#include <linux/string.h>
#include <linux/fs.h>
#include <linux/slab.h>
#include <linux/mm.h>
#include <linux/uio.h>
#include <linux/aio.h>
#include <asm/uaccess.h>
#include <linux/sched.h>
#include <linux/ratelimit.h>
#include <linux/rwsem.h>

#include "config.h"
#include "ufsdapi.h"

//
// Endianess test
//
static const unsigned short szTstEnd[3] __attribute__ ((used)) = {0x694C,0x4274,0x6769};

#ifdef UFSD_TRACE

#include <linux/module.h>
#include <linux/seq_file.h>

char ufsd_trace_level_[16] = {0};

//
// Activate this define to build driver with predefined trace and log
//
// #define UFSD_DEFAULT_LOGTO  "/ufsd/ufsd.log"

#ifdef UFSD_DEFAULT_LOGTO
  char ufsd_trace_file[128]       = UFSD_DEFAULT_LOGTO;
  unsigned long ufsd_trace_level  = ~(UFSD_LEVEL_VFS_WBWE|UFSD_LEVEL_MEMMNGR|UFSD_LEVEL_IO|UFSD_LEVEL_UFSDAPI);
  unsigned long ufsd_cycle_mb     = 25;
#else
  char ufsd_trace_file[128]       = "";
  unsigned long ufsd_trace_level  = UFSD_LEVEL_DEFAULT;
  unsigned long ufsd_cycle_mb     = 0;
#endif

atomic_t ufsd_trace_indent;
static DECLARE_RWSEM(log_file_mutex);
static struct file *log_file;
static int log_file_opened;
static int indent_printed;

static void ufsd_vlog( const char *fmt, va_list ap );
static void ufsd_log( const char *fmt, int len, int err_msg );

//
// This mutex is used to protect 'ufsd_trace_level'
//
struct mutex  s_MountMutex;

//#define UFSD_ACTIVATE_KEEP_TRACE_ON

#ifdef UFSD_ACTIVATE_KEEP_TRACE_ON

static int        s_KeepLogs;
static atomic_t   s_LogCnt;
#define MAX_LOG_CNT   10000
static LIST_HEAD( s_MountStr );
static DEFINE_SPINLOCK( s_TraceSpin ); // to protect s_MountStr

struct str_entry{
  struct list_head entry;
  int     len;
  char    buf[1];
};


///////////////////////////////////////////////////////////
// ufsd_keep_trace_on
//
// activate trace keep. Called from fill_super after locking s_MountMutex
///////////////////////////////////////////////////////////
void
ufsd_keep_trace_on( void )
{
  assert( mutex_is_locked( &s_MountMutex ) );
  assert( 0 == s_KeepLogs );
  s_KeepLogs  = 1;
  atomic_set( &s_LogCnt, 0 );
}


///////////////////////////////////////////////////////////
// ufsd_keep_trace_off
//
// deactivate trace keep. Called from fill_super before unlocking s_MountMutex
///////////////////////////////////////////////////////////
void
ufsd_keep_trace_off(
    IN int print_logs
    )
{
  assert( mutex_is_locked( &s_MountMutex ) );
  s_KeepLogs = 0;

  spin_lock( &s_TraceSpin );
  while( !list_empty( &s_MountStr ) ) {
    struct str_entry* e = list_entry( s_MountStr.next, struct str_entry, entry );
    list_del( &e->entry );
    spin_unlock( &s_TraceSpin );

    if ( print_logs )
      ufsd_log( e->buf, e->len, '*' == e->buf[0] && '*' == e->buf[1] && '*' == e->buf[2] && '*' == e->buf[3] );

    kfree( e );
    spin_lock( &s_TraceSpin );
  }

  spin_unlock( &s_TraceSpin );
}
#endif // #ifdef UFSD_ACTIVATE_KEEP_TRACE_ON


///////////////////////////////////////////////////////////
// ufsd_trace_inc
//
//
///////////////////////////////////////////////////////////
UFSDAPI_CALL void
ufsd_trace_inc_dbg(
    IN int indent
    )
{
  atomic_add( indent, &ufsd_trace_indent );
}

#ifndef CONFIG_VERSION_SIGNATURE
  #if defined HAVE_GENERATED_COMPILE_H && HAVE_GENERATED_COMPILE_H
    #include <generated/compile.h>
  #endif

  #if defined HAVE_GENERATED_UTSRELEASE_H && HAVE_GENERATED_UTSRELEASE_H
    #include <generated/utsrelease.h>
  #endif

  #ifndef UTS_RELEASE
    #define UTS_RELEASE ""
  #endif

  #ifndef UTS_VERSION
    #define UTS_VERSION ""
  #endif

  #define CONFIG_VERSION_SIGNATURE  UTS_RELEASE ", " UTS_VERSION
#endif


#if defined HAVE_STRUCT_MODULE_MODULE_CORE && HAVE_STRUCT_MODULE_MODULE_CORE
  #define UFSD_MODULE_CORE() __this_module.module_core
#elif defined HAVE_STRUCT_MODULE_MODULE_CORE_RX && HAVE_STRUCT_MODULE_MODULE_CORE_RX
  #define UFSD_MODULE_CORE() __this_module.module_core_rx
#else
  #define UFSD_MODULE_CORE() (void*)0
#endif


extern const char s_FileVer[];
extern const char s_DriverVer[];

///////////////////////////////////////////////////////////
// format_hdr
//
// Formats standard header for log file
///////////////////////////////////////////////////////////
static inline unsigned
format_hdr(
    IN char *buffer,
    IN unsigned buflen
    )
{
  return
    snprintf( buffer, buflen,
              CONFIG_VERSION_SIGNATURE"\n"
              "Kernel version %d.%d.%d, cpus="_QUOTE2(NR_CPUS)"\n"
              "%s"
              "%s%s\n"
              "Module address %p\n"
#ifdef UFSD_DEBUG
              "sizeof(inode)=%zu\n"
#endif
              ,
              LINUX_VERSION_CODE>>16, (LINUX_VERSION_CODE>>8)&0xFF, LINUX_VERSION_CODE&0xFF,
              ufsdapi_library_version( NULL ),
              s_FileVer, s_DriverVer,
              UFSD_MODULE_CORE()
#ifdef UFSD_DEBUG
              , sizeof(struct inode)
#endif
              );
}


///////////////////////////////////////////////////////////
// ufsd_vfs_write
//
// Helper function to use filp->f_op->write/f_op->aio_write/filp->f_op->write_iter
///////////////////////////////////////////////////////////
static ssize_t
ufsd_vfs_write(
    IN struct file  *file,
    IN const char   *buf,
    IN size_t       len,
    IN OUT loff_t   *ppos
    )
{
  ssize_t ret;
  mm_segment_t old_limit = get_fs();
  set_fs( KERNEL_DS );

#if defined HAVE_DECL___VFS_WRITE && HAVE_DECL___VFS_WRITE
  // 4.1+
  ret = __vfs_write( file, buf, len, ppos );
#else
  if ( NULL != file->f_op->write )
    ret = file->f_op->write( file, buf, len, ppos );
  else{
#if defined HAVE_DECL_NEW_SYNC_WRITE && HAVE_DECL_NEW_SYNC_WRITE
    // Use f_op->write_iter
    ret = file->f_op->write_iter
      ? new_sync_write( file, buf, len, ppos )
      : -EINVAL;
#else
    // Use f_op->aio_write
    ret = file->f_op->aio_write
      ? do_sync_write( file, buf, len, ppos )
      : -EINVAL;
#endif
  }
#endif

  set_fs( old_limit );
  return ret;
}


///////////////////////////////////////////////////////////
// write_header_in_log_file
//
// Print header in provided log file
// Negative return value - error
///////////////////////////////////////////////////////////
static ssize_t
write_header_in_log_file(
    struct file *log_file
    )
{
  ssize_t werr = -1;
  const unsigned buflen = 1024;
  char *buffer = kmalloc( buflen, GFP_NOFS );
  if ( NULL != buffer ) {
    unsigned hdr_len = format_hdr( buffer, buflen );
    if ( hdr_len > buflen )
      hdr_len = buflen;
    werr = ufsd_vfs_write( log_file, buffer, hdr_len, &log_file->f_pos );
    kfree( buffer );
  }
  return werr;
}


///////////////////////////////////////////////////////////
// ufsd_log
//
// The main logging function
///////////////////////////////////////////////////////////
noinline static void
ufsd_log(
    IN const char *fmt,
    IN int len,
    IN int err_msg
    )
{
  int log_status = 0;

  if ( len <= 0 || 0 == fmt[0] )
    return;

#ifdef UFSD_ACTIVATE_KEEP_TRACE_ON
  if ( s_KeepLogs && mutex_is_locked( &s_MountMutex ) ) {
    //
    // This function may be called from different threads
    //
    if ( atomic_inc_return( &s_LogCnt ) < MAX_LOG_CNT ) {
      struct str_entry* e = (struct str_entry*)kmalloc( len + offsetof(struct str_entry, buf) + 1, GFP_KERNEL );
      if ( NULL != e ) {
        spin_lock( &s_TraceSpin );
        list_add_tail( &e->entry, &s_MountStr );
        spin_unlock( &s_TraceSpin );
        e->len = len;
        memcpy( e->buf, fmt, len );
        e->buf[len] = 0;
      }
    }
    return;
  }
#endif

  down_read( &log_file_mutex );

  if ( ( NULL != log_file || !log_file_opened ) && !( current->flags & (PF_MEMALLOC|PF_KSWAPD) ) ) {
    long werr = 0;

    if ( !log_file_opened && 0 != ufsd_trace_file[0] ) {
      int need_close = 0;
      struct file *new_log_file = filp_open( ufsd_trace_file, O_WRONLY | O_CREAT | O_TRUNC | O_LARGEFILE, S_IRUGO | S_IWUGO );
      if ( IS_ERR( new_log_file ) ) {
        printk( KERN_NOTICE  QUOTED_UFSD_DEVICE ": failed to start log to '%s' (errno=%ld), use system log\n", ufsd_trace_file, PTR_ERR( new_log_file ) );
        new_log_file = NULL;
      }
      up_read( &log_file_mutex );
      down_write( &log_file_mutex );
      if ( 0 == log_file_opened ) {
        log_file_opened = 1;
        log_file = new_log_file;
      }
      else {
        // Someone already opened file
        need_close = 1;
      }
      downgrade_write( &log_file_mutex );
      if ( need_close ) {
        if ( NULL != new_log_file )
          filp_close( new_log_file, NULL );
      }

      if ( !need_close && NULL != log_file ) {
        // We opened file - write log header
        werr = write_header_in_log_file( log_file );
        if ( werr < 0 )
          goto log_failed;
      }
    }

    if ( NULL != log_file ) {
      // preserve 'fmt' and 'len'. They may be used later in printk
      int lenw = len;
      const char* fmtw = fmt;
      if ( 0 != ufsd_cycle_mb ) {
        size_t bytes  = ufsd_cycle_mb << 20;
        int to_write  = log_file->f_pos + len > bytes? (bytes - log_file->f_pos) : len;
        if ( to_write > 0 ) {
          werr = ufsd_vfs_write( log_file, fmtw, to_write, &log_file->f_pos );
          fmtw += to_write;
          lenw -= to_write;
        }

        if ( 0 != lenw )
          log_file->f_pos = 0;
      }

      if ( 0 != lenw )
        werr = ufsd_vfs_write( log_file, fmtw, lenw, &log_file->f_pos );

      if ( werr < 0 ) {
log_failed:
        printk( KERN_ERR QUOTED_UFSD_DEVICE ": log write failed: %ld\n", werr );
        up_read( &log_file_mutex );
        down_write( &log_file_mutex );
        filp_close( log_file, NULL );
        log_file = NULL;
        downgrade_write( &log_file_mutex );
      }
    }

    if ( werr > 0 && !err_msg )
      log_status = 1; // This is normal way of logging in file
  }

  up_read( &log_file_mutex );

  if ( log_status )
    return;

//  printk( KERN_NOTICE  QUOTED_UFSD_DEVICE ":%*.s", len, fmt );
  printk( err_msg
          ? KERN_ERR    QUOTED_UFSD_DEVICE ": %s"
          : KERN_NOTICE QUOTED_UFSD_DEVICE ": %s",
          fmt );
}


///////////////////////////////////////////////////////////
// ufsd_close_trace
//
// need_reopen - if non-zero value, then try to open new log file
///////////////////////////////////////////////////////////
void
ufsd_close_trace( int need_reopen )
{
  struct file *new_log_file = NULL;

  if ( need_reopen && 0 != ufsd_trace_file[0] ) {
    new_log_file = filp_open( ufsd_trace_file, O_WRONLY | O_CREAT | O_TRUNC | O_LARGEFILE, S_IRUGO | S_IWUGO );
    if ( IS_ERR( new_log_file ) ) {
      printk( KERN_NOTICE  QUOTED_UFSD_DEVICE ": failed to start log to '%s' (errno=%ld), use system log\n", ufsd_trace_file, PTR_ERR( new_log_file ) );
      new_log_file = NULL;
    }
    else {
      // We opened file - write log header
      ssize_t werr = write_header_in_log_file( new_log_file );
      if ( werr < 0 ) {
        printk( KERN_ERR QUOTED_UFSD_DEVICE ": new log write failed: %zd\n", werr );
        filp_close( new_log_file, NULL );
        new_log_file = NULL;
      }
    }
  }

  down_write( &log_file_mutex );
  if ( NULL != log_file )
    filp_close( log_file, NULL );
  log_file_opened = 1;
  log_file = new_log_file;
  indent_printed = 0;
  up_write( &log_file_mutex );
}


///////////////////////////////////////////////////////////
// _UFSDTrace
//
//
///////////////////////////////////////////////////////////
UFSDAPI_CALLv void
_UFSDTrace( const char *fmt, ... )
{
  va_list ap;
  va_start( ap, fmt );
  ufsd_vlog( fmt, ap );
  va_end( ap );
}


///////////////////////////////////////////////////////////
// UFSDError
//
//
///////////////////////////////////////////////////////////
UFSDAPI_CALL void
UFSDError( int Err, const char *FileName, int Line )
{
  const char *Name = strrchr( FileName, '/' );
  if ( NULL == Name )
    Name = FileName - 1;

  // Print the line number first 'cause the full name can be too long
//  _UFSDTrace( "**** UFSD error 0x%x, %d, %s\n", Err, Line, Name + 1 );
  _UFSDTrace( "\"%s\": UFSD error 0x%x, %d, %s\n", current->comm, Err, Line, Name + 1 );
//  BUG_ON( 1 );
}


///////////////////////////////////////////////////////////
// ufsd_vlog
//
//
///////////////////////////////////////////////////////////
noinline static void
ufsd_vlog(
    IN const char *fmt,
    IN va_list    ap
    )
{
  char buf[160];
  int len;
  int err_msg = '*' == fmt[0] && '*' == fmt[1] && '*' == fmt[2] && '*' == fmt[3];

  if ( err_msg ) {
    //
    // always print assert from position 0
    // The first **** will print
    len = 0;
  } else {
    len = atomic_read( &ufsd_trace_indent );
    if ( len < 0 ) {
      //
      // Don't assert( len < 0 ): - it calls _UFSDTrace -> ufsd_vlog -> assert -> _UFSDTrace -> ufsd_vlog ->....
      //
      if ( !indent_printed ) {
        indent_printed = 1;
        ufsd_log( "**** trace_indent < 0\n", sizeof("**** trace_indent < 0\n")-1, 1 );
      }
      len = 0;
    } else if ( len > 0 ) {
      len %= 20;
      memset( buf, ' ', len );
    }
  }

  len += vsnprintf( buf + len, sizeof(buf) - len, fmt, ap );

  if ( len > sizeof(buf) ) {
    len = sizeof(buf);
    buf[sizeof(buf)-3] = '.';
    buf[sizeof(buf)-2] = '.';
    buf[sizeof(buf)-1] = '\n';
  }

  if ( err_msg && len < sizeof(buf) ) {
    //
    // Insert in the begin the current process name
    //
    int ln = strlen( current->comm );
    if ( ln + len >= sizeof(buf) )
      ln = sizeof(buf) - len - 1;
    if ( ln > 0 ) {
      memmove( buf + ln, buf, len + 1 );
      memcpy( buf, current->comm, ln );
      len += ln;
    }
  }

  ufsd_log( buf, len, err_msg );

  // to stop on asserts just uncomment this line
//  BUG_ON( err_msg );
}


///////////////////////////////////////////////////////////
// parse_trace_level
//
// parses string for trace level
// It sets global variables 'ufsd_trace_level'
///////////////////////////////////////////////////////////
void
parse_trace_level(
    IN const char *v
    )
{
  if ( NULL == v || 0 == v[0] )
    ufsd_trace_level = UFSD_LEVEL_DEFAULT;
  else if ( 0 == strcmp( v, "all" ) )
    ufsd_trace_level = UFSD_LEVEL_STR_ALL;
  else if ( 0 == strcmp( v, "vfs" ) )
    ufsd_trace_level = UFSD_LEVEL_STR_VFS;
  else if ( 0 == strcmp( v, "lib" ) )
    ufsd_trace_level = UFSD_LEVEL_STR_LIB;
  else if ( 0 == strcmp( v, "mid" ) )
    ufsd_trace_level = UFSD_LEVEL_STR_MID;
  else if ( 0 == strcmp( v, "io" ) )
    ufsd_trace_level = UFSD_LEVEL_IO;
  else if ( 0 == strcmp( v, "tst" ) )
    ufsd_trace_level = UFSD_LEVEL_STR_TST;
  else if ( 0 == strcmp( v, "default" ) )
    ufsd_trace_level = UFSD_LEVEL_DEFAULT;
  else if ( '-' == v[0] )
    ufsd_trace_level = simple_strtol( v, NULL, 10 );
  else
    ufsd_trace_level = simple_strtoul( v, NULL, 16 );
  DebugTrace( 0, UFSD_LEVEL_ALWAYS, ("trace mask set to %08lx (\"%s\")\n", ufsd_trace_level, v));
}


///////////////////////////////////////////////////////////
// parse_cycle_value
//
// parses string for cycle=XXX
// It sets global variables 'ufsd_cycle_mb'
///////////////////////////////////////////////////////////
void
parse_cycle_value(
    IN const char *v
    )
{
  unsigned long tmp;
  // Support both forms: 'cycle' and 'cycle=256'
  if ( NULL == v || 0 == v[0] )
    tmp = 1;
  else {
    char* n;
    tmp = simple_strtoul( v, &n, 0 );
    if ( 'K' == *n )
      tmp *= 1024;
    else if ( 'M' == *n )
      tmp *= 1024*1024;
  }
  ufsd_cycle_mb = (tmp + 1024*1024 - 1) >> 20;
}


///////////////////////////////////////////////////////////
// ufsd_bd_name
//
// Returns the name of block device
///////////////////////////////////////////////////////////
const char*
UFSDAPI_CALL
ufsd_bd_name(
    IN struct super_block *sb
    )
{
  return sb->s_id;
}


///////////////////////////////////////////////////////////
// ufsd_proc_dev_trace_show
//
// /proc/fs/ufsd/trace
///////////////////////////////////////////////////////////
static int
ufsd_proc_dev_trace_show(
    IN struct seq_file  *m,
    IN void             *o
    )
{
  const char *hint;
  switch( ufsd_trace_level ) {
  case UFSD_LEVEL_STR_ALL:  hint = "all"; break;
  case UFSD_LEVEL_STR_VFS:  hint = "vfs"; break;
  case UFSD_LEVEL_STR_LIB:  hint = "lib"; break;
  case UFSD_LEVEL_STR_MID:  hint = "mid"; break;
  case UFSD_LEVEL_STR_TST:  hint = "tst"; break;
  case UFSD_LEVEL_STR_DEFAULT:  hint = "default"; break;
  default:
    seq_printf( m, "%lx\n", ufsd_trace_level );
    return 0;
  }
  seq_printf( m, "%s\n", hint );
  return 0;
}


static int ufsd_proc_dev_trace_open(struct inode *inode, struct file *file)
{
  return single_open( file, ufsd_proc_dev_trace_show, NULL );
}


///////////////////////////////////////////////////////////
// ufsd_proc_dev_trace_write
//
// /proc/fs/ufsd/trace
///////////////////////////////////////////////////////////
static ssize_t
ufsd_proc_dev_trace_write(
    IN struct file  *file,
    IN const char __user *buffer,
    IN size_t       count,
    IN OUT loff_t   *ppos
    )
{
  //
  // Copy buffer into kernel memory
  //
  char kbuffer[16];
  size_t len = count;
  if ( len > sizeof(kbuffer)-1 )
    len = sizeof(kbuffer)-1;

  if ( 0 != copy_from_user( kbuffer, buffer, len ) )
    return -EINVAL;

  // Remove last '\n'
  while( len > 0 && '\n' == kbuffer[len-1] )
    len -= 1;

  // Set last zero
  kbuffer[len] = 0;

  mutex_lock( &s_MountMutex );
  parse_trace_level( kbuffer );
  mutex_unlock( &s_MountMutex );

  *ppos += count;
  return count;
}


const struct file_operations ufsd_proc_dev_trace_fops = {
  .owner    = THIS_MODULE,
  .read     = seq_read,
  .llseek   = seq_lseek,
  .release  = single_release,
  .open     = ufsd_proc_dev_trace_open,
  .write    = ufsd_proc_dev_trace_write,
};


///////////////////////////////////////////////////////////
// ufsd_proc_dev_log_show
//
// /proc/fs/ufsd/trace
///////////////////////////////////////////////////////////
static int
ufsd_proc_dev_log_show(
    IN struct seq_file  *m,
    IN void             *o
    )
{
  seq_printf( m, "%s\n", ufsd_trace_file );
  return 0;
}

static int ufsd_proc_dev_log_open( struct inode *inode, struct file *file )
{
  return single_open( file, ufsd_proc_dev_log_show, NULL );
}


///////////////////////////////////////////////////////////
// ufsd_proc_dev_log_write
//
// /proc/fs/ufsd/trace
///////////////////////////////////////////////////////////
static ssize_t
ufsd_proc_dev_log_write(
    IN struct file  *file,
    IN const char __user *buffer,
    IN size_t       count,
    IN OUT loff_t   *ppos
    )
{
  //
  // Copy buffer into kernel memory
  //
  char kbuffer[sizeof(ufsd_trace_file)];
  size_t len = count;
  if ( len > sizeof(kbuffer)-1 )
    len = sizeof(kbuffer)-1;

  if ( 0 != copy_from_user( kbuffer, buffer, len ) )
    return -EINVAL;

  // Remove last '\n'
  while( len > 0 && '\n' == kbuffer[len-1] )
    len -= 1;

  // Set last zero
  kbuffer[len] = 0;

  if ( 0 != strcmp( ufsd_trace_file, kbuffer ) ) {
    memcpy( ufsd_trace_file, kbuffer, len + 1 );
    ufsd_close_trace( 1 );
  }

  *ppos += count;
  return count;
}


const struct file_operations ufsd_proc_dev_log_fops = {
  .owner    = THIS_MODULE,
  .read     = seq_read,
  .llseek   = seq_lseek,
  .release  = single_release,
  .open     = ufsd_proc_dev_log_open,
  .write    = ufsd_proc_dev_log_write,
};


///////////////////////////////////////////////////////////
// ufsd_proc_dev_cycle_show
//
// /proc/fs/ufsd/cycle
///////////////////////////////////////////////////////////
static int
ufsd_proc_dev_cycle_show(
    IN struct seq_file  *m,
    IN void             *o
    )
{
  seq_printf( m, "%lu\n", ufsd_cycle_mb );
  return 0;
}


static int ufsd_proc_dev_cycle_open( struct inode *inode, struct file *file )
{
  return single_open( file, ufsd_proc_dev_cycle_show, NULL );
}


///////////////////////////////////////////////////////////
// ufsd_proc_dev_cycle_write
//
// /proc/fs/ufsd/cycle
///////////////////////////////////////////////////////////
static ssize_t
ufsd_proc_dev_cycle_write(
    IN struct file  *file,
    IN const char __user *buffer,
    IN size_t       count,
    IN OUT loff_t   *ppos
    )
{
  //
  // Copy buffer into kernel memory
  //
  char kbuffer[16];
  size_t len = count;
  if ( len > sizeof(kbuffer)-1 )
    len = sizeof(kbuffer)-1;

  if ( 0 != copy_from_user( kbuffer, buffer, len ) )
    return -EINVAL;

  // Remove last '\n'
  while( len > 0 && '\n' == kbuffer[len-1] )
    len -= 1;

  // Set last zero
  kbuffer[len] = 0;

  parse_cycle_value( kbuffer );
  *ppos += count;
  return count;
}


const struct file_operations ufsd_proc_dev_cycle_fops = {
  .owner    = THIS_MODULE,
  .read     = seq_read,
  .llseek   = seq_lseek,
  .release  = single_release,
  .open     = ufsd_proc_dev_cycle_open,
  .write    = ufsd_proc_dev_cycle_write,
};
#endif // #ifdef UFSD_TRACE


#ifdef UFSD_TRACEK
//
// This variable is used to get the bias
//
extern struct timezone sys_tz;

///////////////////////////////////////////////////////////
// ufsd_time_str
//
// Returns current time to sting form
///////////////////////////////////////////////////////////
int UFSDAPI_CALL
ufsd_time_str(
    OUT char *buffer,
    IN int buffer_len
    )
{
  struct tm tm;
#if 0
  // print time in UTC
  time_to_tm( get_seconds(), 0, &tm );
  return snprintf( buffer, buffer_len, "%ld-%02d-%02d %02d:%02d:%02d UTC", 1900 + tm.tm_year, tm.tm_mon + 1, tm.tm_mday, tm.tm_hour, tm.tm_min, tm.tm_sec );
#else
  // print local time
  time_to_tm( get_seconds(), -sys_tz.tz_minuteswest * 60, &tm );
  return snprintf( buffer, buffer_len, "%ld-%02d-%02d %02d:%02d:%02d", 1900 + tm.tm_year, tm.tm_mon + 1, tm.tm_mday, tm.tm_hour, tm.tm_min, tm.tm_sec );
#endif
}
#endif


///////////////////////////////////////////////////////////
// ufsd_printk
//
// Used to show different messages (errors and warnings)
///////////////////////////////////////////////////////////
void UFSDAPI_CALLv
ufsd_printk(
    IN struct super_block  *sb,
    IN const char *fmt, ...
    )
{
  va_list va;
  struct va_format vaf;
  const char *comm = current->comm;

  if ( !printk_ratelimit() )
    return;

  va_start( va, fmt );
//  assert( '\n' == fmt[strlen(fmt)-1] );

  vaf.fmt = fmt;
  vaf.va  = &va;

  printk( KERN_CRIT QUOTED_UFSD_DEVICE ": \"%s\" (%s): %pV", comm, NULL == sb? "" : sb->s_id, &vaf );

  va_end( va );

#ifdef UFSD_TRACE
  //
  // Duplicate error in log file (if not default)
  //
  if ( NULL != log_file && !( current->flags & (PF_MEMALLOC|PF_KSWAPD) ) ) {
    //
    // rebuild 'vaf'
    //
    va_start( va, fmt );
    vaf.fmt = fmt;
    vaf.va  = &va;
    _UFSDTrace( "\"%s\" (%s): %pV", comm, NULL == sb? "" : sb->s_id, &vaf );
    va_end( va );
  }
#endif
}


#ifdef UFSD_DEBUG

///////////////////////////////////////////////////////////
// ufsd_dump_stack
//
// Sometimes it is usefull to call this function from library
///////////////////////////////////////////////////////////
UFSDAPI_CALL void
ufsd_dump_stack( void )
{
  dump_stack();
}


static long ufsd_trace_level_Old;
///////////////////////////////////////////////////////////
// ufsd_turn_on_trace_level
//
//
///////////////////////////////////////////////////////////
UFSDAPI_CALL void
ufsd_turn_on_trace_level( void )
{
  ufsd_trace_level_Old = ufsd_trace_level;
  ufsd_trace_level = -1;
}


///////////////////////////////////////////////////////////
// ufsd_revert_trace_level
//
//
///////////////////////////////////////////////////////////
void UFSDAPI_CALL
ufsd_revert_trace_level( void )
{
  ufsd_trace_level  = ufsd_trace_level_Old;
}


///////////////////////////////////////////////////////////
// is_zero
//
//
///////////////////////////////////////////////////////////
int
is_zero(
    IN const char *data,
    IN size_t     bytes
    )
{
  if ( 0 == (((size_t)data)%sizeof(int)) ) {
    while( bytes >= sizeof(int) ) {
      if ( 0 != *(int*)data )
        return 0;
      bytes -= sizeof(int);
      data  += sizeof(int);
    }
  }

  while( 0 != bytes-- ) {
    if ( 0 != *data++ )
      return 0;
  }
  return 1;
}

#if 0
#include <linux/buffer_head.h>
///////////////////////////////////////////////////////////
// ufsd_trace_page_buffers
//
//
///////////////////////////////////////////////////////////
void
ufsd_trace_page_buffers(
    IN struct page  *page,
    IN int          hdr
    )
{
  if ( hdr ) {
    DebugTrace(+1, UFSD_LEVEL_PAGE_RW, ("p=%p f=%lx:\n", page, page->flags ));
  } else if ( ufsd_trace_level & UFSD_LEVEL_PAGE_RW ) {
    ufsd_trace_inc( +1 );
  }

  if ( page_has_buffers( page ) ) {
    struct buffer_head *head  = page_buffers(page);
    struct buffer_head *bh    = head;
    char*d = kmap( page );

    do {
      int zero = is_zero( d + bh_offset( bh ), bh->b_size );
      if ( (sector_t)-1 == bh->b_blocknr ) {
        DebugTrace( 0, UFSD_LEVEL_PAGE_RW, ("bh=%p,%lx%s\n", bh, bh->b_state, zero? ", z":"") );
      } else {
        DebugTrace( 0, UFSD_LEVEL_PAGE_RW, ("bh=%p,%lx,%"PSCT"x%s\n", bh, bh->b_state, bh->b_blocknr, zero? ", z":"" ) );
      }
      bh = bh->b_this_page;
    } while( bh != head );

    kunmap( page );
  } else {
    DebugTrace(0, UFSD_LEVEL_PAGE_RW, ("no buffers\n" ));
  }

  if ( ufsd_trace_level & UFSD_LEVEL_PAGE_RW )
    ufsd_trace_inc( -1 );
}

#include <linux/pagevec.h>
///////////////////////////////////////////////////////////
// trace_pages
//
//
///////////////////////////////////////////////////////////
unsigned
trace_pages(
    IN struct address_space *mapping
    )
{
  struct pagevec pvec;
  pgoff_t next = 0;
  unsigned Ret = 0;
  unsigned long i;

  pagevec_init( &pvec, 0 );

  while ( pagevec_lookup( &pvec, mapping, next, PAGEVEC_SIZE ) ) {
    for ( i = 0; i < pvec.nr; i++ ) {
      struct page *page = pvec.pages[i];
      void *d = kmap( page );
      DebugTrace( 0, UFSD_LEVEL_VFS, ("p=%p o=%llx f=%lx%s\n", page, (UINT64)page->index << PAGE_CACHE_SHIFT, page->flags, is_zero( d, PAGE_CACHE_SIZE )?", zero" : "" ));
      ufsd_trace_page_buffers( page, 0 );
      kunmap( page );
      if ( page->index > next )
        next = page->index;
      Ret += 1;
      next += 1;
    }
    pagevec_release(&pvec);
  }
  if ( 0 == next )
    DebugTrace( 0, UFSD_LEVEL_VFS, ("no pages\n"));
  return Ret;
}


///////////////////////////////////////////////////////////
// trace_page
//
//
///////////////////////////////////////////////////////////
void
trace_page(
    IN struct address_space *mapping,
    IN pgoff_t index
    )
{
  struct pagevec pvec;
  unsigned long i = 0;

  pagevec_init( &pvec, 0 );

  if ( pagevec_lookup( &pvec, mapping, index, PAGEVEC_SIZE ) ) {
    for ( i = 0; i < pvec.nr; i++ ) {
      struct page *page = pvec.pages[i];
      if ( page->index == index ) {
        char *d = kmap( page );
        DebugTrace( 0, UFSD_LEVEL_VFS, ("p=%p o=%llx f=%lx%s\n", page, (UINT64)page->index << PAGE_CACHE_SHIFT, page->flags, is_zero( d, PAGE_CACHE_SIZE )?", zero" : "" ));
        ufsd_trace_page_buffers( page, 0 );
        kunmap( page );
      }
    }
    pagevec_release(&pvec);
  }

  if ( 0 == i )
    DebugTrace( 0, UFSD_LEVEL_VFS, ("no page at %lx\n", index ));
}


///////////////////////////////////////////////////////////
// ufsd_drop_pages
//
//
///////////////////////////////////////////////////////////
void
ufsd_drop_pages(
    IN struct address_space *m
    )
{
  filemap_fdatawrite( m );
  unmap_mapping_range( m, 0, 0, 1 );
  truncate_inode_pages( m, 0 );
  unmap_mapping_range( m, 0, 0, 1 );
}


#if 0
struct bio_batch {
  atomic_t          done;
  unsigned long     flags;
  struct completion *wait;
};

static void bio_end_io( struct bio *bio, int err )
{
  struct bio_batch *bb = bio->bi_private;
  struct bio_vec *bvec = &bio->bi_io_vec[bio->bi_vcnt-1];
  int error  = !test_bit( BIO_UPTODATE, &bio->bi_flags );
  if ( error ){
    ufsd_printk( NULL, "bio read I/O error." );
  }

  do {
    struct page *page = bvec->bv_page;
    if ( !error ) {
      SetPageUptodate( page );
    } else {
      ClearPageDirty( page );
      SetPageError( page );
    }
    unlock_page( page );
  } while ( --bvec >= bio->bi_io_vec );

  if ( err && EOPNOTSUPP != err )
    clear_bit( BIO_UPTODATE, &bb->flags );
  if ( atomic_dec_and_test( &bb->done ) )
    complete( bb->wait );

  bio_put( bio );

  printk( "bio_end_io %d\n", error );
}


///////////////////////////////////////////////////////////
// ufsd_bd_check
//
///////////////////////////////////////////////////////////
int
UFSDAPI_CALL
ufsd_bd_check(
    IN struct super_block *sb
    )
{
  int err;
  struct bio_batch bb;
  struct page *page = alloc_page( GFP_KERNEL | __GFP_ZERO );
  struct bio *bio;
#ifdef DECLARE_COMPLETION_ONSTACK
  DECLARE_COMPLETION_ONSTACK( wait );
#else
  DECLARE_COMPLETION( wait );
#endif

  if ( NULL == page )
    return -ENOMEM;

  atomic_set( &bb.done, 1 );
  err       = 0;
  bb.flags  = 1 << BIO_UPTODATE;
  bb.wait   = &wait;

  bio = bio_alloc( GFP_NOFS, 1 );
  if ( !bio ) {
    err = -ENOMEM;
    goto out;
  }

  bio->bi_sector  = 0x7379;
  bio->bi_bdev    = sb->s_bdev;
  bio->bi_end_io  = bio_end_io;
  bio->bi_private = &bb;

  {
    char* kmap = atomic_kmap( page );
    memset( kmap, -1, PAGE_SIZE );
    atomic_kunmap( kmap );
  }

  bio_add_page( bio, page, 0x200, 0 );

  atomic_inc( &bb.done );
  submit_bio( READ, bio );

  if ( !atomic_dec_and_test( &bb.done ) )
    wait_for_completion( &wait );

  err = 0;
  {
    unsigned char* kmap = atomic_kmap( page );
    ufsdapi_dump_memory( kmap, 0x20 );
    if ( 0xC0 == kmap[0] )
      err = 1;
    atomic_kunmap( kmap );
  }

out:
  __free_page( page );
  return err;
}
#endif
#endif

#endif // #ifdef UFSD_DEBUG
