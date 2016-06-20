/*++


Module Name:

    vfsdebug.h

Abstract:

    This module defines debug services for VFS

Author:

    Ahdrey Shedel

Revision History:

    27/12/2002 - Andrey Shedel - Created
    Since 29/07/2005 - Alexander Mamaev

--*/


#ifdef UFSD_TRACE

  void ufsd_close_trace( int need_reopen );
  int is_zero( const char *data, size_t bytes );

  void  ufsd_trace_page_buffers( struct page  *page, int hdr );
  unsigned trace_pages( struct address_space *mapping );
  void trace_page( struct address_space *mapping, pgoff_t index );

  void ufsd_keep_trace_on( void );
  void ufsd_keep_trace_off( int print_logs );

  void  parse_trace_level( const char *v );
  void  parse_cycle_value( const char *v );

  extern const struct file_operations ufsd_proc_dev_trace_fops;
  extern struct file_operations ufsd_proc_dev_log_fops;
  extern const struct file_operations ufsd_proc_dev_cycle_fops;

  extern struct mutex   s_MountMutex;

#else

  #define ufsd_close_trace(x)

#endif
