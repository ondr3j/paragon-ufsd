/*++

Module Name:

    ufsdapi.h

Abstract:

    This module is a common include file for
    linux vfs modules.

Author:

    Ahdrey Shedel

Revision History:

    27/12/2002 - Andrey Shedel - Created

--*/
#ifndef __UFSDAPI_INC__
#define __UFSDAPI_INC__

#if defined UFSD_REFS && !defined UFSD_REFS2
  #define UFSD_REFS2
#endif

#if defined UFSD_NTFS && (!defined UFSD_HFS && !defined UFSD_EXFAT && !defined UFSD_FAT && !defined UFSD_REFS2 )
  #define  NTFS_ONLY(x) x
#else
  #define  NTFS_ONLY(x)
#endif

#ifdef UFSD_HFS
  #define  HFS_ONLY(x) x
#else
  #define  HFS_ONLY(x)
#endif

#ifdef UFSD_EXFAT
  #define  EXFAT_ONLY(x) x
#else
  #define  EXFAT_ONLY(x)
#endif

#if defined UFSD_HFS || defined UFSD_EXFAT || defined UFSD_FAT
  #define UFSD_USE_POSIX_TIME
#endif

#if defined UFSD_NTFS || defined UFSD_REFS2
  #define UFSD_USE_NT_TIME
#endif

#if defined UFSD_HFS && (!defined UFSD_NTFS && !defined UFSD_EXFAT && !defined UFSD_FAT && !defined UFSD_REFS2 )
  #define UFSD_HFS_ONLY
#endif



// Missing but useful declarations.
#define ARGUMENT_PRESENT(p) (NULL != (p))

#ifndef _TYPEDEF_UINT64_
typedef unsigned long long  UINT64;
#define _TYPEDEF_UINT64_
#endif

#define MINUS_ONE_ULL 0xffffffffffffffffull

#ifndef SetFlag
  #define SetFlag(flags, single_flag) (flags |= (single_flag))
#endif

#ifndef ClearFlag
  #define ClearFlag(flags, single_flag) (flags &= ~(single_flag))
#endif

#ifndef FlagOn
  #define FlagOn(flags, single_flag) ( 0 != ((flags) & (single_flag)))
#endif

#ifndef IN
  #define IN
#endif

#ifndef OUT
  #define OUT
#endif

#ifndef OPTIONAL
  #define OPTIONAL
#endif

#ifndef NOTHING
  #define NOTHING {;}
#endif

typedef int
(*SEQ_PRINTF)(
    IN struct seq_file *m,
    IN const char *fmt,
    IN ...
    )
#if __GNUC__ >= 3
    __attribute__ ((format (printf, 2, 3)))
#endif
    ;

#ifndef min
#define min(x,y) ({ \
  const typeof(x) _x = (x); \
  const typeof(y) _y = (y); \
  (void) (&_x == &_y);    \
  _x < _y ? _x : _y; })

#define max(x,y) ({ \
  const typeof(x) _x = (x); \
  const typeof(y) _y = (y); \
  (void) (&_x == &_y);    \
  _x > _y ? _x : _y; })

#define min_t(type,x,y) \
  ({ type __x = (x); type __y = (y); __x < __y ? __x: __y; })
#define max_t(type,x,y) \
  ({ type __x = (x); type __y = (y); __x > __y ? __x: __y; })

#endif


#define _QUOTE1(name) #name
#define _QUOTE2(name) _QUOTE1(name)
#define QUOTED_UFSD_DEVICE  _QUOTE2(UFSD_DEVICE)



// 0 - is default
#define UFSD_SAFE_JNL   0
#define UFSD_SAFE_BASIC 1
#define UFSD_SAFE_ORDER 2

typedef struct mount_options {
    struct nls_table *nls[8];     // if NULL == nls[i] then this is a builtin utf8
#ifdef UFSD_FAT
    struct nls_table *nls_oem;    // oem codepage
#endif
    int               nls_count;  // always >= 1
    int               bias;       // bias = UTC - local time. Eastern time zone: +300, Paris,Berlin: -60, Moscow: -180
    unsigned int      raKb;       // readahead size in Kb
    unsigned int      fs_uid;
    unsigned int      fs_gid;
    unsigned int      wb;         // writeback mode
    unsigned int      wbMb_in_pages;       // writeback mode (via size in Mb converted in pages)
    unsigned short    fs_fmask;
    unsigned short    fs_dmask;
    char fmask;           // fmask was set
    char dmask;           // dmask was set
    char uid;             // uid was set
    char gid;             // gid was set
    char showmeta;        // set = show meta files
    char showexec;        // set = only set x bit for com/exe/bat
    char sys_immutable;   // set = system files are immutable
    char nocase;          // Does this need case conversion? 0=need case conversion
    char noatime;         // do not update atime.
    char bestcompr;       // Use best compression instead of standard
    char sparse;          // Always create sparse files
    char force;           // Force to mount dirty volume
    char nohidden;        // Skip hidden files while enumerating
    char user_xattr;      // Extended user attributes
    char acl;             // POSIX Access Control Lists
    char chkcnv;          // Check string convertation UNICODE->MBCS->UNCIODE
    char usrquota;
    char grpquota;
    char sync;
    char nolazy;          // Lazy open
    char nobarrier;       // Turn off barrier
    char nobuf;           // Do not buffer BdRead/BdWrite
    char discard;         // try discard
    char nojnl;           // nojnl flag
    char safe;            // safe=UFSD_SAFE_XXX

    // These members are used to return useful information from mount/remount
    char delim;           // Stream delimiter
    char journal;         // Journal status: 0 - absent, 1 - ok, 2 - replayed, 3 - need replay
    char ugm;             // Volume supports UGM
    char posixtime;       // filesystem uses posix time (HFS+)
    char ntfs;            // filesystem is ntfs
    char hfs;             // filesystem is hfs
    char exfat;           // filesystem is exfat
    char fat;             // filesystem is fat
    char refs;            // filesystem is refs
    char no_acs_rules;    // "no access rules" flag
} mount_options;


#if defined UFSD_NTFS && !defined UFSD_HFS && !defined UFSD_EXFAT && !defined UFSD_FAT && !defined UFSD_REFS2
  #define is_ntfs( o ) 1
#elif defined UFSD_NTFS
  #define is_ntfs( o ) (o)->ntfs
#else
  #define is_ntfs( o ) 0
#endif

#if !defined UFSD_NTFS && defined UFSD_HFS && !defined UFSD_EXFAT && !defined UFSD_FAT && !defined UFSD_REFS2
  #define is_hfs( o ) 1
#elif defined UFSD_HFS
  #define is_hfs( o ) (o)->hfs
#else
  #define is_hfs( o ) 0
#endif

#if !defined UFSD_NTFS && !defined UFSD_HFS && defined UFSD_EXFAT && !defined UFSD_FAT && !defined UFSD_REFS2
  #define is_exfat( o ) 1
#elif defined UFSD_EXFAT
  #define is_exfat( o ) (o)->exfat
#else
  #define is_exfat( o ) 0
#endif

#if !defined UFSD_NTFS && !defined UFSD_HFS && !defined UFSD_EXFAT && defined UFSD_FAT && !defined UFSD_REFS2
  #define is_fat( o ) 1
#elif defined UFSD_FAT
  #define is_fat( o ) (o)->fat
#else
  #define is_fat( o ) 0
#endif

#if !defined UFSD_NTFS && !defined UFSD_HFS && !defined UFSD_EXFAT && !defined UFSD_FAT && defined UFSD_REFS2
  #define is_refs( o ) 1
#elif defined UFSD_REFS2
  #define is_refs( o ) (o)->refs
#else
  #define is_refs( o ) 0
#endif

#if defined UFSD_USE_POSIX_TIME && defined UFSD_USE_NT_TIME
  #define is_posixtime( o ) (o)->posixtime
#elif defined UFSD_USE_POSIX_TIME
  #define is_posixtime( o ) 1
#else
  #define is_posixtime( o ) 0
#endif

#define JOURNAL_STATUS_ABSENT       0
#define JOURNAL_STATUS_OK           1
#define JOURNAL_STATUS_REPLAYED     2
#define JOURNAL_STATUS_NEED_REPLAY  3
#define JOURNAL_STATUS_NEED_REPLAY_NATIVE 4

#ifdef __cplusplus
  extern "C"{
#endif

// Translates ufsd error codes into linux error codes
int
UFSDAPI_CALL
ufsd_to_linux(
    IN unsigned err // ufsd error
    );

UINT64
UFSDAPI_CALL
current_time_nt( void );

unsigned long
UFSDAPI_CALL
current_time_posix( void );

int UFSDAPI_CALL
ufsd_time_str(
    OUT char *buffer,
    IN int buffer_len
    );

const char*
UFSDAPI_CALL
ufsdapi_library_version(
    OUT int *EndianError
    );

unsigned
UFSDAPI_CALL
ufsd_bd_read(
    IN  struct super_block  *sb,
    IN  UINT64  Offset,
    IN  size_t  Bytes,
    OUT void    *Buffer
    );

unsigned
UFSDAPI_CALL
ufsd_bd_write(
    IN struct super_block *sb,
    IN UINT64   Offset,
    IN size_t   Bytes,
    IN const void *Buffer,
    IN size_t   Wait
    );

unsigned
UFSDAPI_CALL
ufsd_bd_map(
    IN  struct super_block  *sb,
    IN  UINT64  Offset,
    IN  size_t  Bytes,
    IN  size_t  Flags,
    OUT struct buffer_head  **Bcb,
    OUT void    **Mem
    );

void
UFSDAPI_CALL
ufsd_bd_unmap(
#ifdef UFSD_DEBUG
    IN struct super_block *sb,
#endif
    IN struct buffer_head *bh,
    IN int Forget
    );

unsigned
UFSDAPI_CALL
ufsd_bd_set_dirty(
    IN struct super_block *sb,
    IN struct buffer_head *bh,
    IN size_t   Wait
    );

void
UFSDAPI_CALL
ufsd_bd_lock_buffer(
    IN struct buffer_head *bh
    );

void
UFSDAPI_CALL
ufsd_bd_unlock_buffer(
    IN struct buffer_head *bh
    );

unsigned
UFSDAPI_CALL
ufsd_bd_discard(
    IN struct super_block *sb,
    IN UINT64   Offset,
    IN UINT64   Bytes
    );

int
UFSDAPI_CALL
ufsd_bd_zero(
    IN struct super_block *sb,
    IN UINT64 Offset,
    IN UINT64 Bytes
    );

int
UFSDAPI_CALL
ufsd_bd_isreadonly(
    IN struct super_block *sb
    );

unsigned
UFSDAPI_CALL
ufsd_bd_flush(
    IN struct super_block *sb,
    IN unsigned Wait
    );



//
// Some forwards and helper API declarations.
//

typedef struct ufsd_volume  ufsd_volume;
typedef struct ufsd_file    ufsd_file;

#define UFSDAPI_RDONLY       0x00000001  //  Read-only file
#define UFSDAPI_SYSTEM       0x00000004  //  System file
#define UFSDAPI_SUBDIR       0x00000010  //  Subdirectory
#define UFSDAPI_SPARSE       0x00000200  //  File is sparsed
#define UFSDAPI_LINK         0x00000400  //  File is link (Reparse point)
#define UFSDAPI_COMPRESSED   0x00000800  //  NTFS Compressed file
#define UFSDAPI_ENCRYPTED    0x00004000  //  NTFS Encrypted file
#define UFSDAPI_TASIZE       0x00800000  //  TotalAllocSize field is valid
#define UFSDAPI_VSIZE        0x04000000  //  FileInfo contains valid field 'ValidSize'
#define UFSDAPI_UGM          0x08000000  //  FileInfo contains valid fields 'Mode','Uid','Gid'
#define UFSDAPI_STREAMS      0x10000000  //  File contains additional data streams. For NTFS use CFSObject::GetObjectInfo
#define UFSDAPI_EA           0x20000000  //  File contains Extended attributes. For NTFS use CFSObject::GetObjectInfo
#define UFSDAPI_RESIDENT     0x40000000  //  NTFS resident default data stream. Use CFSObject::GetObjectInfo

typedef struct finfo{

  UINT64          Id;               // Volume unique file/folder

  // All times are 64 bit number of 100 nanoseconds  seconds since 1601 year
  UINT64          CrTime;           // utc creation time (not used)
  UINT64          ReffTime;         // utc last access time (atime)
  UINT64          ModiffTime;       // utc last modification time (mtime)
  UINT64          ChangeTime;       // utc last attribute modification time (ctime)
  UINT64          AllocSize;        // Allocated bytes for file
  UINT64          FileSize;         // Length of file in bytes
  UINT64          ValidSize;        // Valid size in bytes
  UINT64          TotalAllocSize;   // The sum of the allocated clusters for a file (usefull for sparse/compressed files) Valid if FlagOn(Attrib,UFSD_TASIZE)

  unsigned int    Attrib;           // File attributes. See UFSD_SUBDIR, UFSD_SYSTEM and so on
  unsigned int    FSAttrib;         // File system specific attributes. Valid if FlagOn(Attrib,UFSD_FSSPEC)

  unsigned short  Reserved;
  unsigned short  Mode;             // mode       valid if FlagOn(Attrib, UFSDAPI_UGM)
  unsigned int    Uid;              // user ID    valid if FlagOn(Attrib, UFSDAPI_UGM)
  unsigned int    Gid;              // group ID   valid if FlagOn(Attrib, UFSDAPI_UGM)
  unsigned int    Dev;              // if U_IFBLK == mode || U_IFCHR == mode  valid if FlagOn(Attrib,UFSD_UGM)

  unsigned short  HardLinks;        // Count of hardlinks. NOTE: NTFS does not fill this member in FindFirst/FindNext. Use CFSObject::GetObjectInfo instead.
  unsigned short  Gen;              // Generation of file

} finfo;


typedef struct{
  ufsd_file       *lnk;
  const void      *data;
  size_t          len;
  unsigned int    uid;
  unsigned int    gid;
  unsigned short  mode;
} ucreate;


//
// Layout of file fragment
//
typedef struct mapinfo2{
  UINT64    lbo;        // Logical byte offset
  UINT64    len;        // Length of map in bytes
  UINT64    alloc;      // The allocated size for file
  UINT64    total_alloc; // The sum of the allocated clusters for a file
  UINT64    head;       // How many bytes left from Lbo in the same fragment
  size_t    flags;      // Properties of fragment
} mapinfo2;


///////////////////////////////////////////////////////////
// ufsd_on_close_file
//
// update sbi->clear_list && sbi->write_list
///////////////////////////////////////////////////////////
int
UFSDAPI_CALL
ufsd_on_close_file(
    IN struct super_block *sb,
    IN ufsd_file          *ufile
    );

///////////////////////////////////////////////////////////
// ufsd_on_set_dirty
//
// Callback function. Called when volume becomes dirty
///////////////////////////////////////////////////////////
void
UFSDAPI_CALL
ufsd_on_set_dirty(
    IN struct super_block *sb
    );

///////////////////////////////////////////////////////////
// ufsd_bias
//
// Returns minutes west of Greenwich
///////////////////////////////////////////////////////////
int UFSDAPI_CALL
ufsd_bias( void );

int
UFSDAPI_CALL
ufsdapi_names_equal(
    IN ufsd_volume          *Volume,
    IN const unsigned char  *Name1,
    IN unsigned             Name1Len,
    IN const unsigned char  *Name2,
    IN unsigned             Name2Len
    );

unsigned int
UFSDAPI_CALL
ufsdapi_names_hash(
    IN ufsd_volume          *Volume,
    IN const unsigned char  *Name,
    IN unsigned             NameLen
    );

// This function is called once on module initialization/deinitialization
int
UFSDAPI_CALL
ufsdapi_main(
    IN size_t Flags
    );

int
UFSDAPI_CALL
ufsdapi_volume_mount(
    IN struct super_block *sb,
    IN unsigned int       bytes_per_sector,
    IN const UINT64       *BytesPerSb,
    IN OUT mount_options  *opts,
    OUT ufsd_volume       **Volume,
    IN unsigned long      TotalRam,
    IN unsigned int       BytesPerPage,
    OUT finfo**           fi
    );

int
UFSDAPI_CALL
ufsdapi_volume_remount(
    IN ufsd_volume        *Volume,
    IN OUT int            *ReadOnly,
    IN OUT mount_options  *opts
    );

void
UFSDAPI_CALL
ufsdapi_volume_umount(
    IN ufsd_volume  *Volume
    );

int
UFSDAPI_CALL
ufsdapi_is_volume_dirty(
    IN ufsd_volume  *Volume
    );

int
UFSDAPI_CALL
ufsdapi_volume_flush(
    IN ufsd_volume  *Volume,
    IN int          Wait
    );

void
UFSDAPI_CALL
ufsdapi_set_free_space_callback(
    IN  ufsd_volume *Volume,
    IN  void (*FreeSpaceCallBack)(
        IN size_t Lcn,
        IN size_t Len,
        IN int    AsUsed,
        IN void   *Arg
        ),
    IN void *Arg
    );


typedef struct{

  UINT64        maxbytes;
  UINT64        end_of_dir;
  UINT64        total_clusters;

  unsigned long fs_signature;
  unsigned int  bytes_per_cluster;
  unsigned int  namelen;
  unsigned int  dirty;

  char          ReadOnly;
} ufsd_volume_info;


unsigned
UFSDAPI_CALL
ufsdapi_query_volume_id(
    IN  ufsd_volume *Volume
    );

int
UFSDAPI_CALL
ufsdapi_query_volume_info(
    IN  ufsd_volume       *Volume,
    OUT ufsd_volume_info  *Info OPTIONAL,
    OUT unsigned char     *Label OPTIONAL,
    IN  size_t            BytesPerLabel OPTIONAL,
    OUT UINT64            *free_clusters OPTIONAL
    );

void
UFSDAPI_CALL
ufsdapi_trace_volume_info(
    IN  ufsd_volume     *Volume,
    OUT struct seq_file *m,
    IN  SEQ_PRINTF      SeqPrintf
    );

typedef struct{
  unsigned int DirAge;
  unsigned int JnlRam;
} ufsd_volume_tune;

int
UFSDAPI_CALL
ufsdapi_query_volume_tune(
    IN  ufsd_volume *Volume,
    OUT ufsd_volume_tune  *Tune
    );

int
UFSDAPI_CALL
ufsdapi_set_volume_tune(
    IN  ufsd_volume *Volume,
    IN  const ufsd_volume_tune  *Tune
    );

int
UFSDAPI_CALL
ufsdapi_ioctl(
    IN ufsd_volume  *Volume,
    IN ufsd_file    *FileHandle,
    IN size_t       IoControlCode,
    IN const void   *InputBuffer OPTIONAL,
    IN size_t       InputBufferSize OPTIONAL,
    OUT void        *OutputBuffer OPTIONAL,
    IN size_t       OutputBufferSize OPTIONAL,
    OUT size_t      *BytesReturned OPTIONAL,
    OUT finfo       **Info
    );

int
UFSDAPI_CALL
ufsdapi_file_info(
    IN ufsd_volume    *Volume,
    IN ufsd_file      *File,
    OUT struct finfo  **Info
    );

int
UFSDAPI_CALL
ufsdapi_read_link(
    IN  ufsd_file *FileHandle,
    OUT char      *LinkBuffer,
    IN  size_t    MaxCharsInLink
    );

UINT64
UFSDAPI_CALL
ufsdapi_get_dir_size(
    IN ufsd_file  *Dir
    );

UINT64
UFSDAPI_CALL
ufsdapi_get_file_size(
    IN ufsd_file*   File,
    OUT UINT64*     ValidSize,
    OUT UINT64*     AllocSize
    );

int
UFSDAPI_CALL
ufsdapi_u2a(
    IN ufsd_volume*           Volume,
    IN  const unsigned short* strSrc,
    IN  size_t                SrcLen,
    OUT unsigned char*        strDest,
    IN  size_t                MaxOut
    );

int
UFSDAPI_CALL
ufsdapi_a2u(
    IN ufsd_volume*           Volume,
    IN  const unsigned char*  strSrc,
    IN  size_t                SrcLen,
    OUT unsigned short*       strDest,
    IN  size_t                MaxOut
    );

// Returns offset from file handle to internal list entry
#define usdapi_file_to_list_offset()  2*sizeof(size_t)
#define usdapi_file_inode_offset()    4*sizeof(size_t)

int
UFSDAPI_CALL
ufsdapi_file_open(
    IN ufsd_volume          *Volume,
    IN ufsd_file            *ParentDir,
    IN const unsigned char  *Name,
    IN size_t               NameLen,
    IN const ucreate        *Create,
    OUT int                 *subdir_count,
    OUT ufsd_file           **File,
    OUT struct finfo        **Info
    );

int
UFSDAPI_CALL
ufsdapi_file_open_fork(
    IN ufsd_volume*         Volume,
    IN ufsd_file*           ParentFile,
    OUT ufsd_file**         File,
    OUT struct finfo**      Info
    );

int
UFSDAPI_CALL
ufsdapi_file_close(
    IN ufsd_volume  *Volume,
    IN ufsd_file    *File
    );

int
UFSDAPI_CALL
ufsdapi_file_map(
    IN  ufsd_file *File,
    IN  UINT64    Vbo,
    IN  UINT64    Bytes,
    IN  size_t    Flags,
    OUT mapinfo2  *Map
    );

int
UFSDAPI_CALL
ufsdapi_file_read(
    IN ufsd_volume          *Volume,
    IN ufsd_file            *FileHandle,
    IN const unsigned char  *StreamName,
    IN int                  StreamNameLen,
    IN UINT64               Offset,
    IN size_t               BytesCount,
    OUT void                *Buffer,
    OUT size_t              *BytesDone
    );

int
UFSDAPI_CALL
ufsdapi_file_write(
    IN ufsd_volume          *Volume,
    IN ufsd_file            *FileHandle,
    IN const unsigned char  *StreamName,
    IN int                  StreamNameLen,
    IN UINT64               Offset,
    IN size_t               BytesCount,
    IN const void           *Buffer,
    OUT size_t              *BytesDone
    );

int
UFSDAPI_CALL
ufsdapi_file_set_size(
    IN ufsd_file      *FileHandle,
    IN UINT64         BytesPerFile,
    IN const UINT64   *ValidSize, OPTIONAL
    OUT UINT64        *AllocatedSize OPTIONAL
    );

int
UFSDAPI_CALL
ufsdapi_file_move(
    IN ufsd_volume  *Volume,
    IN ufsd_file    *OldDirHandle,
    IN ufsd_file    *NewDirHandle,
    IN ufsd_file    *OldFileHandle,
    IN const unsigned char  *OldName,
    IN size_t       OldNameLen,
    IN const unsigned char  *NewName,
    IN size_t       NewNameLen,
    OUT UINT64      *OldDirSize,
    OUT UINT64      *NewDirSize
    );

int
UFSDAPI_CALL
ufsdapi_file_flush(
    IN ufsd_volume  *Volume,
    IN ufsd_file    *FileHandle,
    IN const finfo  *fi,
    IN unsigned     ia_valid,
    IN void*        inode,
    OUT UINT64*     asize
    );

int
UFSDAPI_CALL
ufsdapi_is_dir_empty(
    IN ufsd_volume  *Volume,
    IN ufsd_file    *Dir
    );

int
UFSDAPI_CALL
ufsdapi_unlink(
    IN ufsd_volume* Volume,
    IN ufsd_file*   Dir,
    IN const unsigned char* Name,
    IN size_t       NameLen,
    IN const unsigned char* sName,
    IN size_t       sNameLen,
    IN int          LastRef,
    IN OUT ufsd_file**  pObj,
    OUT UINT64*     DirSize
    );

int
UFSDAPI_CALL
ufsdapi_set_volume_info(
    IN ufsd_volume  *Volume,
    IN const char   *Label,
    IN size_t       LabelLen
    );

int
UFSDAPI_CALL
ufsdapi_set_xattr(
    IN ufsd_volume  *Volume,
    IN ufsd_file    *File,
    IN const char   *Name,
    IN size_t       NameLen,
    IN const void   *Buffer,
    IN size_t       BytesPerBuffer,
    IN int          Flags
    );

int
UFSDAPI_CALL
ufsdapi_list_xattr(
    IN  ufsd_volume *Volume,
    IN  ufsd_file   *File,
    OUT void        *Buffer,
    IN  size_t      BytesPerBuffer,
    OUT size_t      *Bytes
    );

int
UFSDAPI_CALL
ufsdapi_get_xattr(
    IN  ufsd_volume *Volume,
    IN  ufsd_file   *FileHandle,
    IN  const char  *Name,
    IN  size_t      NameLen,
    OUT void        *Buffer,
    IN  size_t      BytesPerBuffer,
    OUT size_t      *Len
    );

int
UFSDAPI_CALL
ufsdapi_get_dosattr(
    IN  ufsd_volume*  Volume,
    IN  ufsd_file*    File,
    OUT unsigned*     Attrib // Can't be NULL
    );

int
UFSDAPI_CALL
ufsdapi_set_dosattr(
    IN ufsd_volume*   Volume,
    IN ufsd_file*     File,
    IN unsigned       Attrib
    );

int
UFSDAPI_CALL
ufsdapi_file_open_by_id(
    IN  ufsd_volume *Volume,
    IN  size_t      Id,
    OUT ufsd_file   **File,
    OUT finfo       **Info
    );

int
UFSDAPI_CALL
ufsdapi_encode_fh(
    IN ufsd_volume  *Volume,
    IN  ufsd_file   *Fso,
    OUT void        *fh,
    IN OUT int      *MaxLen
    );

unsigned
UFSDAPI_CALL
ufsdapi_decode_fh(
    IN ufsd_volume  *Volume,
    IN const void   *fh,
    IN int          fh_len,
    IN const int    *fh_type,
    IN int          parent,
    OUT ufsd_file   **File,
    OUT struct finfo**Info
    );

unsigned
UFSDAPI_CALL
ufsdapi_file_get_name(
    IN  ufsd_volume   *Volume,
    IN  ufsd_file     *File,
    IN  size_t        ParNo,
    OUT unsigned char *Name,
    IN  size_t        MaxLen
    );

unsigned
UFSDAPI_CALL
ufsdapi_file_get_parent(
    IN  ufsd_volume *Volume,
    IN  ufsd_file   *File,
    OUT ufsd_file   **Parent,
    OUT struct finfo**Info
    );



typedef struct ufsd_search ufsd_search;

typedef struct ufsd_direntry
{
  size_t        ino;
  unsigned char *name;
  size_t        namelen;
  unsigned      attrib;

} ufsd_direntry;


int
UFSDAPI_CALL
ufsdapi_find_open(
    IN ufsd_volume  *Volume,
    IN ufsd_file    *Dir,
    IN UINT64       Pos,
    OUT ufsd_search **Scan
    );

int
UFSDAPI_CALL
ufsdapi_find_get(
    IN ufsd_search  *Scan,
    IN OUT UINT64   *Pos,
    OUT ufsd_direntry* de
    );

void
UFSDAPI_CALL
ufsdapi_find_close(
    IN ufsd_search  *Scan
    );


//
//  API to Linux' NLS package.
//

///////////////////////////////////////////////////////////
// ufsd_char2uni
//
// Converts multibyte string to UNICODE string
// Returns the length of destination string in symbols
///////////////////////////////////////////////////////////
int
UFSDAPI_CALL
ufsd_char2uni(
    OUT unsigned short      *ws,
    IN  int                 max_out,
    IN  const unsigned char *s,
    IN  int                 len,
    IN  struct nls_table    *nls
    );

///////////////////////////////////////////////////////////
// ufsd_uni2char
//
// Converts UNICODE string to multibyte
// Returns the length of destination string in chars
///////////////////////////////////////////////////////////
int
UFSDAPI_CALL
ufsd_uni2char(
    OUT unsigned char       *s,
    IN  int                 max_out,
    IN  const unsigned short*ws,
    IN  int                 len,
    IN  struct nls_table    *nls
    );

#ifdef UFSD_FAT
///////////////////////////////////////////////////////////
// ufsd_toupper
//
// Converts UTF8 oe OEM string to upcase
// Returns 0 if ok
///////////////////////////////////////////////////////////
void
UFSDAPI_CALL
ufsd_toupper(
    IN  struct nls_table      *nls,       // Code pages
    IN OUT unsigned char      *s,         // Source and Destination string
    IN  int                   len         // The length of ASCII or OEM string
    );
#endif

///////////////////////////////////////////////////////////
// ufsd_dump_memory(function redirects to UFSD_SDK)
//
// This function dumps memory into trace
///////////////////////////////////////////////////////////
void
UFSDAPI_CALL
ufsdapi_dump_memory(
    IN const void *mem,
    IN size_t     bytes
    );

#ifdef __cplusplus
  }  //extern "C"{
#endif


#if defined __STDC_VERSION__
#if __STDC_VERSION__ < 199901L
 # if __GNUC__ >= 2
 #  define __func__ __FUNCTION__
 # else
 #  define __func__ "<unknown>"
 # endif
#endif
#endif

//
// Duplicate defines from UFSD_SDK
// If someone changes it in UFSD_SDK
// we get warning here
//

// Possible flags for CFile::GetMap
// Allocate clusters if requested range is not allocated yet
#define UFSD_MAP_VBO_CREATE             0x0001
// Allow CFile::GetMap( Vbo, Bytes, ... ) to allocate only 'continues' fragment
// Must be combined with UFSD_MAP_VBO_CREATE
#define UFSD_MAP_VBO_CREATE_CONTINUES   0x0002
// Allow CFile::GetMap( Vbo, Bytes, ... ) to allocate less than 'Bytes'
// Must be combined with UFSD_MAP_VBO_CREATE
#define UFSD_MAP_VBO_CREATE_PARTITIAL   0x0004
// Do not call any lock operations
#define UFSD_MAP_VBO_NOLOCK             0x0008

// Possible flags for MapInfo::Flags
#define UFSD_MAP_LBO_NEW                0x0001

// Fragment of file is not allocated (sparsed)
#define UFSD_VBO_LBO_HOLE         ((UINT64)-1)
// File is resident
#define UFSD_VBO_LBO_RESIDENT     ((UINT64)-2)
// Fragment is really compressed (need decompress)
#define UFSD_VBO_LBO_COMPRESSED   ((UINT64)-3)
// File is encrypted
#define UFSD_VBO_LBO_ENCRYPTED    ((UINT64)-4)


// Possible options for SetWait
#define UFSD_RW_WAIT_SYNC        0x01

// Possible options for Rw->Map
#define UFSD_RW_MAP_NO_READ      0x01

#ifndef __cplusplus

//===============================================
// Some of the UFSD errors
//===============================================

#define ERR_BADPARAMS             0xa0000101

// No memory
#define ERR_NOMEMORY              0xa0000107

// No such file or directory
#define ERR_NOFILEEXISTS          0xa000010E

// Read I/O
#define ERR_READFILE              0xa000010C

// Write I/O
#define ERR_WRITEFILE             0xa000010D

// File exists
#define ERR_FILEEXISTS            0xa000010F

#define ERR_BADNAME_LEN           0xa0000115

// Read-only
#define ERR_WPROTECT              0xa0000120

// Not enough free space
#define ERR_NOSPC                 0xa0000123

// This function is not implemented
#define ERR_NOTIMPLEMENTED        0xa0000124

// If the output buffer is too small to return any data
#define ERR_INSUFFICIENT_BUFFER   0xa0000125

// If the output buffer is too small to hold all of the data but can hold some entries
#define ERR_MORE_DATA             0xa0000126

#define ERR_DIRNOTEMPTY           0xa0000121

// Can't mount 'cause journal is not empty
// obsolete (will be removed)
#define ERR_NEED_REPLAY           0xa000012b

// Maximum hardlinks count reached
#define ERR_MAXIMUM_LINK          0xa0000138

// File size is bigger than maximum allowed
// This can happen if driver with 64-bit cluster addresses creates file
// that uses more than 2^32 clusters and then this file is opened by
// another driver with 32-bit cluster addresses (in this case not all
// clusters belong to the file can be addressed).
// Or if we try to truncate/posix_fallocate the file to the size bigger
// than is supported by FS (and current mount options/driver flags).
#define ERR_FILE_TOO_BIG          0xa0000139

#ifndef Add2Ptr
  #define Add2Ptr(P,I)   ((unsigned char*)(P) + (I))
  #define PtrOffset(B,O) ((size_t)((size_t)(O) - (size_t)(B)))
#endif

#if defined CONFIG_LBD | defined CONFIG_LBDAF
  // sector_t - 64 bit value
  #define PSCT      "ll"
#else
  // sector_t - 32 bit value
  #define PSCT      "l"
#endif

// Add missing defines
#ifndef offsetof
  #define offsetof(type, member) ((long) &((type *) 0)->member)
#endif
#ifndef container_of
  #define container_of(ptr, type, member) ({                    \
          const typeof( ((type *)0)->member ) *__mptr = (ptr);  \
          (type *)( (char *)__mptr - offsetof(type,member) );})
#endif

  #define UFSD_IOC_GETSIZES         _IOC(_IOC_READ, 'f', 89, 4*sizeof(long long))
  #define UFSD_IOC_SETVALID         _IOW('f', 91, unsigned long long)
  #define UFSD_IOC_SETCLUMP         _IOW('f', 101, unsigned int)
  #define UFSD_IOC_SETTIMES         _IOC(_IOC_WRITE,'f', 75, 4*sizeof(long long))
  #define UFSD_IOC_GETTIMES         _IOC(_IOC_READ, 'f', 73, 4*sizeof(long long))
  #define UFSD_IOC_SETATTR          _IOW('f', 99, unsigned int)
  #define UFSD_IOC_GETATTR          _IOR('f', 95, unsigned int)
  #define UFSD_IOC_GETMEMUSE        _IOC(_IOC_READ,'v', 20, 4*sizeof(size_t) )
  #define UFSD_IOC_GETVOLINFO       _IOC(_IOC_READ,'v', 21, 196 )

  #define UFSD_IOC32_GETMEMUSE      _IOC(_IOC_READ,'v', 20, 4*sizeof(int) )

#endif // #ifndef __cplusplus

#endif // #ifndef __UFSDAPI_INC__
