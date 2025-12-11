#ifndef CROSS_H_
#define CROSS_H_

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <time.h>

#ifdef _WIN32
#  include <windows.h>
#  include <direct.h>
#else
#  include <sys/stat.h>
#  include <unistd.h>
#  include <errno.h>
#  include <pthread.h>
#  include <dirent.h>
#endif

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

#ifdef _WIN32
#  define CROSS_OS_WINDOWS 1
#else
#  define CROSS_OS_POSIX 1
#endif

#ifdef _WIN32
#  define CROSS_OS_WINDOWS 1
#  define PATH_JOIN "\\"
#else
#  define CROSS_OS_POSIX 1
#  define PATH_JOIN "/"
#endif

//──────────────────────────────
// PLATFORM INFO
//──────────────────────────────
const char* cross_platform_name(void);
const char* cross_arch_name(void);
bool        cross_is_windows(void);
bool        cross_is_posix(void);

//──────────────────────────────
// FILESYSTEM
//──────────────────────────────
bool     cross_file_exists(const char* path);
bool     cross_dir_exists(const char* path);
bool     cross_mkdir(const char* path);
bool     cross_mkdir_ifnot_exists(const char* path);
bool     cross_remove(const char* path);
bool     cross_rename(const char* from, const char* to);
int64_t  cross_file_size(const char* path);
int64_t  cross_file_mtime(const char* path);
char*    cross_read_file(const char* path);
bool     cross_write_file(const char* path, const char* data);
bool     cross_write_file_n(const char* path, const void* data, size_t size);
char*    cross_get_cwd(void);
bool     cross_set_cwd(const char* path);

// extra FS
bool     cross_copy_file(const char* from, const char* to);
bool     cross_list_dir
(const char* path,
void (*callback)(const char* name, bool is_dir, void* user),
void* user);

//──────────────────────────────
// PROCESS / ENVIRONMENT
//──────────────────────────────
int      cross_run(const char* cmd);
char*    cross_env_get(const char* name);

//──────────────────────────────
// TIME
//──────────────────────────────
uint64_t cross_now_ms(void);
uint64_t cross_now_us(void);
double   cross_now_seconds(void);
void     cross_sleep_ms(uint32_t ms);

//──────────────────────────────
// MEMORY (with allocator injection)
//──────────────────────────────
typedef void* (*cross_malloc_fn)(size_t);
typedef void* (*cross_realloc_fn)(void*, size_t);
typedef void  (*cross_free_fn)(void*);

void cross_set_allocator(cross_malloc_fn m, cross_realloc_fn r, cross_free_fn f);

void* cross_malloc(size_t size);
void* cross_realloc(void* ptr, size_t size);
void  cross_free(void* ptr);
void* cross_calloc(size_t n, size_t size);

//──────────────────────────────
// LOGGING
//──────────────────────────────
typedef enum {
    CROSS_LOG_DEBUG,
    CROSS_LOG_INFO,
    CROSS_LOG_WARN,
    CROSS_LOG_ERROR
} cross_log_level;

void cross_log(const char* tag, const char* fmt, ...);
void cross_log_info(const char* fmt, ...);
void cross_log_warn(const char* fmt, ...);
void cross_log_err(const char* fmt, ...);
void cross_log_debug(const char* fmt, ...);

void cross_log_set_level(cross_log_level level);
void cross_log_to_file(const char* path);
void cross_log_timestamp(bool enabled);

//──────────────────────────────
// SYSTEM / USER
//──────────────────────────────
char* cross_temp_dir(void);
char* cross_home_dir(void);
char* cross_user_name(void);
char* cross_executable_path(void);

//──────────────────────────────
// THREADS / MUTEX
//──────────────────────────────
typedef struct cross_thread cross_thread_t;
typedef struct cross_mutex  cross_mutex_t;

cross_thread_t* cross_thread_create(void (*fn)(void*), void* arg);
void cross_thread_join(cross_thread_t* t);

cross_mutex_t* cross_mutex_create(void);
void cross_mutex_lock(cross_mutex_t* m);
void cross_mutex_unlock(cross_mutex_t* m);
void cross_mutex_destroy(cross_mutex_t* m);

#endif // CROSS_H_

#ifndef FORGE_H_
#define FORGE_H_

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdarg.h>
#include <assert.h>
#include <string.h>

#ifdef FORGE_IMPLEMENTATION
#define CROSS_IMPLEMENTATION
#endif // FORGE_IMPLEMENTATION

#ifndef C_COMPILER
#ifdef _WIN32
#define C_COMPILER "cl.exe"
#else
#define C_COMPILER "cc"
#endif // _WIN32
#endif // C_COMPILER

#ifndef FORGE_NOLOG
#ifndef forge_log
#define forge_log cross_log_info
#endif // forge_log
#else
#define forge_log
#endif // FORGE_NOLOG

#ifndef FORGE_NOWARN
#ifndef forge_warn
#define forge_warn cross_log_warn
#endif // forge_warn
#else
#define forge_warn
#endif // FORGE_NOWARN

#ifndef forge_error
#define forge_error cross_log_err
#endif // forge_error

#define FORGE_TODO(...) assert(0 && __VA_ARGS__)

// Compiler detection
#ifdef _WIN32
    #define IS_MSVC 1
#else
    #define IS_MSVC 0
#endif

// DEVELOPMENT FLAGS
#if IS_MSVC
    #ifndef DEVELOPMENT_FLAGS
    #define DEVELOPMENT_FLAGS "/W3 /Od /DDEBUG"
    #endif
#else
    #ifndef DEVELOPMENT_FLAGS
    #define DEVELOPMENT_FLAGS "-Wall -Wextra -Wpedantic -O0 -DDEBUG"
    #endif
#endif

// DEBUG FLAGS (can inherit development flags)
#ifndef DEBUG_FLAGS
#define DEBUG_FLAGS DEVELOPMENT_FLAGS
#endif

// RELEASE FLAGS
#if IS_MSVC
    #ifndef RELEASE_FLAGS
    #define RELEASE_FLAGS "/O2 /GL"
    #endif
#else
    #ifndef RELEASE_FLAGS
    #define RELEASE_FLAGS "-O3 -flto"
    #endif
#endif

#ifndef FORGE_INIT_CAP
#define FORGE_INIT_CAP 16
#endif // FORGE_INIT_CAP

#define forge_da_alloc(list, exp_cap)           \
    do {                                        \
        if ((exp_cap) > (list)->capacity) {     \
            if ((list)->capacity == 0) {        \
                (list)->capacity = FORGE_INIT_CAP;\
            }                                   \
            while ((exp_cap) > (list)->capacity) { \
                (list)->capacity *= 2;             \
            }                                      \
            (list)->data = (typeof((list)->data))realloc((list)->data,(list)->capacity * sizeof(*(list)->data)); \
            assert((list)->data != NULL && "Ram is not enough!"); \
        } \
    } while (0)

#define forge_da_append(list, element)            \
    do {                                       \
        forge_da_alloc((list), (list)->count + 1); \
        (list)->data[(list)->count++] = (element);   \
    } while (0)

#define forge_da_append_many(list, new_el, new_el_count)          \
    do {                                                          \
        forge_da_alloc((list), (list)->count + (new_el_count)); \
        memcpy((list)->data + (list)->count, (new_el), (new_el_count)*sizeof(*(list)->data)); \
        (list)->count += (new_el_count); \
    } while (0)

#define forge_da_append_null(list) forge_da_append(list,0)
#define forge_da_append_cstr(list,str) forge_da_append_many(list,str,strlen(str))
#define forge_da_clear(list) \
do {memset((list)->data,0,(list)->capacity); (list)->count = 0; } while(0)
#define forge_da_free(list) \
do { free((list)->data); (list)->data = NULL; (list)->count = 0; (list)->capacity = 0; } while(0)

typedef enum {
    no_flags = 0,
    all_build = 1 << 1,
} forge_flags_t;
static uint64_t forge_flags;

typedef struct {
    char* data;
    uint32_t count;
    uint32_t capacity;
} string_t;

typedef char** str_list_t;

typedef struct {
    string_t list;
} cmd_t;

#define forge_append_cmd(cmd,...) \
    forge_append_many_cmd_null(cmd,__VA_ARGS__,NULL)
void forge_append_many_cmd_null(cmd_t* cmd,...);
void forge_append_cmd_strlist(cmd_t* cmd,str_list_t);
void forge_clear_cmd(cmd_t* cmd);
void forge_free_cmd(cmd_t* cmd);

#define forge_rebuild_yourself() forge_rebuild_yourself_(__FILE__,argv,argc)
void forge_rebuild_yourself_(char* src,char** argv,int argc);

bool forge_rename(char* path1,char* path2);
bool forge_check_timestaps_after_list(const char* file,const char** paths,uint32_t count);
bool forge_check_timestaps_1after2(const char* path1,const char* path2);
#define forge_change_extension_many(ext,...) \
    forge_change_extension_(ext,__VA_ARGS__,NULL)
str_list_t forge_change_extension_(char* ext,...);
str_list_t forge_change_extension_strlist(char* ext,str_list_t list);
char* forge_change_extension(char* ext,char* str);
void forge_free_strlist(str_list_t list);
uint32_t forge_count_strlist(str_list_t list);

bool forge_rm_path(char* path);
bool forge_rm_path_strlist(str_list_t list);

#define forge_add_prefix(fix,...) \
    forge_addfix(true,fix,__VA_ARGS__,NULL)

#define forge_add_suffix(fix,...) \
    forge_addfix(false,fix,__VA_ARGS__,NULL)

str_list_t forge_addfix
(bool is_prefix,char* fix,...);

typedef struct {
    bool clear;
    bool free;
    bool no_fail_log;
} run_cmd_ctx_t;

#define forge_run_cmd(cmd,...) \
    forge_run_cmd_(cmd,(run_cmd_ctx_t){__VA_ARGS__})
bool forge_run_cmd_(cmd_t* cmd,run_cmd_ctx_t ctx);

typedef struct {
    cross_thread_t** data;
    uint32_t count;
    uint32_t capacity;
    cross_mutex_t* mutex;
} async_group_t;

void forge_wait_async_group(async_group_t* group);
async_group_t forge_create_async_group(void);
void forge_async_group_free(async_group_t* group);

#ifdef FORGE_SHORT_NAMES
#define ag_t async_group_t
#define sl_t str_list_t
#endif // FORGE_SHORT_NAMES
#ifdef FORGE_STRIP_PREFIX
#define da_alloc forge_da_alloc
#define da_append forge_da_append
#define da_append_many forge_da_append_many
#define da_append_null forge_da_append_null
#define da_append_cstr forge_da_append_cstr
#define da_clear forge_da_clear
#define da_free forge_da_free
#define append_cmd forge_append_cmd
#define append_many_cmd_null forge_append_many_cmd_null
#define append_cmd_strlist forge_append_cmd_strlist
#define clear_cmd forge_clear_cmd
#define free_cmd forge_free_cmd
#define rebuild_yourself forge_rebuild_yourself
#define f_rename forge_rename
#define check_ts_list forge_check_timestaps_after_list
#define check_ts_1af2 forge_check_timestaps_1after2
#define change_extension forge_change_extension
#define change_extension_strlist forge_change_extension_strlist
#define change_extension forge_change_extension
#define free_strlist forge_free_strlist
#define count_strlist forge_count_strlist
#define rm_path forge_rm_path
#define rm_path_strlist forge_rm_path_strlist
#define add_prefix forge_add_prefix
#define add_suffix forge_add_suffix
#define add_fix forge_addfix
#define run_cmd forge_run_cmd
#define wait_async_group forge_wait_async_group
#define create_async_group forge_create_async_group
#define async_group_free forge_async_group_free
#endif // FORGE_STRIP_PREFIX


#endif // FORGE_H_

#ifdef CROSS_IMPLEMENTATION
#ifndef CROSS_IS_FIRST_IMPLEMENTATION
#define CROSS_IS_FIRST_IMPLEMENTATION

//──────────────────────────────
// PLATFORM INFO
//──────────────────────────────
const char* cross_platform_name(void) {
#if defined(_WIN32)
    return "Windows";
#elif defined(__APPLE__)
    return "macOS";
#elif defined(__linux__)
    return "Linux";
#else
    return "Unknown";
#endif
}

const char* cross_arch_name(void) {
#if defined(__x86_64__) || defined(_M_X64)
    return "x86_64";
#elif defined(__aarch64__)
    return "arm64";
#elif defined(__i386__) || defined(_M_IX86)
    return "x86";
#else
    return "unknown";
#endif
}

bool cross_is_windows(void) {
    #ifdef CROSS_OS_WINDOWS
    return true;
    #else
    return false;
    #endif
}
bool cross_is_posix(void) {
    #ifdef CROSS_OS_POSIX
    return true;
    #else
    return false;
    #endif
}

//──────────────────────────────
// MEMORY
//──────────────────────────────
static cross_malloc_fn cross_malloc_impl = malloc;
static cross_realloc_fn cross_realloc_impl = realloc;
static cross_free_fn cross_free_impl = free;

void cross_set_allocator(cross_malloc_fn m, cross_realloc_fn r, cross_free_fn f) {
    cross_malloc_impl = m ? m : malloc;
    cross_realloc_impl = r ? r : realloc;
    cross_free_impl = f ? f : free;
}

void* cross_malloc(size_t size) { return cross_malloc_impl(size); }
void* cross_realloc(void* p, size_t s) { return cross_realloc_impl(p, s); }
void  cross_free(void* p) { cross_free_impl(p); }
void* cross_calloc(size_t n, size_t s) {
    void* ptr = cross_malloc(n*s);
    if (ptr) memset(ptr,0,n*s);
    return ptr;
}

//──────────────────────────────
// FILESYSTEM
//──────────────────────────────
bool cross_file_exists(const char* path) {
#ifdef _WIN32
    DWORD attr = GetFileAttributesA(path);
    return (attr != INVALID_FILE_ATTRIBUTES && !(attr & FILE_ATTRIBUTE_DIRECTORY));
#else
    return access(path,F_OK)==0;
#endif
}

bool cross_dir_exists(const char* path) {
#ifdef _WIN32
    DWORD attr = GetFileAttributesA(path);
    return (attr != INVALID_FILE_ATTRIBUTES && (attr & FILE_ATTRIBUTE_DIRECTORY));
#else
    struct stat s;
    return stat(path,&s)==0 && S_ISDIR(s.st_mode);
#endif
}

bool cross_mkdir(const char* path) {
#ifdef _WIN32
    return _mkdir(path)==0 || errno==EEXIST;
#else
    return mkdir(path,0755)==0 || errno==EEXIST;
#endif
}

bool cross_mkdir_ifnot_exists(const char* path) {
    if(!cross_dir_exists(path)) {
        return cross_mkdir(path);
    }
    return true;
}

bool cross_remove(const char* path) {
#ifdef _WIN32
    return DeleteFileA(path);
#else
    return unlink(path)==0;
#endif
}

bool cross_rename(const char* from,const char* to) { return rename(from,to)==0; }

int64_t cross_file_size(const char* path) {
    FILE* f=fopen(path,"rb"); if(!f) return -1;
    fseek(f,0,SEEK_END); int64_t size=ftell(f); fclose(f); return size;
}

int64_t cross_file_mtime(const char* path) {
#ifdef _WIN32
    WIN32_FILE_ATTRIBUTE_DATA data;
    if(!GetFileAttributesExA(path,GetFileExInfoStandard,&data)) return -1;
    ULARGE_INTEGER t; t.LowPart=data.ftLastWriteTime.dwLowDateTime; t.HighPart=data.ftLastWriteTime.dwHighDateTime;
    return (int64_t)(t.QuadPart/10000ULL);
#else
    struct stat s; if(stat(path,&s)<0) return -1; return (int64_t)s.st_mtime*1000;
#endif
}

char* cross_read_file(const char* path) {
    FILE* f=fopen(path,"rb"); if(!f) return NULL;
    fseek(f,0,SEEK_END); size_t size=ftell(f); rewind(f);
    char* buf=(char*)cross_malloc(size+1); fread(buf,1,size,f); buf[size]=0; fclose(f); return buf;
}

bool cross_write_file(const char* path,const char* data) {
    FILE* f=fopen(path,"wb"); if(!f) return false; fwrite(data,1,strlen(data),f); fclose(f); return true;
}

bool cross_write_file_n(const char* path,const void* data,size_t size) {
    FILE* f=fopen(path,"wb"); if(!f) return false; fwrite(data,1,size,f); fclose(f); return true;
}

char* cross_get_cwd(void) {
    char* buf=(char*)cross_malloc(512);
#ifdef _WIN32
    _getcwd(buf,512);
#else
    getcwd(buf,512);
#endif
    return buf;
}

bool cross_set_cwd(const char* path) {
#ifdef _WIN32
    return _chdir(path)==0;
#else
    return chdir(path)==0;
#endif
}

// extra FS
bool cross_copy_file(const char* from,const char* to) {
    char* data=cross_read_file(from);
    if(!data) return false;
    bool ok=cross_write_file(to,data);
    cross_free(data);
    return ok;
}

bool cross_list_dir(const char* path, void (*callback)(const char*,bool,void*), void* user) {
#ifdef _WIN32
    char search[512]; snprintf(search,512,"%s\\*",path);
    WIN32_FIND_DATAA fd; HANDLE h=FindFirstFileA(search,&fd);
    if(h==INVALID_HANDLE_VALUE) return false;
    do { if(strcmp(fd.cFileName,".") && strcmp(fd.cFileName,"..")) callback(fd.cFileName,(fd.dwFileAttributes&FILE_ATTRIBUTE_DIRECTORY)!=0,user);
    } while(FindNextFileA(h,&fd)); FindClose(h);
#else
    DIR* d=opendir(path); if(!d) return false;
    struct dirent* e; while((e=readdir(d))) { if(strcmp(e->d_name,".") && strcmp(e->d_name,"..")) callback(e->d_name,(e->d_type==DT_DIR),user); } closedir(d);
#endif
    return true;
}

//──────────────────────────────
// PROCESS / ENV
//──────────────────────────────
int cross_run(const char* cmd) { return system(cmd); }

char* cross_env_get(const char* name) {
    char* v=getenv(name); return v?strdup(v):NULL;
}

//──────────────────────────────
// TIME
//──────────────────────────────
uint64_t cross_now_ms(void) {
#ifdef _WIN32
    return GetTickCount64();
#else
    struct timespec ts; clock_gettime(CLOCK_REALTIME,&ts); return (uint64_t)ts.tv_sec*1000+ts.tv_nsec/1000000;
#endif
}

uint64_t cross_now_us(void) {
#ifdef _WIN32
    LARGE_INTEGER freq, t;
    QueryPerformanceFrequency(&freq); QueryPerformanceCounter(&t);
    return (uint64_t)(t.QuadPart*1000000/freq.QuadPart);
#else
    struct timespec ts; clock_gettime(CLOCK_REALTIME,&ts); return (uint64_t)ts.tv_sec*1000000+ts.tv_nsec/1000;
#endif
}

double cross_now_seconds(void) { return (double)cross_now_ms()/1000.0; }

void cross_sleep_ms(uint32_t ms) {
#ifdef _WIN32
    Sleep(ms);
#else
    usleep(ms*1000);
#endif
}

//──────────────────────────────
// LOGGING
//──────────────────────────────
static cross_log_level cross_log_level_current=CROSS_LOG_DEBUG;
static FILE* cross_log_file=NULL;
static bool cross_log_ts=true;

void cross_log_set_level(cross_log_level level) { cross_log_level_current=level; }
void cross_log_to_file(const char* path) { if(path) cross_log_file=fopen(path,"a"); }
void cross_log_timestamp(bool enabled) { cross_log_ts=enabled; }

void cross_log_va(const char* tag, const char* fmt, va_list args)
{
    if (cross_log_level_current > CROSS_LOG_DEBUG)
        return;
    va_list copy;
    va_copy(copy, args);
    if (cross_log_ts) {
        time_t t = time(NULL);
        struct tm tm;
        localtime_r(&t, &tm);
        printf("[%02d:%02d:%02d]", tm.tm_hour, tm.tm_min, tm.tm_sec);
        if (cross_log_file)
            fprintf(cross_log_file, "[%02d:%02d:%02d]", tm.tm_hour, tm.tm_min, tm.tm_sec);
    }
    printf("[%s] ", tag);
    if (cross_log_file)
        fprintf(cross_log_file, "[%s] ", tag);
    vprintf(fmt, args);
    if (cross_log_file)
        vfprintf(cross_log_file, fmt, copy);
    printf("\n");
    if (cross_log_file)
        fprintf(cross_log_file, "\n");
    va_end(copy);
}

void cross_log_info(const char* fmt, ...)
{
    if (cross_log_level_current <= CROSS_LOG_INFO) {
        va_list a;
        va_start(a, fmt);
        cross_log_va("INFO", fmt, a);
        va_end(a);
    }
}

void cross_log_warn(const char* fmt, ...)
{
    if (cross_log_level_current <= CROSS_LOG_WARN) {
        va_list a;
        va_start(a, fmt);
        cross_log_va("WARN", fmt, a);
        va_end(a);
    }
}

void cross_log_err(const char* fmt, ...)
{
    if (cross_log_level_current <= CROSS_LOG_ERROR) {
        va_list a;
        va_start(a, fmt);
        cross_log_va("ERR", fmt, a);
        va_end(a);
    }
}

void cross_log_debug(const char* fmt, ...)
{
    if (cross_log_level_current <= CROSS_LOG_DEBUG) {
        va_list a;
        va_start(a, fmt);
        cross_log_va("DEBUG", fmt, a);
        va_end(a);
    }
}


//──────────────────────────────
// SYSTEM / USER
//──────────────────────────────
char* cross_temp_dir(void) {
#ifdef _WIN32
    char buf[MAX_PATH]; GetTempPathA(MAX_PATH,buf); return strdup(buf);
#else
    const char* t=getenv("TMPDIR"); return strdup(t?t:"/tmp");
#endif
}

char* cross_home_dir(void) {
#ifdef _WIN32
    char buf[MAX_PATH]; GetEnvironmentVariableA("USERPROFILE",buf,MAX_PATH); return strdup(buf);
#else
    const char* h=getenv("HOME"); return strdup(h?h:"/");
#endif
}

char* cross_user_name(void) {
#ifdef _WIN32
    char buf[256]; DWORD len=256; GetUserNameA(buf,&len); return strdup(buf);
#else
    const char* u=getenv("USER"); return strdup(u?u:"unknown");
#endif
}

char* cross_executable_path(void) {
#ifdef _WIN32
    char buf[MAX_PATH]; GetModuleFileNameA(NULL,buf,MAX_PATH); return strdup(buf);
#else
    char buf[512]; ssize_t s=readlink("/proc/self/exe",buf,512); if(s<0) return NULL; buf[s]=0; return strdup(buf);
#endif
}

//──────────────────────────────
// THREADS / MUTEX
//──────────────────────────────
struct cross_thread {
#ifdef _WIN32
    HANDLE handle;
#else
    pthread_t handle;
#endif
};

struct cross_mutex {
#ifdef _WIN32
    HANDLE handle;
#else
    pthread_mutex_t handle;
#endif
};

cross_thread_t* cross_thread_create(void (*fn)(void*), void* arg) {
    cross_thread_t* t=(cross_thread_t*)cross_malloc(sizeof(cross_thread_t));
#ifdef _WIN32
    t->handle=CreateThread(NULL,0,(LPTHREAD_START_ROUTINE)fn,arg,0,NULL);
#else
    pthread_create(&t->handle,NULL,(void*(*)(void*))fn,arg);
#endif
    return t;
}

void cross_thread_join(cross_thread_t* t) {
#ifdef _WIN32
    WaitForSingleObject(t->handle,INFINITE); CloseHandle(t->handle);
#else
    pthread_join(t->handle,NULL);
#endif
    cross_free(t);
}

cross_mutex_t* cross_mutex_create(void) {
    cross_mutex_t* m=(cross_mutex_t*)cross_malloc(sizeof(cross_mutex_t));
#ifdef _WIN32
    m->handle=CreateMutexA(NULL,FALSE,NULL);
#else
    pthread_mutex_init(&m->handle,NULL);
#endif
    return m;
}

void cross_mutex_lock(cross_mutex_t* m) {
#ifdef _WIN32
    WaitForSingleObject(m->handle,INFINITE);
#else
    pthread_mutex_lock(&m->handle);
#endif
}

void cross_mutex_unlock(cross_mutex_t* m) {
#ifdef _WIN32
    ReleaseMutex(m->handle);
#else
    pthread_mutex_unlock(&m->handle);
#endif
}

void cross_mutex_destroy(cross_mutex_t* m) {
#ifdef _WIN32
    CloseHandle(m->handle);
#else
    pthread_mutex_destroy(&m->handle);
#endif
    cross_free(m);
}

#endif // CROSS_IS_FIRST_IMPLEMENTATION
#endif // CROSS_IMPLEMENTATION

#ifdef FORGE_IMPLEMENTATION
#ifndef FORGE_IS_FIRST_IMPLEMENTATION
#define FORGE_IS_FIRST_IMPLEMENTATION

void forge_async_group_free
(async_group_t* group)
{
    free(group->data);
    group->count = 0;
    group->capacity = 0;
    cross_mutex_destroy(group->mutex);
}

async_group_t forge_create_async_group
(void)
{
    async_group_t group = {0};
    group.mutex = cross_mutex_create();
    return group;
}

void forge_wait_async_group
(async_group_t* group)
{
    cross_mutex_lock(group->mutex);
    for (uint32_t i = 0; i < group->count; ++i) {
        cross_thread_t* t = group->data[i];
        if (t) {
            cross_mutex_unlock(group->mutex);
            cross_thread_join(t);
            cross_mutex_lock(group->mutex);
            group->data[i] = NULL;
        }
    }
    cross_mutex_unlock(group->mutex);
}

typedef struct {
    cmd_t cmd;
    uint32_t index;
    async_group_t* group;
} forge_run_async_ctx;

void forge_run_async
(void* arg)
{
    forge_run_async_ctx* ctx = (forge_run_async_ctx*)arg;
    forge_run_cmd(&ctx->cmd,.free = true);
    ctx->group->data[ctx->index] = 0;
    free(ctx);
}

bool forge_check_timestaps_after_list
(const char* file,const char** paths,uint32_t count)
{
    uint32_t i = 0;
    for(;i < count;++i)
    {
        // Skip flags
        if(*paths[i] == '-') continue;
        if(!forge_check_timestaps_1after2(file,paths[i]))
        return true;
    }
    return false;
}

bool forge_check_timestaps_1after2
(const char* path1,const char* path2)
{
    int64_t first = cross_file_mtime(path1);
    int64_t second = cross_file_mtime(path2);
    if (first < 0) return false;
    if (second < 0)  return false;
    return first > second;
}

bool forge_rename
(char* to,char* from)
{
    forge_log("%s -> %s",from,to);
    if (!cross_rename(from, to)) {
        forge_error("could not rename %s to %s", from, to);
        return false;
    }
    return true;
}

bool forge_rm_path_list
(uint32_t start,...)
{
    va_list list;
    va_start(list,start);
    char* cur = va_arg(list,char*);
    while(*cur) {
        bool res = forge_rm_path(cur);
        if(!res) return false;
        cur = va_arg(list,char*);
    }
    va_end(list);
    return true;
}

bool forge_rm_path_strlist
(str_list_t list)
{
    while(*list) {
        forge_log("Removing %s",*list);
        if(!cross_remove(*list)){
            forge_error("could not remove file %s",*list);
            return false;
        }
        ++list;
    }
    return true;
}

bool forge_rm_path
(char* path)
{
    forge_log("Removing %s",path);
    if(!cross_remove(path)){
        forge_error("could not remove file %s",path);
        return false;
    }
    return true;
}

void forge_rebuild_yourself_
(char* src,char** argv,int argc)
{
    char* path = argv[0];
    forge_flags = no_flags;
    bool need_rebuild = false;
    for(uint32_t i = 0;i < argc;++i)
    {
        if(strcmp("-f",argv[i]) == 0) {
            forge_flags = forge_flags | all_build;
            need_rebuild = true;
        }
    }
    if(!need_rebuild)
    {need_rebuild = !forge_check_timestaps_1after2(path,src);}
    string_t old_name = {0};
    forge_da_append_cstr(&old_name,path);
    forge_da_append_cstr(&old_name,".old");
    forge_da_append_null(&old_name);
    if(need_rebuild) {
        forge_rename(old_name.data,path);
        cmd_t cmd = {0};
        #if IS_MSVC
        forge_append_cmd(&cmd,C_COMPILER, "/O", path, src);
        #else
        forge_append_cmd(&cmd,C_COMPILER, "-o", path, src);
        #endif
        if(forge_run_cmd(&cmd,.free = true))
        {
            forge_rm_path(old_name.data);
        }
        else
        {
            forge_rename(path,old_name.data);
        }
        forge_da_free(&old_name);
        exit(0);
    }
    forge_da_free(&old_name);
}

void forge_append_cmd_strlist
(cmd_t* cmd,str_list_t list)
{
    while(*list)
    {
        forge_append_cmd(cmd,*list);
        ++list;
    }
}

void forge_append_many_cmd_null
(cmd_t* cmd,...)
{
    va_list list;
    va_start(list,cmd);
    char* cur = va_arg(list,char*);
    char space[] = {' ',0};
    if(cmd->list.data && cmd->list.count)
    {
        if(!cmd->list.data[cmd->list.count-1])
        {
            cmd->list.count--;
        }
    }
    while(cur)
    {
        forge_da_append_cstr(&cmd->list,cur);
        forge_da_append_cstr(&cmd->list,space);
        cur = va_arg(list,char*);
    }
    forge_da_append_null(&cmd->list);
    va_end(list);
}

char* forge_change_extension
(char* ext,char* str)
{
    char *ptr = 0,*tmp = 0;
    ptr = strrchr(str,'.');
    uint32_t ext_len = strlen(ext);
    if(!ptr) {
        tmp = (char*)malloc(strlen(str) + ext_len + 1);
        sprintf(tmp,"%s.%s",str,ext);
    }else {
        tmp = (char*)malloc((ptr-str) + ext_len + 1);
        memcpy(tmp,str,(ptr-str));
        tmp[(ptr-str)] = '.';
        memcpy(&tmp[(ptr-str)+1],ext,ext_len);
    }
    return tmp;
}

str_list_t forge_change_extension_strlist
(char* ext,str_list_t list)
{
    uint32_t count = forge_count_strlist(list);
    char** strs = (char**)malloc(sizeof(char*)*(count+1));
    strs[count] = 0;
    for(uint32_t i = 0;i < count;++i)
    {
        strs[i] = forge_change_extension(ext,list[i]);
    }
    return strs;
}

str_list_t forge_change_extension_
(char* ext,...)
{
    va_list list_counter,list;
    uint32_t count = 0;
    va_start(list_counter,ext);
    char* cur = va_arg(list_counter,char*);
    while(cur) {count++;cur = va_arg(list_counter,char*);}
    va_end(list_counter);
    char** strs = (char**)malloc(sizeof(char*)*(count+1));
    strs[count] = 0;
    va_start(list,ext);
    cur = va_arg(list,char*);
    uint32_t i = 0;
    while(cur)
    {
        strs[i++] = forge_change_extension(ext,cur);
        cur = va_arg(list,char*);
    }
    va_end(list);
    return strs;
}

str_list_t forge_addfix
(bool is_prefix,char* fix,...)
{
    va_list list_counter,list;
    uint32_t count = 0;
    va_start(list_counter,fix);
    char* cur = va_arg(list_counter,char*);
    while(cur) {count++;cur = va_arg(list_counter,char*);}
    va_end(list_counter);
    char** strs = (char**)malloc(sizeof(char*)*(count+1));
    strs[count] = 0;
    va_start(list,fix);
    cur = va_arg(list,char*);
    uint32_t i = 0;
    uint32_t fix_len = strlen(fix);
    char* tmp = 0;
    char* ptr = 0;
    while(cur)
    {
        tmp = (char*)malloc(strlen(cur) + fix_len + 1);
        if(is_prefix)
        {sprintf(tmp,"%s%s",fix,cur);}
        else
        {sprintf(tmp,"%s%s",cur,fix);}
        strs[i++] = tmp;
        cur = va_arg(list,char*);
    }
    va_end(list);
    return strs;
}

void forge_free_strlist
(str_list_t list)
{
    str_list_t ptr = list;
    while(*ptr) {
        free(*ptr);
        ++ptr;
    }
    free(list);
}

uint32_t forge_count_strlist
(str_list_t list)
{
    uint32_t count = 0;
    while(*list) {
        ++list;
        ++count;
    }
    return count;
}


bool forge_run_cmd_
(cmd_t* cmd,run_cmd_ctx_t ctx)
{
    forge_log("%s",cmd->list.data);
    bool status = system(cmd->list.data);
    if(!ctx.no_fail_log && status) forge_log("[FAILED] %s",cmd->list.data);
    if(ctx.clear) forge_da_clear(&cmd->list);
    if(ctx.free) forge_da_free(&cmd->list);
    return status == 0;
}

void forge_free_cmd(cmd_t* cmd)
{
    forge_da_free(&cmd->list);
}

void forge_clear_cmd(cmd_t* cmd)
{
    forge_da_clear(&cmd->list);
}

#endif // FORGE_IS_FIRST_IMPLEMENTATION
#endif // FORGE_IMPLEMENTATION

/*
 *  forge - Basic build system in C for C
 *  Copyright (C) 2025 Menderes Sabaz <sabazmenders@proton.me>
 *
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */
