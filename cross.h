#ifndef CROSS_H_
#define CROSS_H_

/*
    cross.h — STB-style cross-platform C foundation library (v1.1)
    ---------------------------------------------------------------
    Usage:
        #define CROSS_IMPLEMENTATION
        #include "cross.h"

    Features:
        - Platform info, filesystem, process
        - Logging with levels, file, timestamps
        - Memory with custom allocator support
        - Time utilities (ms/us/seconds)
        - Threads and mutexes
        - Portable, single-header, dependency-free
*/

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

#ifdef _WIN32
#  define CROSS_OS_WINDOWS 1
#else
#  define CROSS_OS_POSIX 1
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

//──────────────────────────────
// IMPLEMENTATION
//──────────────────────────────
#ifdef CROSS_IMPLEMENTATION

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

#endif // CROSS_IMPLEMENTATION


/*
 *  cross - Single-header cross-platform C library.
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
