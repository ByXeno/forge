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
#include "cross.h"
#else
#include "cross.h"
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
#endif // FORGE_NOLOG

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
            (list)->data = realloc((list)->data,(list)->capacity * sizeof(*(list)->data)); \
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

typedef struct {
    char* data;
    uint32_t count;
    uint32_t capacity;
} string_t;

typedef struct {
    string_t list;
} cmd_t;

cmd_t forge_make_cmd(void);
#define forge_append_cmd(cmd,...) \
    forge_append_many_cmd_null(cmd,__VA_ARGS__,NULL)
void forge_append_many_cmd_null(cmd_t* cmd,...);
void forge_clear_cmd(cmd_t* cmd);
void forge_free_cmd(cmd_t* cmd);

#define forge_rebuild_yourself() forge_rebuild_yourself_(argv[0],__FILE__)
void forge_rebuild_yourself_(char* path,char* src);

bool forge_rename(char* path1,char* path2);
bool forge_check_timestaps_after_list(const char* file,const char** paths,uint32_t count);
bool forge_check_timestaps_1after2(const char* path1,const char* path2);

typedef struct {
    bool clear;
    bool free;
    bool no_fail_log;
} run_cmd_ctx_t;

#define forge_run_cmd(cmd,...) \
    forge_run_cmd_(cmd,(run_cmd_ctx_t){__VA_ARGS__})
bool forge_run_cmd_(cmd_t* cmd,run_cmd_ctx_t ctx);

typedef struct {
    const char* output;
    const char** depend;
    const uint32_t dep_c;
} forge_target_t;

typedef struct {
    cross_thread_t** data;
    uint32_t count;
    uint32_t capacity;
    cross_mutex_t* mutex;
} async_group_t;

typedef struct {
    async_group_t* async;
} forge_build_target_ctx_t;

#define forge_build_target(target,...) \
    forge_build_target_(target,(forge_build_target_ctx_t){__VA_ARGS__})
bool forge_build_target_(forge_target_t target,forge_build_target_ctx_t ctx);
void forge_wait_async_group(async_group_t* group);
async_group_t forge_create_async_group(void);
void forge_async_group_free(async_group_t* group);

#define FORGE_TARGET(name, output_name, ...) \
    static const char *name##_depends[] = { __VA_ARGS__ }; \
    static const forge_target_t name = { \
        .output = output_name, \
        .depend = name##_depends, \
        .dep_c = sizeof(name##_depends) / sizeof(*name##_depends), \
    };

#define FORGE_TARGET_BUILD(name,output_name,...) \
    FORGE_TARGET(name,output_name,__VA_ARGS__); \
    forge_build_target(name);

#define FORGE_TARGET_BUILD_ASYNC(group,name,output_name,...) \
    FORGE_TARGET(name,output_name,__VA_ARGS__); \
    forge_build_target(name,.async = group);

#endif // FORGE_H_

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

bool forge_build_target_
(forge_target_t target,forge_build_target_ctx_t ctx)
{
    if(forge_check_timestaps_after_list(
    target.output,target.depend,target.dep_c))
    {
        cmd_t cmd = {0};
        forge_append_cmd(&cmd,C_COMPILER);
        forge_append_cmd(&cmd,"-o",target.output);
        uint32_t i = 0;
        for(;i < target.dep_c;++i)
        {
            if(!(*target.depend[i])) continue;
            if(target.depend[i][strlen(target.depend[i])-1] == 'h') continue;
            forge_append_cmd(&cmd,target.depend[i]);
        }
        if(!ctx.async)
        {
            return forge_run_cmd(&cmd,.free = true);
        }
        else
        {
            cross_mutex_lock(ctx.async->mutex);
            cross_thread_t* thread = 0;
            forge_run_async_ctx* as_ctx = malloc(sizeof(forge_run_async_ctx));
            as_ctx->cmd = cmd;
            as_ctx->index = ctx.async->count;
            as_ctx->group = ctx.async;
            thread = cross_thread_create(forge_run_async,as_ctx);
            forge_da_append(ctx.async,thread);
            cross_mutex_unlock(ctx.async->mutex);
            return true;
        }
    }
    forge_log("'%s' is up to date! Skipping...",target.output);
    return true;
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
    return first > second;
}

bool forge_rename
(char* to,char* from)
{
    forge_log("%s -> %s",from,to);
    if (cross_rename(from, to) < 0) {
        forge_error("could not rename %s to %s", from, to);
        return false;
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
(char* path,char* src)
{
    const char* paths[] = {src,"forge.h"};
    bool need_rebuild = forge_check_timestaps_after_list(path,paths,2);
    string_t old_name = {0};
    forge_da_append_cstr(&old_name,path);
    forge_da_append_cstr(&old_name,".old");
    forge_da_append_null(&old_name);
    if(need_rebuild) {
        forge_rename(old_name.data,path);
        cmd_t cmd = {0};
        forge_append_cmd(&cmd,C_COMPILER, "-o", path, src);
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

void forge_append_many_cmd_null
(cmd_t* cmd,...)
{
    va_list list;
    va_start(list,cmd);
    char* cur = va_arg(list,char*);
    char* space = " ";
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
