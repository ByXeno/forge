#ifndef FORGE_H_
#define FORGE_H_

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
#define forge_log(str,...) printf("[Forge] " str "\n",__VA_ARGS__)
#else
#define forge_log(...)
#endif // FORGE_NOLOG

#define forge_warn(str,...) printf("[Warning] " str "\n",__VA_ARGS__)
#define forge_panic(str,...) fprintf(stderr,"[Panic] "str "\n",__VA_ARGS__)
#define FORGE_TODO(...) assert(0 && __VA_ARGS__)

#ifndef DEVELOPMENT_FLAGS
#define DEVELOPMENT_FLAGS "-Wall -Wextra -Wpedantic -O0 -DDEBUG"
#endif // DEVELOPMENT_FLAGS

#ifndef DEBUG_FLAGS
#define DEBUG_FLAGS DEVELOPMENT_FLAGS 
#endif // DEBUG_FLAGS

#ifndef RELEASE_FLAGS
#define RELEASE_FLAGS "-O3 -flto"
#endif // RELEASE_FLAGS

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdarg.h>
#include <assert.h>
#include <string.h>

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
#define forge_da_free(list) free(list.data)
#define forge_da_clear(list) memset(list.data,0,list.capacity)
    
typedef struct {
    char* data;
    uint32_t count;
    uint32_t capacity;
} string_t;

typedef struct {
    string_t list;
} Cmd;

Cmd forge_make_cmd(void);
#define forge_append_cmd(cmd,...) \
    forge_append_many_cmd_null(cmd,__VA_ARGS__,NULL)
void forge_append_many_cmd_null(Cmd* cmd,...);
void forge_clear_cmd(Cmd* cmd);
void forge_free_cmd(Cmd* cmd);

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
bool forge_run_cmd_(Cmd* cmd,run_cmd_ctx_t ctx);

typedef struct {
    const char* output;
    const char** depend;
    const uint32_t dep_c;
} forge_target_t;

#define FORGE_TARGET(name, output_name, ...) \
    static const char *name##_depends[] = { __VA_ARGS__ }; \
    static const forge_target_t name = { \
        .output = output_name, \
        .depend = name##_depends, \
        .dep_c = sizeof(name##_depends) / sizeof(*name##_depends), \
    };

bool forge_build_target(forge_target_t target);

#endif // FORGE_H_

#ifdef FORGE_IMPLEMENTATION
#ifndef FORGE_IS_FIRST_IMPLEMENTATION
#define FORGE_IS_FIRST_IMPLEMENTATION

bool forge_build_target
(forge_target_t target)
{
    if(forge_check_timestaps_after_list(
    target.output,target.depend,target.dep_c))
    {
        Cmd cmd = {0};
        forge_append_cmd(&cmd,C_COMPILER);
        forge_append_cmd(&cmd,"-o",target.output);
        uint32_t i = 0;
        for(;i < target.dep_c;++i)
        {
            forge_append_cmd(&cmd,target.depend[i]);
        }
        return forge_run_cmd(&cmd,.free = true);
    }
    return true;
}

bool forge_check_timestaps_after_list
(const char* file,const char** paths,uint32_t count)
{
    uint32_t i = 0;
    for(;i < count;++i)
    {
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
    if(first == -1)
        forge_panic("no file named %s",path1);
    if(second == -1)
        forge_panic("no file named %s",path2);
    return first > second;
}

bool forge_rename
(char* to,char* from)
{
    forge_log("%s -> %s",from,to);
    if (cross_rename(from, to) < 0) {
        forge_panic("could not rename %s to %s", from, to);
    }
}

void forge_rm_path
(char* path)
{
    forge_log("Removing %s",path);
    if(!cross_remove(path)){
        forge_panic("could not remove file %s",path);
    }
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
        Cmd cmd = {0};
        forge_append_cmd(&cmd,C_COMPILER, "-o", path, src);
        if(forge_run_cmd(&cmd,.free = true))
        {
            forge_rm_path(old_name.data);
        }
        else
        {
            forge_rename(path,old_name.data);
        }
        forge_da_free(old_name);
        exit(0);
    }
    forge_da_free(old_name);
}

void forge_append_many_cmd_null
(Cmd* cmd,...)
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
(Cmd* cmd,run_cmd_ctx_t ctx)
{
    forge_log("%s",cmd->list.data);
    bool status = system(cmd->list.data);
    if(!ctx.no_fail_log && status) forge_log("[FAILED] %s",cmd->list.data);
    if(ctx.clear) forge_da_clear(cmd->list);
    if(ctx.free) forge_da_free(cmd->list);
    return status == 0;
}

void forge_free_cmd(Cmd* cmd)
{
    forge_da_free(cmd->list);    
}

void forge_clear_cmd(Cmd* cmd)
{
    forge_da_clear(cmd->list);    
}

#endif // FORGE_IS_FIRST_IMPLEMENTATION
#endif // FORGE_IMPLEMENTATION
