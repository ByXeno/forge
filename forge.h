#ifndef FORGE_H_
#define FORGE_H_

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>

#ifndef XTB_DA_DEF_SIZE
#define XTB_DA_DEF_SIZE 16
#endif // XTB_DA_DEF_SIZE

#if XTB_DA_DEF_SIZE == 0
#error "XTB_DA_DEF_SIZE can not be 0"
#endif

#ifndef XTB_DA_MUL
#define XTB_DA_MUL 2
#endif // XTB_DA_MUL

#if XTB_DA_MUL < 2
#error "XTB_DA_DEF_SIZE can not be less than 2"
#endif

#define __error__(msg) \
    {printf("%s:%d:%s\n",__FILE__,__LINE__,msg);exit(1);}

#define Panic_Nullptr()     {__error__("Got null ptr");}
#define Panic_OutOfMemory() {__error__("Out of memory");}
#define Panic_OutOfBounds() {__error__("Out of bound");}
#define Panic_ElSizeZero() {__error__("Element size can not be 0");}

typedef struct {
    void* data;
    uint32_t count;
    uint32_t capacity;
    const uint32_t el_size;
} da_list_t;

#define empty_da_list (da_list_t){0}

bool da_is_empty(da_list_t list);
da_list_t da_create(uint32_t el_size);
da_list_t da_clone(da_list_t list);
void da_append(da_list_t* list,void* element);
void* da_get_element(da_list_t* list,uint32_t index);
void* da_get_first(da_list_t* list);
void* da_get_last(da_list_t* list);
void da_free(da_list_t* list);
void da_realloc(da_list_t* list);
void da_clear(da_list_t* list);
void da_pop(da_list_t* list);
void da_append_cstr(da_list_t* list,char* element);
void da_append_cstr_null(da_list_t* list);

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
#define forge_panic(str,...) fprintf(stderr,"[Panic] "str,__VA_ARGS__)
#define FORGE_TODO(...) assert(0 && __VA_ARGS__)

#define DEVELOPMENT_FLAGS "-Wall -Wextra -Wpedantic -O0 -DDEBUG"
#define DEBUG_FLAGS DEVELOPMENT_FLAGS 
#define RELEASE_FLAGS "-O3 -march=native -flto"

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <assert.h>

#ifdef _WIN32

#else
#include <sys/stat.h>
#include <unistd.h>
#include <errno.h>
#endif // _WIN32

typedef struct {
    da_list_t list;
} Cmd;

Cmd forge_make_cmd(void);
#define forge_append_cmd(cmd,...) \
    forge_append_many_cmd_null(cmd,__VA_ARGS__,NULL)
void forge_append_many_cmd_null(Cmd* cmd,...);
void forge_clear_cmd(Cmd* cmd);
void forge_free_cmd(Cmd* cmd);

void forge_rebuild_yourself(char* path,char* src);

bool forge_check_timestaps_1after2(char* path1,char* path2);
bool forge_rename(char* path1,char* path2);
bool forge_check_timestaps_after_list(char* file,char** paths,uint32_t count);
bool forge_check_timestaps_1after2(char* path1,char* path2);

typedef struct {
    bool clear;
    bool free;
    bool no_fail_log;
} run_cmd_ctx_t;

#define forge_run_cmd(cmd,...) \
    forge_run_cmd_(cmd,(run_cmd_ctx_t){__VA_ARGS__})
bool forge_run_cmd_(Cmd* cmd,run_cmd_ctx_t ctx);

#endif // FORGE_H_

#ifdef FORGE_IMPLEMENTATION
#ifndef FORGE_IS_FIRST_IMPLEMENTATION
#define FORGE_IS_FIRST_IMPLEMENTATION

bool forge_check_timestaps_after_list
(char* file,char** paths,uint32_t count)
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
(char* path1,char* path2)
{
    #ifdef _WIN32
    FORGE_TODO("_WIN32 forge_check_timestaps_1after2");
    #else
    struct stat statbuf = {0};
    if (stat(path1, &statbuf) < 0) {
        forge_panic("could not stat %s: %s\n", path1, strerror(errno));
    }
    int path1_time = statbuf.st_mtime;
    if (stat(path2, &statbuf) < 0) {
        forge_panic("could not stat %s: %s\n", path2, strerror(errno));
    }
    int path2_time = statbuf.st_mtime;
    return path1_time > path2_time;
    #endif
}

bool forge_rename
(char* to,char* from)
{
    #ifdef _WIN32
    FORGE_TODO("WIN32 forge_rename");
    #else
    forge_log("%s -> %s",from,to);
    if (rename(from, to) < 0) {
        forge_panic("could not rename %s to %s: %s", from, to,strerror(errno));
    }
    #endif // _WIN32
}

void forge_rm_path
(char* path)
{
    #ifdef _WIN32
    FORGE_TODO("WIN32 forge_warn");
    #else
    forge_log("Removing %s",path);
    if (unlink(path) < 0) {
        if (errno == ENOENT) {
            errno = 0;
            forge_warn("file %s does not exist", path);
        } else {
            forge_panic("could not remove file %s: %s", path, strerror(errno));
        }
    }
    #endif // _WIN32
}

void forge_rebuild_yourself
(char* path,char* src)
{
    char* paths[] = {src,"forge.h"};
    bool need_rebuild = forge_check_timestaps_after_list(path,paths,2);
    da_list_t old_name = da_create(sizeof(char));
    da_append_cstr(&old_name,path);
    da_append_cstr(&old_name,".old");
    da_append_cstr_null(&old_name);
    if(need_rebuild) {
        forge_rename(old_name.data,path);
        Cmd cmd = forge_make_cmd( );
        forge_append_cmd(&cmd,C_COMPILER, "-o", path, src);
        if(forge_run_cmd(&cmd,.free = true))
        {
            forge_rm_path(old_name.data);
        }
        else
        {
            forge_rename(path,old_name.data);
        }
        da_free(&old_name);
        exit(0);
    }
    da_free(&old_name);
}

void forge_append_many_cmd_null
(Cmd* cmd,...)
{
    va_list list;
    va_start(list,cmd);
    char* cur = va_arg(list,char*);
    char* space = " ";
    while(cur)
    {
        da_append_cstr(&cmd->list,cur);
        da_append_cstr(&cmd->list,space);
        cur = va_arg(list,char*);
    }
    da_append_cstr_null(&cmd->list);
    va_end(list);
}

bool forge_run_cmd_
(Cmd* cmd,run_cmd_ctx_t ctx)
{
    forge_log("%s",cmd->list.data);
    bool status = system(cmd->list.data);
    if(!ctx.no_fail_log && status) forge_log("[FAILED] %s",cmd->list.data);
    if(ctx.clear) forge_clear_cmd(cmd);
    if(ctx.free) forge_free_cmd(cmd);
    return status == 0;
}

Cmd forge_make_cmd
(void)
{
    return (Cmd){.list = da_create(sizeof(const char))};
}

void forge_clear_cmd
(Cmd* cmd)
{
    da_clear(&cmd->list);
}

void forge_free_cmd
(Cmd* cmd)
{
    da_free(&cmd->list);
}

// Dynamic Array

bool da_is_empty
(da_list_t list)
{
    if(!list.data && !list.count && !list.capacity && !list.el_size)
    {return true;}
    return false;
}

void da_pop
(da_list_t* list)
{
    if (!list || !list->data) { Panic_Nullptr(); }
    if (list->count == 0) { Panic_OutOfBounds(); }
    list->count--;
}

da_list_t da_clone
(da_list_t list)
{
    da_list_t tmp = list;
    tmp.data = calloc(list.capacity,list.el_size);
    memcpy(tmp.data,list.data,list.el_size * list.count);
    return tmp;
}

da_list_t da_create
(uint32_t el_size)
{
    if(el_size == 0) {Panic_ElSizeZero();}
    return (da_list_t){
        .el_size = el_size,
        .capacity = XTB_DA_DEF_SIZE,
        .count = 0,
        .data = calloc(XTB_DA_DEF_SIZE,el_size),
    };
}

void da_clear
(da_list_t* list)
{
    if(!list) {Panic_Nullptr();}
    if(!list->data) { Panic_Nullptr(); }
    memset(list->data,0,list->el_size * list->count);
    list->count = 0;
}

void da_free
(da_list_t* list)
{
    if(!list) {Panic_Nullptr();}
    if(!list->data) { Panic_Nullptr(); }
    free(list->data);
    list->data = 0;
    list->count = 0;
    list->capacity = 0;
}

void da_append
(da_list_t* list,void* element)
{
    if(!list) {Panic_Nullptr();}
    if(!list->data) { Panic_Nullptr(); }
    if(!element) {Panic_Nullptr();}
    if(list->count >= list->capacity)
    {da_realloc(list);}
    uint32_t off = list->el_size*list->count;
    memcpy((uint8_t*)list->data + off, element, list->el_size);
    list->count++;
}

void da_append_cstr
(da_list_t* list,char* element)
{
    if(!list) {Panic_Nullptr();}
    if(!list->data) { Panic_Nullptr(); }
    if(!element) {Panic_Nullptr();}
    uint32_t len = strlen(element);
    if(list->count+len >= list->capacity)
    {da_realloc(list);da_append_cstr(list,element);return;}
    uint32_t off = list->el_size*list->count;
    memcpy((uint8_t*)list->data + off, element, len);
    list->count+=len;
}

void da_append_cstr_null
(da_list_t* list)
{
    if(!list) {Panic_Nullptr();}
    if(!list->data) { Panic_Nullptr(); }
    if(list->count+1 >= list->capacity)
    {da_realloc(list);da_append_cstr_null(list);return;}
    uint32_t off = list->el_size*list->count;
    char* element = "";
    memcpy((uint8_t*)list->data + off, element, 1);
    list->count++;
}

void* da_get_first
(da_list_t* list)
{
    return da_get_element(list,0);
}

void* da_get_last
(da_list_t* list)
{
    return da_get_element(list,list->count-1);
}

void* da_get_element
(da_list_t* list,uint32_t index)
{
    if(!list) {Panic_Nullptr();}
    if(!list->data) { Panic_Nullptr(); }
    if(index >= list->count) {Panic_OutOfBounds();}
    return (uint8_t*)list->data + index * list->el_size;
}

void da_realloc(da_list_t* list)
{
    if (!list) { Panic_Nullptr(); }
    if (!list->data) { Panic_Nullptr(); }
    size_t old_capacity = list->capacity;
    list->capacity *= XTB_DA_MUL;
    void* new_data = realloc(list->data, list->capacity * list->el_size);
    if (!new_data) { Panic_OutOfMemory(); }
    list->data = new_data;
    memset((char*)list->data + old_capacity * list->el_size,
    0,
    (list->capacity - old_capacity) * list->el_size);
}


#endif // FORGE_IS_FIRST_IMPLEMENTATION
#endif // FORGE_IMPLEMENTATION
