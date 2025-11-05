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


#ifdef _WIN32
#define C_COMPILER ""
#else
#define C_COMPILER "cc"
#endif

#ifndef MAX_STR_LEN
#define MAX_STR_LEN 128
#endif // MAX_STR_LEN
#if MAX_STR_LEN % 8 != 0
#error "MAX_STR_LEN must divisible with 8"
#endif

#ifndef FORGE_NOLOG
#define forge_log(buf) printf("[Forge] %s\n",buf);
#else
#define forge_log(buf)
#endif // FORGE_NOLOG

#define DEVELOPMENT_FLAGS "-Wall -Wextra -Wpedantic -O0 -DDEBUG"
#define DEBUG_FLAGS DEVELOPMENT_FLAGS 
#define RELEASE_FLAGS "-O3 -march=native -flto"

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>

typedef struct {
    da_list_t list;
} Cmd;

Cmd forge_make_cmd(void);
#define forge_append_cmd(cmd,...) \
    forge_append_many_cmd_null(cmd,__VA_ARGS__,NULL)
void forge_append_many_cmd_null(Cmd* cmd,...);
void forge_clear_cmd(Cmd* cmd);
void forge_free_cmd(Cmd* cmd);

void forge_rebuild_yourself(char* path);

typedef struct {
    bool clear;
    bool free;
} run_cmd_ctx_t;

#define forge_run_cmd(cmd,...) \
    forge_run_cmd_(cmd,(run_cmd_ctx_t){__VA_ARGS__})
bool forge_run_cmd_(Cmd* cmd,run_cmd_ctx_t ctx);

#endif // FORGE_H_

#ifdef FORGE_IMPLEMENTATION
#ifndef FORGE_IS_FIRST_IMPLEMENTATION
#define FORGE_IS_FIRST_IMPLEMENTATION

void forge_rebuild_yourself
(char* path)
{
    
}

void forge_append_many_cmd_null
(Cmd* cmd,...)
{
    va_list list;
    va_start(list,cmd);
    char* cur = va_arg(list,char*);
    while(cur)
    {
        int len = strlen(cur);
        if(len > MAX_STR_LEN)
        {
            fprintf(stderr,"Please increase the MAX_STR_LEN "
            "macro\nSupplied:%d\nNeeded:%d\n",
            MAX_STR_LEN,len);
        }
        da_append(&cmd->list,cur);
        cur = va_arg(list,char*);
    }
    va_end(list);
}

bool forge_run_cmd_
(Cmd* cmd,run_cmd_ctx_t ctx)
{
    uint32_t len = 0;
    uint32_t i = 0;
    for(;i < cmd->list.count;++i)
    {
        len += strlen((char*)da_get_element(&cmd->list,i)) + 1;
    }
    char* buf = calloc(len,sizeof(char));
    for(i = 0;i < cmd->list.count;++i)
    {
        if(i == 0)
        {
            sprintf(buf,"%s",(char*)da_get_element(&cmd->list,i));
            continue;
        }
        sprintf(buf,"%s %s",buf,(char*)da_get_element(&cmd->list,i));
    }
    forge_log(buf);
    bool status = system(buf);
    free(buf);
    if(ctx.clear) forge_clear_cmd(cmd);
    if(ctx.free) forge_free_cmd(cmd);
    return status == 0;
}

Cmd forge_make_cmd
(void)
{
    return (Cmd){.list = da_create(sizeof(const char*)*MAX_STR_LEN/8)};
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
