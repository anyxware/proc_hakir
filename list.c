#include "list.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

LIST* list_init(){
    return (LIST*)calloc(1, sizeof(LIST));
}

void* list_append(LIST* List, void* data, size_t data_size){
    ITEM* ptr = (ITEM*)malloc(sizeof(ITEM));
    if(!ptr) return 0;
    ptr->data = malloc(data_size);
    if(!ptr->data) return 0;
    memcpy(ptr->data, data, data_size);
    ptr->next = NULL;
    if(!List->head){
        List->head = ptr;
        List->tail = ptr;
    }else{
        List->tail->next = ptr;
        List->tail = ptr;
    }
    return ptr->data;
}

void* list_pop(LIST* List, int i){
    ITEM* ptr = List->head, *ptr_prev = NULL;
    int j = 0;
    void* c;
    if(i == -1){
        while (ptr && ptr->next) {
            ptr_prev = ptr;
            ptr = ptr->next;
        }
    }else{
        while (ptr && j++ < i) {
            ptr_prev = ptr;
            ptr = ptr->next;
        }
    }
    if (!ptr) return NULL;
    if (ptr == List->head) List->head = ptr->next;
    if (ptr == List->tail) List->tail = ptr_prev;
    if (ptr_prev) ptr_prev->next = ptr->next;
    c = ptr->data;
    free(ptr);
    return c;
}

int list_insert(LIST *List, void* data, int i, size_t data_size) {
    ITEM* ptr = List->head, *ptr_prev = NULL;
    int j = 0;
    while (ptr && j++ < i) {
        ptr_prev = ptr;
        ptr = ptr->next;
    }
    ITEM *new = (ITEM *) malloc(sizeof(ITEM));
    if (!new) return -1;
    new->data = malloc(data_size);
    memcpy(new->data, data, data_size);
    new->next = ptr;
    if (ptr_prev) ptr_prev->next = new;
    else List->head = new;
    if (!ptr) List->tail = new;
    return 0;
}

void list_remove(LIST* List, void* data, size_t data_size) {
    ITEM* ptr = List->head, *ptr_prev = NULL;
    while (ptr && memcmp(ptr->data, data, data_size)) {
        ptr_prev = ptr;
        ptr = ptr->next;
    }
    if (!ptr) return;
    if (ptr == List->head) List->head = ptr->next;
    if (ptr == List->tail) List->tail = ptr_prev;
    if (ptr_prev) ptr_prev->next = ptr->next;
    free(ptr->data);
    free(ptr);
}

void list_clear(LIST* List) {
    ITEM* ptr = List->head, *ptr_prev;
    while (ptr) {
        ptr_prev = ptr;
        ptr = ptr->next;
        free(ptr_prev->data);
        free(ptr_prev);
    }
    free(List);
}

void list_extend(LIST* List, LIST* List1){
    if(!List->head){
        List->head = List1->head;
        List->tail = List1->tail;
    }else{
        List->tail->next = List1->head;
        List->tail = List1->tail;
    }
}

void list_print(LIST* List){
    ITEM* ptr = List->head;
    while(ptr){
        printf("%c", *((char*)ptr->data));
        ptr = ptr->next;
    }
    printf("\n");
}