#ifndef PROJECT_LIST_H
#define PROJECT_LIST_H

#include <stddef.h>

typedef struct ITEM{
    void* data;
    struct ITEM *next;
}ITEM;

typedef struct{
    ITEM *head;
    ITEM *tail;
} LIST;

LIST* list_init(void);
void* list_append(LIST* List, void* data, size_t data_size);
void* list_pop(LIST* List, int i);
int list_insert(LIST *List, void* data, int i, size_t data_size);
void list_remove(LIST* List, void* data, size_t data_size);
void list_clear(LIST* list);
void list_extend(LIST* List, LIST* List1);
void list_print(LIST* List);

#endif //PROJECT_LIST_H
