#ifndef _LIST_
#define _LIST_

#include <stdlib.h>
#include <stdio.h>


enum state{

    ACCESS,
    CREATE,
    MODIFY,
    DELETE,
    IDLE

};

typedef struct list{

    char* filename;
    enum state type;
    struct list* next;

}inf_t;

inf_t* inf_new();
int inf_insert(inf_t* head, char* filename, enum state type);
void inf_print(inf_t* head);
int inf_search(inf_t* head, char* filename);

#endif