#include "list.h"
#include <string.h>

inf_t* inf_new(){

    inf_t* new;
    new = (inf_t*)malloc(sizeof(inf_t));
    new->filename = NULL;
    new->type = IDLE;
    new->next = NULL;

    return new;

}

int inf_getLength(inf_t* head){

    inf_t* curr = head;
    int counter = 0;

    while(curr != NULL){
        counter++;
        curr = curr->next;
    }

    return counter - 1;

}

int inf_insert(inf_t* head, char* filename, enum state type){

    inf_t* current = head;
    inf_t* temp;

    while(current != NULL){         

        if(current->filename == NULL){
            current = current->next;
            continue;
        }

        if(!strcmp(current->filename, filename) && current->type == type)
            return 0;
        current = current->next;
    }

    current = head;
    temp = inf_new();
    temp->filename = filename;
    temp->type = type;
    while(current->next != NULL){
        current = current->next;
    }
    current->next = temp;

    return 1;

}

void inf_print(inf_t* head){

    inf_t* curr = head;
    char* type;

    while(curr != NULL){
        if(curr->filename != NULL){
            if(curr->type == 4)
                type = "Idle";
            else if(curr->type == 0)
                type = "Access";
            else if(curr->type == 1)
                type = "Create";
            else if(curr->type == 2)
                type = "Modify";
            else if(curr->type == 3)
                type = "Delete";
            
            printf("file: %s, type: %s\n", curr->filename, type);
        }
        curr = curr->next;
    }

}

int inf_search(inf_t* head, char* filename){

    inf_t* curr = head;

    while(curr != NULL){
        if(curr->filename != NULL){
            if(!strcmp(curr->filename, filename))
                return 1;
        }
        curr = curr->next;
    }

    return 0;

}