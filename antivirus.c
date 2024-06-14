#include <stdlib.h>
#include <stdio.h>
#include <dirent.h>
#include <string.h>
#include <openssl/sha.h>
#include <openssl/md5.h>
#include <time.h>
#include <regex.h>
#include <curl/curl.h>
#include <sys/inotify.h>
#include <poll.h>
#include <unistd.h>
#include <math.h>
#include "list.h"

#define _MAX_LINE_ 256

void print_info(char* message);

/* predetermined virus characteristics */
char* virus_md5 = "85578cd4404c6d586cd0ae1b36c98aca";
char* virus_sha = "d56d67f2c43411d966525b3250bfaa1a85db34bf371468df1b6a9882fee78849";
char* virus_bitcoin = "bc1qa5wkgaew2dkv56kfvj49j0av5nml45x9ek9hz6";
char virus_signature[] = {
    0x98, 0x1d, 0x00, 0x00,
    0xec, 0x33, 0xff, 0xff,
    0xfb, 0x06, 0x00, 0x00,
    0x00, 0x46, 0x0e, 0x10
};

/* helping variables for stats */
int files = 0;
int processed = 0;
int infected = 0;

/* list for events */
inf_t* head;





/* Function 1 (./antivirus scan <dir>) */

int md5_file(char* path, char output[33]){

    FILE* file = fopen(path, "rb");
    unsigned char hash[MD5_DIGEST_LENGTH];
    const int bufSize = 16384;
    char* buffer = malloc(bufSize);
    int bytesRead = 0;
    MD5_CTX md5;

    if(!file || !buffer){
        free(buffer);
        return -1;
    }
        
    MD5_Init(&md5);

    while((bytesRead = fread(buffer, 1, bufSize, file))){
        MD5_Update(&md5, buffer, bytesRead);
    }

    MD5_Final(hash, &md5);

    md5_hash_string(hash, output);

    fclose(file);
    free(buffer);

    return 0;

}

void md5_hash_string(unsigned char hash[MD5_DIGEST_LENGTH], char outputBuffer[33]){

    int i = 0;

    for(i = 0; i < MD5_DIGEST_LENGTH; i++){
        sprintf(outputBuffer + (i * 2), "%02x", (unsigned char)hash[i]);
    }

    outputBuffer[32] = 0;

}

int sha256_file(char* path, char output[65]){

    FILE* file = fopen(path, "rb");
    unsigned char hash[SHA256_DIGEST_LENGTH];
    const int bufSize = 32768;
    char* buffer = malloc(bufSize);
    int bytesRead = 0;
    SHA256_CTX sha256;

    if(!file || !buffer){
        free(buffer);
        return -1;
    }
        
    SHA256_Init(&sha256);

    while((bytesRead = fread(buffer, 1, bufSize, file))){
        SHA256_Update(&sha256, buffer, bytesRead);
    }

    SHA256_Final(hash, &sha256);

    sha256_hash_string(hash, output);

    fclose(file);
    free(buffer);

    return 0;
}      

void sha256_hash_string(unsigned char hash[SHA256_DIGEST_LENGTH], char outputBuffer[65]){
    int i = 0;

    for(i = 0; i < SHA256_DIGEST_LENGTH; i++){
        sprintf(outputBuffer + (i * 2), "%02x", (unsigned char)hash[i]);
    }

    outputBuffer[64] = 0;
}

int bitcoin_file(char* path){

    FILE* file = fopen(path, "rb");

    if(!file){
        return -1;
    }

    int bytesRead = 0;
    const int bufSize = 32768;
    char* buffer = malloc(bufSize);

    while((bytesRead = fread(buffer, 1, bufSize, file))){
        if(strstr(buffer, virus_bitcoin)){
            infected++;
            printf("%s: \033[0;31mREPORTED_BITCOIN\033[0m\n", path);
        }
            
    }

    return 0;

}

int sign_file(char* path){

    FILE* file = fopen(path, "rb");

    if(!file){
        printf("error with file opening");
        return -1;
    }
    
    fseek(file, 0, SEEK_END);
    unsigned long filelen = ftell(file);
    fseek(file, 0, SEEK_SET);
    char* buffer = malloc(filelen);
    unsigned int i;

    if(buffer)
        fread(buffer, 1, filelen, file);

    for(i = 0; i + 16 <= filelen; i++){
        if(memcmp(buffer + i, virus_signature, 16) == 0){
            infected++;
            printf("%s: \033[0;31mREPORTED_VIRUS\033[0m\n", path);
        }

    }

    return 0;

}

void scan_dir(char* base_path){

    char path[_MAX_LINE_];
    struct dirent* dp;
    DIR* dir = opendir(base_path);
    unsigned char file_sha[65];
    unsigned char file_md5[33];

    if(!dir)
        return;

    while((dp = readdir(dir)) != NULL){
        if(strcmp(dp->d_name, ".") == 0 || strcmp(dp->d_name, "..") == 0)
            continue;
        
        strcpy(path, base_path);
        strcat(path, "/");
        strcat(path, dp->d_name);

        if(dp->d_type == DT_REG){

            /* calculate the sha256 and md5 sums of each file */
            sha256_file(path, file_sha);
            md5_file(path, file_md5);

            /* compare the file sums with the virus' and if they match print the file info */
            if(!strcmp(file_sha, virus_sha)){
                infected++;
                printf("%s: \033[0;31m%s\033[0m\n", path, "REPORTED_SHA256_HASH");
            }
            
            if(!strcmp(file_md5, virus_md5)){
                infected++;
                printf("%s: \033[0;31m%s\033[0m\n", path, "REPORTED_MD5_HASH");
            }
                
            bitcoin_file(path);

            sign_file(path);

            processed++;
        }
        
        scan_dir(path);

        
    }

    closedir(dir);

}





/* Function 2 (./antivirus inspect <dir>) */

typedef struct memory{

    char *response;
    size_t size;

}mem_t;

static size_t callback(void *data, size_t size, size_t nmemb, void *clientp){

  size_t realsize = size * nmemb;
  mem_t* mem = (mem_t*)clientp;
 
  char* ptr = realloc(mem->response, mem->size + realsize + 1);
  if(!ptr)
    return 0; 
 
  mem->response = ptr;
  memcpy(&(mem->response[mem->size]), data, realsize);
  mem->size += realsize;
  mem->response[mem->size] = 0;
 
  return realsize;

}

void inspect_dir(char* base_path){

    char path[_MAX_LINE_];
    struct dirent* dp;
    DIR* dir = opendir(base_path);

    if(!dir)
        return;

    while((dp = readdir(dir)) != NULL){
        if(strcmp(dp->d_name, ".") == 0 || strcmp(dp->d_name, "..") == 0)
            continue;

        strcpy(path, base_path);
        strcat(path, "/");
        strcat(path, dp->d_name);
        
        if(dp->d_type == DT_REG){
            
            FILE* file = fopen(path, "rb");

            if(!file){
                printf("error with file opening");
                return;
            }
            
            fseek(file, 0, SEEK_END);
            unsigned long filelen = ftell(file);
            fseek(file, 0, SEEK_SET);
            char* buffer = malloc(filelen + 1);
            if(!buffer)
                printf("error with buffer memory allocate\n");
            fread(buffer, filelen, 1, file);

            //printf("buffer: %s\n", buffer);
            int start = 0, end = 0;
            for(int i = 0; i < filelen; i++){
                if(buffer[end] >= 32 && buffer[end] <= 126){
                    fread(*&buffer + i, 1, 1, file);
                    end++;
                    continue;
                }                    
                    
                if((end - start + 1) >= 4){
                    regex_t domain_name;
                    int value;
                    // [a-zA-Z0-9.-]+\\.[a-zA-Z]{2,3}(/[^[:space:]]*)?$
                    // (https:\/\/)*(www.)*[a-zA-z0-9]{3,}.[a-zA-z]*$
                    value = regcomp(&domain_name, "(https:\/\/)*(www.)*[a-zA-z0-9]{3,}.[a-zA-z]*$", REG_EXTENDED);
                    if(value){
                        fprintf(stderr, "Could not compile regex\n");
                        exit(EXIT_FAILURE);
                    }
                    value = regexec(&domain_name, &buffer[start], 0, NULL, 0);

                    if(value == 0 && (strstr(&buffer[start], "https://") != NULL || strstr(&buffer[start], "www.") != NULL)){
                        char* url = strtok(&buffer[start], " ");
                        while(url != NULL){
                            if((strstr(url, "https://") != NULL || strstr(url, "www.") != NULL)){
                                
                                // remove https:// from url
                                if(strstr(url, "https://"))
                                    url = &url[8];

                                // append the cloudflare prefix  before url
                                
                                char* prefix = "https://family.cloudflare-dns.com/dns-query?name=";
                                int query_len = strlen(prefix) + strlen(url) + 1;
                                char* query = malloc(query_len);
                                for(int i = 0; i < strlen(prefix); i++){
                                    query[i] = prefix[i];
                                }
                                int index = strlen(prefix);
                                for(int i = 0; i < strlen(url); i++){
                                    query[index++] = url[i];
                                }
                                query[index] = '\0';
                                
                                // curl url and save response in a string
                                CURL* curl;
                                CURLcode result;
                                mem_t chunk = {0};
                                struct curl_slist* list = NULL;

                                curl = curl_easy_init();
                                if(!curl){
                                    fprintf(stderr, "HTTP request failed\n");
                                    exit(EXIT_FAILURE);
                                }
                                
                                curl_easy_setopt(curl, CURLOPT_URL, query);
                                list = curl_slist_append(list, "accept: application/dns-json");
                                curl_easy_setopt(curl, CURLOPT_HTTPHEADER, list);
                                curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, callback);
                                curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&chunk);

                                result = curl_easy_perform(curl);
                                if(result != CURLE_OK){
                                    fprintf(stderr, "Error: %s\n", curl_easy_strerror(result));
                                    exit(EXIT_FAILURE);
                                }    

                                curl_easy_cleanup(curl);
                                
                                // if the response contains "Censored" then print it                           
                                if(strstr(chunk.response, "Censored"))
                                    printf("| %s | %s | \033[0;31mMalware\033[0m\n", path, url);
                                else
                                    printf("| %s | %s | \033[0;32mSafe\033[0m\n", path, url);

                                //printf("query: %s\n", query);
                                
                            }
                                
                            url = strtok(NULL, " ");
                        }
                        //printf("%s\n", &buffer[start]);
                    }

                } 

                end++;
                start = end;
            }

            free(buffer);
            fclose(file);

            processed++;
        }
        
        inspect_dir(path);

        
    }

    closedir(dir);

}





/* Function 3 (./antivirus monitor <dir>) */

void search_events(){

    inf_t* unique = inf_new();
    inf_t* curr = head;
    inf_t* curr_unique;

    while(curr != NULL){

        /* insert into a new list all unique files excluding those with .locked appended to them */
        if(curr->filename != NULL){
            if(inf_search(unique, curr->filename) == 0 && strstr(curr->filename, ".locked") == NULL)
                inf_insert(unique, curr->filename, IDLE);
        }
        curr = curr->next;

    }

    curr = head;
    curr_unique = unique;

    /* for each unique file search for the events in the original list */
    while(curr_unique != NULL){

        if(curr_unique->filename == NULL){
            curr_unique = curr_unique->next;
            continue;
        }

        int flag[4] = {0};

        while(curr != NULL){

            if(curr->filename == NULL){
                curr = curr->next;
                continue;
            }

            if(!strcmp(curr->filename, curr_unique->filename)){

                /*  */
                if(curr->type == ACCESS || curr->type == DELETE)
                    flag[curr->type] = 1;

            }

            if(strstr(curr->filename, curr_unique->filename) != NULL && strstr(curr->filename, ".locked") != NULL){

                /*  */
                if(curr->type == CREATE || curr->type == MODIFY)
                    flag[curr->type] = 1;

            }
            
            curr = curr->next;

        }

        /* if all events are present then we have a ransomware attack */
        if(flag[ACCESS] && flag[CREATE] && flag[MODIFY] && flag[DELETE]){
            printf("[\033[0;31mWARN\033[0m] \033[0;31mRansomware attack detected on file \e[4;31m%s\033[0m\n", curr_unique->filename);
        }

        curr_unique = curr_unique->next;

    }

}

void handle_events(int fd, int wd){

    int buf_len = 1024 * (sizeof(struct inotify_event) + 16);
    char buffer[buf_len];
    int len, i = 0;
    len = read(fd, buffer, buf_len);

    if(len < 0){
        fprintf(stderr, "read failed\n");
        exit(EXIT_FAILURE);
    }

    struct inotify_event* event;
    char* event_name;

    while(i < len){

        event = (struct inotify_event*)&buffer[i];
        if (event->len) {
            event_name = strdup(event->name);
            if(event->mask & IN_ACCESS){
                
                inf_insert(head, event_name, ACCESS);
                printf("File accessed: %s\n", event_name);
            }
            if(event->mask & IN_CREATE){
                inf_insert(head, event_name, CREATE);
                printf("File created: %s\n", event_name);  
            }
                                
            if (event->mask & IN_MODIFY){
                inf_insert(head, event_name, MODIFY);
                printf("File modified: %s\n", event_name); 
            }               
            if(event->mask & IN_DELETE){
                inf_insert(head, event_name, DELETE);
                printf("File deleted: %s\n", event_name);
            }
            
        }
        search_events();

        i += sizeof(struct inotify_event) + event->len;

    }

}

void monitor_dir(char* base_path){

    int fd, wd;
    char buf;

    fd = inotify_init();
    if(fd == -1){
        fprintf(stderr, "inotify_init failed\n");
        exit(EXIT_FAILURE);
    }

    wd = inotify_add_watch(fd, base_path, IN_ACCESS | IN_CREATE | IN_MODIFY | IN_DELETE);
    if(wd == -1){
        fprintf(stderr, "inotify_add_watch failed\n");
        exit(EXIT_FAILURE);
    }

    int poll_num;
    struct pollfd fds[2];
    nfds_t nfds;

    nfds = 2;
    fds[0].fd = STDIN_FILENO;
    fds[0].events = POLLIN;

    fds[1].fd = fd;
    fds[1].events = POLLIN;

    printf("Press enter to stop.\n\n");
    while(1){ 

        poll_num = poll(fds, nfds, -1);
        if(poll_num == -1){
            fprintf(stderr, "poll failed\n");
            exit(EXIT_FAILURE);
        }

        if(poll_num == 0)
            continue;

        if(fds[0].revents & POLLIN){
            
            while(read(STDIN_FILENO, &buf, 1) > 0 && buf != '\n')
                continue;
            break;

        }

        if(fds[1].revents & POLLIN){
            
            handle_events(fd, wd);

        }

    }
    printf("Listening for events stopped.\n\n");

    printf("Original list:\n");
    inf_print(head);

    inotify_rm_watch(fd, wd);
    close(fd);

}





/* Function 4 (./antivirus slice <number>) */

int f(int x, int a0, int a1, int a2){

    return a2*(int)pow((double)x, 2.0) + a1*x + a0;

}

void slice_key(int key){

    int x, f_x;
    int a1, a2;
    srand(time);
    a1 = rand() % 100;
    a2 = rand() % 100;

    for(int i = 1; i < 11; i++){
        f_x = f(i, key, a1, a2);
        printf("(%d, %d)\n", i, f_x);
    }
    
    printf("\n");

}





/* Function 4 (./antivirus unlock <pair1> <pair2> <pair3>) */

double find_det(double mat[3][3]){

    double det;
    det = mat[0][0] * (mat[1][1] * mat[2][2] - mat[2][1] * mat[1][2])
          - mat[0][1] * (mat[1][0] * mat[2][2] - mat[1][2] * mat[2][0])
          + mat[0][2] * (mat[1][0] * mat[2][1] - mat[1][1] * mat[2][0]);

    return det;

}

void unlock_file(char* pair1, char* pair2, char* pair3){

    int x1, x2, x3;
    int f_x1, f_x2, f_x3;
    int len;
    char* temp;

    temp = strtok(pair1, " ");
    len = strlen(temp);
    temp[len - 1] = '\0';
    temp++;
    x1 = atoi(temp);
    f_x1 = atoi(strtok(NULL, ")"));

    temp = strtok(pair2, " ");
    len = strlen(temp);
    temp[len - 1] = '\0';
    temp++;
    x2 = atoi(temp);
    f_x2 = atoi(strtok(NULL, ")"));

    temp = strtok(pair3, " ");
    len = strlen(temp);
    temp[len - 1] = '\0';
    temp++;
    x3 = atoi(temp);
    f_x3 = atoi(strtok(NULL, ")"));

    double D[3][3] = { pow((double)x1, 2.0), (double)x1, 1.0,
                       pow((double)x2, 2.0), (double)x2, 1.0,
                       pow((double)x3, 2.0), (double)x3, 1.0 };

    double D1[3][3] = { (double)f_x1, (double)x1, 1.0,
                        (double)f_x2, (double)x2, 1.0,
                        (double)f_x3, (double)x3, 1.0 };

    double D2[3][3] = { pow((double)x1, 2.0), (double)f_x1, 1.0,
                        pow((double)x2, 2.0), (double)f_x2, 1.0,
                        pow((double)x3, 2.0), (double)f_x3, 1.0 };

    double D3[3][3] = { pow((double)x1, 2.0), (double)x1, (double)f_x1,
                        pow((double)x2, 2.0), (double)x2, (double)f_x2,
                        pow((double)x3, 2.0), (double)x3, (double)f_x3 };

    double d = find_det(D);
    double d1 = find_det(D1);
    double d2 = find_det(D2);
    double d3 = find_det(D3);

    if(D != 0){

        double a2 = d1 / d;
        double a1 = d2 / d;
        double a0 = d3 / d;

        print_info("Computed that ");
        printf("a = %d and b = %d\n", (int)a2, (int)a1);
        print_info("Encryption key is: ");
        printf("\033[0;34m%d\033[0m\n", (int)a0);

    }

}





/* Helping Functions */

void print_info(char* message){

    time_t mytime;
    char* curr_time;

    printf("[INFO] [9046] [");
    mytime = time(NULL);
    curr_time = ctime(&mytime);
    for(int i = 0; i < strlen(curr_time) - 1; i++){
        printf("%c", curr_time[i]);
    }
    printf("] %s", message);

}

void search_files(char* base_path){

    char path[_MAX_LINE_];
    struct dirent* dp;
    DIR* dir = opendir(base_path);

    if(!dir)
        return;

    while((dp = readdir(dir)) != NULL){
        if(strcmp(dp->d_name, ".") != 0 && strcmp(dp->d_name, "..") != 0){

            strcpy(path, base_path);
            strcat(path, "/");
            strcat(path, dp->d_name);

            if(dp->d_type == DT_REG)
                files++;

            search_files(path);

        }
    }

    closedir(dir);

}

/* Main Function */

int main(int argc, char* argv[]){

    if(argc < 3){
        fprintf(stderr, "Usage: <executable> <opCode> <dirname>\n");
        exit(EXIT_FAILURE);
    }

    if(!strcmp(argv[1], "scan")){

        print_info("Application Started\n");
        print_info("Scanning Directory\n");
        printf("%s\n", argv[2]);
        print_info("Found ");
        files = 0;
        search_files(argv[2]);
        printf("%d regular files\n", files);

        print_info("Searching...\n\n");
        processed = 0;
        infected = 0;
        scan_dir(argv[2]);
        printf("\n");
        print_info("Operation Finished\n");

        print_info("Processed ");
        printf("%d regular files. \033[0;31mFound %d infected\033[0m\n", processed, infected);
        printf("\n");

    }else if(!strcmp(argv[1], "inspect")){

        print_info("Application Started\n");
        print_info("Scanning Directory\n");
        printf("%s\n", argv[2]);
        print_info("Found ");
        files = 0;
        search_files(argv[2]);
        printf("%d regular files\n", files);
        print_info("Searching...\n\n");

        processed = 0;
        inspect_dir(argv[2]);

        printf("\n");
        print_info("Operation Finished\n");
        print_info("Processed ");
        printf("%d regular files\n", processed);
        printf("\n");

    }else if(!strcmp(argv[1], "monitor")){

        head = inf_new();

        print_info("Application Started\n");
        print_info("Monitoring Directory ");
        printf("%s\n", argv[2]);
        print_info("Waiting for events...\n");
        printf("\n");

        monitor_dir(argv[2]);

    }else if(!strcmp(argv[1], "slice")){

        int key = atoi(argv[2]);

        print_info("Application Started\n");
        print_info("Generating shares for key ");
        printf("'%d'\n\n", key);

        slice_key(key);

    }else if(!strcmp(argv[1], "unlock")){

        int no_pairs = argc - 2;
        char* pair1, pair2, pair3;

        if(no_pairs < 3){
            fprintf(stderr, "You need at least 3 pairs to unlock the file\n");
            exit(EXIT_FAILURE);
        }

        print_info("Application Started\n");
        print_info("Received ");
        printf("%d different shares\n", no_pairs);

        unlock_file(argv[2], argv[3], argv[4]);


    }else{
        fprintf(stderr, "Wrong opCode. Terminating...\n");
        exit(EXIT_FAILURE);
    }

    exit(EXIT_SUCCESS);

}