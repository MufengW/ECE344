#define _GNU_SOURCE
#include "request.h"
#include "server_thread.h"
#include "common.h"
#include <stdbool.h>
#include <limits.h>
#include <stdatomic.h>
struct server {
    int nr_threads;
    int max_requests;
    int max_cache_size;
    int exiting;
    /* add any other parameters you need */
    pthread_t **worker_threads;
    int *buf;
    struct cache *cache;
};

struct cache {
    struct node **entry;
};

struct node {
    struct file_data *data;
    struct node *next;
};

#define TABLE_SIZE 4999

int in_evict = 0;
atomic_int current_cache_size = 0;
int ref_count[TABLE_SIZE];
int request_count[TABLE_SIZE];
pthread_mutex_t queue_lock = PTHREAD_MUTEX_INITIALIZER;
pthread_cond_t full = PTHREAD_COND_INITIALIZER;
pthread_cond_t empty = PTHREAD_COND_INITIALIZER;
int buf_write_idx = 0;
int buf_read_idx = 0;
int buff_request_count = 0;

/* static functions */
struct cache *cache_init();
struct node *entry_init();

void request_main_loop();

void server_destroy(struct server *sv);
void cache_destroy_all(struct server *sv);
void thread_destroy_all(struct server *sv);

bool try_fill_data(struct server *sv, struct file_data *data);
struct node *cache_lookup(struct node *entry, char *name);
void cache_insert(struct server *sv, struct file_data *data);
void copy_data_to_entry(struct file_data *data, struct node *entry);
struct file_data *copy_file_data(struct file_data *data);
void cache_evict(struct server *sv, int next_size);
void clear_entry(struct node *entry);
void clear_node(struct node *entry);

unsigned long get_hash_key(char *file_name);
void update_request_count();
void increment();
static int atomic_add(int *val, int num);
static int atomic_sub(int *val, int num);

/* initialize file data */
static struct file_data *file_data_init(void)
{
    struct file_data *data;

    data = Malloc(sizeof(struct file_data));
    data->file_name = NULL;
    data->file_buf = NULL;
    data->file_size = 0;
    return data;
}

/* free all file data */
static void file_data_free(struct file_data *data)
{
    free(data->file_name);
    free(data->file_buf);
    free(data);
}

static void do_server_request(struct server *sv, int connfd)
{
    int ret;
    struct request *rq;
    struct file_data *data;

    data = file_data_init();

    /* fill data->file_name with name of the file being requested */
    rq = request_init(connfd, data);
    if (!rq) {
        file_data_free(data);
        return;
    }
    if(sv->max_cache_size == 0) goto read;
    if(try_fill_data(sv, data)) goto send;

read:
    ret = request_readfile(rq);
    if (ret == 0) { /* couldn't read file */
        goto out;
    }
    if(sv->max_cache_size != 0) cache_insert(sv, data);
send:
    /* send file to client */
    request_sendfile(rq);
out:
    request_destroy(rq);
    file_data_free(data);
}

/* entry point functions */

struct server *server_init(int nr_threads, int max_requests, int max_cache_size)
{
    struct server *sv;

    int buf_size = max_requests + 1;
    sv = Malloc(sizeof(struct server));
    sv->nr_threads = nr_threads;
    sv->max_requests = max_requests;
    sv->max_cache_size = max_cache_size;
    sv->exiting = 0;

    sv->buf = (int *)malloc(buf_size * sizeof(int));
    if (nr_threads > 0 || max_requests > 0 || max_cache_size > 0) {
        sv->worker_threads = (pthread_t **)malloc(nr_threads * sizeof(pthread_t *));
    if(max_cache_size > 0) sv->cache = cache_init(TABLE_SIZE);
        for(int i = 0; i < nr_threads; ++i) {
            sv->worker_threads[i] = (pthread_t *)malloc(sizeof(pthread_t));
            pthread_create(sv->worker_threads[i], NULL, (void *)&request_main_loop, sv);
        }
    }
    buf_write_idx = 0;
    buf_read_idx = 0;

    /* Lab 4: create queue of max_request size when max_requests > 0 */

    /* Lab 5: init server cache and limit its size to max_cache_size */

    /* Lab 4: create worker threads when nr_threads > 0 */

    return sv;
}

struct cache *cache_init() {
    struct cache *cache = (struct cache*) Malloc(sizeof(struct cache));
    memset(cache, 0, sizeof(struct cache));

    cache->entry = (struct node **)Malloc(sizeof(struct node *) * TABLE_SIZE);
    memset(cache->entry, 0, sizeof(struct node *) * TABLE_SIZE);
    for(int i = 0; i < TABLE_SIZE; ++i) {
        cache->entry[i] = entry_init();
        ref_count[i] = 0;
    }
    return cache;
}

struct node *entry_init() {
    struct node *new_node = (struct node *)Malloc(sizeof(struct node));
    memset(new_node, 0, sizeof(struct node));
    new_node->data = NULL;
    new_node->next = NULL;
    return new_node;
}

void request_main_loop(struct server *sv) {
    while(!sv->exiting) {
        pthread_mutex_lock(&queue_lock);
        while(buff_request_count == 0) {
            if(sv->exiting) {
                pthread_mutex_unlock(&queue_lock);
                return;
            }
            pthread_cond_wait(&empty, &queue_lock);
        }
        if(buff_request_count == sv->max_requests) {
            pthread_cond_broadcast(&full);
        }
        int connfd = sv->buf[buf_read_idx];
        increment(&buf_read_idx, sv->max_requests + 1);
        pthread_mutex_unlock(&queue_lock);
        do_server_request(sv, connfd);
    }
}

void server_request(struct server *sv, int connfd)
{
    if (sv->nr_threads == 0) { /* no worker threads */
        do_server_request(sv, connfd);
    } else {
        /*  Save the relevant info in a buffer and have one of the
         *  worker threads do the work. */
        pthread_mutex_lock(&queue_lock);
        while(buff_request_count == sv->max_requests){
            pthread_cond_wait(&full, &queue_lock);
        }

        sv->buf[buf_write_idx] = connfd;

        if(buff_request_count == 0){
            pthread_cond_broadcast(&empty);
        }

        increment(&buf_write_idx, sv->max_requests + 1);

        pthread_mutex_unlock(&queue_lock);
    }
}

void server_exit(struct server *sv)
{
    /* when using one or more worker threads, use sv->exiting to indicate to
     * these threads that the server is exiting. make sure to call
     * pthread_join in this function so that the main server thread waits
     * for all the worker threads to exit before exiting. */
    sv->exiting = 1;
    pthread_cond_broadcast(&empty);
    pthread_cond_broadcast(&full);

    server_destroy(sv);
    free(sv->buf);

    /* make sure to free any allocated resources */
    free(sv);
}

void server_destroy(struct server *sv) {
    thread_destroy_all(sv);
    if(sv->max_cache_size > 0) cache_destroy_all(sv);
}

void thread_destroy_all(struct server *sv) {
    for(int i = 0; i < sv->nr_threads; ++i) {
        pthread_join(*sv->worker_threads[i], NULL);
    }
    free(sv->worker_threads);
}

void cache_destroy_all(struct server *sv) {
    for(int i = 0; i < TABLE_SIZE; ++i) {
        struct node *tmp_entry = sv->cache->entry[i];
        if(tmp_entry->data != NULL) clear_entry(tmp_entry);
        free(tmp_entry);
    }
    free(sv->cache);
    sv->cache = NULL;
}

bool try_fill_data(struct server *sv, struct file_data *data) {
    char *name = data->file_name;
    unsigned long key = get_hash_key(name);
    int hash_idx = key % TABLE_SIZE;
    while(atomic_add(&ref_count[hash_idx], 1) != 0) {
        // someone else is working on this entry,
        //yield this thread and come back later
        atomic_sub(&ref_count[hash_idx], 1);
        pthread_yield();
    }

    // ref count = 1
    struct node *found_node = cache_lookup(sv->cache->entry[hash_idx], name);
    if(found_node == NULL) {
        //not found
        atomic_sub(&ref_count[hash_idx], 1);
        // ref count = 0
        return false;
    }

    //found
    struct file_data *found_data = found_node->data;
    data->file_buf = Malloc(found_data->file_size);
    memcpy(data->file_buf, found_data->file_buf, found_data->file_size);
    data->file_size = found_data->file_size;
    atomic_add(&request_count[hash_idx], 1);
    atomic_sub(&ref_count[hash_idx], 1);
    //ref count = 0
    return true;
}

struct node *cache_lookup(struct node *entry, char *name) {
    if(entry->data == NULL) return NULL;
    struct node *tmp = entry;
    while(tmp != NULL) {
        if(strcmp(tmp->data->file_name, name) == 0) {
            // found
            return tmp;
        }
        tmp = tmp->next;
    }
    return tmp;
}

void cache_insert(struct server *sv, struct file_data *data) {
    while(atomic_add(&in_evict, 1) != 0) {
        atomic_sub(&in_evict, 1);
        pthread_yield();
    }
    if(current_cache_size + data->file_size > sv->max_cache_size) {
        cache_evict(sv, data->file_size);
    }
    atomic_sub(&in_evict, 1);

    char *name = data->file_name;
    unsigned long key = get_hash_key(name);
    int hash_idx = key % TABLE_SIZE;
    while(atomic_add(&ref_count[hash_idx], 1) != 0) {
        atomic_sub(&ref_count[hash_idx], 1);
        pthread_yield();
    }

    // ref count = 1
    copy_data_to_entry(data, sv->cache->entry[hash_idx]);
    atomic_sub(&ref_count[hash_idx], 1);
}

void copy_data_to_entry(struct file_data *data, struct node *entry) {
    struct node *tmp_entry = entry;
    if(tmp_entry->data == NULL) goto fill_entry;
    while(tmp_entry != NULL) tmp_entry = tmp_entry->next;
    tmp_entry = entry_init();

fill_entry:
    tmp_entry->data = copy_file_data(data);
}

struct file_data *copy_file_data(struct file_data *data) {
    struct file_data *new_data = Malloc(sizeof(struct file_data));
    memset(new_data, 0, sizeof(struct file_data));

    new_data->file_name = Malloc(strlen(data->file_name) + 1);
    memset(new_data->file_name, 0, strlen(data->file_name) + 1);
    memcpy(new_data->file_name, data->file_name, strlen(data->file_name));

    new_data->file_size = data->file_size;

    new_data->file_buf = Malloc(data->file_size);
    memset(new_data->file_buf, 0, data->file_size);
    memcpy(new_data->file_buf, data->file_buf, data->file_size);
    current_cache_size += data->file_size;
    return new_data;
}

void cache_evict(struct server *sv, int next_size) {
    for(int i = 0; i < TABLE_SIZE; ++i) {
        if(atomic_add(&ref_count[i], 1) != 0) {
            atomic_sub(&ref_count[i], 1);
            continue;
        }
        struct node *tmp_entry = sv->cache->entry[i];
        if(tmp_entry->data != NULL && ref_count[i] <= 1) {
            clear_entry(tmp_entry);
            if(current_cache_size + next_size < sv->max_cache_size) {
                atomic_sub(&ref_count[i], 1);
                break;
            }
        }
        atomic_sub(&ref_count[i], 1);
    }
    memset(request_count, 0, TABLE_SIZE * sizeof(int));
}

void clear_entry(struct node *entry) {
    clear_node(entry);
    struct node *cur_entry = entry->next;
    struct node *next_entry = NULL;
    entry->next = NULL;
    while(cur_entry != NULL) {
        next_entry = cur_entry->next;
        clear_node(cur_entry);
        free(cur_entry);
        cur_entry = next_entry;
    }
}

void clear_node(struct node *entry) {
    int free_size = entry->data->file_size;
    free(entry->data->file_name);
    entry->data->file_name = NULL;

    free(entry->data->file_buf);
    entry->data->file_buf = NULL;

    free(entry->data);
    entry->data = NULL;
    current_cache_size -= free_size;
}

unsigned long get_hash_key(char *file_name) {
    unsigned long hash = 5381;
    int c;

    while((int)(c = *file_name++))
        hash = ((hash << 5) + hash) + c; // hash * 33 + c
    return hash;
}

void update_request_count(int buf_size) {
    buff_request_count = (buf_write_idx - buf_read_idx + buf_size) % buf_size;
}

void increment(int *idx, int buf_size) {
    ++(*idx);
    *idx = (*idx) % buf_size;
    update_request_count(buf_size);
}

static int atomic_add(int *val, int num) {
    return __atomic_fetch_add(val, num, __ATOMIC_SEQ_CST);
}

static int atomic_sub(int *val, int num) {
    return __atomic_fetch_sub(val, num, __ATOMIC_SEQ_CST);
}
