#include "request.h"
#include "server_thread.h"
#include "common.h"
#include <stdbool.h>

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
    int current_size;
};

struct node {
    struct file_data *data;
    int request_count;
};

pthread_mutex_t queue_lock = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t cache_lock = PTHREAD_MUTEX_INITIALIZER;
pthread_cond_t full = PTHREAD_COND_INITIALIZER;
pthread_cond_t empty = PTHREAD_COND_INITIALIZER;
int buf_write_idx = 0;
int buf_read_idx = 0;
int buff_request_count = 0;
int max_request_count = 0;

/* static functions */
void request_main_loop();
void update_request_count();
void increment();
void server_destory(struct server *sv);
void cache_destroy_all(struct server *sv);
void thread_destroy_all(struct server *sv);
struct cache *cache_init(int max_cache_size);
void cache_add(struct file_data *data, struct node *entry);
struct file_data *copy_file_data(struct file_data *data);
void cache_free(struct node *entry);
bool cache_lookup(struct server *sv, struct file_data *data);
void cache_insert(struct server *sv, struct file_data *data);
void cache_evict(struct server *sv, int amount_to_evict);
unsigned long get_key(char *file_name);


bool cache_lookup(struct server *sv, struct file_data *data) {
    char *name = data->file_name;
    unsigned long key = get_key(name);
    int hash_idx = key %sv->max_cache_size;
    int counter = 0;
    while(counter < sv->max_cache_size) {
        if(sv->cache->entry[hash_idx] == NULL ||
                strcmp(sv->cache->entry[hash_idx]->data->file_name, name) != 0) {
            hash_idx = (hash_idx + 1) % sv->max_cache_size;
            ++counter;
            continue;
        }
        struct file_data *found_data = sv->cache->entry[hash_idx]->data;
        data->file_buf = Malloc(found_data->file_size);
        memcpy(data->file_buf, found_data->file_buf, found_data->file_size);
        data->file_size = found_data->file_size;
        ++sv->cache->entry[hash_idx]->request_count;
        if(max_request_count < sv->cache->entry[hash_idx]->request_count) {
        max_request_count = sv->cache->entry[hash_idx]->request_count;
    }
        return true;
    }
    return false;
}

void cache_insert(struct server *sv, struct file_data *data) {
    if(sv->cache->current_size == sv->max_cache_size) {
        cache_evict(sv, sv->max_cache_size / 5);
    }
    char *name = data->file_name;
    unsigned long key = get_key(name);
    int hash_idx = key % sv->max_cache_size;
    while(sv->cache->entry[hash_idx] != NULL) {
        hash_idx = (hash_idx + 1) % sv->max_cache_size;
    }
    sv->cache->entry[hash_idx] = (struct node *)Malloc(sizeof(struct node));
    memset(sv->cache->entry[hash_idx], 0, sizeof(struct node));
    cache_add(data, sv->cache->entry[hash_idx]);
    ++(sv->cache->current_size);
    return;
}

void cache_add(struct file_data *data, struct node *entry) {
    entry->data = Malloc(sizeof(struct file_data));
    memset(entry->data, 0, sizeof(struct file_data));

    entry->data = copy_file_data(data);
    entry->request_count = 0;
}

struct file_data *copy_file_data(struct file_data *data) {
    struct file_data *new_data = Malloc(sizeof(struct file_data));
    memset(new_data, 0, sizeof(struct file_data));

    new_data->file_name = Malloc(strlen(data->file_name));
    memcpy(new_data->file_name, data->file_name, strlen(data->file_name));

    new_data->file_size = data->file_size;

    new_data->file_buf = Malloc(data->file_size);
    memset(new_data->file_buf, 0, data->file_size);
    memcpy(new_data->file_buf, data->file_buf, data->file_size);
    return new_data;
}

void cache_free(struct node *entry) {
    free(entry->data->file_name);
    entry->data->file_name = NULL;

    free(entry->data->file_buf);
    entry->data->file_buf = NULL;

    free(entry->data);
    entry->data = NULL;

    free(entry);
}

void cache_evict(struct server *sv, int amount_to_evict) {
    int evict_count = 0;
    for(int i = 0; i < sv->max_cache_size; ++i) {
//        if(evict_count < amount_to_evict &&
            if(sv->cache->entry[i] != NULL &&
	  (sv->cache->entry[i]->request_count < max_request_count/4 ||
	    sv->cache->entry[i]->request_count == 0)) {
            cache_free(sv->cache->entry[i]);
            sv->cache->entry[i] = NULL;
            //printf("data at %d evicted\n", i);
            ++evict_count;
            --(sv->cache->current_size);
        }
    }
    for(int i = 0; i < sv->max_cache_size; ++i) {
	    if(sv->cache->entry[i] != NULL) {
		    sv->cache->entry[i]->request_count = 0;
	    }
    }
    //printf("evict %d caches, now size is %d...\n\n", evict_count, sv->cache->current_size);
}

struct cache *cache_init(int max_cache_size) {
    struct cache *cache = (struct cache*) Malloc(sizeof(struct cache));
    memset(cache, 0, sizeof(struct cache));

    cache->entry = (struct node **)Malloc(sizeof(struct node *) * max_cache_size);
    memset(cache->entry, 0, sizeof(struct node *) * max_cache_size);
    for(int i = 0; i < max_cache_size; ++i) {
        cache->entry[i] = NULL;
//        cache->entry[i] = (struct node *)Malloc(sizeof(struct node));
//    memset(cache->entry[i], 0, sizeof(struct node));
    }
    cache->current_size = 0;
    max_request_count = 0;
    return cache;
}

unsigned long get_key(char *file_name) {
    unsigned long hash = 5381;
    int c;

    while((int)(c = *file_name++))
        hash = ((hash << 5) + hash) + c; // hash*33 + c
    return hash;
}

/* initialize file data */
static struct file_data *
file_data_init(void)
{
    struct file_data *data;

    data = Malloc(sizeof(struct file_data));
    data->file_name = NULL;
    data->file_buf = NULL;
    data->file_size = 0;
    return data;
}

/* free all file data */
static void
file_data_free(struct file_data *data)
{
    free(data->file_name);
    free(data->file_buf);
    free(data);
}

static void
do_server_request(struct server *sv, int connfd)
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
    pthread_mutex_lock(&cache_lock);
    if(sv->cache != NULL && cache_lookup(sv, data)) {
	    pthread_mutex_unlock(&cache_lock);
        // if found data in matcing the file name in cache then data is updated in rq->data
        //printf("found!\n");
        goto send;
    } else {
        // cache not found, need to request to read
        /* read file,
         * fills data->file_buf with the file contents,
         * data->file_size with file size. */
	pthread_mutex_unlock(&cache_lock);
	//printf("not found!\n");
        ret = request_readfile(rq);
        if (ret == 0) { /* couldn't read file */
            goto out;
        }
	pthread_mutex_lock(&cache_lock);
        if(sv->cache != NULL) cache_insert(sv, data);
	pthread_mutex_unlock(&cache_lock);
    }
    /* send file to client */
send:
    request_sendfile(rq);
out:
    request_destroy(rq);
    file_data_free(data);
}

/* entry point functions */

struct server *
server_init(int nr_threads, int max_requests, int max_cache_size)
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
        for(int i = 0; i < nr_threads; ++i) {
            sv->worker_threads[i] = (pthread_t *)malloc(sizeof(pthread_t));
            pthread_create(sv->worker_threads[i], NULL, (void *)&request_main_loop, sv);
        }
        if(max_cache_size > 0) sv->cache = cache_init(max_cache_size);
    }
    buf_write_idx = 0;
    buf_read_idx = 0;

    /* Lab 4: create queue of max_request size when max_requests > 0 */

    /* Lab 5: init server cache and limit its size to max_cache_size */

    /* Lab 4: create worker threads when nr_threads > 0 */

    return sv;
}

void update_request_count(int buf_size) {
    buff_request_count = (buf_write_idx - buf_read_idx + buf_size) % buf_size;
}

void increment(int *idx, int buf_size) {
    ++(*idx);
    *idx = (*idx) % buf_size;
    update_request_count(buf_size);
}

void thread_destroy_all(struct server *sv) {
    for(int i = 0; i < sv->nr_threads; ++i) {
        pthread_join(*sv->worker_threads[i], NULL);
    }
    free(sv->worker_threads);
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

void
server_request(struct server *sv, int connfd)
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

void cache_destroy_all(struct server *sv) {
    for(int i = 0; i < sv->max_cache_size; ++i) {
        if(sv->cache->entry[i] != NULL) {
		cache_free(sv->cache->entry[i]);
		sv->cache->entry[i] = NULL;
        }
    }
    free(sv->cache);
}

void server_destroy(struct server *sv) {
    thread_destroy_all(sv);
    cache_destroy_all(sv);

}

void
server_exit(struct server *sv)
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
