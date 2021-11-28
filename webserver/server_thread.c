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
pthread_mutex_t request_lock = PTHREAD_MUTEX_INITIALIZER;
pthread_cond_t full = PTHREAD_COND_INITIALIZER;
pthread_cond_t empty = PTHREAD_COND_INITIALIZER;
int buf_write_idx = 0;
int buf_read_idx = 0;
int request_count = 0;

/* static functions */
void request_main_loop();
void update_request_count();
void increment();
void server_destory(struct server *sv);
void cache_destroy_all(struct server *sv);
void thread_destroy_all(struct server *sv);
struct cache *cache_init(int max_cache_size);
bool cache_lookup(struct server *sv, struct file_data *data);
void cache_insert(struct server *sv, struct file_data *data);
void cache_evict(struct server *sv, int amount_to_evict);


bool cache_lookup(struct server *sv, struct file_data *data) {
    return false;
}

void cache_insert(struct server *sv, struct file_data *data) {
    pthread_mutex_lock(&request_lock);
    if(sv->cache->current_size == sv->max_cache_size) {
        cache_evict(sv, sv->max_cache_size / 3);
    }
    printf("now size is %d, insert data %s...\n\n", sv->cache->current_size, data->file_name);
    ++sv->cache->current_size;
    pthread_mutex_unlock(&request_lock);
    return;
}

void cache_evict(struct server *sv, int amount_to_evict) {
    sv->cache->current_size -= amount_to_evict;
    printf("ecivct %d caches, now size is %d...\n\n", amount_to_evict, sv->cache->current_size);
}

struct cache *cache_init(int max_cache_size) {
    struct cache *cache = (struct cache*) Malloc(sizeof(struct cache));
    memset(cache, 0, sizeof(struct cache));

    cache->entry = (struct node **)Malloc(sizeof(struct node *) * max_cache_size);
    memset(cache->entry, 0, sizeof(struct node *) * max_cache_size);
    for(int i = 0; i < max_cache_size; ++i) {
        cache->entry[i] = (struct node *)Malloc(sizeof(struct node));
        cache->entry[i]->data = (struct file_data *)Malloc(sizeof(struct file_data));
    }
    cache->current_size = 0;
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
    if(cache_lookup(sv, data)) {
        // if found data in matcing the file name in cache then data is updated in rq->data
        goto send;
    } else {
        // cache not found, need to request to read
        /* read file,
         * fills data->file_buf with the file contents,
         * data->file_size with file size. */
        ret = request_readfile(rq);
        if (ret == 0) { /* couldn't read file */
            goto out;
        }
        cache_insert(sv, data);
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
    request_count = 0;

    /* Lab 4: create queue of max_request size when max_requests > 0 */

    /* Lab 5: init server cache and limit its size to max_cache_size */

    /* Lab 4: create worker threads when nr_threads > 0 */

    return sv;
}

void update_request_count(int buf_size) {
    request_count = (buf_write_idx - buf_read_idx + buf_size) % buf_size;
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
        while(request_count == 0) {
            if(sv->exiting) {
                pthread_mutex_unlock(&queue_lock);
                return;
            }
            pthread_cond_wait(&empty, &queue_lock);
        }
        if(request_count == sv->max_requests) {
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
        while(request_count == sv->max_requests){
            pthread_cond_wait(&full, &queue_lock);
        }

        sv->buf[buf_write_idx] = connfd;

        if(request_count == 0){
            pthread_cond_broadcast(&empty);
        }

        increment(&buf_write_idx, sv->max_requests + 1);

        pthread_mutex_unlock(&queue_lock);
    }
}

void cache_destroy_all(struct server *sv) {
    for(int i = 0; i < sv->max_cache_size; ++i) {
        if(sv->cache->entry[i]->data != NULL) {
            free(sv->cache->entry[i]->data);
            free(sv->cache->entry[i]);
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
