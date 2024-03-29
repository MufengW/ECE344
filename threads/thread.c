#include <assert.h>
#include <stdlib.h>
#include <ucontext.h>
#include "thread.h"
#include "interrupt.h"
#include <stdbool.h>

#define State int

enum state {
    EMPTY,
    READY,
    RUNNING,
    BLOCKED,
    EXITED
};

enum state state_list[THREAD_MAX_THREADS];
Tid parent_list[THREAD_MAX_THREADS];
int active_thread_count = 0;

/* This is the thread control block */
struct thread {
    /* ... Fill this in ... */
    Tid tid;
    void* stack_ptr;
    bool holding_lock;
    ucontext_t context;
};

struct thread_node {
    struct thread *node;
    struct thread_node *next;
};

/* This is the wait queue structure */
struct wait_queue {
    /* ... Fill this in Lab 3 ... */
    struct thread_node *head;
} wait_queue;

typedef struct wait_queue thread_queue;

struct wait_queue *wait_list[THREAD_MAX_THREADS];

struct thread *current_thread;
thread_queue *ready_queue;
thread_queue *exit_queue;

void global_list_init() {
    Tid tid = 0;
    for(tid = 0; tid < THREAD_MAX_THREADS; ++tid) {
        state_list[tid] = EMPTY;
        wait_list[tid] = wait_queue_create();
        parent_list[tid] = THREAD_NONE;

    }
}
void set_current_thread(struct thread *t)
{
    current_thread = t;
}

void push_to_end(thread_queue *queue, struct thread *t)
{
    struct thread_node *tmp_thread_node = (struct thread_node *)malloc(sizeof(struct thread_node));
    tmp_thread_node->node = t;
    tmp_thread_node->next = NULL;

    if(queue->head == NULL) {
        queue->head = tmp_thread_node;
        return;
    }

    struct thread_node *tmp = queue->head;

    while(tmp->next != NULL) {
        tmp = tmp->next;
    }
    tmp->next = tmp_thread_node;
}

struct thread *delete_node(thread_queue *queue, Tid tid_to_delete)
{
    if(queue->head == NULL) {
        return NULL;
    }
    struct thread_node *node_to_delete = NULL;

    struct thread *ret = NULL;

    if(queue->head->node->tid == tid_to_delete) {
        node_to_delete = queue->head;
        queue->head = queue->head->next;
        node_to_delete->next = NULL;
        ret = node_to_delete->node;
        free(node_to_delete);
        return ret;
    }
    struct thread_node *tmp = queue->head;

    while(tmp->next != NULL) {
        if(tmp->next->node->tid != tid_to_delete) tmp = tmp->next;
        else {
            // found
            struct thread_node *node_to_delete = tmp->next;
            tmp->next = tmp->next->next;
            node_to_delete->next = NULL;
            ret = node_to_delete->node;
            free(node_to_delete);
            return ret;
        }
    } return NULL;

}

void thread_destroy(struct thread *t) {
    Tid tid = t->tid;
    assert(t != NULL);
    parent_list[tid] = THREAD_NONE;
    state_list[tid] = EMPTY;
    free(t->stack_ptr);
    free(t);
}

void
thread_init(void)
{
    /* your optional code here */
    ready_queue = (thread_queue *)malloc(sizeof(thread_queue));
    exit_queue = (thread_queue *)malloc(sizeof(thread_queue));
    global_list_init();
    struct thread *thread0 = (struct thread*)malloc(sizeof(struct thread));    // kernel thread
    thread0->tid = 0;
    thread0->holding_lock = false;
    thread0->stack_ptr = malloc(THREAD_MIN_STACK);
    state_list[0] = RUNNING;
    ++active_thread_count;
    set_current_thread(thread0);
}

Tid
thread_id()
{
    return current_thread->tid;
}

void
thread_stub(void (*thread_main)(void *), void *arg)
{
    interrupts_on();
    thread_main(arg);
    thread_exit();
}

Tid
thread_create(void (*fn) (void *), void *parg)
{
    int enabled = interrupts_off();
    Tid thread_id;
    for (thread_id = 0; thread_id < THREAD_MAX_THREADS; ++thread_id){
        if(state_list[thread_id] == EXITED) {
            thread_kill(thread_id);
        }
    }
    for (thread_id = 0; thread_id < THREAD_MAX_THREADS; ++thread_id){
        if(state_list[thread_id] == EMPTY) {
            // found empty slot
            struct thread *new_thread = (struct thread *)malloc(sizeof(struct thread));
            if(new_thread == NULL) {
                interrupts_set(enabled);
                return THREAD_NOMEMORY;
            }
            new_thread->tid = thread_id;
            new_thread->holding_lock = false;
            void *stack_pointer = malloc(THREAD_MIN_STACK);
            if(stack_pointer == NULL) {
                free(new_thread);
                interrupts_set(enabled);
                return THREAD_NOMEMORY;
            }
            int err = getcontext(&(new_thread->context));
            assert(!err);

            state_list[thread_id] = READY;
            ++active_thread_count;
            new_thread->stack_ptr = stack_pointer;
            new_thread->context.uc_stack.ss_sp = stack_pointer;
            new_thread->context.uc_mcontext.gregs[REG_RSP] = (long long int)stack_pointer + THREAD_MIN_STACK - 8;
            new_thread->context.uc_mcontext.gregs[REG_RIP] = (long long int)&thread_stub;
            new_thread->context.uc_mcontext.gregs[REG_RDI] = (long long int)fn;
            new_thread->context.uc_mcontext.gregs[REG_RSI] = (long long int)parg;

            push_to_end(ready_queue, new_thread);
            interrupts_set(enabled);
            return thread_id;
        }
    }
    interrupts_set(enabled);
    return THREAD_NOMORE;
}

Tid
thread_yield(Tid want_tid)
{
    int enabled = interrupts_off();
    int current_tid = thread_id();
    struct thread_node *tmp;
    for(tmp = exit_queue->head; tmp != NULL && tmp->next != NULL; tmp = tmp->next) {
        if(tmp->node->tid != current_tid) {
            thread_kill(tmp->node->tid);
        }
    }
    if(want_tid < THREAD_SELF || want_tid > THREAD_MAX_THREADS) {
        interrupts_set(enabled);
        return THREAD_INVALID;
    }
    if(want_tid == THREAD_SELF || want_tid == current_tid) {
        interrupts_set(enabled);
        return current_tid;
    }
    if(want_tid == THREAD_ANY) {
        if(ready_queue->head == NULL) {
            // ready queue empty
            interrupts_set(enabled);
            return THREAD_NONE;
        }
        want_tid = ready_queue->head->node->tid;
    }
    if(state_list[want_tid] == EMPTY) {
        interrupts_set(enabled);
        return THREAD_INVALID;
    }
    volatile bool context_is_called = false;
    int err;
    err = getcontext(&(current_thread->context));
    assert(!err);
    if(!context_is_called) {
        context_is_called = true;
        struct thread *new_thread = delete_node(ready_queue, want_tid);
        if(new_thread == NULL) {
            interrupts_set(enabled);
            return THREAD_INVALID;
        }
        if(state_list[current_tid] == RUNNING) {
            state_list[current_tid] = READY;
            push_to_end(ready_queue, current_thread);
        }
        set_current_thread(new_thread);
        state_list[want_tid] = RUNNING;
        err = setcontext(&(current_thread->context));
        assert(!err);
    }
    interrupts_set(enabled);
    return want_tid;
}

void
thread_exit()
{
    int enabled = interrupts_off();
    if(active_thread_count == 1) {
        interrupts_set(enabled);
        exit(0);
    }
    Tid tid = thread_id();
    --active_thread_count;
    state_list[tid] = EXITED;
    push_to_end(exit_queue, current_thread);

    thread_wakeup(wait_list[tid], 1);
    thread_yield(THREAD_ANY);
    interrupts_set(enabled);
    return;
}

Tid
thread_kill(Tid tid)
{
    int enabled = interrupts_off();
    if(tid <= THREAD_ANY || tid >= THREAD_MAX_THREADS) {
        interrupts_set(enabled);
        return THREAD_INVALID;
    }

    enum state thread_state = state_list[tid];
    thread_queue *queue = NULL;
    switch(thread_state) {
        case RUNNING:
        case EMPTY: {
            interrupts_set(enabled);
            return THREAD_INVALID;
        }
        case BLOCKED: {
            --active_thread_count;
            queue = wait_list[parent_list[tid]];
            break;
        }
        case READY: {
            --active_thread_count;
        queue = ready_queue;
            break;
        }
        case EXITED: {
            queue = exit_queue;
            break;
        }
        default:
            break;
    }
    struct thread *thread_to_kill = delete_node(queue, tid);
    thread_destroy(thread_to_kill);
    interrupts_set(enabled);
    return tid;
}

/*******************************************************************
 * Important: The rest of the code should be implemented in Lab 3. *
 *******************************************************************/

/* make sure to fill the wait_queue structure defined above */
struct wait_queue *
wait_queue_create()
{
    struct wait_queue *wq;

    wq = (struct wait_queue *)malloc(sizeof(struct wait_queue));
    assert(wq);

    return wq;
}

void
wait_queue_destroy(struct wait_queue *wq)
{
    if(wq == NULL) {
        return;
    }
    struct thread_node *tmp_node = wq->head;
    while(tmp_node != NULL) {
        struct thread_node *next_node = tmp_node->next;
        thread_destroy(tmp_node->node);
        tmp_node->next = NULL;
        free(tmp_node);
        tmp_node = next_node;
    }
    free(wq);
}

Tid
thread_sleep(struct wait_queue *queue)
{
    int enabled = interrupts_off();
    if(queue == NULL) {
        interrupts_set(enabled);
        return THREAD_INVALID;
    }
    if(active_thread_count == 1) {
        interrupts_set(enabled);
        return THREAD_NONE;
    }
    Tid current_tid = thread_id();
    state_list[current_tid] = BLOCKED;
    push_to_end(queue, current_thread);
    interrupts_set(enabled);
    Tid ret = thread_yield(THREAD_ANY);
    if(ret != THREAD_INVALID) {
        return ret;
    }
    exit(0);
}

/* when the 'all' parameter is 1, wakeup all threads waiting in the queue.
 * returns whether a thread was woken up on not. */
int
thread_wakeup(struct wait_queue *queue, int all)
{
    int enabled = interrupts_off();
    int ret = 0;
    if(queue == NULL) {
        interrupts_set(enabled);
        return ret;
    }
    if(queue->head == NULL) {
        interrupts_set(enabled);
        return ret;
    }
    Tid head_tid = queue->head->node->tid;
    if(!all) {
        struct thread *thread_to_wakeup = delete_node(queue,head_tid);
        state_list[head_tid] = READY;
        parent_list[head_tid] = THREAD_NONE;
        push_to_end(ready_queue, thread_to_wakeup);
        interrupts_set(enabled);
        return 1;
    } else{
        while(thread_wakeup(queue,0)) {
            ++ret;
        }
        interrupts_set(enabled);
        return ret;
    }
}

/* suspend current thread until Thread tid exits */
Tid
thread_wait(Tid tid)
{
    int enabled = interrupts_off();
    Tid current_tid = thread_id();
    if(tid <= THREAD_SELF || tid >= THREAD_MAX_THREADS) {
        interrupts_set(enabled);
        return THREAD_INVALID;
    }
    if(state_list[tid] != READY && state_list[tid] != BLOCKED) {
        interrupts_set(enabled);
        return THREAD_INVALID;
    }
    parent_list[current_tid] = tid;
    thread_sleep(wait_list[tid]);
    interrupts_set(enabled);
    return tid;
}

struct lock {
    /* ... Fill this in ... */
    struct wait_queue *queue;
    bool in_use;
};

struct lock *
lock_create()
{
    struct lock *lock;

    lock = malloc(sizeof(struct lock));
    assert(lock);

    lock->queue = wait_queue_create();
    lock->in_use = false;

    return lock;
}

void
lock_destroy(struct lock *lock)
{
    assert(lock != NULL);

    wait_queue_destroy(lock->queue);
    free(lock);
}

void
lock_acquire(struct lock *lock)
{
    assert(lock != NULL);

    interrupts_off();

    if(current_thread->holding_lock) {
        interrupts_on();
        return;
    }

    while(lock->in_use) {
        thread_sleep(lock->queue);
    }

    lock->in_use = true;
    current_thread->holding_lock = true;

    interrupts_on();
}

void
lock_release(struct lock *lock)
{
    assert(lock != NULL);

    interrupts_off();

    if(!current_thread->holding_lock) {
        interrupts_on();
        return;
    }

    lock->in_use = false;
    current_thread->holding_lock = false;
    thread_wakeup(lock->queue, 1);

    interrupts_on();
}

struct cv {
    /* ... Fill this in ... */
    struct wait_queue *queue;
};

struct cv *
cv_create()
{
    struct cv *cv;

    cv = malloc(sizeof(struct cv));
    assert(cv);

    cv->queue = wait_queue_create();
    return cv;
}

void
cv_destroy(struct cv *cv)
{
    assert(cv != NULL);

    wait_queue_destroy(cv->queue);
    free(cv);
}

void
cv_wait(struct cv *cv, struct lock *lock)
{
    assert(cv != NULL);
    assert(lock != NULL);

    lock_release(lock);
    thread_sleep(cv->queue);
    lock_acquire(lock);
}

void
cv_signal(struct cv *cv, struct lock *lock)
{
    assert(cv != NULL);
    assert(lock != NULL);

    lock_acquire(lock);
    thread_wakeup(cv->queue, 0);
    lock_release(lock);
}

void
cv_broadcast(struct cv *cv, struct lock *lock)
{
    assert(cv != NULL);
    assert(lock != NULL);

    lock_acquire(lock);
    thread_wakeup(cv->queue, 1);
    lock_release(lock);
}
