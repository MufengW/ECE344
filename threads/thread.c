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

enum state state_list[THREAD_MAX_THREADS] = {EMPTY};
int active_thread_count = 0;

/* This is the thread control block */
struct thread {
    /* ... Fill this in ... */
    Tid tid;
    //State state;
    void* stack_ptr;
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

struct wait_queue *wait_list[THREAD_MAX_THREADS] = {NULL};

struct thread *current_thread;
thread_queue *ready_queue;
thread_queue *exit_queue;

void wait_list_init() {
	Tid tid = 0;
	for(tid = 0; tid < THREAD_MAX_THREADS; ++tid) {
		wait_list[tid] = wait_queue_create();
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
    struct thread *thread0 = (struct thread*)malloc(sizeof(struct thread));    // kernel thread
    thread0->tid = 0;
    thread0->stack_ptr = malloc(THREAD_MIN_STACK);
    state_list[0] = RUNNING;
    ++active_thread_count;
    set_current_thread(thread0);
    wait_list_init();
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
    int last_state = interrupts_off();
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
                interrupts_set(last_state);
                return THREAD_NOMEMORY;
            }
            new_thread->tid = thread_id;
            void *stack_pointer = malloc(THREAD_MIN_STACK);
            if(stack_pointer == NULL) {
                free(new_thread);
                interrupts_set(last_state);
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
            interrupts_set(last_state);
            return thread_id;
        }
    }
    interrupts_set(last_state);
    return THREAD_NOMORE;
}

Tid
thread_yield(Tid want_tid)
{
    int last_state = interrupts_off();
    int current_tid = thread_id();
    struct thread_node *tmp;
    for(tmp = exit_queue->head; tmp != NULL && tmp->next != NULL; tmp = tmp->next) {
        if(tmp->node->tid != current_tid) {
            thread_kill(tmp->node->tid);
        }
    }
    if(want_tid < THREAD_SELF || want_tid > THREAD_MAX_THREADS) {
        interrupts_set(last_state);
        return THREAD_INVALID;
    }
    if(want_tid == THREAD_SELF || want_tid == current_tid) {
        interrupts_set(last_state);
        return current_tid;
    }
    if(want_tid == THREAD_ANY) {
        if(ready_queue->head == NULL) {
            // ready queue empty
            interrupts_set(last_state);
            return THREAD_NONE;
        }
        want_tid = ready_queue->head->node->tid;
    }
    if(state_list[want_tid] == EMPTY) {
        interrupts_set(last_state);
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
            interrupts_set(last_state);
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
    interrupts_set(last_state);
    return want_tid;
}

void
thread_exit()
{
    int last_state = interrupts_off();
    if(active_thread_count == 1) {
        interrupts_set(last_state);
        exit(0);
    }
    Tid tid = thread_id();
    --active_thread_count;
    state_list[tid] = EXITED;
    push_to_end(exit_queue, current_thread);

    if(wait_list[tid] != NULL) {
        thread_wakeup(wait_list[tid], 1);
    }
    thread_yield(THREAD_ANY);
    interrupts_set(last_state);
    return;
}

Tid
thread_kill(Tid tid)
{
    int last_state = interrupts_off();
    if(tid <= THREAD_ANY || tid >= THREAD_MAX_THREADS) {
        interrupts_set(last_state);
        return THREAD_INVALID;
    }

    enum state thread_state = state_list[tid];
    switch(thread_state) {
        case RUNNING:
        case EMPTY: {
            interrupts_set(last_state);
            return THREAD_INVALID;
        }
        case BLOCKED:
            break;
        case READY:
            --active_thread_count;
        case EXITED: {
            struct thread *thread_to_kill = delete_node((thread_state == READY) ? ready_queue:exit_queue, tid);
            thread_destroy(thread_to_kill);
        interrupts_set(last_state);
            return tid;
        }
        default:
            break;
    }
    interrupts_set(last_state);
    return THREAD_FAILED;
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
        struct thread_node* next_node = tmp_node->next;
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
    return thread_yield(THREAD_ANY);
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
    if(tid <= THREAD_SELF || tid >= THREAD_MAX_THREADS) {
        interrupts_set(enabled);
        return THREAD_INVALID;
    }
    if(state_list[tid] != READY && state_list[tid] != BLOCKED) {
        interrupts_set(enabled);
        return THREAD_INVALID;
    }
    interrupts_set(enabled);
    return thread_sleep(wait_list[tid]);
}

struct lock {
    /* ... Fill this in ... */
};

struct lock *
lock_create()
{
    struct lock *lock;

    lock = malloc(sizeof(struct lock));
    assert(lock);

    TBD();

    return lock;
}

void
lock_destroy(struct lock *lock)
{
    assert(lock != NULL);

    TBD();

    free(lock);
}

void
lock_acquire(struct lock *lock)
{
    assert(lock != NULL);

    TBD();
}

void
lock_release(struct lock *lock)
{
    assert(lock != NULL);

    TBD();
}

struct cv {
    /* ... Fill this in ... */
};

struct cv *
cv_create()
{
    struct cv *cv;

    cv = malloc(sizeof(struct cv));
    assert(cv);

    TBD();

    return cv;
}

void
cv_destroy(struct cv *cv)
{
    assert(cv != NULL);

    TBD();

    free(cv);
}

void
cv_wait(struct cv *cv, struct lock *lock)
{
    assert(cv != NULL);
    assert(lock != NULL);

    TBD();
}

void
cv_signal(struct cv *cv, struct lock *lock)
{
    assert(cv != NULL);
    assert(lock != NULL);

    TBD();
}

void
cv_broadcast(struct cv *cv, struct lock *lock)
{
    assert(cv != NULL);
    assert(lock != NULL);

    TBD();
}
