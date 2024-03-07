#include "uthreads.h"
#include <iostream>
#include <setjmp.h>
#include <deque>
#include <signal.h>
#include <sys/time.h>
#include "algorithm"
#include "unordered_map"
#include "list"


enum ReturnValue {
    success = 0,
    failure = -1
};

enum ExitStatus {
    suc = 0,
    fail = 1
};

enum State {
    ready,
    running,
    blocked,
    terminated,
    sleeping,
    both
};

#ifdef __x86_64__

/* code for 64 bit Intel arch */

typedef unsigned long address_t;

#define JB_SP 6
#define JB_PC 7
#define MIC_SEC 1000000
#define MAIN_THREAD_ID 0

/* A translation is required when using an address of a variable.
   Use this as a black box in your code. */
address_t translate_address(address_t addr)
{
    address_t ret;
    asm volatile("xor    %%fs:0x30,%0\n"
                 "rol    $0x11,%0\n"
            : "=g" (ret)
            : "0" (addr));
    return ret;
}

#else
/* code for 32 bit Intel arch */

typedef unsigned int address_t;
#define JB_SP 4
#define JB_PC 5


/* A translation is required when using an address of a variable.
   Use this as a black box in your code. */
address_t translate_address(address_t addr)
{
    address_t ret;
    asm volatile("xor    %%gs:0x18,%0\n"
                 "rol    $0x9,%0\n"
            : "=g" (ret)
            : "0" (addr));
    return ret;
}


#endif

struct Thread {
    int ID = 0;
    sigjmp_buf env;
    State state = terminated;
    int quantum_counter = 0;
    int waking_quantum = 0;
    char *stack = nullptr;


    Thread(int tid, char *tstack, thread_entry_point entry_point)
    {
        ID = tid;
        stack = tstack;
        if (ID == MAIN_THREAD_ID)
        {
            state = State::running;
        }
        else {
            state = State::ready;
        }
        address_t sp = (address_t) stack + STACK_SIZE - sizeof (address_t);
        address_t pc = (address_t) entry_point;
        sigsetjmp (env, 1);
        (env->__jmpbuf)[JB_SP] = translate_address (sp);
        (env->__jmpbuf)[JB_PC] = translate_address (pc);
//        std::cout << tid << ": " << translate_address(sp) << " " << translate_address(pc) << std::endl;
        if (sigemptyset(&env->__saved_mask))
        {
            std::cerr << "system error: Blocking failure" << std::endl;
            exit (ExitStatus::fail);
        }
    }
};

int total_quantum_counter = 0;
int running_thread_ID = 0;
Thread *threads[MAX_THREAD_NUM];
std::deque<int> ready_threads_IDs;
std::unordered_map<int, std::list<int>> sleeping_threads_IDs;
int curr_quantum_usecs = 0;
int thread_counter = 0;
sigset_t maskedSet;
struct itimerval timer{};

bool block_signals() {
    return sigprocmask(SIG_BLOCK, &maskedSet, nullptr) == ReturnValue::success;
}

bool unblock_signals() {
    return sigprocmask(SIG_UNBLOCK, &maskedSet, nullptr) == ReturnValue::success;
}


void free_not_main_thread(int id) {
    if (id == 0) {
        exit(ExitStatus::fail);
    }
    if (threads[id]) {
        if (threads[id]->stack) {
            delete[] threads[id]->stack;
            threads[id]->stack = nullptr;
        }
        delete threads[id];
        threads[id] = nullptr;
    }
}

void free_all() {
    block_signals();
    for (int id = 1; id < MAX_THREAD_NUM; id++) {
        if (threads[id]) {
            if (threads[id]->stack) {
                delete[] threads[id]->stack;
                threads[id]->stack = nullptr;
            }
            delete threads[id];
            threads[id] = nullptr;
        }
    }
    unblock_signals();
}

void free_and_exit(const char *msg, ExitStatus exit_status) {
    free_all();
    unblock_signals();
    std::cerr << msg << std::endl;
    exit(exit_status);
}

void set_time() {
    timer.it_value.tv_sec = curr_quantum_usecs / MIC_SEC;
    timer.it_value.tv_usec = curr_quantum_usecs % MIC_SEC;
    timer.it_interval.tv_sec = 0;
    timer.it_interval.tv_usec = 0;
    if (setitimer(ITIMER_VIRTUAL, &timer, nullptr) == -1) {
        free_and_exit("System error: Timer reset failed", ExitStatus::fail);
    }
}

ReturnValue thread_library_error(const char *msg, ReturnValue returnValue) {
    std::cerr << msg << std::endl;
    return returnValue;
}

void wakeup() {
    if (sleeping_threads_IDs.empty() ||
    sleeping_threads_IDs.find(total_quantum_counter) == sleeping_threads_IDs.end()) {
        return;
    }
    for (auto i : sleeping_threads_IDs.at(total_quantum_counter)) {
        if (threads[i] == nullptr) {
            continue;
        }
        if (threads[i]->state == sleeping) {
            threads[i]->state = ready;
            ready_threads_IDs.push_back(i);
        }
        else if (threads[i]->state == both) {
            threads[i]->state = blocked;
        }
        threads[i]->waking_quantum = -1;
    }
    sleeping_threads_IDs.erase(total_quantum_counter);
}

void scheduler(bool blocked, bool terminated) {
    // block the SIGVTALRM signal
    if (!block_signals()) {
        free_and_exit("system error: Masking failure", ExitStatus::fail);
    }
    int ret_val = sigsetjmp(threads[running_thread_ID]->env, 1);
    if (ret_val != 0) {  // came from longjmp and not the alarm
        if (!unblock_signals()) {
            free_and_exit("system error: Masking failure", ExitStatus::fail);
        }
        return;
    }
    wakeup();
    if (terminated) {
        free_not_main_thread(running_thread_ID);
    }
    else if (blocked) {
        threads[running_thread_ID]->state = State::blocked;
    }
    else if (threads[running_thread_ID]->state == running) {
        threads[running_thread_ID]->state = State::ready;
        ready_threads_IDs.push_back(running_thread_ID);
    }

    if (!ready_threads_IDs.empty()) {
        // empty when no one is ready, when there is only main thread or the others are blocked
        running_thread_ID = ready_threads_IDs.front();
        ready_threads_IDs.pop_front();
    }

    threads[running_thread_ID]->state = running;
    threads[running_thread_ID]->quantum_counter ++;
    total_quantum_counter ++;
    // Unblock the SIGVTALRM signal
    if (!unblock_signals())
    {
        free_and_exit("system error: Masking failure", ExitStatus::fail);
    }
    set_time();
    siglongjmp(threads[running_thread_ID]->env, 1);
}

void sigvtalrm_handler(int signal)
{
    scheduler(false, false);
}


int uthread_init(int quantum_usecs) {
    if (quantum_usecs <= 0) {
        return thread_library_error("thread library error: quantum_usecs must get a positive integer",
                                    ReturnValue::failure);
    }
    curr_quantum_usecs = quantum_usecs;
    auto *new_thread = new (std::nothrow) Thread(0, nullptr, nullptr);
    if (new_thread == nullptr) {
        free_and_exit("system error: Memory allocation failed", ExitStatus::fail);
    }
    threads[0] = new_thread;
    thread_counter ++;
    total_quantum_counter++;
    threads[MAIN_THREAD_ID]->quantum_counter++;
    int ret_val = sigsetjmp(threads[MAIN_THREAD_ID]->env, 1);
    if (ret_val) {
        return ReturnValue::success;
    }
    // Set the SIGVTALRM signal handler to sigvtalrm_handler function
    struct sigaction sa = {0};
    sa.sa_handler = &sigvtalrm_handler;

    if (sigaction(SIGVTALRM, &sa, nullptr) < 0) {
        free_and_exit("system error: Masking failure", ExitStatus::fail);
    }
    set_time();
    // Mask the SIGVTALRM signal
    if (sigemptyset(&maskedSet)) {
        free_and_exit("system error: Masking failure", ExitStatus::fail);
    }
    if (sigaddset(&maskedSet, SIGVTALRM)) {
        free_and_exit("system error: Masking failure", ExitStatus::fail);
    }
    if (sigprocmask(SIG_SETMASK, &maskedSet, nullptr) == -1) {
        free_and_exit("system error: Masking failure", ExitStatus::fail);
    }
    // Unblock the SIGVTALRM signal
    if (!unblock_signals()) {
        free_and_exit("system error: Masking failure", ExitStatus::fail);
    }
    return ReturnValue::success;
}


int uthread_spawn(thread_entry_point entry_point) {
    // tries to block SIGVTALRM
    if (!block_signals()) {
        free_and_exit("system error: Masking failure", ExitStatus::fail);
    }
    // check for validity of the input
    if (entry_point == nullptr) {
        return thread_library_error("thread library error: entry_point cannot get a null, but a value of type "
                             "thread_entry_point.", ReturnValue::failure);
    }
    if (thread_counter == MAX_THREAD_NUM) {
        return thread_library_error("thread library error: the number of concurrent threads exceeds the limit",
                                    ReturnValue::failure);
    }
    // find the first available id which will be the id of the new thread
    int new_id = 0;
    for (int id = 1; id < MAX_THREAD_NUM; id++) {
        if (threads[id] == nullptr) {
            new_id = id;
            break;
        }
    }
    // create new stack for the new thread
    char *new_stack = new (std::nothrow) char [STACK_SIZE];
    if (new_stack == nullptr) {
        free_and_exit("system error: memory allocation failed.", ExitStatus::fail);
    }
    // initialize new thread and set it to the matching id in the threads array
    auto *new_thread = new (std::nothrow) Thread(new_id, new_stack, entry_point);
    if (new_thread == nullptr) {
        free_and_exit("system error: memory allocation failed", ExitStatus::fail);
    }
    threads[new_id] = new_thread;
    // increment the thread_counter
    thread_counter ++;
    // push the new id thread to the end of the ready queue
    ready_threads_IDs.push_back(new_id);
    if (!unblock_signals()) {
        free_and_exit("system error: Masking failure", ExitStatus::fail);
    }
    return new_id;
}


void remove_ready_ID(int id) {
    ready_threads_IDs.erase(std::remove(ready_threads_IDs.begin(),
                                      ready_threads_IDs.end(), id),
                            ready_threads_IDs.end());
}

void remove_sleeping_ID(int id) {
    sleeping_threads_IDs[threads[id]->waking_quantum].remove(id);
    if (sleeping_threads_IDs[threads[id]->waking_quantum].empty()) {
        sleeping_threads_IDs.erase(threads[id]->waking_quantum);
    }
}

int uthread_terminate(int tid) {
    if (!block_signals()) {
        free_and_exit("system error: Masking failure", ExitStatus::fail);
    }
    if (tid < 0 || tid >= MAX_THREAD_NUM) { // >= MAX
        return thread_library_error("thread library error: a tid can be only with the value 0 to MAX_THREAD_NUM",
                                    ReturnValue::failure);
    }
    if (threads[tid] == nullptr) { // >= MAX
        return thread_library_error("thread library error: The given thread id doesn't exist",
                                    ReturnValue::failure);
    }
    if (tid == 0) {
        free_all();
        exit(ExitStatus::suc);
    }
    
    thread_counter --;
    if (threads[tid]->state == ready) {
        remove_ready_ID(tid);
    } else if (threads[tid]->state == sleeping) {
        remove_sleeping_ID(tid);
    } else if (threads[tid]->state == running) {
        scheduler(false, true);
    }
    free_not_main_thread(tid);
    if (!unblock_signals()) {
        free_and_exit("system error: Masking failure", ExitStatus::fail);
    }
    return ReturnValue::success;
}

int uthread_block(int tid) {
    if (!block_signals()) {
        free_and_exit("system error: Masking failure", ExitStatus::fail);
    }
    if (tid < 0 || tid >= MAX_THREAD_NUM) {
        return thread_library_error("thread library error: A thread id can be only with the value 0 to MAX_THREAD_NUM",
                             ReturnValue::failure);
    }
    if (threads[tid] == nullptr) {
        return thread_library_error("thread library error: The given thread id doesn't exist",
                             ReturnValue::failure);
    }
    if (threads[tid] == nullptr) {
        return thread_library_error("thread library error: The given thread id doesn't hold any active thread",
                             ReturnValue::failure);
    }
    if (tid == 0) {
        thread_library_error("thread library error: The main thread cannot be blocked",
                             ReturnValue::failure);
        if (!unblock_signals()) {
            free_and_exit("system error: Masking failure", ExitStatus::fail);
        }
        return ReturnValue::failure;
    }

    if (threads[tid]->state == sleeping) {
        threads[tid]->state = both;
    }
    if (threads[tid]->state == ready) {
        threads[tid]->state = blocked;
        remove_ready_ID(tid);
    }
    if (threads[tid]->state == running) {  // if sleeping then this condition is false
        if (!unblock_signals()) {
            free_and_exit("system error: Masking failure", ExitStatus::fail);
        }
        scheduler(true, false);
    }

    if (!unblock_signals()) {
        free_and_exit("system error: Masking failure", ExitStatus::fail);
    }
    return ReturnValue::success;
}

int uthread_resume(int tid) {
    if (!block_signals()) {
        free_and_exit("system error: Masking failure", ExitStatus::fail);
    }
    if (tid < 0 || tid >= MAX_THREAD_NUM) {
        return thread_library_error("thread library error: a tid can be only with the value 0 to MAX_THREAD_NUM",
                             ReturnValue::failure);
    }
    if (threads[tid] == nullptr) {
        return thread_library_error("thread library error: The given thread id doesn't exist",
                                    ReturnValue::failure);
    }
    if (threads[tid]->state == blocked) {
        threads[tid]->state = ready;
        ready_threads_IDs.push_back(tid);
    }
    if (threads[tid]->state == both){
        threads[tid]->state = sleeping;
    }
    if (!unblock_signals()) {
        free_and_exit("system error: Masking failure", ExitStatus::fail);
    }
    return ReturnValue::success;
}

int uthread_sleep(int num_quantums) {
    if (!block_signals()) {
        free_and_exit("system error: Masking failure", ExitStatus::fail);
    }
    if (running_thread_ID == 0) {
        return thread_library_error("thread library error: The main thread cannot sleep",
                                    ReturnValue::failure);
    }
    if (num_quantums <= 0) {
        return thread_library_error("thread library error: Invalid quantum value", ReturnValue::failure);
    }
    threads[running_thread_ID]->state = sleeping;
    threads[running_thread_ID]->waking_quantum = num_quantums + total_quantum_counter;
    sleeping_threads_IDs[num_quantums + total_quantum_counter].push_back(running_thread_ID);
    if (!unblock_signals()) {
        free_and_exit("system error: Masking failure", ExitStatus::fail);
    }
    scheduler(false, false);
    return ReturnValue::success;
}

int uthread_get_tid() {
    if (!block_signals()) {
        free_and_exit("system error: Masking failure", ExitStatus::fail);
    }
    int ret_val =  running_thread_ID;
    if (!unblock_signals()) {
        free_and_exit("system error: Masking failure", ExitStatus::fail);
    }
    return ret_val;
}

int uthread_get_total_quantums() {
    if (!block_signals()) {
        free_and_exit("system error: Masking failure", ExitStatus::fail);
    }
    int ret_val = total_quantum_counter;
    if (!unblock_signals()) {
        free_and_exit("system error: Masking failure", ExitStatus::fail);
    }
    return ret_val;
}

int uthread_get_quantums(int tid) {
    if (!block_signals()) {
        free_and_exit("system error: Masking failure", ExitStatus::fail);
    }

    if (tid < 0 || tid >= MAX_THREAD_NUM) { // >= MAX
        return thread_library_error("thread library error: a tid can be only with the value o to MAX_THREAD_NUM",
                                    ReturnValue::failure);
    }
    if (threads[tid] == nullptr) {
        return thread_library_error("thread library error: The given thread id doesn't exist",
                                    ReturnValue::failure);
    }
    if (!unblock_signals()) {
        free_and_exit("system error: Masking failure", ExitStatus::fail);
    }
    return threads[tid]->quantum_counter;
}
