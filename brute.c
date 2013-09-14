#include <stdio.h>
#define __USE_GNU
#include <crypt.h>
#include <stdbool.h>
#include <unistd.h>
#include <string.h>
#include <semaphore.h>
#include <pthread.h>

#define ALPH3 "abc"
#define ALPH4 "csit"
#define ALPH15 "abcdefghijklmno"
#define ALPH26 "abcdefghijklmnopqrstuvwxyz"

#define ALPH ALPH26
#define PSWD_LEN 4
#define QUEUE_LENGTH 16

#define HELP_STRING "SYNTAX:\n	brute [ -i | -r ] [ -s | -m ] HASH\n"
#define ARRAY_SIZE(x) (sizeof (x) / sizeof (x[0]))

typedef char pswd_t[PSWD_LEN + 1];

typedef enum brute_mode_t{
    BM_ITER,
    BM_REC,
} brute_mode_t;

typedef enum run_mode_t {
  RM_MULTI,
  RM_SINGLE,
} run_mode_t;

typedef struct task_t {
    int index[PSWD_LEN];
    pswd_t pswd;
    int from, to;
} task_t;

typedef struct queue_t {
    task_t tasks[QUEUE_LENGTH];
    int tail;
    int head;
    pthread_mutex_t tail_mutex;
    pthread_mutex_t head_mutex;
    sem_t full_sem;
    sem_t empty_sem;
} queue_t;

typedef struct context_t {
  char *alph;
  int pswd_len;
  int alph_len;
  char *hash;
  brute_mode_t brute_mode;
  run_mode_t run_mode;
  pswd_t pswd;
  int complete;
  queue_t queue;
} context_t;

typedef int (* task_handler_t)(context_t * context, task_t * task,
        struct crypt_data * data);

void clear_task_index(task_t * task)
{
  int i;
  for(i = task->from; i < task->to; i++)
    {
      task->index[i] = 0;
    }
}

void clear_pass (context_t * context, task_t * task)
{
  memset (task->pswd, context->alph[0], context->pswd_len);
  clear_task_index (task);
}

void queue_init(queue_t * queue) {
    queue->head = 0;
    queue->tail = 0;
    sem_init (&(queue->full_sem), 0, ARRAY_SIZE (queue->tasks));
    sem_init (&(queue->empty_sem), 0, 0);
    pthread_mutex_init (&(queue->tail_mutex), NULL);
    pthread_mutex_init (&(queue->head_mutex), NULL);
}

void queue_push (queue_t * queue, task_t * task) {
    sem_wait (&(queue->full_sem));
    pthread_mutex_lock (&(queue->tail_mutex));
    queue->tasks[queue->tail] = *task;
    if(++queue->tail == ARRAY_SIZE (queue->tasks)) {
        queue->tail = 0;
    }
    pthread_mutex_unlock (&(queue->tail_mutex));
    sem_post (&(queue->empty_sem));
}

void queue_pop (queue_t * queue, task_t * task) {
    sem_wait (&(queue->empty_sem));
    pthread_mutex_lock (&(queue->head_mutex));
    *task = queue->tasks[queue->head];
    if(++queue->head == ARRAY_SIZE (queue->tasks)) {
        queue->head = 0;
    }
    pthread_mutex_unlock (&(queue->head_mutex));
    sem_post (&(queue->full_sem));
}

void brute_iter(context_t * context, task_t * task,
        task_handler_t handler, struct crypt_data * data)
{
  int i;
  clear_task_index (task);
  while(!0)
    {
      if (handler(context, task, data))
        {
	  break;
        }
      for (i = task->to - 1;
	   (i >= task->from) && (task->index[i] == context->alph_len - 1); i--)
        {
	  task->index[i] = 0;
	  task->pswd[i] = context->alph[0];
        }

      if (i < task->from)
        {
	  break;
        }
      task->index[i]++;
      task->pswd[i] = context->alph[task->index[i]];
    }
}

int brute_rec (context_t * context, task_t * task, int pos,
	       task_handler_t handler, struct crypt_data * data)
{
  if (pos >= task->to)
    {
      return handler(context, task, data);
    }
  int i;
  for (i = 0; i < context->alph_len; i++)
    {
      task->pswd[pos] = context->alph[i];
      if (brute_rec (context, task, pos + 1, handler, data))
	return !0;
    }
  return 0;
}

brute_rec_wrapper (context_t * context, task_t * task, task_handler_t handler, struct crypt_data * data)
{
  return brute_rec (context, task, task->from, handler, data);
}

void brute_all(context_t * context, task_t * task,
	       task_handler_t handler, struct crypt_data * data)
{
  switch(context->brute_mode)
    {
    case BM_REC :
      brute_rec_wrapper (context, task, handler, data);
      break;
    case BM_ITER :
      brute_iter (context, task, handler, data);
      break;
    }
}

int parse_args (context_t *context, int argc, char *argv[]) {

  for (;;)
    {
      int current_getopt = getopt(argc, argv, "rismh");
      if (current_getopt < 0)
	break;
      switch ( current_getopt )
	{
	case 'r' :
	  context->brute_mode = BM_REC;
	  break;
	case 'i' :
	  context->brute_mode = BM_ITER;
	  break;
	case 'm' :
	  context->run_mode = RM_MULTI;
	  break;
	case 's' :
	  context->run_mode = RM_SINGLE;
	  break;
	case 'h' :
	  return -1;
	default :
	  break;
	}
    }

  if ((optind >= 0) && (optind < argc)) {
    context->hash = argv[optind];
    context->hash[strlen(context->hash)] = '\0';
    return 0;
  }
  else {
    printf("Hash not found\n");
    return -1;
  }
}

int check_pswd (context_t * context, task_t * task, struct crypt_data * data) {
  if (strcmp (crypt_r (task->pswd, context->hash, data), context->hash) == 0) {
    memcpy(context->pswd, task->pswd, context->pswd_len + 1);
    context->complete = !0;
    return !0;
  }
  return 0;
}

int push_task (context_t * context, task_t * task, struct crypt_data * data) {
  if (context->complete) {
    return !0;
  }
  task_t new_task = *task;
  new_task.from = task->to;
  new_task.to = context->pswd_len;
  queue_push (&(context->queue), &new_task);
  return 0;
}

void producer(context_t * context) {
    task_t task = {
        .from = 0,
        .to = context->pswd_len / 2
    };
    clear_pass(context, &task);
    brute_all(context, &task, &push_task, NULL);
    task_t stop;
    stop.to = -1;
    queue_push(&(context->queue), &stop);
}

void consumer (context_t * context) {
  struct crypt_data data = {
    .initialized = 0,
  };
  for (;;) {
    task_t current_task = queue_pop(&(context->queue));
    if(current_task.to == -1) {
      queue_push(&(context->queue), &current_task);
      pthread_exit(NULL);
    }
    brute_all(context, &current_task, &check_pswd, &data);
  }
}

void * consumer_wrapper (void * arg)
{
  consumer (arg);
  return (NULL);
}

void threads_join(pthread_t * threads, int size) {
  int i;
  for (i = 0; i < size; i++)
    {
      pthread_join (threads[i], NULL);
    }
}

void multi_brute(context_t * context) {
  queue_init (&context->queue);
    int threads_count = sysconf(_SC_NPROCESSORS_ONLN);
    pthread_t threads[threads_count];
    int i;

    for (i = 0; i < threads_count; i++)
    {
        pthread_create(&threads[i], NULL, consumer_wrapper, context);
    }
    producer(context);
    threads_join(threads, threads_count);
}

void single_brute(context_t * context) {
    struct crypt_data data={
        .initialized=0,
    };
    task_t task={
        .from = 0,
        .to = context->pswd_len,
    };
    clear_pass(context, &task);
    brute_all(context, &task, &check_pswd, &data);
}

int main(int argc, char *argv[])
{
    context_t context={
        .alph=ALPH,
        .pswd_len=PSWD_LEN,
        .alph_len=strlen(ALPH),
        .brute_mode=BM_ITER,
        .run_mode=RM_SINGLE,
        .complete=0,
    };
    if (parse_args(&context, argc, argv) != 0) {
        printf(HELP_STRING);
        return -1;
    }
    switch (context.run_mode)
    {
        case RM_MULTI :
            multi_brute(&context);
            break;
        case RM_SINGLE :
            single_brute(&context);
            break;
        default :
            break;
    }
    if(context.complete == 1) {
        printf("Password: \"%s\"\n", context.pswd);
    } else {
        printf("Pass not found\n");
    }
    return 0;
}
