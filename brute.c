#include <stdio.h>
#define __USE_GNU
#include <crypt.h>
#include <stdbool.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <semaphore.h>
#include <pthread.h>
#include <signal.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/types.h>
#include <netinet/in.h>

#define ALPH3 "abc"
#define ALPH4 "csit"
#define ALPH15 "abcdefghijklmno"
#define ALPH26 "abcdefghijklmnopqrstuvwxyz"

#define ALPH ALPH26
#define PSWD_LEN (4)
#define QUEUE_LENGTH (8)
#define PREFIX_SIZE (2)

#define HELP_STRING "SYNTAX:\n        brute [ -i | -r ] [ -s | -m ] HASH\n"
#define PORT (54321)

#define SEND_JOB_TMPL "<msg>\n"                        \
  "<type>MT_SEND_JOB</type>\n"                        \
  "<args>\n"                                        \
  "<job>\n"                                        \
  "<job>\n"                                        \
  "<password>%s </password>\n"                  \
  "<id>%d</id>\n"                                \
  "<idx>%d</idx>\n"                                \
  "<hash>%s </hash>\n"                                \
  "<alphabet>%s </alphabet>\n"                  \
  "<from>%d</from>\n"                                \
  "<to>%d</to>\n"                                \
  "</job>\n"                                        \
  "</job>\n"                                        \
  "</args>\n"                                        \
  "</msg>\n"

#define REPORT_RESULT_TMPL "<msg>\n"                \
  "<type>MT_REPORT_RESULTS</type>\n"                \
  "<args>\n"                                        \
  "<result>\n"                                        \
  "<result>\n"                                        \
  "<password>%s </passwdord>\n"                        \
  "<id>%d</id>\n"                                \
  "<idx>%d</idx>\n"                                \
  "<password_found>%d</password_found>\n"        \
  "<mutex/>\n"                                        \
  "</result>\n"                                        \
  "</result>\n"                                        \
  "</args>\n"                                        \
  "</msg>\n"                                        \

typedef char pswd_t[PSWD_LEN + 1];

typedef enum brute_mode_t
{
  BM_ITER,
  BM_REC,
} brute_mode_t;

typedef enum run_mode_t
{
  RM_MULTI,
  RM_SINGLE,
  RM_SERVER,
  RM_CLIENT,
} run_mode_t;

typedef enum result_t
{
  SUCCESS,
  FAIL,
} result_t;

typedef struct task_t
{
  pswd_t pswd;
  int from, to;
} task_t;

typedef struct queue_t
{
  task_t tasks[QUEUE_LENGTH];
  int count;
  int tail;
  int head;
  int closed;
  pthread_mutex_t mutex;
  pthread_cond_t empty_cond;
  pthread_cond_t full_cond;
} queue_t;

typedef struct context_t
{
  char *alph;
  int pswd_len;
  int alph_len;
  char *hash;
  brute_mode_t brute_mode;
  run_mode_t run_mode;
  pswd_t pswd;
  result_t complete;
  queue_t queue;
  int tip;
  pthread_mutex_t mutex;
  pthread_cond_t cond;
} context_t;

typedef struct ext_context_t
{
  context_t * context;
  int sock;
  pthread_mutex_t * context_mutex;
} ext_context_t;

typedef result_t (* task_handler_t)(context_t * context, task_t * task,
        struct crypt_data * data);
        
void ref (context_t* context)
{
  pthread_mutex_lock (&context->mutex);
  context->tip++;
  pthread_mutex_unlock (&context->mutex);
}

void unref (context_t* context)
{
  pthread_mutex_lock (&context->mutex);
  if (0 == --context->tip)
  {
    pthread_cond_signal (&context->cond);
  }
  pthread_mutex_unlock (&context->mutex);
}

void clear_pass (context_t * context, task_t * task)
{
  memset (task->pswd, context->alph[0], context->pswd_len);
}

void queue_init (queue_t * queue)
{
  queue->count = 0;
  queue->closed = 0;
  queue->head = 0;
  queue->tail = 0;
  pthread_cond_init (&queue->empty_cond, NULL);
  pthread_cond_init (&queue->full_cond, NULL);
  pthread_mutex_init (&queue->mutex, NULL);
}

result_t queue_push (queue_t * queue, task_t * task)
{
  result_t status = FAIL;
  pthread_mutex_lock (&queue->mutex);
  while ((queue->count == QUEUE_LENGTH) &&
    (!queue->closed))
  {
    pthread_cond_wait (&queue->full_cond, &queue->mutex);
  }
  if (!queue->closed)
  {
    queue->tasks[queue->tail] = *task;
    if (++queue->tail == QUEUE_LENGTH)
      {
        queue->tail = 0;
      }
    ++queue->count;
    pthread_cond_broadcast (&queue->empty_cond);
    status = SUCCESS;
  }
  pthread_mutex_unlock (&queue->mutex);
  return status;
}

result_t queue_pop (queue_t * queue, task_t * task)
{
  result_t status = FAIL;
  pthread_mutex_lock (&queue->mutex);
  while ((queue->count == 0) && !queue->closed)
  {
    pthread_cond_wait (&queue->empty_cond, &queue->mutex);
  }
  if (!queue->closed)
    {
      *task = queue->tasks[queue->head];
      if (++queue->head == QUEUE_LENGTH)
        {
          queue->head = 0;
        }
      --queue->count;
      pthread_cond_broadcast (&queue->full_cond);
      status = SUCCESS;
    }
  pthread_mutex_unlock (&queue->mutex);
  return status;
}

void queue_cancel (queue_t * queue)
{
  queue->closed = !0;
  pthread_cond_broadcast (&queue->full_cond);
  pthread_cond_broadcast (&queue->empty_cond);
}

result_t brute_iter (context_t * context, task_t * task,
            task_handler_t handler, struct crypt_data * data)
{
  int i;
  int index[PSWD_LEN];
  memset (index, 0, PSWD_LEN * sizeof (index [0]));
  for (;;)
    {
      if (handler (context, task, data) == FAIL)
        {
          return SUCCESS;
        }
      for (i = task->to - 1;
           (i >= task->from) && (index[i] == context->alph_len - 1); i--)
        {
          index[i] = 0;
          task->pswd[i] = context->alph[0];
        }
      if (i < task->from)
        {
          break;
        }
      index[i]++;
      task->pswd[i] = context->alph[index[i]];
    }
  return FAIL;
}

result_t brute_rec (context_t * context, task_t * task, int pos,
               task_handler_t handler, struct crypt_data * data)
{
  if (pos >= task->to)
    {
      if (handler (context, task, data) == FAIL)
        {
          return SUCCESS;
        }
      else
        {
          return FAIL;
        }
    }
  int i;
  for (i = 0; i < context->alph_len; i++)
    {
      task->pswd[pos] = context->alph[i];
      if (brute_rec (context, task, pos + 1, handler, data) == SUCCESS)
        return SUCCESS;
    }
  return FAIL;
}

result_t brute_rec_wrapper (context_t * context, task_t * task,
                       task_handler_t handler, struct crypt_data * data)
{
  return brute_rec (context, task, task->from, handler, data);
}

void brute_all(context_t * context, task_t * task,
               task_handler_t handler, struct crypt_data * data)
{
  switch (context->brute_mode)
    {
    case BM_REC :
      brute_rec_wrapper (context, task, handler, data);
      break;
    case BM_ITER :
      brute_iter (context, task, handler, data);
      break;
    }
}

int parse_args (context_t *context, int argc, char *argv[])
{
  for (;;)
    {
      int current_getopt = getopt (argc, argv, "riomhsc");
      if (current_getopt < 0)
        break;
      switch (current_getopt)
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
        case 'o' :
          context->run_mode = RM_SINGLE;
          break;
        case 's' :
          context->run_mode = RM_SERVER;
          break;
        case 'c' :
          context->run_mode = RM_CLIENT;
          break;
        case 'h' :
          return 0;
        default :
          break;
        }
    }

  if ((optind >= 0) && (optind < argc))
    {
      context->hash = argv[optind];
      context->hash[strlen(context->hash)] = '\0';
      return !0;
    }
  else
    {
      return 0;
    }
}

result_t check_pswd (context_t * context, task_t * task, struct crypt_data * data)
{
  printf ("%s\n", task->pswd);
  if (strcmp (crypt_r (task->pswd, context->hash, data), context->hash) == 0)
    {
      memcpy (context->pswd, task->pswd, context->pswd_len + 1);
      context->complete = SUCCESS;
      queue_cancel (&context->queue);
      return FAIL;
    }
  return SUCCESS;
}

result_t push_task (context_t * context, task_t * task, struct crypt_data * data)
{
  task_t new_task = *task;
  new_task.from = 0;
  new_task.to = task->from;
  ref (context);
  if (queue_push (&context->queue, &new_task) == FAIL)
    {
      unref (context);
      return FAIL;
    }
  return SUCCESS;
}

void producer (context_t * context)
{
  task_t task = {
    .from = PREFIX_SIZE,
    .to = context->pswd_len,
  };
  clear_pass (context, &task);
  brute_all (context, &task, push_task, NULL);
}

void consumer (context_t * context)
{
  struct crypt_data data = {
    .initialized = 0,
  };
  for (;;)
    {
      task_t current_task;
      if (queue_pop (&context->queue, &current_task) == FAIL)
        {
          return;
        }
      brute_all (context, &current_task, &check_pswd, &data);
    }
}

void * consumer_wrapper (void * arg)
{
  consumer (arg);
  return (NULL);
}

void threads_join (pthread_t * threads, int size)
{
  int i;
  for (i = 0; i < size; i++)
    {
      pthread_join (threads[i], NULL);
    }
}

void multi_brute (context_t * context)
{
  queue_init (&context->queue);
  int threads_count = sysconf (_SC_NPROCESSORS_ONLN);
  pthread_t threads[threads_count];
  int i;
  for (i = 0; i < threads_count; i++)
    {
      pthread_create (&threads[i], NULL, consumer_wrapper, context);
    }
  producer (context);
  queue_cancel (&context->queue);
  threads_join (threads, threads_count);
}

void single_brute (context_t * context)
{
  struct crypt_data data = {
    .initialized = 0,
  };
  task_t task = {
    .from = 0,
    .to = context->pswd_len,
  };
  clear_pass (context, &task);
  brute_all (context, &task, &check_pswd, &data);
}

void mediator (ext_context_t * context)
{
  ext_context_t ext_context = *context;
  pthread_mutex_unlock (context->context_mutex);

  queue_t * queue = &ext_context.context->queue;
  char * hash = ext_context.context->hash;
  char * alph = ext_context.context->alph;
  int fd = ext_context.sock;
  for (;;)
    {
      task_t task;
      if (queue_pop (queue, &task) == FAIL)
        {
          return;
        }
      char task_string [1023];
      uint32_t size = sprintf (task_string, SEND_JOB_TMPL, task.pswd, 0, 0,
                               hash, alph, task.from, task.to) + 1;
      if (write (fd, &size, sizeof (size)) < 0 ||
          write (fd, &task_string, size) < 0)
        {
          fprintf (stderr, "Write error\n");
          queue_push (queue, &task);
          return;
        }

      uint32_t reply_size;
      if (read (fd, &reply_size, sizeof (uint32_t)) < 0)
        {
          fprintf (stderr, "Read error\n");
          queue_push (queue, &task);
          return;
        }
      char reply [reply_size];
      if (read (fd, reply, reply_size) < 0)
        {
          fprintf (stderr, "Read error\n");
          queue_push (queue, &task);
          return;
        }
      
      unref (ext_context.context);
      int result;
      int id, idx;
      char password [PSWD_LEN + 1];
      sscanf (reply, REPORT_RESULT_TMPL, password, &id, &idx, &result);
      if (result)
        {
          memcpy (ext_context.context->pswd, password, ext_context.context->pswd_len);
	  queue_cancel (queue);
          ext_context.context->complete = SUCCESS;
	  pthread_cond_signal (&ext_context.context->cond);
          return;
        }
    }
  
}

void * mediator_wrapper (void * arg)
{
  ext_context_t * context = (ext_context_t *) arg;
  int sock = context->sock;
  mediator (context);
  printf ("**************\n");
  shutdown (sock, SHUT_RDWR);
  close (sock);
  return (NULL);
}

void serv_producer (context_t * context, int sock)
{
  struct sockaddr_in serv_addr;
  memset (&serv_addr, 0, sizeof (serv_addr));
  serv_addr.sin_family = AF_INET;
  serv_addr.sin_addr.s_addr = INADDR_ANY;
  serv_addr.sin_port = htons (PORT);
  if (bind (sock, (struct sockaddr *) &serv_addr, sizeof (serv_addr)) < 0)
    {
      fprintf (stderr, "Bind error\n");
      return;
    }
  if (listen (sock, 5) < 0)
    {
      fprintf (stderr, "Listen error\n");
      return;
    }
  
  for (;;)
    {
      int fd = accept (sock, NULL, NULL);
      if (fd < 0)
        {
          fprintf (stderr, "Accept error\n");
          return;
        }

      pthread_t mediator;
      ext_context_t * ext_context = malloc (sizeof (ext_context_t));
      pthread_mutex_t mutex;
      ext_context->context = context;
      ext_context->sock = fd;
      ext_context->context_mutex = &mutex;
      pthread_mutex_init (ext_context->context_mutex, NULL);
      pthread_mutex_lock (ext_context->context_mutex);
      pthread_create (&mediator, NULL, (void *) mediator_wrapper, (void *) ext_context);
      pthread_mutex_lock (ext_context->context_mutex);
      free (ext_context);
    }
}

void server (context_t * context)
{
  int sock = socket (PF_INET, SOCK_STREAM, IPPROTO_TCP);
  if (sock < 0)
    {
      fprintf (stderr, "Socket error\n");
      return;
    }

  serv_producer (context, sock);
  
  shutdown (sock, SHUT_RDWR);
  close (sock);
}

void server_wrapper (context_t * context)
{
  queue_init (&context->queue);
  pthread_cond_init (&context->cond, NULL);
  pthread_mutex_init (&context->mutex, NULL);

  pthread_t serv;
  pthread_create (&serv, NULL, (void *) server, (void *) context);

  producer (context);
  
  pthread_mutex_lock (&context->mutex);
  if (context->tip != 0)
    {
      pthread_cond_wait (&context->cond, &context->mutex);
    }
  pthread_mutex_unlock (&context->mutex);
  queue_cancel (&context->queue); 
}

void cl_consumer (context_t * context, int fd)
{
  struct sockaddr_in serv_addr;
  memset (&serv_addr, 0, sizeof (serv_addr));
  serv_addr.sin_family = AF_INET;
  serv_addr.sin_port = htons (PORT);
  serv_addr.sin_addr.s_addr = INADDR_ANY;

  if (connect (fd, (struct sockaddr *) &serv_addr, sizeof (serv_addr)) < 0)
    {
      fprintf (stderr, "Connect error\n");
      return;
    }
  for (;;)
    {
      uint32_t size;
      if (read (fd, &size, sizeof (uint32_t)) < 0)
        {
          fprintf (stderr, "Read error\n");
          return;
        }
      char task_string [size];
      if (read (fd, task_string, size) < 0)
        {
          fprintf (stderr, "Read error\n");
          return;
        }
      task_t task;
      int id, idx;
      char hash [127];
      char alph [127];
      sscanf (task_string, SEND_JOB_TMPL, task.pswd, &id, &idx, hash,
              alph, &task.from, &task.to);
      context->alph = alph;
      context->hash = hash;

      struct crypt_data data = {
        .initialized = 0,
      };
      brute_all (context, &task, &check_pswd, &data);

      int result = 0;
      if (context->complete == SUCCESS) {
        result = 1;
      }
  
      char reply [1023];
  
      uint32_t reply_size = sprintf (reply, REPORT_RESULT_TMPL,
                                     context->pswd, 0, 0, result) + 1;
      if (write (fd, &reply_size, sizeof (reply_size)) < 0 ||
          write (fd, reply, reply_size) < 0)
        {
          fprintf (stderr, "Write error\n");
          return;
        }
    }
}

void client (context_t * context)
{
  int sock = socket (PF_INET, SOCK_STREAM, IPPROTO_TCP);
  if (sock < 0)
    {
      fprintf (stderr, "Socket error\n");
      return;
    }

  cl_consumer (context, sock);

  shutdown (sock, SHUT_RDWR);
  close (sock);
  return;
}

int main (int argc, char *argv[])
{
  context_t context = {
    .alph = ALPH,
    .pswd_len = PSWD_LEN,
    .alph_len = strlen (ALPH),
    .brute_mode = BM_ITER,
    .run_mode = RM_SINGLE,
    .complete = FAIL,
    .tip = 0
  };
  
  if (!parse_args (&context, argc, argv) && context.run_mode != RM_CLIENT)
    {
      printf (HELP_STRING);
      return EXIT_FAILURE;
    }

  signal (SIGPIPE, SIG_IGN);

  switch (context.run_mode)
    {
    case RM_MULTI :
      multi_brute (&context);
      break;
    case RM_SINGLE :
      single_brute (&context);
      break;
    case RM_SERVER :
      server_wrapper (&context);
      break;
    case RM_CLIENT :
      client (&context);
      return EXIT_SUCCESS;
    default :
      break;
    }
  if (context.complete == SUCCESS)
    {
      printf ("Password: \"%s\"\n", context.pswd);
    }
  else
    {
      printf ("Pass not found\n");
    }
  return EXIT_SUCCESS;
}
