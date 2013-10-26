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
  "<password>%s </password>\n"                        \
  "<id>%d</id>\n"                                \
  "<idx>%d</idx>\n"                                \
  "<hash>%s </hash>\n"                                \
  "<alphabet>%s </alphabet>\n"                        \
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
  "<password>%s </passwdord>\n"                               \
  "<id>%d</id>\n"                                \
  "<idx>%d</idx>\n"                                \
  "<password_found>%d</password_found>\n"        \
  "<mutex/>\n"                                        \
  "</result>\n"                                        \
  "</result>\n"                                        \
  "</args>\n"                                        \
  "</msg>\n"

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

typedef struct task_t
{
  pswd_t pswd;
  int from, to;
} task_t;

typedef struct queue_t
{
  task_t tasks[QUEUE_LENGTH];
  int tail;
  int head;
  int closed;
  pthread_mutex_t tail_mutex;
  pthread_mutex_t head_mutex;
  sem_t full_sem;
  sem_t empty_sem;
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
  int complete;
  queue_t queue;
} context_t;

typedef struct med_context_t
{
  context_t * context;
  int fd;
  pthread_mutex_t * context_mutex;
  pthread_mutex_t * close_mutex;
  pthread_cond_t * close_cond;
} med_context_t;

typedef struct accepter_context_t
{  
  int sock;
  pthread_mutex_t * context_mutex;
  pthread_mutex_t * close_mutex;
  pthread_cond_t * close_cond;
  context_t * context;
} accepter_context_t;

typedef int (* task_handler_t)(context_t * context, task_t * task,
        struct crypt_data * data);

void clear_pass (context_t * context, task_t * task)
{
  memset (task->pswd, context->alph[0], context->pswd_len);
}

void queue_init (queue_t * queue)
{
  queue->closed = 0;
  queue->head = 0;
  queue->tail = 0;
  sem_init (&queue->full_sem, 0, QUEUE_LENGTH);
  sem_init (&queue->empty_sem, 0, 0);
  pthread_mutex_init (&queue->tail_mutex, NULL);
  pthread_mutex_init (&queue->head_mutex, NULL);
}

void queue_push (queue_t * queue, task_t * task)
{
  sem_wait (&queue->full_sem);
  pthread_mutex_lock (&queue->tail_mutex);
  queue->tasks[queue->tail] = *task;
  if (++queue->tail == QUEUE_LENGTH)
    {
      queue->tail = 0;
    }
  pthread_mutex_unlock (&queue->tail_mutex);
  sem_post (&queue->empty_sem);
}

void queue_pop (queue_t * queue, task_t * task)
{
  sem_wait (&queue->empty_sem);
  pthread_mutex_lock (&queue->head_mutex);
  *task = queue->tasks[queue->head];
  if (++queue->head == QUEUE_LENGTH)
    {
      queue->head = 0;
    }
  pthread_mutex_unlock (&queue->head_mutex);
  sem_post (&queue->full_sem);
}

void queue_cancel (queue_t * queue)
{
  queue->closed = !0;
  sem_post (&queue->full_sem);
  sem_post (&queue->empty_sem);
}

int brute_iter (context_t * context, task_t * task,
            task_handler_t handler, struct crypt_data * data)
{
  int i;
  int index[PSWD_LEN];
  memset (index, 0, PSWD_LEN * sizeof (index [0]));
  while (!0)
    {
      if (handler (context, task, data))
        {
          break;
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
  return (0);
}

int brute_rec (context_t * context, task_t * task, int pos,
               task_handler_t handler, struct crypt_data * data)
{
  if (pos >= task->to)
    {
      return handler (context, task, data);
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

int brute_rec_wrapper (context_t * context, task_t * task,
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
          return -1;
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
      printf ("Hash not found\n");
      return 0;
    }
}

int check_pswd (context_t * context, task_t * task, struct crypt_data * data)
{
  if (strcmp (crypt_r (task->pswd, context->hash, data), context->hash) == 0)
    {
      memcpy (context->pswd, task->pswd, context->pswd_len + 1);
      context->complete = !0;
      return !0;
    }
  return 0;
}

int push_task (context_t * context, task_t * task, struct crypt_data * data)
{
  task_t new_task = *task;
  new_task.from = 0;
  new_task.to = task->from;
  queue_push (&context->queue, &new_task);
  return (context->complete);
}

void producer (context_t * context)
{
  task_t task = {
    .from = PREFIX_SIZE,
    .to = context->pswd_len,
  };
  clear_pass (context, &task);
  brute_all (context, &task, push_task, NULL);
  task_t stop;
  stop.to = -1;
  queue_push (&context->queue, &stop);
}

void consumer (context_t * context)
{
  struct crypt_data data = {
    .initialized = 0,
  };
  for (;;)
    {
      task_t current_task;
      queue_pop (&context->queue, &current_task);
      if (current_task.to == -1) {
        queue_push (&context->queue, &current_task);
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

void mediator (med_context_t * context)
{
  med_context_t med_context = *context;
  pthread_mutex_unlock (context->context_mutex);
  queue_t * queue = &med_context.context->queue;
  char * hash = med_context.context->hash;
  char * alph = med_context.context->alph;
  int fd = med_context.fd;
  for (;;)
    {
      task_t task;
      queue_pop (queue, &task);
      if (task.to == -1)
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
      int result;
      int id, idx;
      char password [PSWD_LEN + 1];
      sscanf (reply, REPORT_RESULT_TMPL, password, &id, &idx, &result);
      if (result)
        {
          memcpy (med_context.context->pswd, password, med_context.context->pswd_len);
          med_context.context->complete = !0;
          return;
        }
    }
  
}

void * mediator_wrapper (void * arg)
{
  med_context_t * context = (med_context_t *) arg;
  mediator (context);

  shutdown (context->fd, SHUT_RDWR);
  close (context->fd);
  return (NULL);
}

void * accepter (void * arg)
{
  accepter_context_t accepter_context = *((accepter_context_t *) arg);
  pthread_mutex_unlock (accepter_context.context_mutex);
  int sock = accepter_context.sock;
  for (;;)
    {
      int fd = accept (sock, NULL, NULL);
      if (fd < 0)
        {
          fprintf (stderr, "Accept error\n");
          return (NULL);
        }

      pthread_t mediator;
      med_context_t * med_context = malloc (sizeof (med_context_t));
      med_context->context = accepter_context.context;
      med_context->fd = fd;
      med_context->close_mutex = accepter_context.close_mutex;
      med_context->close_cond = accepter_context.close_cond;
      pthread_mutex_init (med_context->context_mutex, NULL);
      pthread_mutex_lock (med_context->context_mutex);
      pthread_create (&mediator, NULL, (void *) mediator, (void *) med_context);
      pthread_mutex_lock (med_context->context_mutex);
      free (med_context);
    }
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

  pthread_mutex_t close_mutex;
  pthread_mutex_init (&close_mutex, NULL);
  pthread_cond_t close_cond;
  pthread_cond_init (&close_cond, NULL);

  accepter_context_t *  accepter_context = malloc (sizeof (accepter_context_t));
  accepter_context->sock = sock;
  accepter_context->close_mutex = &close_mutex;
  accepter_context->close_cond = &close_cond;
  accepter_context->context = context;
  pthread_mutex_init (accepter_context->context_mutex, NULL);
  pthread_mutex_lock (accepter_context->context_mutex);
  pthread_create (&accepter_thread, NULL, accepter, accepter_context);
  pthread_mutex_lock (accepter_context->context_mutex);
  free (accepter_context);

  pthread_cond_wait (&close_cond, &close_mutex);
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

void server_wrapper(context_t * context)
{
  queue_init (&context->queue);
  pthread_t prod;
  pthread_create (&prod, NULL, (void *) producer, (void *) context);
  server (context);
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
      clear_pass (context, &task);
      brute_all (context, &task, &check_pswd, &data);

      int result = context->complete;
  
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
    .complete = 0,
  };
  
  if (!parse_args (&context, argc, argv))
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
  if (context.complete)
    {
      printf ("Password: \"%s\"\n", context.pswd);
    }
  else
    {
      printf ("Pass not found\n");
    }
  return EXIT_SUCCESS;
}
