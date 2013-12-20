#include <stdio.h>
#define __USE_GNU
#include <errno.h>
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

#define HELP_STRING "SYNTAX:\n        brute [KEYS] [HASH]\n"		\
  "KEYS:\n -i - set brute mode to iteration\n"				\
  " -r - set brute mode to recursion\n"					\
  " -o - run in singlethread mode\n -m - run in multithread mode\n"	\
  " -s - run in sync server mode\n -c - run in sync client mode\n"
#define PORT (54321)

#define SEND_JOB_TMPL "<msg>\n"                        \
  "<type>MT_SEND_JOB</type>\n"			       \
  "<args>\n"					       \
  "<job>\n"					       \
  "<job>\n"					       \
  "<password>%s </password>\n"			       \
  "<id>%d</id>\n"				       \
  "<idx>%d</idx>\n"				       \
  "<hash>%s </hash>\n"				       \
  "<alphabet>%s </alphabet>\n"			       \
  "<from>%d</from>\n"				       \
  "<to>%d</to>\n"				       \
  "</job>\n"					       \
  "</job>\n"					       \
  "</args>\n"					       \
  "</msg>\n"

#define REPORT_RESULT_TMPL "<msg>\n"                   \
  "<type>MT_REPORT_RESULTS</type>\n"		       \
  "<args>\n"					       \
  "<result>\n"					       \
  "<result>\n"					       \
  "<password>%s </passwdord>\n"                        \
  "<id>%d</id>\n"				       \
  "<idx>%d</idx>\n"				       \
  "<password_found>%d</password_found>\n"	       \
  "<mutex/>\n"					       \
  "</result>\n"                                        \
  "</result>\n"                                        \
  "</args>\n"					       \
  "</msg>\n"					       \

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
  RM_SERVER_SYNC,
  RM_CLIENT_SYNC,
  RM_SERVER_ASYNC,
  RM_CLIENT_ASYNC
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
  char* elements;
  int element_size;
  int size;
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

typedef struct server_t
{
  context_t * context;
  int sock;
} server_t;

typedef struct accepter_context_t
{
  context_t * context;
  int sock;
  pthread_mutex_t mutex;
} accepter_context_t;

typedef result_t (* task_handler_t)(context_t * context, task_t * task,
        struct crypt_data * data);
        
void ref (context_t* context)
{
  pthread_mutex_lock (&context->mutex);
  ++context->tip;
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

void queue_init (queue_t * queue, int element_size)
{
  queue->size = 0;
  queue->closed = 0;
  queue->head = 0;
  queue->tail = 0;
  queue->element_size = element_size;
  queue->elements = malloc (element_size * QUEUE_LENGTH);
  pthread_cond_init (&queue->empty_cond, NULL);
  pthread_cond_init (&queue->full_cond, NULL);
  pthread_mutex_init (&queue->mutex, NULL);
}

result_t queue_push (queue_t * queue, char * src)
{
  result_t status = FAIL;
  pthread_mutex_lock (&queue->mutex);
  while ((queue->size == QUEUE_LENGTH) &&
    (!queue->closed))
  {
    pthread_cond_wait (&queue->full_cond, &queue->mutex);
  }
  if (!queue->closed)
  {
    int offset = queue->tail * queue->element_size;
    memcpy(&queue->elements[offset], src, queue->element_size); 
    if (++queue->tail == QUEUE_LENGTH)
      {
        queue->tail = 0;
      }
    if (queue->size++ == 0)
      {
	pthread_cond_broadcast (&queue->empty_cond);
      }
    status = SUCCESS;
  }
  pthread_mutex_unlock (&queue->mutex);
  return status;
}

result_t queue_pop (queue_t * queue, char * dst)
{
  result_t status = FAIL;
  pthread_mutex_lock (&queue->mutex);
  while ((queue->size == 0) && !queue->closed)
  {
    pthread_cond_wait (&queue->empty_cond, &queue->mutex);
  }
  if (!queue->closed)
    {
      int offset = queue->head * queue->element_size;
      memcpy(dst, &queue->elements[offset], queue->element_size);
      if (++queue->head == QUEUE_LENGTH)
        {
          queue->head = 0;
        }
      if (queue->size-- == QUEUE_LENGTH)
	{
	  pthread_cond_broadcast (&queue->full_cond);
	}
      status = SUCCESS;
    }
  pthread_mutex_unlock (&queue->mutex);
  return status;
}

void queue_cancel (queue_t * queue)
{
  if (!queue->closed) {    
    queue->closed = !0;
    free (queue->elements);
    pthread_cond_broadcast (&queue->full_cond);
    pthread_cond_broadcast (&queue->empty_cond);
  }
}

result_t brute_iter (context_t * context, task_t * task,
            task_handler_t handler, struct crypt_data * data)
{
  int i;
  int index[PSWD_LEN];
  memset (index, 0, sizeof (index));
  for (i = task->to - 1; i >= task->from; i--)
    {
      task->pswd[i] = context->alph[0];
    }
  for (;;)
    {
      if (handler (context, task, data) == SUCCESS)
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
      return handler (context, task, data);
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
      int current_getopt = getopt (argc, argv, "riomhscSC");
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
          context->run_mode = RM_SERVER_SYNC;
          break;
        case 'c' :
          context->run_mode = RM_CLIENT_SYNC;
          break;
	case 'S' :
	  context->run_mode = RM_SERVER_ASYNC;
	  break;
	case 'C' :
	  context->run_mode = RM_CLIENT_ASYNC;
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
  if (strcmp (crypt_r (task->pswd, context->hash, data), context->hash) == 0)
    {
      strcpy (context->pswd, task->pswd);
      context->complete = SUCCESS;
      queue_cancel (&context->queue);
      pthread_cond_broadcast (&context->cond);
      return SUCCESS;
    }
  return FAIL;
}

result_t push_task (context_t * context, task_t * task, struct crypt_data * data)
{
  task_t new_task = *task;
  new_task.from = 0;
  new_task.to = task->from;
  ref (context);
  if (queue_push (&context->queue, (char *)&new_task) == FAIL)
    {
      unref (context);
    }
  return context->complete;
}

void producer (context_t * context)
{
  task_t task = {
    .from = PREFIX_SIZE,
    .to = context->pswd_len,
  };
  memset (task.pswd, '-', context->pswd_len);
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
      if (queue_pop (&context->queue, (char *)&current_task) == FAIL)
        {
          break;
        }
      brute_all (context, &current_task, &check_pswd, &data);
      unref (context);
    }
}

void * consumer_wrapper (void * arg)
{
  consumer (arg);
  return (NULL);
}

void multi_brute (context_t * context)
{
  queue_init (&context->queue, sizeof (task_t));
  int threads_count = sysconf (_SC_NPROCESSORS_ONLN);
  pthread_t threads[threads_count];
  int i;
  for (i = 0; i < threads_count; i++)
    {
      pthread_create (&threads[i], NULL, consumer_wrapper, context);
    }
  producer (context);

  pthread_mutex_lock (&context->mutex);
  if (context->tip != 0 && context->complete != SUCCESS)
    {
      pthread_cond_wait (&context->cond, &context->mutex);
    }
  pthread_mutex_unlock (&context->mutex);
  queue_cancel (&context->queue);
  for (i = 0; i < threads_count; i++)
    {
      pthread_join (threads[i], NULL);
    }
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
  brute_all (context, &task, &check_pswd, &data);
}

int reliable_read (int fd, char * buf, int size)
{
  int zr;
  int i;
  for (i = 0; i < size; i += zr)
    {
      zr = TEMP_FAILURE_RETRY (read (fd, &buf[i], size - i));
      if (zr <= 0)
	{
	  break;
	}
    }
  return i;
}

char * read_message (int fd)
{
  uint32_t size;
  if (reliable_read (fd, (char *) &size, sizeof (size)) != sizeof (size))
    {
      return (NULL);
    }
  
  char * str;
  str = malloc (size);
  if (reliable_read (fd, str, size) != size)
    {
      return (NULL);
    }
  return str;
}

int reliable_write (int fd, char * buf, int size)
{
  int zr;
  int i;
  for (i = 0; i < size; i += zr)
    {
      zr = TEMP_FAILURE_RETRY (write (fd, &buf[i], size - i));
      if (zr <= 0)
	{
	  break;
	}
    }
  return i;
}

result_t write_message (int fd, char * str)
{
  uint32_t size = strlen (str) + 1;
  if (reliable_write (fd, (char *) &size, sizeof (size)) != sizeof (size))
    {
      return FAIL;
    }
  if (reliable_write (fd, str, size) != size)
    {
      return FAIL;
    }
  return SUCCESS;
}

result_t handle_task_sync (server_t * srv, task_t * task)
{
  char * hash = srv->context->hash;
  char * alph = srv->context->alph;

  int size = snprintf (NULL, 0, SEND_JOB_TMPL, task->pswd, 0, 0, hash, alph, task->from, task->to) + 1;
  if (size < 0)
    {
      return FAIL;
    }

  char task_string[size];
  sprintf (task_string, SEND_JOB_TMPL, task->pswd, 0, 0, hash, alph, task->from, task->to);
  if (write_message (srv->sock, task_string) == FAIL)
    {
      fprintf (stderr, "Write error\n");
      return FAIL;
    }
  
  char * reply = read_message (srv->sock);
  if (reply == NULL)
    {
      fprintf (stderr, "Read error\n");
      return FAIL;
    }

  int result;
  int id, idx;
  char password [PSWD_LEN + 1];
  sscanf (reply, REPORT_RESULT_TMPL, password, &id, &idx, &result);
  if (result)
    {
      memcpy (srv->context->pswd, password, srv->context->pswd_len);
      srv->context->complete = SUCCESS;
    }
  free (reply);

  return SUCCESS;
} 

void mediator_sync (context_t * context, int sock)
{
  queue_t * queue = &context->queue;
  task_t task;
  server_t srv;
  srv.context = context;
  srv.sock = sock;
  for (;;)
    {
      if (queue_pop (queue, (char *)&task) == FAIL)
        {
          break;
        }
      if (handle_task_sync (&srv, &task) == SUCCESS)
	{
	  unref (context);
	}
      else
	{
	  break;
	}	
    }
  queue_push (queue, (char *)&task);
  shutdown (sock, SHUT_RDWR);
}

void * mediator_wrapper_sync (void * arg)
{
  accepter_context_t * accepter_context = (accepter_context_t *) arg;
  accepter_context_t local = * accepter_context;
  pthread_mutex_unlock (&accepter_context->mutex);
  mediator_sync (local.context, local.sock);
  close (local.sock);
  return (NULL);
}

void serv_producer_sync (context_t * context, int sock)
{
  struct sockaddr_in serv_addr;
  memset (&serv_addr, 0, sizeof (serv_addr));
  serv_addr.sin_family = AF_INET;
  serv_addr.sin_addr.s_addr = INADDR_ANY;
  serv_addr.sin_port = htons (PORT);
  if (bind (sock, (struct sockaddr *) &serv_addr, sizeof (serv_addr)) < 0)
    {
      fprintf (stderr, "Bind error\n");
      exit (EXIT_FAILURE);
    }
  if (listen (sock, 5) < 0)
    {
      fprintf (stderr, "Listen error\n");
    }
  else
    {
      for (;;)
	{
	  int fd = accept (sock, NULL, NULL);
	  if (fd < 0)
	    {
	      fprintf (stderr, "Accept error\n");
	      break;
	    }

	  pthread_t mediator;
	  accepter_context_t accepter_context;

	  accepter_context.context =context;
	  accepter_context.sock = fd;
	  pthread_mutex_init (&accepter_context.mutex, NULL);
	  pthread_mutex_lock (&accepter_context.mutex);
	  pthread_create (&mediator, NULL, (void *) mediator_wrapper_sync, &accepter_context);
	  pthread_mutex_lock (&accepter_context.mutex);
	}
    }
  shutdown (sock, SHUT_RDWR);
}
void server_sync (server_t * server_context)
{
  int sock = socket (PF_INET, SOCK_STREAM, IPPROTO_TCP);
  server_context->sock = sock;
  if (sock < 0)
    {
      fprintf (stderr, "Socket error\n");
      return;
    }

  serv_producer_sync (server_context->context, server_context->sock);
  
  close (sock);
}

void server_wrapper_sync (context_t * context)
{
  queue_init (&context->queue, sizeof(task_t));
  pthread_cond_init (&context->cond, NULL);
  pthread_mutex_init (&context->mutex, NULL);

  server_t server_context;
  server_context.context = context;

  pthread_t serv;
  pthread_create (&serv, NULL, (void *) server_sync, (void *) &server_context);

  producer (context);
  
  pthread_mutex_lock (&context->mutex);
  if (context->tip != 0 && context->complete != SUCCESS)
    {
      pthread_cond_wait (&context->cond, &context->mutex);
    }
  pthread_mutex_unlock (&context->mutex);  
  queue_cancel (&context->queue);
  shutdown (server_context.sock, SHUT_RDWR);
  pthread_join (serv, NULL);
}

result_t cl_handle_task (context_t * context, int fd, struct crypt_data * data)
{
  char * task_string = read_message (fd);
  if (task_string == NULL)
    {
      fprintf (stderr, "Read error\n");
      return FAIL;
    }
  task_t task;
  int id, idx;
  char hash [127];
  char alph [127];
  sscanf (task_string, SEND_JOB_TMPL, task.pswd, &id, &idx, hash,
	  alph, &task.from, &task.to);
  context->alph = alph;
  context->hash = hash;
  free (task_string);

  brute_all (context, &task, &check_pswd, data);

  int result = 0;
  if (context->complete == SUCCESS)
    {
      result = !0;
    }
  else
    {
      strcpy (context->pswd, "-");
    }
      
  int reply_size = snprintf (NULL, 0, REPORT_RESULT_TMPL, context->pswd, 0, 0, result) + 1;
  char reply[reply_size];
  sprintf (reply, REPORT_RESULT_TMPL, context->pswd, 0, 0, result);
  if (reply_size < 0)
    {
      fprintf (stderr, "Sprintf error\n");
      return FAIL;
    }
  if (write_message (fd, reply) == FAIL)
    {
      fprintf (stderr, "Write error\n");
      return FAIL;
    }
  return SUCCESS;
}

void cl_consumer_sync (context_t * context, int fd)
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

  struct crypt_data data = {
    .initialized = 0,
  };

  for (;;)
    {
      if (cl_handle_task(context, fd, &data) == FAIL)
	{
	  break;
	}
    }
}

void client_sync (context_t * context)
{
  int sock = socket (PF_INET, SOCK_STREAM, IPPROTO_TCP);
  if (sock < 0)
    {
      fprintf (stderr, "Socket error\n");
      return;
    }

  cl_consumer_sync (context, sock);

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
  
  if (!parse_args (&context, argc, argv) && context.run_mode != RM_CLIENT_SYNC)
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
    case RM_SERVER_SYNC :
      server_wrapper_sync (&context);
      break;
    case RM_CLIENT_SYNC :
      client_sync (&context);
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
