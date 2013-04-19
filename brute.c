#include <stdio.h>
#define _GNU_SOURCE         
#include <crypt.h>
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

#define array_size(x) (sizeof(x)/sizeof(x[0]))

typedef char pswd_t[PSWD_LEN+1];

typedef enum brute_mode_t{
	BM_ITER,
	BM_REC,
} brute_mode_t;

typedef enum run_mode_t{
	RM_MULTI,
	RM_SINGLE,
} run_mode_t;

typedef enum check_mode_t{
	CM_CHECK,
	CM_PUSH,
} check_mode_t;

typedef struct context_t{
	char *alph;
	int pswd_len;
	int alph_len;
	char *hash;
	brute_mode_t brute_mode;
	run_mode_t run_mode;
} context_t;

typedef struct task_t {	
	int index[PSWD_LEN];
	pswd_t pswd;
	int from, to;
	check_mode_t check_mode;
} task_t;

typedef struct result_t {
	pswd_t pswd;
	int complete;
} result_t;

typedef struct queue_t {
	task_t * tasks[QUEUE_LENGTH];
	int tail;
	int head;
	pthread_mutex_t tail_mutex;
	pthread_mutex_t head_mutex;
	sem_t full_sem;
	sem_t empty_sem;
} queue_t;

struct crypt_data { 
      char keysched[16 * 8]; 
      char sb0[32768]; 
      char sb1[32768]; 
      char sb2[32768]; 
      char sb3[32768]; 
      char crypt_3_buf[14]; 
      char current_salt[2]; 
      long int current_saltbits; 
      int  direction, initialized; 
};

queue_t queue;
result_t result={
	.complete=0,
};

void clear_pass(context_t * context, task_t * task)
{
	int i=0;
	for(i; i<context->pswd_len; i++)
	{
		task->index[i]=0;
		task->pswd[i]=context->alph[0];
	}
	task->pswd[i]='\0';
}

void brute_iter(context_t * context, task_t * task)
{
	check(context, task);
	while(1)
	{
		if(task->index[task->from]==context->alph_len-1)
		{
			int i=task->from;
			while(task->index[i]==context->alph_len-1)
			{
				if(i==task->to - 1)
				{
					return;
				}
				task->index[i]=0;
				task->pswd[i]=context->alph[0];
				i++;
			}
			task->index[i]++;
			task->pswd[i] = context->alph[task->index[i]];
			check(context, task);
		}
		else
		{
			task->index[task->from]++;
			task->pswd[task->from] = context->alph[task->index[task -> from]];
			check(context, task);
		}
	}
}

void brute_rec(context_t * context, task_t * task, int pos)
{
	if(pos<task->from)
	{
		check(context, task);
		return;
	}
	int i;
	for(i=0;i<context->alph_len;i++)
	{
		task->pswd[pos]=context->alph[i];
		brute_rec(context, task, pos-1);
	}
}

void brute_all(context_t * context, task_t * task) {
	switch(context->brute_mode)
	{
		case BM_REC :
			brute_rec(context, task, task->to - 1);
			break;
		case BM_ITER :
			brute_iter(context, task);
			break;
		default :
			break;
	}
}

void parse_args(context_t *context, int argc, char *argv[]) {
	int current_getopt = getopt(argc, argv, "rism");
	while (current_getopt!=-1)
	{
		switch ( current_getopt )
		{
			case 'r' :
				context->brute_mode=BM_REC;
				break;
			case 'i' :
				context->brute_mode=BM_ITER;
				break;
			case 'm' :
				context->run_mode=RM_MULTI;
				break;
			case 's' :
				context->run_mode=RM_SINGLE;
				break;
			default :
				break;
		}
		current_getopt = getopt(argc, argv, "rism");
	}
	if(optind>=0 && optind<argc) {
		context->hash = argv[optind];
		context->hash[strlen(context->hash)] = '\0';
	}
	else {
		context->hash = '\0';
	}
}

int check(context_t * context, task_t * task) {
	switch (task->check_mode)
	{
		case CM_PUSH :
			if(result.complete==1) {
				pthread_exit(NULL);
			}
			task_t * new_task=(task_t *) malloc(sizeof(task_t));
			memcpy(new_task->pswd, task->pswd, context->pswd_len + 1);			
			memcpy(new_task->index, task->index, context->pswd_len);
			new_task->from = task->to;
			new_task->to = context->pswd_len;
			new_task->check_mode = CM_CHECK;
			queue_push(&queue, new_task);
			break;
		case CM_CHECK :
			if(strcmp(crypt(task->pswd, context->hash), context->hash) == 0) {
				memcpy(result.pswd, task->pswd, context->pswd_len + 1);
				result.complete = 1;
			}
			break;
		default :
			break;
	}
}

void queue_init(queue_t * queue) {
	queue->head=0;
	queue->tail=0;
	sem_init(&(queue->full_sem), 0, array_size(queue->tasks));
	sem_init(&(queue->empty_sem), 0, 0);
	pthread_mutex_init(&(queue->tail_mutex), NULL);
	pthread_mutex_init(&(queue->head_mutex), NULL);
}

void queue_push(queue_t * queue, task_t * task){
	sem_wait(&(queue->full_sem));
	pthread_mutex_lock(&(queue->tail_mutex));
	queue->tasks[queue->tail] = task;
	queue->tail++;
	if(queue->tail == array_size(queue->tasks)) {
		queue->tail = 0;
	}
	pthread_mutex_unlock(&(queue->tail_mutex));
	sem_post(&(queue->empty_sem));
}

task_t * queue_pop(queue_t * queue) {
	task_t * task;
	sem_wait(&(queue->empty_sem));
	pthread_mutex_lock(&(queue->head_mutex));
	task = queue->tasks[queue->head];
	queue->head++;
	if(queue->head == array_size(queue->tasks)) {
		queue->head = 0;
	}
	pthread_mutex_unlock(&(queue->head_mutex));
	sem_post(&(queue->full_sem));
	return task;
}

void producer(context_t * context) {
	task_t task={
		.from = 0,
		.to=context->pswd_len/2,
		.check_mode=CM_PUSH,
	};
	clear_pass(context, &task);
	brute_all(context, &task);
	task_t * stop=NULL;
	queue_push(&queue, stop);
	pthread_exit(NULL);
}

void consumer(context_t * context) {
	struct crypt_data data;
	data.initialized=0;
	while(1) {
		task_t * current_task = queue_pop(&queue);
		if(result.complete==1) {
			pthread_exit(NULL);
		}
		if(current_task==NULL) {
			queue_push(&queue, current_task);
			pthread_exit(NULL);			
		}
		brute_all(context, current_task);
		free(current_task);
	}
}

void multi_brute(context_t * context) {
	queue_init(&queue);
	int threads_count = sysconf(_SC_NPROCESSORS_ONLN) + 1;	
	pthread_t * threads;
	threads = (pthread_t *) malloc(threads_count * sizeof(pthread_t));
	pthread_create(&threads[0], NULL, &producer, context);
	int i=1;
	for(i; i<threads_count; i++)
	{
		pthread_create(&threads[i], NULL, &consumer, context);
	}
	for(i=0; i<threads_count; i++)
	{
		pthread_join(threads[i], NULL);
	}
}

void single_brute(context_t * context) {
	task_t task={
		.from = 0,
		.to=context->pswd_len,
		.check_mode=CM_CHECK,
	};
	clear_pass(context, &task);
	brute_all(context, &task);
}

int main(int argc, char *argv[])
{
	context_t context={
		.alph=ALPH,
		.pswd_len=PSWD_LEN,
		.alph_len=strlen(ALPH),
		.brute_mode=BM_ITER,
		.run_mode=RM_SINGLE,
	};
	parse_args(&context, argc, argv);
	if(context.hash == '\0') {
		printf("Hash not found\n");
		return;
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
	if(result.complete == 1) {		
		printf("Password: \"%s\"\n", result.pswd);
	} else {
		printf("Pass not found\n");
	}
	return 0;
}
