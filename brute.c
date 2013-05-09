#include <stdio.h>
#define __USE_GNU
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

#define HELP_STRING "SYNTAX:\n	brute [ -i | -r ] [ -s | -m ] HASH\n"
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

typedef struct context_t{
	char *alph;
	int pswd_len;
	int alph_len;
	char *hash;
	brute_mode_t brute_mode;
	run_mode_t run_mode;
	pswd_t pswd;
	int complete;
} context_t;

typedef struct task_t {
	int index[PSWD_LEN];
	pswd_t pswd;
	int from, to;
} task_t;

typedef struct queue_t {
	task_t * tasks[QUEUE_LENGTH];
	int tail;
	int head;
	pthread_mutex_t tail_mutex;
	pthread_mutex_t head_mutex;
	sem_t full_sem;
	sem_t empty_sem;
} queue_t;

queue_t queue;

void clear_pass(context_t * context, task_t * task)
{
	memset(task->pswd, context->alph[0], context->pswd_len);
	clear_task_index(task);
}

void clear_task_index(task_t * task)
{
	int i=task->from;
	for(i; i<task->to; i++)
	{
		task->index[i]=0;
	}
}


void brute_iter(context_t * context, task_t * task,
		int (* check)(context_t * context, task_t * task))
{
	int i;
	clear_task_index(task);
	while(1)
	{
		if(check(context, task)==1)
		{
			break;
		}
		for (i=task->to - 1;
				i>=task->from && task->index[i]==context->alph_len - 1; i--)
		{
			task->index[i]=0;
			task->pswd[i]=context->alph[0];
		}
		if(i < task->from)
		{
			break;
		}
		task->index[i]++;
		task->pswd[i] = context->alph[task->index[i]];
	}
}

int brute_rec(context_t * context, task_t * task, int pos,
		int (* check)(context_t * context, task_t * task))
{
	if(pos>=task->to)
	{
		return check(context, task);
	}
	int i;
	for(i=0; i<context->alph_len; i++)
	{
		task->pswd[pos]=context->alph[i];
		if (brute_rec(context, task, pos+1, check) == 1)
			return 1;
	}
	return 0;
}

void brute_all(context_t * context, task_t * task,
		int (* check)(context_t * context, task_t * task))
{
	switch(context->brute_mode)
	{
		case BM_REC :
			brute_rec(context, task, task->from, check);
			break;
		case BM_ITER :
			brute_iter(context, task, check);
			break;
		default :
			break;
	}
}

int parse_args(context_t *context, int argc, char *argv[]) {
	int current_getopt = getopt(argc, argv, "rismh");
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
			case 'h' :
				return -1;
			default :
				break;
		}
		current_getopt = getopt(argc, argv, "rismh");
	}
	if(optind>=0 && optind<argc) {
		context->hash = argv[optind];
		context->hash[strlen(context->hash)] = '\0';
		return 0;
	}
	else {
		printf("Hash not found\n");
		return -1;
	}
}

int check_pswd(context_t * context, task_t * task) {
	if(strcmp(crypt(task->pswd, context->hash), context->hash) == 0) {
		memcpy(context->pswd, task->pswd, context->pswd_len + 1);
		context->complete = 1;
		return 1;
	}
	return 0;
}

int push_task(context_t * context, task_t * task) {
	if(context->complete==1) {
		pthread_exit(NULL);
	}
	task_t * new_task=(task_t *) malloc(sizeof(task_t));
	memcpy(new_task->pswd, task->pswd, context->pswd_len + 1);
	memcpy(new_task->index, task->index, context->pswd_len);
	new_task->from = task->to;
	new_task->to = context->pswd_len;
	queue_push(&queue, new_task);
	return 0;
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
	};
	clear_pass(context, &task);
	brute_all(context, &task, &push_task);
	task_t * stop=NULL;
	queue_push(&queue, stop);
	pthread_exit(NULL);
}

void consumer(context_t * context) {
	struct crypt_data data;
	data.initialized=0;
	while(1) {
		task_t * current_task = queue_pop(&queue);
		if(context->complete==1) {
			pthread_exit(NULL);
		}
		if(current_task==NULL) {
			queue_push(&queue, current_task);
			pthread_exit(NULL);
		}
		brute_all(context, current_task, &check_pswd);
		free(current_task);
	}
}

void threads_join(pthread_t * threads, int size) {
	int i;
	for(i=0; i<size; i++)
	{
		pthread_join(threads[i], NULL);
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
	threads_join(threads, threads_count);
}

void single_brute(context_t * context) {
	task_t task={
		.from = 0,
		.to=context->pswd_len,
	};
	clear_pass(context, &task);
	brute_all(context, &task, &check_pswd);
}

int context_init(context_t * context, int argc, char * argv[]) {
	context->alph=ALPH;
	context->pswd_len=PSWD_LEN;
	context->alph_len=strlen(ALPH);
	context->brute_mode=BM_ITER;
	context->run_mode=RM_SINGLE;
	context->complete=0;
	if (parse_args(context, argc, argv) != 0) {
		return -1;
	}
	return 0;
}

int main(int argc, char *argv[])
{
	context_t context;
	if(context_init(&context, argc, argv) == -1) {
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
