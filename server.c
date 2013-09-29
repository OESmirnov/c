#include <sys/socket.h>
#include <sys/un.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <pthread.h>

int serv (int fd)
{
  uint32_t size;
  if (read (fd, &size, sizeof (size)) < 0)
    {
      printf ("Read error\n");
      close (fd);
      return !0;
    }
  
  char str [size + 1];
  if (read (fd, str, size) < 0)
    {
      printf ("Read error\n");
      close (fd);	
      return !0;
    }
  str [size] = '\0';
  int cnt;
  sscanf (str, "%d", &cnt);
  printf ("Cnt from client: %d;    ", cnt);
  printf ("Next cnt: %d.\n", ++cnt);
  char reply [255];
  uint32_t reply_size = sprintf (reply, "%d", cnt);
  if (write (fd, &reply_size, sizeof (reply_size)) < 0)
    {
      printf ("Write error\n");
      close (fd);
      return !0;
    }

  if (write (fd, reply, reply_size) < 0)
    {
      printf ("Write error\n");
      close (fd);
      return !0;
    }
  return 0;
}
 
void serv_wrapper (void * arg)
{
  for (;;)
    {
      if (serv ((int) arg))
        {
          printf ("Server error\n");
          return;
        }
    }
}

int main (int argc, char ** argv)
{
  int sock = socket (PF_INET, SOCK_STREAM, IPPROTO_TCP);
  if (sock < 0)
    {
      printf("Socket error\n");
      return EXIT_FAILURE;
    }

  struct sockaddr_in serv_addr;
  memset (&serv_addr, 0, sizeof (serv_addr));
  serv_addr.sin_family = AF_INET;
  serv_addr.sin_addr.s_addr = INADDR_ANY;
  serv_addr.sin_port = htons (54321);
  if (bind (sock, (struct sockaddr *) &serv_addr, sizeof(serv_addr)) < 0)
    {
      printf ("Bind error\n");
      close (sock); 
      return EXIT_FAILURE;
    }

  if (listen (sock, 5) < 0)
    {
      printf ("Listen error\n");
      close(sock);
      return EXIT_FAILURE;
    }

  for (;;)
    {
      int fd = accept(sock, NULL, NULL);
      if (fd < 0)
	{
	  printf ("Accept error\n");
	  close(sock);
	  return EXIT_FAILURE;
	}
      pthread_t srv;
      pthread_create (&srv, NULL, (void *)serv_wrapper, (void *)fd);
    }
  shutdown (sock, SHUT_RDWR);
  close (sock);
  return EXIT_SUCCESS;
}
