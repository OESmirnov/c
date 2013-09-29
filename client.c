#include <sys/socket.h>
#include <sys/un.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <pthread.h>
#include <time.h>

int client (int fd, int cnt)
{
  char str [255];
  uint32_t size = sprintf (str, "%d", cnt);  
  printf ("Cnt = %d\n", cnt);
  if (write (fd, &size, sizeof (size)) < 0)
    {
      printf ("Write error\n");
      close (fd);
      return !0;
    }

  if (write (fd, str, size) < 0)
    {
      printf ("Write error\n");
      close (fd);
      return !0;
    }
  
  uint32_t reply_size;
  if (read (fd, &reply_size, sizeof (reply_size)) < 0)
    {
      printf ("Read error\n");
      close (fd);
      return !0;
    }
    
  char reply [reply_size + 1];
  if (read (fd, reply, reply_size) < 0)
    {
      printf ("Read error\n");
      close (fd);	
      return !0;
    }
  reply [reply_size] = '\0';
  sscanf (reply, "%d", &cnt);
  printf ("Server reply: %d\n", cnt);
  return client (fd, cnt);
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
  serv_addr.sin_port = htons (54321);
  serv_addr.sin_addr.s_addr = INADDR_ANY;

  if (connect(sock, (struct sockaddr *) &serv_addr, sizeof (serv_addr)) < 0)
    {
      printf ("Connect error\n");
      close (sock);
      return EXIT_FAILURE;
    }
  
  srand (time (NULL));
  client (sock, rand() % 5000);
  shutdown (sock, SHUT_RDWR);
  close (sock);
  return EXIT_SUCCESS;
}
