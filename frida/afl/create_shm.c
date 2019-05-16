#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/ipc.h>
#include <sys/shm.h>

int main(int argc, const char **argv)
{
   int shmid;
   key_t key = 0x20137;
   char *shared_memory;

   if ((shmid = shmget(key, 0xffff, IPC_CREAT | 0666)) < 0)
      printf("Error getting shared memory id");
}