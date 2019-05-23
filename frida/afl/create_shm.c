#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/ipc.h>
#include <sys/shm.h>

int main(int argc, const char **argv)
{
   int shmid;
   key_t key = 0x1337;

   if ((shmid = shmget(key, 0x10000, IPC_CREAT | IPC_EXCL | 0666)) < 0)
      printf("Error getting shared memory id");
}
