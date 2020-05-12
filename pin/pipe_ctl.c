#include <stdio.h>
#include <Windows.h>

#define VERSION "0.11"
#define BUF_SIZE 0x1000

HANDLE stat_pipe;
char *buf;

int main(void)
{
  HANDLE hStdout;
	unsigned int num_read;
  hStdout = GetStdHandle(STD_OUTPUT_HANDLE);
	buf = (char *) malloc(BUF_SIZE);
	stat_pipe = CreateFile(
         "\\\\.\\pipe\\pin_stat",   // pipe name
         GENERIC_READ |  // read and write access
         GENERIC_WRITE,
         0,              // no sharing
         NULL,           // default security attributes
         OPEN_EXISTING,  // opens existing pipe
         0,              // default attributes
         NULL);          // no template file
  if(stat_pipe == INVALID_HANDLE_VALUE)
  {
    printf("error opening pipe\n");
    return -1;
  }

  while(1)
  {
    memset(buf, '\x00', BUF_SIZE);
    ReadFile(stat_pipe, buf, BUF_SIZE, &num_read, 0);
    if(num_read)
      printf("%s", buf);
    else
    {
      printf("no data from pipe\n");
      break;
    }
  }

  return 0;
}