#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdlib.h>

int main(int argc, char  **argv)
{
	ssize_t default_len = 1024;
	int fd = open("/dev/memaudit", O_RDWR);
	char *temp = (char *)malloc(sizeof(char *));
	if(argv[1] == NULL) {
		printf("argv is null\n");
	}
	else {
		free(temp);
		temp = argv[1];
		write(fd, temp, strlen(temp));
	}
	read(fd, temp, default_len);
	printf("Read: %s\n", temp);
	return 0;
}
