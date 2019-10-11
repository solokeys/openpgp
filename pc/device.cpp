#include <sys/time.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <netinet/in.h>
#include <time.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <fcntl.h>
#include <dirent.h>
#include <fnmatch.h>

int udp_server()
{
    static int run_already = 0;
    static int fd = -1;
    if (run_already && fd >= 0) return fd;
    run_already = 1;

    if ( (fd = socket(AF_INET, SOCK_DGRAM, 0)) < 0 ) {
        perror( "socket failed" );
        return 1;
    }

    struct timeval read_timeout;
    read_timeout.tv_sec = 0;
    read_timeout.tv_usec = 10;
    if (setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &read_timeout, sizeof(struct timeval)) != 0)
    {
        perror( "setsockopt" );
        exit(1);
    }

    struct sockaddr_in serveraddr;
    memset( &serveraddr, 0, sizeof(serveraddr) );
    serveraddr.sin_family = AF_INET;
    serveraddr.sin_port = htons( 8111 );
    serveraddr.sin_addr.s_addr = htonl( INADDR_ANY );

    if ( bind(fd, (struct sockaddr *)&serveraddr, sizeof(serveraddr)) < 0 ) {
        perror( "bind failed" );
        exit(1);
    }
    return fd;
}

int udp_recv(int fd, uint8_t * buf, int size)
{

    fd_set         input;
    FD_ZERO(&input);
    FD_SET(fd, &input);
    struct timeval timeout;
    timeout.tv_sec  = 0;
    timeout.tv_usec = 100;
    int n = select(fd + 1, &input, NULL, NULL, &timeout);
    if (n == -1) {
        perror("select\n");
        exit(1);
    } else if (n == 0)
        return 0;
    if (!FD_ISSET(fd, &input))
    {

    }
    int length = recvfrom( fd, buf, size, 0, NULL, 0 );
    if ( length < 0 ) {
        perror( "recvfrom failed" );
        exit(1);
    }
    return length;
}


void udp_send(int fd, uint8_t * buf, int size)
{
    struct sockaddr_in serveraddr;
    memset( &serveraddr, 0, sizeof(serveraddr) );
    serveraddr.sin_family = AF_INET;
    serveraddr.sin_port = htons( 7112 );
    serveraddr.sin_addr.s_addr = htonl( 0x7f000001 ); // (127.0.0.1)

    if (sendto( fd, buf, size, 0, (struct sockaddr *)&serveraddr, sizeof(serveraddr)) < 0 ) {
        perror( "sendto failed" );
        exit(1);
    }
}

static int fd = 0;
void ccid_init()
{
    fd = udp_server();
}

uint32_t ccid_recv(uint8_t * msg)
{
    int l;
    l = udp_recv(fd, msg, 1024);
    return l;
}

void ccid_send(uint8_t * msg, uint32_t sz)
{
    udp_send(fd, msg, sz);
}

void make_work_directory(char* dir) {
	if (access(dir, F_OK) != 0) {
		mkdir(dir, 0777);
	}
}

bool fileexist(char* name) {

	char fname[100] = {0};
	char dir[] = "./data/";
	make_work_directory(dir);

	strcpy(fname, dir);
	strcat(fname, name);

	printf("is exist: %s\n", fname);
	// check if it exist and have read permission
	if (access(fname, R_OK) != 0)
		return false;

	return true;
}

int readfile(char* name, uint8_t * buf, size_t max_size, size_t *size) {

	char fname[100] = {0};
	char dir[] = "./data/";
	make_work_directory(dir);

	strcpy(fname, dir);
	strcat(fname, name);

	printf("read: %s\n", fname);
	// check if it exist and have read permission
	if (access(fname, R_OK) != 0)
		return 1;

	FILE *f  = fopen(fname, "r");
	if (f <= 0)
		return 2;

	*size = fread(buf, 1, max_size, f);
	fclose(f);

	return 0;
}

int writefile(char* name, uint8_t * buf, size_t size) {
	char fname[100] = {0};
	char dir[] = "./data/";
	make_work_directory(dir);

	strcpy(fname, dir);
	strcat(fname, name);

	printf("write: %s\n", fname);
	FILE *f  = fopen(fname, "w");
	if (f <= 0)
		return 2;

	size_t sz = fwrite(buf, 1, size, f);
	fclose(f);

	if (sz != size)
		return 3;

	return 0;
}

int deletefile(char* name) {
	char fname[100] = {0};
	char dir[] = "./data/";
	make_work_directory(dir);

	strcpy(fname, dir);
	strcat(fname, name);

	printf("delete: %s\n", fname);
	remove(fname);
	return 0;
}

int deletefiles(char* name) {
	char fname[100] = {0};
	char dir[] = "./data/";
	make_work_directory(dir);

    DIR *dirp=opendir(dir);
    struct dirent entry;
    struct dirent *dp=&entry;
    while((dp = readdir(dirp)))
    {
	    if((fnmatch(name, dp->d_name,0)) == 0)
	    {
	 	    printf("delete: %s\n",dp->d_name);
 		    strcpy(fname, dir);
		    strcat(fname, dp->d_name);
		    remove(fname);
	    }
    }
    closedir(dirp);

    strcpy(fname, dir);
    strcat(fname, name);

    return 0;
}

int hwreboot() {

	return 0;
}

