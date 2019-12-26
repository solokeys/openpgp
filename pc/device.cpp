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

#define SPIFFS_MODE

#ifdef SPIFFS_MODE
#include <spiffs.h>
static spiffs fs;
static uint8_t fsbuf[2048*10] = {0};
static char *SpiffsFileName = (char *)"filesystem.spiffs";
#endif

#define LOG_PAGE_SIZE 64

bool ifileexist(char* name);
int ireadfile(char* name, uint8_t * buf, size_t max_size, size_t *size);
int iwritefile(char* name, uint8_t * buf, size_t size);
int sprintfs();

static u8_t spiffs_work_buf[LOG_PAGE_SIZE * 2];
static u8_t spiffs_fds[32 * 4];
static u8_t spiffs_cache_buf[(LOG_PAGE_SIZE + 32) * 4];

static s32_t hw_spiffs_read(u32_t addr, u32_t size, u8_t *dst) {
	memcpy(dst, fsbuf + addr, size);
	return SPIFFS_OK;
}

static s32_t hw_spiffs_write(u32_t addr, u32_t size, u8_t *src) {
	memcpy(fsbuf + addr, src, size);
	return SPIFFS_OK;
}

static s32_t hw_spiffs_erase(u32_t addr, u32_t size) {
	memset(fsbuf + addr, 0xff, size);
	return SPIFFS_OK;
}

void hw_spiffs_mount() {
	spiffs_config cfg;
	cfg.phys_size = 10*2048; // use all spi flash
	cfg.phys_addr = 0;       // start spiffs at start of spi flash
	cfg.phys_erase_block = 2048; // according to datasheet
	cfg.log_block_size = 2048;   // let us not complicate things
	cfg.log_page_size = LOG_PAGE_SIZE; // as we said

	cfg.hal_read_f = hw_spiffs_read;
	cfg.hal_write_f = hw_spiffs_write;
	cfg.hal_erase_f = hw_spiffs_erase;

	int res = SPIFFS_mount(&fs,
		&cfg,
		spiffs_work_buf,
		spiffs_fds,
		sizeof(spiffs_fds),
		spiffs_cache_buf,
		sizeof(spiffs_cache_buf),
		0);
	printf("mount res: %i\n", res);

	if (res || !SPIFFS_mounted(&fs)) {
		res = SPIFFS_format(&fs);
		printf("format res: %i\n", res);
	}

	uint32_t total = 0;
	uint32_t used = 0;
	SPIFFS_info(&fs, &total, &used);
	printf("Mounted OK. Memory total: %d used: %d\n", total, used);
	sprintfs();
}

int hwinit() {
#ifdef SPIFFS_MODE
	memset(fsbuf, 0xff, sizeof(fsbuf));

	if (ifileexist(SpiffsFileName)) {
		size_t size = 0;
		ireadfile(SpiffsFileName, fsbuf, sizeof(fsbuf), &size);
		if (size != sizeof(fsbuf))
			memset(fsbuf, 0xff, sizeof(fsbuf));

		printf("Loaded OK\n");
	}

	hw_spiffs_mount();
#endif

	return 0;
}

int spiffs_save() {
	return iwritefile(SpiffsFileName, fsbuf, sizeof(fsbuf));
}


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

bool ifileexist(char* name) {
	char fname[100] = {0};
	char dir[] = "./data/";
	make_work_directory(dir);

	strcpy(fname, dir);
	strcat(fname, name);

	// check if it exist and have read permission
	if (access(fname, R_OK) != 0)
		return false;

	return true;
}

bool sfileexist(char* name) {
	spiffs_DIR d;
	struct spiffs_dirent e;
	struct spiffs_dirent *pe = &e;

	SPIFFS_opendir(&fs, "/", &d);
	while ((pe = SPIFFS_readdir(&d, pe))) {
		if (0 == strcmp(name, (char *)pe->name)) {
			return true;
		}
	}
	return false;
}

bool fileexist(char* name) {
#ifdef SPIFFS_MODE
	return sfileexist(name);
#else
	return ifileexist(name);
#endif
}

int ireadfile(char* name, uint8_t * buf, size_t max_size, size_t *size) {

	char fname[100] = {0};
	char dir[] = "./data/";
	make_work_directory(dir);

	strcpy(fname, dir);
	strcat(fname, name);

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

int sreadfile(char* name, uint8_t * buf, size_t max_size, size_t *size) {
	*size = 0;

	spiffs_file fd = SPIFFS_open(&fs, name, SPIFFS_RDWR, 0);
	if (fd < 0)
		return fd;

	int res = SPIFFS_read(&fs, fd, buf, max_size);

	*size = res;
	int cres = SPIFFS_close(&fs, fd) < 0;
	if (cres < 0)
		return cres;

	return (res >= 0) ? 0 : res;
}

bool readfile(char* name, uint8_t * buf, size_t max_size, size_t *size) {
#ifdef SPIFFS_MODE
	return sreadfile(name, buf, max_size, size);
#else
	return ireadfile(name, buf, max_size, size);
#endif
}

int iwritefile(char* name, uint8_t * buf, size_t size) {
	char fname[100] = {0};
	char dir[] = "./data/";
	make_work_directory(dir);

	strcpy(fname, dir);
	strcat(fname, name);

	FILE *f  = fopen(fname, "w");
	if (f <= 0)
		return 2;

	size_t sz = fwrite(buf, 1, size, f);
	fclose(f);

	if (sz != size)
		return 3;

	return 0;
}

int swritefile(char* name, uint8_t * buf, size_t size) {
	spiffs_file fd = SPIFFS_open(&fs, name, SPIFFS_CREAT | SPIFFS_TRUNC | SPIFFS_RDWR, 0);
	if (fd < 0)
		return fd;

	int res = SPIFFS_write(&fs, fd, buf, size);

	int cres = SPIFFS_close(&fs, fd) < 0;
	if (cres < 0)
		return cres;

	// debug only!
	spiffs_save();

	return (res >= 0) ? 0 : res;
}

int writefile(char* name, uint8_t * buf, size_t size) {
#ifdef SPIFFS_MODE
	return swritefile(name, buf, size);
#else
	return iwritefile(name, buf, size);
#endif
}

int ideletefile(char* name) {
	char fname[100] = {0};
	char dir[] = "./data/";
	make_work_directory(dir);

	strcpy(fname, dir);
	strcat(fname, name);

	remove(fname);
	return 0;
}
int deletefile(char* name) {
#ifdef SPIFFS_MODE
	return SPIFFS_remove(&fs, name);
#else
	return ideletefile(name);
#endif
}

int ideletefiles(char* name) {
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

int sprintfs() {
	spiffs_DIR d;
	struct spiffs_dirent e;
	struct spiffs_dirent *pe = &e;

	uint32_t total = 0;
	uint32_t used = 0;
	SPIFFS_info(&fs, &total, &used);
	printf("Memory total: %d used: %d\n", total, used);

	SPIFFS_opendir(&fs, "/", &d);
	while ((pe = SPIFFS_readdir(&d, pe))) {
		printf("  [%4d] %s\n", pe->size, pe->name);
	}
	SPIFFS_closedir(&d);
	return 0;
}

int sdeletefiles(char* name) {
	spiffs_DIR d;
	struct spiffs_dirent e;
	struct spiffs_dirent *pe = &e;
	int res;

	sprintfs();

	SPIFFS_opendir(&fs, "/", &d);
	while ((pe = SPIFFS_readdir(&d, pe))) {
		if ((fnmatch(name, (char *)pe->name, 0)) == 0) {
			fd = SPIFFS_open_by_dirent(&fs, pe, SPIFFS_RDWR, 0);
			if (fd < 0)
				return SPIFFS_errno(&fs);
			res = SPIFFS_fremove(&fs, fd);
			if (res < 0)
				return SPIFFS_errno(&fs);
		}
	}
	SPIFFS_closedir(&d);
	return 0;
}

int deletefiles(char* name) {
#ifdef SPIFFS_MODE
	return sdeletefiles(name);
#else
	return ideletefiles(name);
#endif
}

int hwreboot() {

	return 0;
}

