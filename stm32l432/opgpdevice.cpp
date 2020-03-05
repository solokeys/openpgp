/*
 Copyright 2019 SoloKeys Developers

 Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
 http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
 http://opensource.org/licenses/MIT>, at your option. This file may not be
 copied, modified, or distributed except according to those terms.
 */

#include "opgpdevice.h"

#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

#include "flash.h"
#include "memory_layout.h"
#include "device.h"
#include "util.h"

#include <spiffs.h>
static spiffs fs;

#define LOG_PAGE_SIZE 64
// 2048 for this CPU
#define BLOCK_SIZE PAGE_SIZE
#define TOTAL_FS_SIZE OPENPGP_NUM_PAGES*BLOCK_SIZE

void sprintfs();

PUT_TO_SRAM2 static u8_t spiffs_work_buf[LOG_PAGE_SIZE * 2];
PUT_TO_SRAM2 static u8_t spiffs_fds[32 * 4];
PUT_TO_SRAM2 static u8_t spiffs_cache_buf[(LOG_PAGE_SIZE + 32) * 4];

static s32_t hw_spiffs_read(u32_t addr, u32_t size, u8_t *dst) {
    if (addr < OPENPGP_START_PAGE_ADDR || addr + size > OPENPGP_END_PAGE_ADDR) {
        printf_device("spiffs read address %x error\n", addr);
        return SPIFFS_ERR_INTERNAL;
    }
    
    memmove(dst, (u8_t *)addr, size);
	return SPIFFS_OK;
}

static s32_t hw_spiffs_write(u32_t addr, u32_t size, u8_t *src) {
    if (addr < OPENPGP_START_PAGE_ADDR || addr + size > OPENPGP_END_PAGE_ADDR) {
        printf_device("spiffs write address %x error\n", addr);
        return SPIFFS_ERR_INTERNAL;
    }
    
    flash_write_ex(addr, src, size);
	return SPIFFS_OK;
}

static s32_t hw_spiffs_erase(u32_t addr, u32_t size) {
    for(u32_t x = 0; x < size; x += 2048) {
        uint8_t page = OPENPGP_START_PAGE + (addr - OPENPGP_START_PAGE_ADDR) / BLOCK_SIZE;
        if (page < OPENPGP_START_PAGE || page > OPENPGP_END_PAGE) {
            printf_device("spiffs erase address %x error\n", addr);
            return SPIFFS_ERR_INTERNAL;
        }
        flash_erase_page(page + x / 2048);
    }
	return SPIFFS_OK;
}

void hw_spiffs_mount() {
	spiffs_config cfg;
	cfg.phys_size = TOTAL_FS_SIZE;           // use size as in `memory_layout.h`
	cfg.phys_addr = OPENPGP_START_PAGE_ADDR; // start memory area for OpenPGP
	cfg.phys_erase_block = BLOCK_SIZE;       // block size as in CPU
	cfg.log_block_size = BLOCK_SIZE;         // let us not complicate things
	cfg.log_page_size = LOG_PAGE_SIZE;       // page size for filesystem

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
	printf_device("mount res: %i\n", res);

	if (res || !SPIFFS_mounted(&fs)) {
		res = SPIFFS_format(&fs);
		printf_device("format res: %i\n", res);
	}

	printf_device("SPIFFS mount OK.\n");
	sprintfs();
}

int hwinit() {
	hw_spiffs_mount();

	return 0;
}

bool fileexist(char* name) {
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

int readfile(char* name, uint8_t * buf, size_t max_size, size_t *size) {
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

int writefile(char* name, uint8_t * buf, size_t size) {
	spiffs_file fd = SPIFFS_open(&fs, name, SPIFFS_CREAT | SPIFFS_TRUNC | SPIFFS_RDWR, 0);
	if (fd < 0)
		return fd;

	int res = SPIFFS_write(&fs, fd, buf, size);

	int cres = SPIFFS_close(&fs, fd) < 0;
	if (cres < 0)
		return cres;

	return (res >= 0) ? 0 : res;
}

int deletefile(char* name) {
	return SPIFFS_remove(&fs, name);
}

void sprintfs() {
	spiffs_DIR d;
	struct spiffs_dirent e;
	struct spiffs_dirent *pe = &e;

	u32_t total = 0;
	u32_t used = 0;
	SPIFFS_info(&fs, &total, &used);
	printf_device("Memory total: %d used: %d\n", total, used);

	SPIFFS_opendir(&fs, "/", &d);
	while ((pe = SPIFFS_readdir(&d, pe))) {
		printf_device("  [%4d] %s\n", pe->size, pe->name);
	}
	SPIFFS_closedir(&d);
	return;
}

bool fnmatch(char *pattern, char*name){
    if (strcmp(pattern, name) == 0)
        return true;

    if (strcmp(pattern, "*") == 0)
        return true;
    
    size_t xlen = MIN(strlen(pattern), strlen(name));
    for (size_t i = 0; i < xlen; i++) {
        if (pattern[i] == '*')
            return true;
        if (pattern[i] != '?' &&
            pattern[i] != name[i])
            return false;
    }
    
    // exact match with length
    return (strlen(pattern) == strlen(name));
}

int deletefiles(char* name) {
	spiffs_DIR d;
	struct spiffs_dirent e;
	struct spiffs_dirent *pe = &e;
	int res;

	SPIFFS_opendir(&fs, "/", &d);
	while ((pe = SPIFFS_readdir(&d, pe))) {
		if (fnmatch(name, (char *)pe->name)) {
			spiffs_file fd = SPIFFS_open_by_dirent(&fs, pe, SPIFFS_RDWR, 0);
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

int hw_reset_fs_and_reboot(bool reboot) {
    for (uint8_t page = OPENPGP_START_PAGE; page <= OPENPGP_END_PAGE; page++)
        flash_erase_page(page);
    
    if (reboot)
        return hwreboot();
    else
        return 0;
}

int hwreboot() {
    device_reboot();
	return 0;
}

int gen_random_device_callback(void *parameters, uint8_t *data, size_t size) {
    return gen_random_device(data, size);
}

int gen_random_device(uint8_t * data, size_t size) {
    ctap_generate_rng(data, size);
    return 0;
}
