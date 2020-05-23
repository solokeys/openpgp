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

#include "stm32fs.h"

static Stm32fs fs;

void sprintfs();

void hw_stm32fs_init() {
    static Stm32fsConfig_t cfg;
    cfg.BaseBlockAddress = 0;
    cfg.SectorSize = PAGE_SIZE;
    cfg.Blocks = {{{OPENPGP_START_PAGE}, {OPENPGP_START_PAGE + 1, OPENPGP_START_PAGE + 2, OPENPGP_START_PAGE + 3}}};
    cfg.fnEraseFlashBlock = [](uint8_t blockNo){flash_erase_page(blockNo);return true;};
    cfg.fnWriteFlash = [](uint32_t address, uint8_t *data, size_t len){flash_write_ex(address, data, len);return true;};
    cfg.fnReadFlash = [](uint32_t address, uint8_t *data, size_t len){memcpy(data, (uint8_t *)address, len);return true;};

    fs = Stm32fs(cfg);
    // TODO: check if it needs to call optimize...
    if (fs.isValid())
        printf_device("stm32fs [%d] OK.\n", fs.GetCurrentFsBlockSerial());
    else
        printf_device("stm32fs error\n");
}

int hwinit() {
device_led(COLOR_BLUE);
    hw_stm32fs_init();
device_led(COLOR_GREEN);

	return 0;
}

bool fileexist(char* name) {
    return fs.FileExist(name);
}

int readfile(char* name, uint8_t * buf, size_t max_size, size_t *size) {
    return fs.ReadFile(name, buf, size, max_size);
}

int writefile(char* name, uint8_t * buf, size_t size) {
    return fs.WriteFile(name, buf, size);
}

int deletefile(char* name) {
    return fs.DeleteFile(name);
}

void sprintfs() {
    printf_device("Memory total: %d free: %d free descriptors: %d\n",
                  fs.GetSize(), fs.GetFreeMemory(), fs.GetFreeFileDescriptors());

    /*SPIFFS_opendir(&fs, "/", &d);
	while ((pe = SPIFFS_readdir(&d, pe))) {
		printf_device("  [%4d] %s\n", pe->size, pe->name);
	}
    SPIFFS_closedir(&d);*/
	return;
}

int deletefiles(char* name_filter) {
    return fs.DeleteFiles(name_filter);
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
