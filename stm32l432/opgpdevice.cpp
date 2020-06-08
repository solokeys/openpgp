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
#include "opgputil.h"

#include "stm32fs.h"
#include "uECC.h"

static Stm32fs *fs = nullptr;

void sprintfs();

void OPTIMIZATION_O2 hw_stm32fs_init() {
    static Stm32fsConfig_t cfg;
    cfg.BaseBlockAddress = 0;
    cfg.SectorSize = PAGE_SIZE;
    cfg.Blocks = {{{OPENPGP_START_PAGE}, {OPENPGP_START_PAGE + 1, OPENPGP_START_PAGE + 2, OPENPGP_START_PAGE + 3}}};
    cfg.fnEraseFlashBlock = [](uint8_t blockNo){flash_erase_page(blockNo);return true;};
    cfg.fnWriteFlash = [](uint32_t address, uint8_t *data, size_t len){flash_write_ex(address, data, len);return true;};
    cfg.fnReadFlash = [](uint32_t address, uint8_t *data, size_t len){memcpy(data, (uint8_t *)address, len);return true;};

    static Stm32fs xfs = Stm32fs(cfg);
    fs = &xfs;

    if (fs->isValid()) {
        sprintfs();
        printf_device("stm32fs [%d] OK.\n", fs->GetCurrentFsBlockSerial());
    } else {
        printf_device("stm32fs error\n");
    }

    // check if it needs to call optimize...
    Stm32fsStatistic stat = fs->GetStatistic();
    stat.Print();
    if (stat.OptimizationNeeded()) {
        device_led(COLOR_RED);
        bool res = fs->Optimize();
        printf_device("stm32fs optimization %s\n", res ? "OK" : "ERROR");
        device_led(COLOR_GREEN);
    }
}

int hwinit() {
    //hw_reset_fs_and_reboot(false);  // fully erase fs...
    hw_stm32fs_init();

	return 0;
}

bool fileexist(char* name) {
    if (!fs)
        return false;

    return fs->FileExist(std::string_view(name));
}

int OPTIMIZATION_O2 readfile(char* name, uint8_t * buf, size_t max_size, size_t *size) {
    if (!fs) {
        printf("__error read %s %d\n", name, max_size);
        return 1;
    }
    if (fs->GetCurrentFsBlockSerial() == 0) printf("ERROR fs!!!\n");

    return fs->ReadFile(std::string_view(name), buf, size, max_size) ? 0 : 1;
}

int OPTIMIZATION_O2 writefile(char* name, uint8_t * buf, size_t size) {
    if (!fs)
        return 1;
    if (fs->GetCurrentFsBlockSerial() == 0) printf("ERROR fs!!!\n");

    bool res = fs->WriteFile(std::string_view(name), buf, size);

    // maybe we need to optimize
    if (!res && fs->isNeedsOptimization()) {
        device_led(COLOR_RED);
        res = fs->Optimize();
        printf_device("stm32fs write optimization %s\n", res ? "OK" : "ERROR");
        device_led(COLOR_GREEN);

        // try again
        if (res && fs->GetFreeMemory() >= size && fs->GetFreeFileDescriptors() > 0)
            res = fs->WriteFile(std::string_view(name), buf, size);
    }
    return res ? 0 : 1;
}

int deletefile(char* name) {
    if (!fs)
        return 1;

    return fs->DeleteFile(std::string_view(name)) ? 0 : 1;
}

void sprintfs() {
    printf_device("Memory total: %d free: %d free descriptors: %d\n",
                  fs->GetSize(), fs->GetFreeMemory(), fs->GetFreeFileDescriptors());

    Stm32File_t filerec;
    Stm32File_t *rc = nullptr;

    rc = fs->FindFirst("*", &filerec);
    while (rc != nullptr) {
        printf_device("  [%4d] %.*s\n", rc->FileSize, rc->FileName.size(), rc->FileNameChr);
        rc = fs->FindNext(rc);
    }

	return;
}

int deletefiles(char* name_filter) {
    if (!fs)
        return 1;

    return fs->DeleteFiles(std::string_view(name_filter)) ? 0 : 1;
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

static const uint8_t tls_ec_secp256k1       = 22;
static const uint8_t tls_ec_secp256r1       = 23;

static const struct uECC_Curve_t * ecdsa_get_curve(int curve) {
    switch(curve) {
    case tls_ec_secp256k1:
        return uECC_secp256k1();
    case tls_ec_secp256r1:
        return uECC_secp256r1();
    default:
        return nullptr;
    }
}

void ecdsa_init() {
    uECC_set_rng((uECC_RNG_Function)ctap_generate_rng);
}

bool ecdsa_keygen(uint8_t *sk, size_t *sklen, uint8_t *pk, size_t *pklen,int curve) {
    const struct uECC_Curve_t * curvep = ecdsa_get_curve(curve);
    if (curvep == nullptr)
        return false;

    if (uECC_make_key(pk + 1, sk, curvep) == 0)
        return false;

    pk[0] = 0x04; // uncompressed key

    if (sklen != nullptr)
        *sklen = uECC_curve_private_key_size(curvep);
    if (pklen != nullptr)
        *pklen = uECC_curve_public_key_size(curvep) + 1;

    return true;
}

int ecdsa_sign(uint8_t *sk, uint8_t *data, int len, uint8_t *sig, int curve) {

    const struct uECC_Curve_t * curvep = ecdsa_get_curve(curve);
    if (curvep == nullptr)
        return 0;


    if (uECC_sign(sk, data, len, sig, curvep) == 0)
        return 0;

    return uECC_curve_public_key_size(curvep);
}
