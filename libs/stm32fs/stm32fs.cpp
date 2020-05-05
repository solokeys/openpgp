/*
  Copyright 2019 SoloKeys Developers

  Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
  http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
  http://opensource.org/licenses/MIT>, at your option. This file may not be
  copied, modified, or distributed except according to those terms.
 */

#include "stm32fs.h"

bool Stm32fs::EraseFlashBlock(uint8_t blockNo) {
    printf("- erase block %d\n", blockNo);
    return FsConfig.fnEraseFlashBlock(blockNo);
}

bool Stm32fs::isFlashBlockEmpty(uint8_t blockNo) {
    return false;
}

bool Stm32fs::WriteFlash(uint32_t address, uint8_t *data, size_t length) {
    printf("- write flash %x [%zd]\n", address, length);
    return FsConfig.fnWriteFlash(FsConfig.BaseBlockAddress + address, data, length);
}

bool Stm32fs::ReadFlash(uint32_t address, uint8_t *data, size_t length) {
    printf("- read flash %x [%zd]\n", address, length);
    return FsConfig.fnReadFlash(FsConfig.BaseBlockAddress + address, data, length);
}

bool Stm32fs::CreateFsBlock(Stm32fsConfigBlock_t &blockCfg) {
    for (auto &sector: blockCfg.HeaderSectors) {
        if (!isFlashBlockEmpty(sector)) {
            if (!EraseFlashBlock(sector))
                return false;
        }
    }
    

    return true;
}

Stm32fsConfigBlock_t *Stm32fs::SearchLastFsBlockInFlash() {
    
    return nullptr;
}

Stm32fsConfigBlock_t *Stm32fs::SearchNextFsBlockInFlash() {
    
    return nullptr;
}

Stm32fs::Stm32fs(Stm32fsConfig_t config) {
    Valid = false;
    FsConfig = config;
    
    if (config.Blocks.size() == 0)
        return;

    if (config.Blocks[0].HeaderSectors.size() == 0 || config.Blocks[0].DataSectors.size() == 0)
        return;
    
    auto blk = SearchLastFsBlockInFlash();
    
    if (blk == nullptr) {
        Valid = CreateFsBlock(config.Blocks[0]);
        return;
    }
    
    Valid = true;
}

bool Stm32fs::isValid() {
    return Valid;
}

Stm32File_t *Stm32fs::FindFirst(std::string_view fileFilter, Stm32File_t *filePtr) {

    return nullptr;
}

Stm32File_t *Stm32fs::FindNext(Stm32File_t *filePtr) {
    
    return nullptr;
}

bool Stm32fs::ReadFile(std::string_view fileName, uint8_t *data, size_t *length, size_t maxlength) {
    
    return false;
}

bool Stm32fs::GetFilePtr(std::string_view fileName, uint8_t **ptr, size_t *length) {
    
    return false;
}

bool Stm32fs::WriteFile(std::string_view fileName, uint8_t *data, size_t length) {
    
    return false;
}

bool Stm32fs::DeleteFile(std::string_view fileName) {
    
    return false;
}

bool Stm32fs::DeleteFiles(std::string_view fileFilter) {
    
    return false;
}

bool Stm32fs::Optimize() {
    
    return false;
}
