/*
  Copyright 2019 SoloKeys Developers

  Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
  http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
  http://opensource.org/licenses/MIT>, at your option. This file may not be
  copied, modified, or distributed except according to those terms.
 */

#include "stm32fs.h"

static const size_t BlockSize = 2048;

uint32_t Stm32fs::GetBlockAddress(uint8_t blockNum) {
    return blockNum * BlockSize;
}

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

bool Stm32fs::EraseFs(Stm32fsConfigBlock_t &config) {
    for (auto &sector: config.HeaderSectors) {
        if (!isFlashBlockEmpty(sector)) {
            if (!EraseFlashBlock(sector))
                return false;
        }
    }
    for (auto &sector: config.DataSectors) {
        if (!isFlashBlockEmpty(sector)) {
            if (!EraseFlashBlock(sector))
                return false;
        }
    }
    return true;
}

bool Stm32fs::CheckFsHeader(Stm32FSHeader_t &header) {
    if (header.HeaderStart.StartSeq != 0xaa55)
        return false;

    if (header.HeaderEnd.EndSeq != 0x55aa)
        return false;

    if (header.HeaderStart.Serial == 0)
        return false;
    
    return true;
}

void Stm32fs::FillFsHeader(Stm32FSHeader_t &header, uint32_t serial) {
    header.HeaderStart.StartSeq = 0xaa55;
    header.HeaderEnd.EndSeq = 0x55aa;
    header.HeaderStart.Serial = serial;
}

bool Stm32fs::CreateFsBlock(Stm32fsConfigBlock_t &blockCfg, uint32_t serial) {
    if (!EraseFs(blockCfg))
        return false;
    
    Stm32FSHeader_t header = {0};
    FillFsHeader(header, serial);
    
    return WriteFlash(GetBlockAddress(blockCfg.HeaderSectors[0]), (uint8_t *)&header, sizeof(header));
}

Stm32fsConfigBlock_t *Stm32fs::SearchLastFsBlockInFlash() {
    uint32_t Serial = 0;
    Stm32fsConfigBlock_t *xblock = nullptr;
    for (auto &block: FsConfig.Blocks) {
        Stm32FSHeader_t header;
        ReadFlash(GetBlockAddress(block.HeaderSectors[0]), (uint8_t *)&header, sizeof(header));
        if (CheckFsHeader(header)) {
            if (Serial > header.HeaderStart.Serial) {
                Serial = header.HeaderStart.Serial;
                xblock = &block;
            }
        }
    }
    
    return xblock;
}

Stm32fsConfigBlock_t *Stm32fs::SearchNextFsBlockInFlash() {
    
    return nullptr;
}

bool Stm32fs::GetCurrentFsBlockHeader(Stm32FSHeader_t &header) {
    if (CurrentFsBlock == nullptr)
        return false;
    
    Stm32FSHeader_t iheader;
    ReadFlash(GetBlockAddress(CurrentFsBlock->HeaderSectors[0]), (uint8_t *)&iheader, sizeof(iheader));
    if (CheckFsHeader(header)) {
        header = iheader;
        return true;
    }
    
    return false;
}

uint32_t Stm32fs::GetCurrentFsBlockSerial() {
    Stm32FSHeader_t header;
    
    if (GetCurrentFsBlockHeader(header))
        return header.HeaderStart.Serial;
    
    return 0;
}

Stm32fs::Stm32fs(Stm32fsConfig_t config) {
    Valid = false;
    CurrentFsBlock = nullptr;
    FsConfig = config;
    
    if (config.Blocks.size() == 0)
        return;

    if (config.Blocks[0].HeaderSectors.size() == 0 || config.Blocks[0].DataSectors.size() == 0)
        return;
    
    auto blk = SearchLastFsBlockInFlash();
    
    if (blk == nullptr) {
        Valid = CreateFsBlock(config.Blocks[0], 1);
        CurrentFsBlock = &config.Blocks[0];
        return;
    }
    
    CurrentFsBlock = blk;
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
