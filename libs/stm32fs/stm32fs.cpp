/*
  Copyright 2019 SoloKeys Developers

  Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
  http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
  http://opensource.org/licenses/MIT>, at your option. This file may not be
  copied, modified, or distributed except according to those terms.
 */

#include "stm32fs.h"

#include <algorithm>
#include <cstring>

static const size_t BlockSize = 2048;
static const size_t FileHeaderSize = 16;

uint32_t Stm32fs::GetBlockAddress(uint8_t blockNum) {
    return blockNum * BlockSize;
}

uint32_t Stm32fs::GetBlockFromAddress(uint32_t address) {
    return address / BlockSize;
}

bool Stm32fs::EraseFlashBlock(uint8_t blockNo) {
    printf("- erase block %d\n", blockNo);
    return FsConfig.fnEraseFlashBlock(blockNo);
}

bool Stm32fs::isFlashEmpty(uint32_t address, size_t length, bool reverse, uint32_t *exceptAddr) {
    if(exceptAddr)
        *exceptAddr = 0;
    uint8_t *data = (uint8_t *)(FsConfig.BaseBlockAddress + address);
    
    if (!reverse) {
        for (uint32_t i = 0; i < length; i++)
            if (data[i] != 0xffU) {
                printf("empty except addr=%d len=%zd\n", address, length);
                if (exceptAddr)
                    *exceptAddr = address + i;
                return false;
            }
    } else {
        for (int i = length - 1; i >= 0; i--)
            if (data[i] != 0xffU) {
                if (exceptAddr)
                    *exceptAddr = address + i;
                return false;
            }
    }
    
    printf("empty OK addr=%d len=%zd\n", address, length);
    return true;
}

bool Stm32fs::isFlashBlockEmpty(uint8_t blockNo) {
    return isFlashEmpty(GetBlockAddress(blockNo), BlockSize, false, nullptr);
}

bool Stm32fs::WriteFlash(uint32_t address, uint8_t *data, size_t length) {
    printf("- write flash %x [%zd]\n", address, length);
    return FsConfig.fnWriteFlash(address, data, length);
}

bool Stm32fs::ReadFlash(uint32_t address, uint8_t *data, size_t length) {
    printf("- read flash %x [%zd]\n", address, length);
    return FsConfig.fnReadFlash(address, data, length);
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
    if (CheckFsHeader(iheader)) {
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

uint32_t Stm32fs::GetFirstHeaderAddress() {
    if (CurrentFsBlock == nullptr)
        return 0;
    
    return GetBlockAddress(CurrentFsBlock->HeaderSectors[0]) + sizeof(Stm32FSHeader_t);
}

uint32_t Stm32fs::GetNextHeaderAddress(uint32_t previousAddress) {
    uint32_t addr = previousAddress + FileHeaderSize;
    
    uint32_t xblock = GetBlockFromAddress(addr);
    printf("addr=%d xblock=%d\n", addr, xblock);
    for (auto &sector: CurrentFsBlock->HeaderSectors) {
        if (xblock == sector)
            return addr;
    }
    return 0;
}

Stm32FSFileHeader Stm32fs::SearchFileHeader(std::string_view fileName) {
    Stm32FSFileHeader header;
    header.FileState = fsEmpty;
    
    if (fileName.size() > FileNameMaxLen)
        return header;
    
    uint32_t addr = GetFirstHeaderAddress();
    
    Stm32FSFileRecord filerec;
    while(true) {
        if (addr == 0)
            break;

        ReadFlash(addr, (uint8_t *)&filerec, sizeof(filerec));
        
        // end of catalog
        if (filerec.header.FileState == fsEmpty)
            break;
        
        std::string_view str = {filerec.header.FileName, FileNameMaxLen};
        
        if (str == fileName)
            return filerec.header;
        
        addr = GetNextHeaderAddress(addr);
    }
    
    
    return header;
}

Stm32FSFileVersion Stm32fs::SearchFileVersion(uint16_t fileID) {
    Stm32FSFileVersion fver = {0};
    fver.FileState = fsEmpty;
    
    if (fileID == 0)
        return fver;
    
    uint32_t addr = GetFirstHeaderAddress();
    
    Stm32FSFileRecord filerec;
    while(true) {
        if (addr == 0)
            break;

        ReadFlash(addr, (uint8_t *)&filerec, sizeof(filerec));
        
        // end of catalog
        if (filerec.version.FileState == fsEmpty)
            break;

        if ((filerec.version.FileState == fsFileVersion || filerec.version.FileState == fsDeleted) && filerec.version.FileID == fileID) {
            fver = filerec.version;            
        }
        
        addr = GetNextHeaderAddress(addr);
    }
    
    return fver;
}

Stm32FSFileHeader Stm32fs::AppendFileHeader(std::string_view fileName) {
    Stm32FSFileHeader header = SearchFileHeader(fileName);
    if(header.FileState == fsFileHeader)
        return header;
    
    uint16_t fileID = 0;
    uint32_t addr = GetFirstHeaderAddress();
    
    Stm32FSFileRecord filerec;
    while(true) {
        if (addr == 0)
            break;

        ReadFlash(addr, (uint8_t *)&filerec, sizeof(filerec));
        
        // end of catalog
        if (filerec.header.FileState == fsEmpty)
            break;
        
        if (filerec.header.FileID > fileID)
            fileID = filerec.header.FileID;
        
        addr = GetNextHeaderAddress(addr);
    }

    if (addr != 0) {
        header.FileState = fsFileHeader;
        header.FileID = fileID + 1;
        std::memset(header.FileName, 0x00, FileNameMaxLen);
        std::memcpy(header.FileName, fileName.data(), std::min(fileName.size(), FileNameMaxLen));
        
        WriteFlash(addr, (uint8_t *)&header, sizeof(header));
    } else {
        NeedsOptimization = true;
    }
    
    return header;
}

bool Stm32fs::AppendFileVersion(Stm32FSFileVersion &version) {

    uint32_t addr = GetFirstHeaderAddress();
    
    Stm32FSFileRecord filerec;
    while(true) {
        if (addr == 0)
            break;

        ReadFlash(addr, (uint8_t *)&filerec, sizeof(filerec));
        
        // end of catalog
        if (filerec.header.FileState == fsEmpty)
            return WriteFlash(addr, (uint8_t *)&version, sizeof(Stm32FSFileVersion));
        
        addr = GetNextHeaderAddress(addr);
    }
    NeedsOptimization = true;
    
    return false;
}

uint32_t Stm32fs::FindEmptyDataArea(size_t length) {
    uint32_t daddr = GetBlockAddress(CurrentFsBlock->DataSectors[0]);
    uint32_t addr = GetFirstHeaderAddress();
    
    Stm32FSFileRecord filerec;
    while(true) {
        if (addr == 0)
            break;

        ReadFlash(addr, (uint8_t *)&filerec, sizeof(filerec));
        
        // end of catalog
        if (filerec.version.FileState == fsEmpty)
            break;
        
       if (filerec.version.FileState == fsFileVersion && filerec.version.FileID != 0) {         
            if (filerec.version.FileAddress + filerec.version.FileSize > daddr)
                daddr = filerec.version.FileAddress + filerec.version.FileSize;
       }
        
        addr = GetNextHeaderAddress(addr);
    }
    
    // check for  0xff empty
    
    
    return daddr;
}

Stm32fs::Stm32fs(Stm32fsConfig_t config) {
    Valid = false;
    NeedsOptimization = false;
    CurrentFsBlock = nullptr;
    FsConfig = config;
    
    if (FsConfig.Blocks.size() == 0)
        return;

    if (FsConfig.Blocks[0].HeaderSectors.size() == 0 || FsConfig.Blocks[0].DataSectors.size() == 0)
        return;
    
    auto blk = SearchLastFsBlockInFlash();
    
    if (blk == nullptr) {
        Valid = CreateFsBlock(FsConfig.Blocks[0], 1);
        CurrentFsBlock = &FsConfig.Blocks[0];
        return;
    }
    
    CurrentFsBlock = blk;
    Valid = true;
}

bool Stm32fs::isValid() {
    return Valid;
}

bool Stm32fs::isNeedsOptimization() {
    return NeedsOptimization;
}

Stm32File_t *Stm32fs::FindFirst(std::string_view fileFilter, Stm32File_t *filePtr) {

    return nullptr;
}

Stm32File_t *Stm32fs::FindNext(Stm32File_t *filePtr) {
    
    return nullptr;
}

bool Stm32fs::FileExist(std::string_view fileName) {
    Stm32FSFileHeader header = SearchFileHeader(fileName);
    if (header.FileState != fsFileHeader)
        return false;
    
    Stm32FSFileVersion ver = SearchFileVersion(header.FileID);
    if (ver.FileState != fsFileVersion)
        return false;
     
    return true;
}

bool Stm32fs::ReadFile(std::string_view fileName, uint8_t *data, size_t *length, size_t maxlength) {
    Stm32FSFileHeader header = SearchFileHeader(fileName);
    if (header.FileState != fsFileHeader)
        return false;
    
    Stm32FSFileVersion ver = SearchFileVersion(header.FileID);
    if (ver.FileState != fsFileVersion)
        return false;
    
    size_t len = std::min((size_t)ver.FileSize, maxlength);
    ReadFlash(ver.FileAddress, data, len);
    *length = len;
     
    return false;
}

bool Stm32fs::GetFilePtr(std::string_view fileName, uint8_t **ptr, size_t *length) {
    Stm32FSFileHeader header = SearchFileHeader(fileName);
    if (header.FileState != fsFileHeader)
        return false;
    
    Stm32FSFileVersion ver = SearchFileVersion(header.FileID);
    if (ver.FileState != fsFileVersion)
        return false;
    
    *ptr = (uint8_t *)(FsConfig.BaseBlockAddress + ver.FileAddress);
    *length = ver.FileSize;

    return true;
}

bool Stm32fs::WriteFile(std::string_view fileName, uint8_t *data, size_t length) {
    Stm32FSFileHeader header = SearchFileHeader(fileName);
    if (header.FileState == fsEmpty) {
        header = AppendFileHeader(fileName);
        if (header.FileState == fsEmpty)
            return false;
    }
    
    uint32_t addr = FindEmptyDataArea(length);
    if (addr == 0)
        return false;
    
    if (!WriteFlash(addr, data, length))
        return false;
    
    Stm32FSFileVersion ver = {0};
    ver.FileState = fsFileVersion;
    ver.FileID = header.FileID;
    ver.FileAddress = addr;
    ver.FileSize = length;
    
    if (!AppendFileVersion(ver))
        return false;
    
    return true;
}

bool Stm32fs::DeleteFile(std::string_view fileName) {
    Stm32FSFileHeader header = SearchFileHeader(fileName);
    if (header.FileState != fsFileHeader)
        return false;
    
    // version not found or allready deleted - file deleted...
    Stm32FSFileVersion ver = SearchFileVersion(header.FileID);
    if (ver.FileState != fsFileVersion)
        return true;
    
    ver.FileState = fsDeleted;
    if (!AppendFileVersion(ver))
        return false;

    return true;
}

bool Stm32fs::DeleteFiles(std::string_view fileFilter) {
    
    return false;
}

bool Stm32fs::Optimize() {
    
    return false;
}
