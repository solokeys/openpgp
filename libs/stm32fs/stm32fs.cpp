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

static const size_t FileHeaderSize = 16;
static const uint8_t FlashPadding = 8;

/*
 * --- Stm32fsFlash ---
 */

Stm32fsFlash::Stm32fsFlash() {
    FsConfig = nullptr;
    CurrentFsBlock = nullptr;
}
    
Stm32fsConfigBlock_t *Stm32fsFlash::Init(Stm32fsConfig_t *config) {
    FsConfig = config;

    if (FsConfig == nullptr)
        return nullptr;

    if (FsConfig->Blocks.size() == 0)
        return nullptr;

    for(auto &block: FsConfig->Blocks) {
        if (block.HeaderSectors.size() == 0 || block.DataSectors.size() == 0)
            return nullptr;
    }

    auto blk = SearchLastFsBlockInFlash();

    if (blk == nullptr) {
        blk = &FsConfig->Blocks[0];
        SetCurrentFsBlock(blk);
        if(!CreateFsBlock(FsConfig->Blocks[0], 1)) {
            return nullptr;        
        }
    }

    SetCurrentFsBlock(blk);

    return blk;
}

bool Stm32fsFlash::SetCurrentFsBlock(Stm32fsConfigBlock_t *block) {
    if (block == nullptr)
        return  false;
    
    CurrentFsBlock = block;
    return true;
}


size_t Stm32fsFlash::GetBaseAddress() {
    if (FsConfig == nullptr)
        return 0;
    
    return FsConfig->BaseBlockAddress;
}

uint32_t Stm32fsFlash::GetBlockAddress(uint8_t blockNum) {
    return blockNum * BlockSize;
}

uint32_t Stm32fsFlash::GetBlockFromAddress(uint32_t address) {
    return address / BlockSize;
}

bool Stm32fsFlash::FindBlockInConfigBlock(Stm32fsConfigBlock_t &block, uint32_t sectorNo) {
    if (std::find(block.HeaderSectors.begin(), block.HeaderSectors.end(), sectorNo) != block.HeaderSectors.end())
        return true;

    if (std::find(block.DataSectors.begin(), block.DataSectors.end(), sectorNo) != block.DataSectors.end())
        return true;

    return false;
}

bool Stm32fsFlash::FindBlockInCfg(std::vector<Stm32fsConfigBlock_t> blocks, uint32_t sectorNo) {
    for (auto &block : blocks) {
        if (FindBlockInConfigBlock(block, sectorNo))
            return true;
    }
    return false;
}

bool Stm32fsFlash::AddressInFlash(uint32_t address, size_t length, bool searchAllBlocks) {
    if (CurrentFsBlock != nullptr) {
        uint32_t curAddress = address;
        
        while (true) {
            uint32_t blockNo = GetBlockFromAddress(curAddress);
            if (!FindBlockInConfigBlock(*CurrentFsBlock, blockNo))
                break;
                
            curAddress = GetBlockAddress(blockNo) + BlockSize;
            if (curAddress > address + length - 1)
                return true;
        }
    }
    
    if (searchAllBlocks && FsConfig != nullptr) {
        uint32_t curAddress = address;
        
        while (true) {
            uint32_t blockNo = GetBlockFromAddress(curAddress);
            if (!FindBlockInCfg(FsConfig->Blocks, blockNo))
                break;
                
            curAddress = GetBlockAddress(blockNo) + BlockSize;
            if (curAddress > address + length - 1)
                return true;
        }
        
    }
    
    printf("out of memory!!! adr=%ld len=%zd\n", address, length);
    return false;
}

bool Stm32fsFlash::EraseFlashBlock(uint8_t blockNo) {
    printf("--erase  flash %d\n", blockNo);
    return FsConfig->fnEraseFlashBlock(blockNo);
}

bool Stm32fsFlash::isFlashEmpty(uint32_t address, size_t length, bool reverse, uint32_t *exceptAddr) {
    if(exceptAddr != nullptr)
        *exceptAddr = 0;
    
    // address - start of flash block
    uint32_t addr = (address / FlashPadding) * FlashPadding;
    
    // length - length of flash block
    size_t len = ((length + (address - addr)) / FlashPadding) * FlashPadding;
    if (len != length)
        len += FlashPadding;
    
    if (!AddressInFlash(addr, len, true))
        return false;

    uint8_t *data = (uint8_t *)(FsConfig->BaseBlockAddress + addr);
    
    if (!reverse) {
        for (uint32_t i = 0; i < len; i++)
            if (data[i] != 0xffU) {
                if (exceptAddr)
                    *exceptAddr = addr + i;
                return false;
            }
    } else {
        for (int i = len - 1; i >= 0; i--)
            if (data[i] != 0xffU) {
                if (exceptAddr != nullptr)
                    *exceptAddr = addr + i;
                return false;
            }
    }
    
    return true;
}

bool Stm32fsFlash::isFlashBlockEmpty(uint8_t blockNo) {
    return isFlashEmpty(GetBlockAddress(blockNo), BlockSize, false, nullptr);
}

bool Stm32fsFlash::WriteFlash(uint32_t address, uint8_t *data, size_t length) {
    if (!AddressInFlash(address, length, true))
        return false;
    printf("--write flash %d %d\n", address, length);
    return FsConfig->fnWriteFlash(address, data, length);
}

bool Stm32fsFlash::ReadFlash(uint32_t address, uint8_t *data, size_t length) {
    if (!AddressInFlash(address, length, true))
        return false;
    //printf("--read flash %d %d\n", address, length);
    return FsConfig->fnReadFlash(address, data, length);
}

bool Stm32fsFlash::EraseSectors(UVector &sectors) {
    for (auto &sector: sectors) {
        if (!isFlashBlockEmpty(sector)) {
            if (!EraseFlashBlock(sector))
                return false;
        }
    }
    return true;
}

bool Stm32fsFlash::EraseFs(Stm32fsConfigBlock_t &config) {
    if (!EraseSectors(config.HeaderSectors))
        return false;

    if (!EraseSectors(config.DataSectors))
        return false;
    
    return true;
}

bool Stm32fsFlash::CheckFsHeader(Stm32FSHeader_t &header) {
    if (header.HeaderStart.StartSeq != 0xaa55)
        return false;

    if (header.HeaderEnd.EndSeq != 0x55aa)
        return false;

    if (header.HeaderStart.Serial == 0)
        return false;
    
    return true;
}

void Stm32fsFlash::FillFsHeader(Stm32FSHeader_t &header, uint32_t serial) {
    header.HeaderStart.StartSeq = 0xaa55;
    header.HeaderEnd.EndSeq = 0x55aa;
    header.HeaderStart.Serial = serial;
}

bool Stm32fsFlash::GetFsHeader(Stm32fsConfigBlock_t &config, Stm32FSHeader_t &header) {
    ReadFlash(GetBlockAddress(config.HeaderSectors[0]), (uint8_t *)&header, sizeof(Stm32FSHeader_t));
    if (!CheckFsHeader(header)) 
        return false;
    
    return true;
}

uint32_t Stm32fsFlash::GetFsSerial(Stm32fsConfigBlock_t &config) {
    Stm32FSHeader_t header;

    if (GetFsHeader(config, header))
        return header.HeaderStart.Serial;

    return 0;
}

bool Stm32fsFlash::CreateFsBlock(Stm32fsConfigBlock_t &blockCfg, uint32_t serial) {
    if (!EraseFs(blockCfg))
        return false;

    Stm32FSHeader_t header = {{0,0,0},{0,0,0}};
    FillFsHeader(header, serial);

    return WriteFlash(GetBlockAddress(blockCfg.HeaderSectors[0]), (uint8_t *)&header, sizeof(header));
}

Stm32fsConfigBlock_t *Stm32fsFlash::SearchLastFsBlockInFlash() {
    uint32_t lastSerial = 0;
    Stm32fsConfigBlock_t *xblock = nullptr;
    for (auto &block: FsConfig->Blocks) {
        uint32_t serial = GetFsSerial(block);
        if (serial > 0 && lastSerial < serial) {
            lastSerial = serial;
            xblock = &block;
        }
    }

    return xblock;
}

Stm32fsConfigBlock_t *Stm32fsFlash::SearchNextFsBlockInFlash() {
    Stm32fsConfigBlock_t *nextBlk = nullptr;
    Stm32fsConfigBlock_t *lastBlk = SearchLastFsBlockInFlash();
    if (lastBlk == nullptr)
        return nullptr;
    uint32_t oldSerial = GetFsSerial(*lastBlk); // here max serial
    uint32_t newSerial = oldSerial;
    
    // search block with empty/non recognized header or serial less than oldSerial
    for (auto &block: FsConfig->Blocks) {
        uint32_t serial = GetFsSerial(block);
        if (serial == 0) {
            newSerial = 0;
            nextBlk = &block;
            break;
        }
        
        if (serial < oldSerial && serial < newSerial) {
            newSerial = serial;
            nextBlk = &block;
        }
    }
    
    return nextBlk;
}

/*
 * --- Stm32fs ---
 */

bool Stm32fs::SetCurrentFsBlock(Stm32fsConfigBlock_t *block) {
    if (block == nullptr)
        return false;
    
    CurrentFsBlock = block;
    flash.SetCurrentFsBlock(CurrentFsBlock);
    return true;
}

uint32_t Stm32fs::GetCurrentFsBlockSerial() {
    if (CurrentFsBlock == nullptr)
        return 0;
    
    return flash.GetFsSerial(*CurrentFsBlock);
}

bool Stm32fs::CheckValid() {
    return (Valid && CurrentFsBlock != nullptr);
}

uint32_t Stm32fs::GetFirstHeaderAddress() {
    if (CurrentFsBlock == nullptr)
        return 0;
    
    return flash.GetBlockAddress(CurrentFsBlock->HeaderSectors[0]) + sizeof(Stm32FSHeader_t);
}

uint32_t Stm32fs::GetNextHeaderAddress(uint32_t previousAddress) {
    uint32_t addr = previousAddress + FileHeaderSize;
    if (!flash.AddressInFlash(addr, FileHeaderSize))
        return 0;
    
    uint32_t xblock = flash.GetBlockFromAddress(addr);
    for (auto &sector: CurrentFsBlock->HeaderSectors) {
        if (xblock == sector)
            return addr;
    }
    return 0;
}

uint32_t Stm32fs::GetFirstHeader(Stm32FSFileRecord &header) {
    uint32_t addr = GetFirstHeaderAddress();
    if (addr == 0)
        return 0;

    if (!flash.ReadFlash(addr, (uint8_t *)&header, sizeof(Stm32FSFileRecord)))
        return 0;
    
    if (header.version.FileState == fsEmpty)
        return 0;
    
    return addr;
}

uint32_t Stm32fs::GetNextHeader(uint32_t previousAddress, Stm32FSFileRecord &header) {
    uint32_t addr = GetNextHeaderAddress(previousAddress);
    if (addr == 0)
        return 0;

    if (!flash.ReadFlash(addr, (uint8_t *)&header, sizeof(Stm32FSFileRecord)))
        return 0;
    
    if (header.version.FileState == fsEmpty)
        return 0;
    
    return addr;
}


Stm32FSFileHeader Stm32fs::SearchFileHeader(std::string_view fileName) {
    Stm32FSFileHeader header;
    header.FileState = fsEmpty;
    
    if (fileName.size() > FileNameMaxLen)
        return header;
    
    Stm32FSFileRecord filerec;
    uint32_t addr = GetFirstHeader(filerec);
    
    while(true) {
        if (addr == 0)
            break;

        std::string_view str = {filerec.header.FileName, strnlen(filerec.header.FileName, FileNameMaxLen)};
        
        if (str == fileName)
            return filerec.header;
        
        addr = GetNextHeader(addr, filerec);
    }
    
    
    return header;
}

Stm32FSFileHeader Stm32fs::SearchFileHeaderByID(uint16_t fileId) {
    Stm32FSFileHeader header;
    header.FileState = fsEmpty;

    if (fileId == 0)
        return header;

    Stm32FSFileRecord filerec;
    uint32_t addr = GetFirstHeader(filerec);

    while(true) {
        if (addr == 0)
            break;

        if (filerec.header.FileState == fsFileHeader && filerec.header.FileID == fileId)
            return filerec.header;

        addr = GetNextHeader(addr, filerec);
    }


    return header;
}

Stm32FSFileVersion Stm32fs::SearchFileVersion(uint16_t fileID) {
    Stm32FSFileVersion fver = {};
    fver.FileState = fsEmpty;
    
    if (fileID == 0)
        return fver;
    
    Stm32FSFileRecord filerec;
    uint32_t addr = GetFirstHeader(filerec);
    
    while(true) {
        if (addr == 0)
            break;

        if ((filerec.version.FileState == fsFileVersion || filerec.version.FileState == fsDeleted) && filerec.version.FileID == fileID) {
            fver = filerec.version;            
        }
        
        addr = GetNextHeader(addr, filerec);
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

        if(!flash.ReadFlash(addr, (uint8_t *)&filerec, sizeof(filerec)))
            return header;
        
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
        
        if (!flash.WriteFlash(addr, (uint8_t *)&header, sizeof(header))) {
            header.FileState = fsError;
            return header;
        }
    } else {
        NeedsOptimization = true;
    }
    
    return header;
}

bool Stm32fs::AppendFileVersion(Stm32FSFileVersion &version) {

    uint32_t addr = GetFirstHeaderAddress();
    if (!flash.AddressInFlash(addr, FileHeaderSize))
        return false;
    
    Stm32FSFileRecord filerec;
    while(true) {
        if (addr == 0)
            break;

        if (!flash.ReadFlash(addr, (uint8_t *)&filerec, sizeof(filerec)))
            break;
        
        // end of catalog
        if (filerec.header.FileState == fsEmpty)
            return flash.WriteFlash(addr, (uint8_t *)&version, sizeof(Stm32FSFileVersion));
        
        addr = GetNextHeaderAddress(addr);
    }
    NeedsOptimization = true;
    
    return false;
}

uint32_t Stm32fs::FindEmptyDataArea(size_t length) {
    uint32_t daddr = flash.GetBlockAddress(CurrentFsBlock->DataSectors[0]);
    uint32_t addr = GetFirstHeaderAddress();
    
    Stm32FSFileRecord filerec;
    while(true) {
        if (addr == 0)
            break;

        if (!flash.ReadFlash(addr, (uint8_t *)&filerec, sizeof(filerec)))
            break;
        
        // end of catalog
        if (filerec.version.FileState == fsEmpty)
            break;
        
       if (filerec.version.FileState == fsFileVersion && filerec.version.FileID != 0) {         
            if (filerec.version.FileAddress + filerec.version.FileSize > daddr)
                daddr = filerec.version.FileAddress + filerec.version.FileSize;
       }
        
        addr = GetNextHeaderAddress(addr);
    }
    
    // check for empty. because data writes before it writes a record to a header.
    uint32_t waddress = 0;
    while (!flash.isFlashEmpty(daddr, length, true, &waddress)) {
        if (waddress == 0)
            return 0;
        
        // FlashPadding
        daddr = waddress + 1;
        uint32_t aladdr = (daddr / FlashPadding) * FlashPadding;
        if (daddr != aladdr)
            daddr = aladdr + FlashPadding;
        
        if (!flash.AddressInFlash(daddr, length))
            return false;
    }    
    
    return daddr;
}

Stm32fs::Stm32fs(Stm32fsConfig_t config) {
    Valid = false;
    NeedsOptimization = false;
    CurrentFsBlock = nullptr;
    FsConfig = config;

    CurrentFsBlock = flash.Init(&FsConfig);
    if (CurrentFsBlock == nullptr)
        return;
    
    Valid = true;
}

Stm32fs::Stm32fs() {
    Valid = false;
    NeedsOptimization = false;
    CurrentFsBlock = nullptr;
}

bool Stm32fs::isValid() {
    return CheckValid();
}

bool Stm32fs::isNeedsOptimization() {
    return NeedsOptimization;
}

uint32_t Stm32fs::GetSize() {
    if (!CheckValid())
        return 0;
    
    return CurrentFsBlock->DataSectors.size() * BlockSize;
}

uint32_t Stm32fs::GetFreeMemory() {
    if (!CheckValid())
        return 0;

    int size = FindEmptyDataArea(8) - flash.GetBlockAddress(CurrentFsBlock->DataSectors[0]);
    int freesize = CurrentFsBlock->DataSectors.size() * BlockSize - size;

    if (freesize > 0)
        return freesize;
    else
        return 0;
}

uint32_t Stm32fs::GetFreeFileDescriptors() {
    if (!CheckValid())
        return 0;

    uint32_t addr = GetFirstHeaderAddress();
    
    uint32_t size = sizeof(Stm32FSHeader_t);
    Stm32FSFileRecord filerec;
    while(true) {
        if (addr == 0)
            break;

        if (!flash.ReadFlash(addr, (uint8_t *)&filerec, sizeof(filerec)))
            break;
        
        // end of catalog
        if (filerec.version.FileState == fsEmpty)
            break;
        
        size += FileHeaderSize;
        
        addr = GetNextHeaderAddress(addr);
    }

    return (CurrentFsBlock->HeaderSectors.size() * BlockSize - size) / 16;
}

Stm32fsStatistic Stm32fs::GetStatistic() {
    Stm32fsConfigBlock_t *block = CurrentFsBlock;
    Stm32fsStatistic stat = {};
    stat.Valid = false;
    if (!CheckValid())
        return stat;

    stat.HeaderSize = block->HeaderSectors.size() * BlockSize;
    stat.DataSize = block->DataSectors.size() * BlockSize;
    stat.DataFreeSize = GetFreeMemory();

    Stm32fsStatFileState StatIndex[stat.HeaderSize / 16];
    std::memset(StatIndex, 0x00, sizeof(StatIndex));

    size_t StatIndexId = 0;
    StatIndex[StatIndexId] = Stm32fsStatFileState::Header;
    StatIndexId++;

    uint32_t addr = GetFirstHeaderAddress();

    Stm32FSFileRecord filerec;
    while(StatIndexId < sizeof(StatIndex)) {
        if (addr == 0)
            break;

        if(!flash.ReadFlash(addr, (uint8_t *)&filerec, sizeof(filerec)))
            break;

        if (filerec.header.FileState == fsEmpty)
            StatIndex[StatIndexId] = Stm32fsStatFileState::Free;

        if (filerec.header.FileState == fsDeleted)
            StatIndex[StatIndexId] = Stm32fsStatFileState::DeletedFileVersion;

        if (filerec.header.FileState == fsFileHeader) {
            Stm32FSFileVersion ver = SearchFileVersion(filerec.header.FileID);
            if (ver.FileState == fsFileVersion)
                StatIndex[StatIndexId] = Stm32fsStatFileState::FileName;
            else
                StatIndex[StatIndexId] = Stm32fsStatFileState::DeletedFileName;
        }

        if (filerec.version.FileState == fsFileVersion) {
            Stm32FSFileVersion ver = SearchFileVersion(filerec.header.FileID);

            size_t sz = ver.FileSize;
            // if address is aligned - maybe the size of file should be aligned too
            if (ver.FileAddress % FlashPadding == 0)
                if (sz % FlashPadding != 0)
                    sz = sz + (FlashPadding - sz % FlashPadding);

            if (ver.FileState == fsFileVersion && ver.FileAddress == filerec.version.FileAddress) {
                StatIndex[StatIndexId] = Stm32fsStatFileState::FileVersion;
                stat.DataOccupiedSize += sz;
            } else {
                StatIndex[StatIndexId] = Stm32fsStatFileState::DeletedFileVersion;
                stat.DataDeletedSize += sz;
            }
        }

        addr = GetNextHeaderAddress(addr);
        StatIndexId++;
    }

    for (auto &val : StatIndex) {
        switch (val) {
        case Stm32fsStatFileState::Free:
            stat.HeaderFreeDescriptors++;
            break;
        case Stm32fsStatFileState::FileName:
            stat.HeaderFileDescriptors++;
            break;
        case Stm32fsStatFileState::FileVersion:
            stat.HeaderVersionDescriptors++;
            break;
        case Stm32fsStatFileState::DeletedFileName:
            stat.HeaderDeletedFileDescriptors++;
            break;
        case Stm32fsStatFileState::DeletedFileVersion:
            stat.HeaderDeletedVersionDescriptors++;
            break;
        default:
            stat.HeaderSystemDescriptors++;
        }
    }

    stat.HeaderFreeSize = stat.HeaderFreeDescriptors * FileHeaderSize;

    stat.Valid = true;
    return stat;
}

bool Stm32fs::FileExist(std::string_view fileName) {
    if (!CheckValid())
        return false;

    Stm32FSFileHeader header = SearchFileHeader(fileName);
    if (header.FileState != fsFileHeader)
        return false;
    
    Stm32FSFileVersion ver = SearchFileVersion(header.FileID);
    if (ver.FileState != fsFileVersion)
        return false;
     
    return true;
}

int Stm32fs::FileLength(std::string_view fileName) {
    if (!CheckValid())
        return false;

    Stm32FSFileHeader header = SearchFileHeader(fileName);
    if (header.FileState != fsFileHeader)
        return -1;
    
    Stm32FSFileVersion ver = SearchFileVersion(header.FileID);
    if (ver.FileState != fsFileVersion)
        return -2;
     
    return ver.FileSize;
}

bool Stm32fs::ReadFile(std::string_view fileName, uint8_t *data, size_t *length, size_t maxlength) {
    if (!CheckValid())
        return false;

    if (length != nullptr)
        *length = 0;

    Stm32FSFileHeader header = SearchFileHeader(fileName);
    if (header.FileState != fsFileHeader)
        return false;

    Stm32FSFileVersion ver = SearchFileVersion(header.FileID);
    if (ver.FileState != fsFileVersion)
        return false;

    size_t len = std::min((size_t)ver.FileSize, maxlength);
    if (!flash.ReadFlash(ver.FileAddress, data, len))
        return false;
    
    if (length != nullptr)
        *length = len;
     
    return true;
}

bool Stm32fs::GetFilePtr(std::string_view fileName, uint8_t **ptr, size_t *length) {
    if (!CheckValid())
        return false;

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
    if (!CheckValid())
        return false;

    Stm32FSFileHeader header = SearchFileHeader(fileName);
    if (header.FileState == fsEmpty) {
        header = AppendFileHeader(fileName);
        if (header.FileState == fsEmpty)
            return false;
    }
    
    uint32_t addr = FindEmptyDataArea(length);
    if (addr == 0) {
        NeedsOptimization = true;
        return false;
    }
    
    if (!flash.WriteFlash(addr, data, length))
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
    if (!CheckValid())
        return false;

    Stm32FSFileHeader header = SearchFileHeader(fileName);
    if (header.FileState != fsFileHeader)
        return false;
    
    // version not found or allready deleted - file deleted...
    Stm32FSFileVersion ver = SearchFileVersion(header.FileID);
    if (ver.FileState != fsFileVersion)
        return true;
    
    ver.FileState = fsDeleted;
    ver.FileAddress = 0;
    ver.FileSize = 0;
    if (!AppendFileVersion(ver))
        return false;

    return true;
}

bool fnmatch(std::string_view &pattern, std::string_view &name){
    if (pattern == name)
        return true;

    if (pattern == "*")
        return true;
    
    size_t xlen = std::min(pattern.size(), name.size());
    for (size_t i = 0; i < xlen; i++) {
        if (pattern[i] == '*')
            return true;
        if (pattern[i] != '?' &&
            pattern[i] != name[i])
            return false;
    }
    
    // exact match with length
    return (pattern.size() == name.size());
}

Stm32File_t *Stm32fs::FindFirst(std::string_view fileFilter, Stm32File_t *filePtr) {
    if (!CheckValid() || filePtr == nullptr)
        return nullptr;
    
    size_t slen = std::min(fileFilter.size(), sizeof(filePtr->FileFilterChr));
    std::memset(filePtr->FileFilterChr, 0, sizeof(filePtr->FileFilterChr));
    std::memcpy(filePtr->FileFilterChr, fileFilter.data(), slen);
    filePtr->FileFilter = std::string_view(filePtr->FileFilterChr, slen);
    
    std::memset(filePtr->FileNameChr, 0, sizeof(filePtr->FileNameChr));
    filePtr->FileName = std::string_view(filePtr->FileNameChr, 0);
    
    filePtr->FileAddress = 0;
    filePtr->FileSize = 0;
    filePtr->HeaderAddress = 0;

    return FindNext(filePtr);
}

Stm32File_t *Stm32fs::FindNext(Stm32File_t *filePtr) {
    if (!CheckValid() || filePtr == nullptr)
        return nullptr;
    
    if (filePtr->HeaderAddress == 0)
        filePtr->HeaderAddress = GetFirstHeaderAddress();
    else
        filePtr->HeaderAddress = GetNextHeaderAddress(filePtr->HeaderAddress);
    
    Stm32FSFileRecord filerec;
    while(true) {
        if (filePtr->HeaderAddress == 0)
            break;

        if (!flash.ReadFlash(filePtr->HeaderAddress, (uint8_t *)&filerec, sizeof(filerec)))
            break;
        
        // end of catalog
        if (filerec.header.FileState == fsEmpty)
            break;
        
        std::string_view str = {filerec.header.FileName, strnlen(filerec.header.FileName, FileNameMaxLen)};
        if (filerec.header.FileState == fsFileHeader && fnmatch(filePtr->FileFilter, str)) {

            Stm32FSFileVersion ver = SearchFileVersion(filerec.header.FileID);
            if (ver.FileState == fsFileVersion) {
                size_t slen = strnlen(filerec.header.FileName, FileNameMaxLen);
                std::memset(filePtr->FileNameChr, 0, sizeof(filePtr->FileNameChr));
                std::memcpy(filePtr->FileNameChr, filerec.header.FileName, slen);
                filePtr->FileName = std::string_view(filePtr->FileNameChr, slen);
                
                filePtr->FileID = filerec.header.FileID;
                
                filePtr->FileAddress = ver.FileAddress;
                filePtr->FileSize = ver.FileSize;
                
                return filePtr;
            }
        }
        
        filePtr->HeaderAddress = GetNextHeaderAddress(filePtr->HeaderAddress);
    }

    return nullptr;
}

bool Stm32fs::DeleteFiles(std::string_view fileFilter) {
    if (!CheckValid())
        return false;

    Stm32File_t srecm;
    Stm32File_t *rc = nullptr;
    
    rc = FindFirst(fileFilter, &srecm);
    while (rc != nullptr) {
        if (!DeleteFile(rc->FileName))
            return false;
        
        rc = FindNext(rc);
    }
    
    return true;
}

bool Stm32fs::Optimize() {
    if (!CheckValid())
        return false;

    Stm32fsOptimizer optimizer(*this);
    if (FsConfig.Blocks.size() > 1) {
        Stm32fsConfigBlock_t *nextBlock = flash.SearchNextFsBlockInFlash();
        if (nextBlock != nullptr) {
            bool res = optimizer.OptimizeMultiblock(*CurrentFsBlock, *nextBlock);
            if (res)
                CurrentFsBlock = nextBlock;
            return res;
        }
    }

    return optimizer.OptimizeViaRam(*CurrentFsBlock);
}

/*
 * --- Stm32fsFileList ---
 */

Stm32fsFileList::Stm32fsFileList() {
    Clear();
}

int Stm32fsFileList::FindEmptyID() {
    for (size_t i = 0; i < FileListLength; i++)
        if (FileList[i].isEmpty())
            return i;
    return -1;
}

void Stm32fsFileList::Clear() {
    std::memset((void *)FileList, 0x00, sizeof(FileList));
}

bool Stm32fsFileList::Empty() {
    return FileList[0].isEmpty();
}

int Stm32fsFileList::Size() {
    int id = FindEmptyID();
    if (id > 0)
        return id;
    
    return 0;        
}

bool Stm32fsFileList::Append(Stm32FSFileHeader &header, Stm32FSFileVersion &version) {
    if (header.FileName[0] == 0x00)
        return true;
    
    int id = FindEmptyID();
    if (id < 0)
        return false;
    
    std::memcpy(FileList[id].FileName, header.FileName, FileNameMaxLen);
    FileList[id].FileAddress = version.FileAddress;
    FileList[id].FileSize = version.FileSize;
    
    return true;
}

bool Stm32fsFileList::Sort() {
    for (size_t i = 0; i < FileListLength; i++) {
        if (FileList[i].isEmpty())
            break;

        for (size_t j = i + 1; i < FileListLength; j++) {
            if (FileList[j].isEmpty())
                break;
            
            if (FileList[i].FileAddress > FileList[j].FileAddress) {
                Stm32OptimizedFile_t t = FileList[i];
                FileList[i] = FileList[j];
                FileList[j] = t;            
            }
        }
    }
    
    return true;
}

bool Stm32fsFileList::Write(Stm32fsWriteCache &cache) {
    uint16_t fileID = 1;
    
    for (size_t i = 0; i < FileListLength; i++) {
        if (FileList[i].isEmpty())
            break;

        if (!cache.WriteFileHeader(FileList[i], fileID))
            return false;
    }
    
    return cache.Flush();
}

Stm32OptimizedFile_t &Stm32fsFileList::GetFileByID(size_t id) {
    if (id >= FileListLength)
        return FileList[0];

    return FileList[id];
}

/*
 * --- Stm32fsWriter ---
 */

bool Stm32fsWriter::Init(uint32_t offset) {
    if (sectors.size() == 0)
        return false;
    
    CurrentSectorID = 0;
    CurrentAddress = offset;
    
    if (!flash.EraseSectors(sectors))
        return false;
    
    return true;
}

bool Stm32fsWriter::Write(uint8_t *data, size_t len, uint32_t *newaddr) {
    if (CurrentSectorID < 0)
        return false;

    if (newaddr != nullptr)
        *newaddr = flash.GetBlockAddress(sectors[CurrentSectorID]) + CurrentAddress;
    
    // multisector write
    size_t totalwrlen = 0;
    while (len > 0) {
        if (CurrentSectorID < 0)
            return false;
        
        size_t blen = len;
        if (blen > BlockSize - CurrentAddress)
            blen = BlockSize - CurrentAddress;

        if (!flash.WriteFlash(flash.GetBlockAddress(sectors[CurrentSectorID]) + CurrentAddress, &data[totalwrlen], blen))
            return false;
       
        CurrentAddress += blen;
        // flash align
        uint32_t aladdr = (CurrentAddress / FlashPadding) * FlashPadding;
        if (CurrentAddress != aladdr)
            CurrentAddress = aladdr + FlashPadding;

        len -= blen;
        totalwrlen += blen;
        
        if (CurrentAddress >= BlockSize) {
            CurrentSectorID++;
            if (CurrentSectorID >= (int)sectors.size()) {
                CurrentSectorID = -1;
            } else {
                if (!flash.isFlashBlockEmpty(sectors[CurrentSectorID]))
                    if (!flash.EraseFlashBlock(sectors[CurrentSectorID]))
                        return false;
            }
                
            CurrentAddress = 0;
        }
    }

    return true;
}

bool Stm32fsWriter::WriteFsHeaderToTop(uint32_t serial) {
    if (CurrentSectorID < 0 || sectors.size() == 0)
        return false;
    
    Stm32FSHeader_t header;
    flash.FillFsHeader(header, serial);
    
    return flash.WriteFlash(flash.GetBlockAddress(sectors[0]), (uint8_t *)&header, sizeof(header));
}

bool Stm32fsWriter::WriteFileHeader(Stm32FSFileHeader &header) {
    if (CurrentSectorID < 0)
        return false;
    
    return Write((uint8_t *)&header, sizeof(header));
}

bool Stm32fsWriter::WriteFileVersion(Stm32FSFileVersion &version) {
    if (CurrentSectorID < 0)
        return false;
    
    return Write((uint8_t *)&version, sizeof(version));
}

bool Stm32fsWriter::AppendFileDesc(Stm32FSFileHeader &header, Stm32FSFileVersion &version) {
    if (!WriteFileHeader(header))
        return false;
    return WriteFileVersion(version);
}

bool Stm32fsWriter::Finish() {
    if (CurrentSectorID < 0)
        return false;
    
    CurrentSectorID = -1;
    CurrentAddress = 0;
    return true;
}

/*
 * --- Stm32fsWriteCache ---
 */

void Stm32fsWriteCache::ClearCache() {
    std::memset(cache, 0xffU, sizeof(cache));
}

bool Stm32fsWriteCache::WriteToFlash(uint8_t sectorNum) {
    
    size_t addr = flash.GetBaseAddress() + flash.GetBlockAddress(sectorNum);
    
    if (std::memcmp(cache, (void *)addr, BlockSize) == 0)
        return true;
    
    if (!flash.isFlashBlockEmpty(sectorNum))
        if (!flash.EraseFlashBlock(sectorNum))
            return false;
    
    return flash.WriteFlash(flash.GetBlockAddress(sectorNum), cache, BlockSize);
}

bool Stm32fsWriteCache::Init() {
    if (sectors.size() == 0)
        return false;
    
    ClearCache();
    CurrentSectorID = 0;
    CurrentAddress = 0;
    return true;
}

bool Stm32fsWriteCache::Write(uint8_t *data, size_t len) {
    if (CurrentSectorID < 0)
        return false;
    
    // multisector write
    size_t totalwrlen = 0;
    while (len > 0) {
        if (CurrentSectorID < 0)
            return false;
        
        size_t blen = len;
        if (blen > BlockSize - CurrentAddress)
            blen = BlockSize - CurrentAddress;

        std::memcpy(&cache[CurrentAddress], &data[totalwrlen], blen);
        CurrentAddress += blen;                            // flash align not needs because we write it in single block...

        len -= blen;
        totalwrlen += blen;
        
        if (CurrentAddress >= BlockSize) {
            if (!WriteToFlash(sectors[CurrentSectorID]))
                return false;

            CurrentSectorID++;
            if (CurrentSectorID >= (int)sectors.size())
                CurrentSectorID = -1;

            ClearCache();
            CurrentAddress = 0;
        }
    }
    
    return true;
}

bool Stm32fsWriteCache::WriteFsHeader(uint32_t serial) {
    if (CurrentSectorID < 0)
        return false;
    
    Stm32FSHeader_t header;
    flash.FillFsHeader(header, serial);
    
    return Write((uint8_t *)&header, sizeof(header));
}

bool Stm32fsWriteCache::WriteFileHeader(Stm32OptimizedFile_t &fileHeader, uint16_t &fileID) {
    if (CurrentSectorID < 0)
        return false;
    
    Stm32FSFullFileRecord fullFile = {0};
    fullFile.header.FileState = fsFileHeader;
    fullFile.header.FileID = fileID;
    std::memcpy(fullFile.header.FileName, fileHeader.FileName, FileNameMaxLen);

    fullFile.version.FileState = fsFileVersion;
    fullFile.version.FileID = fileID;
    fullFile.version.FileAddress = fileHeader.FileAddress;
    fullFile.version.FileSize = fileHeader.FileSize;
    
    fileID++;
    return Write((uint8_t *)&fullFile, sizeof(fullFile));
}

bool Stm32fsWriteCache::Flush() {
    if (CurrentSectorID < 0)
        return false;
    
    bool res = true;
    // if we have something to write
    if (CurrentAddress > 0)
        res = WriteToFlash(sectors[CurrentSectorID]);
    CurrentSectorID = -1;
    CurrentAddress = 0;
    return res;
}

/*
 * --- Stm32fsOptimizer ---
 */

Stm32fsOptimizer::Stm32fsOptimizer(Stm32fs &stm32fs) : fs{stm32fs} {
    
}

// multiblock optimization. from flash region to flash region.
bool Stm32fsOptimizer::OptimizeMultiblock(Stm32fsConfigBlock_t &inputBlock, Stm32fsConfigBlock_t &outputBlock) {
    uint32_t serial = fs.GetCurrentFsBlockSerial();
    fs.flash.EraseFs(outputBlock);
    
    Stm32fsWriter fhdrdata(fs.flash, outputBlock.HeaderSectors);
    fhdrdata.Init(sizeof(Stm32FSHeader_t));
    Stm32fsWriter fdata(fs.flash, outputBlock.DataSectors);
    fdata.Init();
    
    Stm32FSFileRecord filerec;
    uint32_t addr = fs.GetFirstHeader(filerec);
    
    while(true) {
        if (addr == 0)
            break;

        if (filerec.header.FileState == fsFileHeader) {
            Stm32FSFileVersion ver = fs.SearchFileVersion(filerec.header.FileID);
            if (ver.FileState == fsFileVersion) {
                uint32_t newAddr = 0;
                // 1st - data
                if (!fdata.Write((uint8_t *)(fs.flash.GetBaseAddress() + ver.FileAddress), ver.FileSize, &newAddr))
                    return false;
                // 2nd - header
                ver.FileAddress = newAddr;
                if (!fhdrdata.AppendFileDesc(filerec.header, ver))
                    return false;
            }
        }        
        addr = fs.GetNextHeader(addr, filerec);
    }
    
    if (!fhdrdata.WriteFsHeaderToTop(serial + 1))
        return false;

    fhdrdata.Finish();
    fdata.Finish();
    
    // switching to the new filesystem
    auto blk = fs.GetFlash().SearchLastFsBlockInFlash();
    if (blk == nullptr)
        return false;
    
    if (!fs.SetCurrentFsBlock(blk))
        return false;
    
    return true;
}

bool Stm32fsOptimizer::OptimizeViaRam(Stm32fsConfigBlock_t &block) {
    
    Stm32fsFileList fileList;

    Stm32FSFileRecord filerec;
    uint32_t addr = fs.GetFirstHeader(filerec);
    
    while(true) {
        if (addr == 0)
            break;

        if (filerec.header.FileState == fsFileHeader) {
            Stm32FSFileVersion ver = fs.SearchFileVersion(filerec.header.FileID);
            if (ver.FileState == fsFileVersion)
                if (!fileList.Append(filerec.header, ver))
                    return false;
        }
        
        addr = fs.GetNextHeader(addr, filerec);
    }
    
    uint32_t serial = fs.GetCurrentFsBlockSerial();
    
    if (fileList.Empty()) {
        return fs.flash.CreateFsBlock(block, serial + 1);
    }
    
    fileList.Sort();

    // optimize data sections
    if (true) {
        Stm32fsWriteCache cdata(fs.flash, block.DataSectors);
        
        if (!cdata.Init())
            return false;
        
        int fsize = fileList.Size();
        uint32_t curAddr = fs.flash.GetBlockAddress(block.DataSectors[0]);
        for (int i = 0; i < fsize; i++) {
            auto &file = fileList.GetFileByID(i);
            if (!cdata.Write((uint8_t *)(fs.flash.GetBaseAddress() + file.FileAddress), file.FileSize))
                return false;
            file.FileAddress = curAddr;
            curAddr += file.FileSize;
        }
        
        if (!cdata.Flush())
            return false;
        
    };
    
    Stm32fsWriteCache cache(fs.flash, block.HeaderSectors);
    if (!cache.Init())
        return false;

    if (!cache.WriteFsHeader(serial + 1))
        return false;

    if (!fileList.Write(cache))
        return false;

    return true;
}

void Stm32fsStatistic::Print() {
    printf("---- stm32fs statistic ----\n");
    printf("Header size: %d free: %d bytes\n", HeaderSize, HeaderFreeSize);
    printf("Descriptors free: %d sys: %d file: %d version: %d del file: %d del version %d\n",
           HeaderFreeDescriptors, HeaderSystemDescriptors,
           HeaderFileDescriptors, HeaderVersionDescriptors,
           HeaderDeletedFileDescriptors, HeaderDeletedVersionDescriptors);
    printf("Data size: %d free: %d occupied: %d deleted: %d delta: %d bytes\n",
           DataSize, DataFreeSize, DataOccupiedSize, DataDeletedSize,
           (int)DataSize - DataFreeSize - DataOccupiedSize - DataDeletedSize);
}
