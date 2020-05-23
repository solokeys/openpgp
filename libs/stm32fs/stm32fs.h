/*
  Copyright 2019 SoloKeys Developers

  Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
  http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
  http://opensource.org/licenses/MIT>, at your option. This file may not be
  copied, modified, or distributed except according to those terms.
 */
 
#ifndef SRC_STM32FS_H_
#define SRC_STM32FS_H_

#include <vector>
#include <string>
#include <functional>

#define PACKED __attribute__((packed))

static const size_t BlockSize = 2048;
static const size_t FileNameMaxLen = 13;

using UVector = std::vector<uint8_t>;

struct PACKED Stm32FSHeaderStart_t {
    uint16_t StartSeq;
    uint32_t Serial;
    uint16_t none;
};

struct PACKED Stm32FSHeaderEnd_t {
    uint32_t none;
    uint16_t none2;
    uint16_t EndSeq;
};

// 16b start of fs sector
struct PACKED Stm32FSHeader_t {
    Stm32FSHeaderStart_t HeaderStart;
    Stm32FSHeaderEnd_t HeaderEnd;
};

// 0xff - empty block, 0x01 - file header, 0x80 - file, 0x00 - deleted
enum Stm32FileState_e {
    fsDeleted = 0x00,
    fsFileHeader = 0x01,
    fsFileVersion = 0x80,
    fsError = 0xf0,
    fsEmpty = 0xff
};

struct PACKED Stm32FSFileHeader {
    uint8_t FileState;
    uint16_t FileID;
    char FileName[FileNameMaxLen];
};

struct PACKED Stm32FSFileVersion {
    uint8_t FileState;
    uint16_t FileID;
    uint8_t none;
    uint32_t none2;
    uint32_t FileAddress;
    uint32_t FileSize;
};

union PACKED Stm32FSFileRecord {
    Stm32FSFileHeader header;
    Stm32FSFileVersion version;
};

struct PACKED Stm32FSFullFileRecord {
    Stm32FSFileHeader header;
    Stm32FSFileVersion version;
};

struct Stm32File_t {
    char FileFilterChr[FileNameMaxLen * 2]; 
    std::string_view FileFilter;
    char FileNameChr[FileNameMaxLen]; 
    std::string_view FileName;
    uint16_t FileID;
    uint32_t FileAddress;
    uint32_t FileSize;
    uint32_t HeaderAddress;
};

struct Stm32fsConfigBlock_t {
    std::vector<uint8_t> HeaderSectors;
    std::vector<uint8_t> DataSectors;
};

struct Stm32fsConfig_t {
    std::vector<Stm32fsConfigBlock_t> Blocks;
    size_t BaseBlockAddress;
    uint32_t SectorSize; //  2048
    std::function<bool (uint8_t)> fnEraseFlashBlock;
    std::function<bool (uint32_t, uint8_t*, size_t)> fnWriteFlash; // address, data, length
    std::function<bool (uint32_t, uint8_t*, size_t)> fnReadFlash;  // address, data, length
};

class Stm32fsFlash {
private:
    Stm32fsConfig_t *FsConfig;
    Stm32fsConfigBlock_t *CurrentFsBlock;
public:
    Stm32fsFlash();
    
    Stm32fsConfigBlock_t *Init(Stm32fsConfig_t *config);
    bool SetCurrentFsBlock(Stm32fsConfigBlock_t *block);
    
    void SetFlashBlocksCount(uint32_t count);
    void SetFlashBlocksCountByCfg(Stm32fsConfigBlock_t *cfg);
    
    size_t GetBaseAddress();
    uint32_t GetBlockAddress(uint8_t blockNum);
    uint32_t GetBlockFromAddress(uint32_t address);
    bool FindBlockInCfg(std::vector<Stm32fsConfigBlock_t> blocks, uint32_t sectorNo);
    bool FindBlockInConfigBlock(Stm32fsConfigBlock_t &block, uint32_t sectorNo);
    bool AddressInFlash(uint32_t address, size_t length, bool searchAllBlocks = false);
    bool EraseFlashBlock(uint8_t blockNo);
    bool isFlashEmpty(uint32_t address, size_t length, bool reverse, uint32_t *exceptAddr);
    bool isFlashBlockEmpty(uint8_t blockNo);
    bool WriteFlash(uint32_t address, uint8_t *data, size_t length);
    bool ReadFlash(uint32_t address, uint8_t *data, size_t length);

    bool CheckFsHeader(Stm32FSHeader_t &header);
    void FillFsHeader(Stm32FSHeader_t &header, uint32_t serial);
    bool GetFsHeader(Stm32fsConfigBlock_t &config, Stm32FSHeader_t &header);
    uint32_t GetFsSerial(Stm32fsConfigBlock_t &config);
    bool EraseSectors(UVector &sectors);
    bool EraseFs(Stm32fsConfigBlock_t &config);
    bool CreateFsBlock(Stm32fsConfigBlock_t &blockCfg, uint32_t serial);
    
    Stm32fsConfigBlock_t *SearchLastFsBlockInFlash();
    Stm32fsConfigBlock_t *SearchNextFsBlockInFlash();
};

class Stm32fs {
private:
    friend class Stm32fsOptimizer;
    
    Stm32fsConfig_t FsConfig = {};
    Stm32fsConfigBlock_t *CurrentFsBlock;
    bool Valid;
    bool NeedsOptimization;
    
    Stm32fsFlash flash;
    
    bool CheckValid();
    uint32_t GetFirstHeaderAddress();
    uint32_t GetNextHeaderAddress(uint32_t previousAddress);
    uint32_t GetFirstHeader(Stm32FSFileRecord &header);
    uint32_t GetNextHeader(uint32_t previousAddress, Stm32FSFileRecord &header);
    
    Stm32FSFileHeader SearchFileHeader(std::string_view fileName);
    Stm32FSFileVersion SearchFileVersion(uint16_t fileID);
    Stm32FSFileHeader AppendFileHeader(std::string_view fileName);
    bool AppendFileVersion(Stm32FSFileVersion &version);
    uint32_t FindEmptyDataArea(size_t length);
public:
    Stm32fs(Stm32fsConfig_t config);
    Stm32fs();

    bool isValid();
    bool isNeedsOptimization();

    bool SetCurrentFsBlock(Stm32fsConfigBlock_t *block);
    uint32_t GetCurrentFsBlockSerial();
    Stm32fsFlash &GetFlash(){return flash;};
    uint32_t GetSize();
    uint32_t GetFreeMemory();
    uint32_t GetFreeFileDescriptors();
    
    Stm32File_t *FindFirst(std::string_view fileFilter, Stm32File_t *filePtr);
    Stm32File_t *FindNext(Stm32File_t *filePtr);

	bool FileExist(std::string_view fileName);
    int FileLength(std::string_view fileName);
	bool ReadFile(std::string_view fileName, uint8_t *data, size_t *length, size_t maxlength);
    bool GetFilePtr(std::string_view fileName, uint8_t **ptr, size_t *length);
	bool WriteFile(std::string_view fileName, uint8_t *data, size_t length);

    bool DeleteFile(std::string_view fileName);
    bool DeleteFiles(std::string_view fileFilter);
    
    bool Optimize();
};

struct PACKED Stm32OptimizedFile_t {
    char FileName[FileNameMaxLen];
    uint32_t FileAddress;
    uint16_t FileSize;
    bool isEmpty() {return (FileName[0] == 0 && FileAddress == 0 && FileSize == 0);}
};

class Stm32fsWriter {
private:
    Stm32fsFlash &flash;
    UVector &sectors;
    int CurrentSectorID = -1;
    size_t CurrentAddress = 0;
public:
    Stm32fsWriter(Stm32fsFlash &fsFlash, UVector &sec) :flash{fsFlash}, sectors{sec}{};
    
    bool Init(uint32_t offset = 0);
    bool Write(uint8_t *data, size_t len, uint32_t *newaddr = nullptr);
    bool WriteFsHeaderToTop(uint32_t serial);
    bool WriteFileHeader(Stm32FSFileHeader &header);
    bool WriteFileVersion(Stm32FSFileVersion &version);
    bool AppendFileDesc(Stm32FSFileHeader &header, Stm32FSFileVersion &version);
    bool Finish();
};

class Stm32fsWriteCache {
private:
    Stm32fsFlash &flash;
    UVector &sectors;
    int CurrentSectorID = -1;
    size_t CurrentAddress = 0;
    uint8_t cache[BlockSize] = {0};
    
    void ClearCache();
    bool WriteToFlash(uint8_t sectorNum);
public:
    Stm32fsWriteCache(Stm32fsFlash &fsFlash, UVector &sec) :flash{fsFlash}, sectors{sec}{};
    
    bool Init();
    bool Write(uint8_t *data, size_t len);
    bool WriteFsHeader(uint32_t serial);
    bool WriteFileHeader(Stm32OptimizedFile_t &fileHeader, uint16_t &fileID);
    bool Flush();
};
    
class Stm32fsFileList {
private:
    static const size_t FileListLength = 110;
    Stm32OptimizedFile_t FileList[FileListLength] = {0};
    
    int FindEmptyID();
public:
    Stm32fsFileList();
    
    void Clear();
    bool Empty();
    int Size();
    bool Append(Stm32FSFileHeader &header, Stm32FSFileVersion &version);
    bool Sort();
    bool Write(Stm32fsWriteCache &cache);
    Stm32OptimizedFile_t &GetFileByID(size_t id);
};

class Stm32fsOptimizer {
private:
    Stm32fs &fs;
public:
    Stm32fsOptimizer(Stm32fs &stm32fs);
    
    bool OptimizeViaRam(Stm32fsConfigBlock_t &block);
    bool OptimizeMultiblock(Stm32fsConfigBlock_t &inputBlock, Stm32fsConfigBlock_t &outputBlock);
};

template<typename T>
size_t strnlen(const T* s, size_t max_len) {
    return std::find(s, s + max_len, 0) - s;
}

#endif  // SRC_STM32FS_H_
