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
    fsEmpty = 0xff,
    fsFileHeader = 0x01,
    fsFileVersion = 0x80,
    fsDeleted = 0x00
};

static const size_t FileNameMaxLen = 13;

struct PACKED Stm32FSFileHeader {
    uint8_t FileState;
    uint16_t FileID;
    char FileName[FileNameMaxLen];
};

struct PACKED Stm32FSFileVersion {
    uint8_t FileState;
    uint16_t FileID;
    uint8_t none;
    uint32_t FileAddress;
    uint32_t FileSize;
};

union PACKED Stm32FSFileRecord {
    Stm32FSFileHeader header;
    Stm32FSFileVersion version;
};

struct Stm32File_t {
    std::string_view FileName;
    size_t FileSize;
};

struct Stm32fsConfigBlock_t {
    std::vector<uint8_t> HeaderSectors;
    std::vector<uint8_t> DataSectors;
};

struct Stm32fsConfig_t {
    std::vector<Stm32fsConfigBlock_t> Blocks;
    uint32_t BaseBlockAddress;
    uint32_t SectorSize; //  2048
    std::function<bool (uint8_t)> fnEraseFlashBlock;
    std::function<bool (uint32_t, uint8_t*, size_t)> fnWriteFlash; // address, data, length
    std::function<bool (uint32_t, uint8_t*, size_t)> fnReadFlash; // address, data, length
};

class Stm32fs {
private:
    Stm32fsConfig_t FsConfig = {};
    Stm32fsConfigBlock_t *CurrentFsBlock;
    bool Valid;
    
    uint32_t GetBlockAddress(uint8_t blockNum);
    uint32_t GetBlockFromAddress(uint32_t address);
    bool EraseFlashBlock(uint8_t blockNo);
    bool isFlashBlockEmpty(uint8_t blockNo);
    bool WriteFlash(uint32_t address, uint8_t *data, size_t length);
    bool ReadFlash(uint32_t address, uint8_t *data, size_t length);
    
    bool CheckFsHeader(Stm32FSHeader_t &header);
    void FillFsHeader(Stm32FSHeader_t &header, uint32_t serial);
    bool EraseFs(Stm32fsConfigBlock_t &config);
    bool CreateFsBlock(Stm32fsConfigBlock_t &blockCfg, uint32_t serial);
    
    Stm32fsConfigBlock_t *SearchLastFsBlockInFlash();
    Stm32fsConfigBlock_t *SearchNextFsBlockInFlash();
    bool GetCurrentFsBlockHeader(Stm32FSHeader_t &header);
    
    bool CheckIsFlashEmpty(uint8_t *data, size_t size);
    //Stm32FSHeader_t *CheckFsHeader(uint8_t *data);
    
    uint32_t GetFirstHeaderAddress();
    uint32_t GetNextHeaderAddress(uint32_t previousAddress);
    
    Stm32FSFileHeader SearchFileHeader(std::string_view fileName);
    Stm32FSFileVersion SearchFileVersion(uint16_t fileID);
    Stm32FSFileHeader AppendFileHeader(std::string_view fileName);
    bool AppendFileVersion(Stm32FSFileVersion &version);
public:
	Stm32fs(Stm32fsConfig_t config);
    
    bool isValid();

    uint32_t GetCurrentFsBlockSerial();
    
    Stm32File_t *FindFirst(std::string_view fileFilter, Stm32File_t *filePtr);
    Stm32File_t *FindNext(Stm32File_t *filePtr);

	bool FileExist(std::string_view fileName);
	bool ReadFile(std::string_view fileName, uint8_t *data, size_t *length, size_t maxlength);
    bool GetFilePtr(std::string_view fileName, uint8_t **ptr, size_t *length);
	bool WriteFile(std::string_view fileName, uint8_t *data, size_t length);

    bool DeleteFile(std::string_view fileName);
    bool DeleteFiles(std::string_view fileFilter);
    
    bool Optimize();
};

#endif  // SRC_STM32FS_H_
