#include <gtest/gtest.h>
 
#include <string>
#include <cstring>
#include <array>
#include "../libs/stm32fs/stm32fs.h"

#define SECTOR_SIZE 2048

static uint8_t StdHeader[] = {0x55, 0xaa, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xaa, 0x55};
static uint8_t StdData[] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10};
static uint8_t vmem[SECTOR_SIZE * 10] = {0};

void InitFS(Stm32fsConfig_t &cfg, uint8_t defaultVal) {
    std::memset(vmem, defaultVal, sizeof(vmem));
    
    cfg.BaseBlockAddress = (size_t)&vmem;
    cfg.SectorSize = SECTOR_SIZE;
    cfg.Blocks = {{{0,1}, {2,3,4}}};
    cfg.fnEraseFlashBlock = [](uint8_t blockNo){std::memset(&vmem[SECTOR_SIZE * blockNo], 0xff, SECTOR_SIZE);return true;};
    cfg.fnWriteFlash = [](uint32_t address, uint8_t *data, size_t len){std::memcpy(&vmem[address], data, len);return true;};
    cfg.fnReadFlash = [](uint32_t address, uint8_t *data, size_t len){std::memcpy(data, &vmem[address], len);return true;};
}

void AssertArrayEQ(uint8_t *data1, uint8_t *data2, uint32_t size) {
    for (uint32_t i = 0; i < size; i++) {
        SCOPED_TRACE(i);
        ASSERT_EQ(data1[i], data2[i]);
    }
}

void AssertArrayEQConst(uint8_t *data, uint32_t size, uint8_t constval) {
    for (uint32_t i = 0; i < size; i++) {
        SCOPED_TRACE(i);
        ASSERT_EQ(data[i], constval);
    }
}

TEST(stm32fsTest, Create) {
    Stm32fsConfig_t cfg;
    InitFS(cfg, 0x00);
    
    Stm32fs fs{cfg};
    ASSERT_TRUE(fs.isValid());
    ASSERT_FALSE(fs.isNeedsOptimization());
    
    ASSERT_EQ(fs.GetCurrentFsBlockSerial(), 1);
  
    AssertArrayEQ(vmem, StdHeader, sizeof(StdHeader));
    AssertArrayEQConst(vmem + 16, SECTOR_SIZE * 5 - 16, 0xff); // 5 sectors of filesystem
    
    ASSERT_EQ(fs.GetSize(), SECTOR_SIZE * 3);
} 

TEST(stm32fsTest, WriteFile) {
    Stm32fsConfig_t cfg;
    InitFS(cfg, 0xff);
    
    Stm32fs fs{cfg};
    ASSERT_TRUE(fs.isValid());
    
    ASSERT_FALSE(fs.FileExist("testfile"));

    ASSERT_TRUE(fs.WriteFile("testfile", StdData, sizeof(StdData)));
    
    Stm32FSFileHeader *header = (Stm32FSFileHeader *)&vmem[16];
    ASSERT_EQ(header->FileState, fsFileHeader);
    ASSERT_EQ(header->FileID, 1);
    ASSERT_EQ(std::strncmp("testfile", header->FileName, 8), 0);
    
    Stm32FSFileVersion *version = (Stm32FSFileVersion *)&vmem[32];
    ASSERT_EQ(version->FileState, fsFileVersion);
    ASSERT_EQ(version->FileID, 1);
    ASSERT_EQ(version->FileAddress, 2 * SECTOR_SIZE);
    ASSERT_EQ(version->FileSize, sizeof(StdData));
    
    ASSERT_TRUE(std::memcmp(vmem + 2 * SECTOR_SIZE, StdData, sizeof(StdData)) == 0);
    
    ASSERT_TRUE(fs.FileExist("testfile"));
}

TEST(stm32fsTest, WriteFileNameLen) {
    Stm32fsConfig_t cfg;
    InitFS(cfg, 0xff);
    Stm32fs fs{cfg};
    
    ASSERT_TRUE(fs.WriteFile("t", StdData, 1));
    ASSERT_TRUE(fs.WriteFile("1234567890123", StdData, 1));
    ASSERT_TRUE(fs.WriteFile("-234567890123e", StdData, 1));

    ASSERT_TRUE(fs.FileExist("t"));
    ASSERT_TRUE(fs.FileExist("1234567890123"));
    ASSERT_FALSE(fs.FileExist("-234567890123e"));
    ASSERT_TRUE(fs.FileLength("-234567890123e") < 0);
    ASSERT_TRUE(fs.FileExist("-234567890123"));
    ASSERT_TRUE(fs.FileLength("-234567890123") > 0);
}

TEST(stm32fsTest, WriteFileLen) {
    Stm32fsConfig_t cfg;
    InitFS(cfg, 0xff);
    Stm32fs fs{cfg};
    
    uint8_t testmem[SECTOR_SIZE * 2 + 1] = {0};
    std::memset(testmem, 0xab, sizeof(testmem));

    ASSERT_TRUE(fs.WriteFile("file_1b", StdData, 1));
    ASSERT_TRUE(fs.WriteFile("file_3kb", testmem, sizeof(testmem)));

    ASSERT_TRUE(fs.FileExist("file_1b"));
    ASSERT_EQ(fs.FileLength("file_1b"), 1);
    ASSERT_TRUE(fs.FileExist("file_3kb"));
    ASSERT_EQ(fs.FileLength("file_3kb"), sizeof(testmem));
}

TEST(stm32fsTest, WriteFileMaxLen) {
    Stm32fsConfig_t cfg;
    InitFS(cfg, 0xff);
    Stm32fs fs{cfg};
    
    uint8_t testmem[SECTOR_SIZE * 3] = {0};
    std::memset(testmem, 0xab, sizeof(testmem));

    ASSERT_TRUE(fs.WriteFile("file_6kb", testmem, SECTOR_SIZE * 3));
    ASSERT_TRUE(fs.FileExist("file_6kb"));
}

TEST(stm32fsTest, WriteFileMaxLenMore) {
    Stm32fsConfig_t cfg;
    InitFS(cfg, 0xff);
    Stm32fs fs{cfg};
    
    uint8_t testmem[SECTOR_SIZE * 4] = {0};
    std::memset(testmem, 0xab, sizeof(testmem));

    ASSERT_FALSE(fs.WriteFile("file_6kb+", testmem, SECTOR_SIZE * 3 + 1));
    ASSERT_FALSE(fs.FileExist("file_6kb+"));
}

TEST(stm32fsTest, ReadFile) {
    Stm32fsConfig_t cfg;
    InitFS(cfg, 0xff);
    Stm32fs fs{cfg};
    
    uint8_t testmem[SECTOR_SIZE] = {0};
    std::memset(testmem, 0xab, sizeof(testmem));

    ASSERT_TRUE(fs.WriteFile("testfile", StdData, sizeof(StdData)));
    
    ASSERT_EQ(fs.FileLength("testfile"), sizeof(StdData));
    
    size_t rxlength = 0;
    ASSERT_TRUE(fs.ReadFile("testfile", testmem, &rxlength, sizeof(StdData)));
    
    ASSERT_EQ(rxlength, sizeof(StdData));
    ASSERT_EQ(std::memcmp(testmem, StdData, sizeof(StdData)), 0);
    
    ASSERT_TRUE(fs.ReadFile("testfile", testmem, nullptr, sizeof(StdData)));
    
    std::memset(testmem, 0xab, sizeof(testmem));
    rxlength = 0;
    ASSERT_TRUE(fs.ReadFile("testfile", testmem, &rxlength, 5));
    ASSERT_EQ(rxlength, 5);
    ASSERT_EQ(std::memcmp(testmem, StdData, 5), 0);
    ASSERT_NE(std::memcmp(testmem, StdData, sizeof(StdData)), 0);
}

TEST(stm32fsTest, ReadFileMaxLen) {
    Stm32fsConfig_t cfg;
    InitFS(cfg, 0xff);
    Stm32fs fs{cfg};
    
    uint8_t testmem[SECTOR_SIZE * 4] = {0};
    uint8_t testmemr[SECTOR_SIZE * 4] = {0};
    std::memset(testmem, 0xab, sizeof(testmem));
    std::memset(testmemr, 0x00, sizeof(testmemr));

    ASSERT_TRUE(fs.WriteFile("file_6kb", testmem, SECTOR_SIZE * 3));

    size_t rxlength = 0;
    ASSERT_TRUE(fs.ReadFile("file_6kb", testmemr, &rxlength, sizeof(testmemr)));
    
    ASSERT_EQ(rxlength, SECTOR_SIZE * 3);
    ASSERT_EQ(std::memcmp(testmem, testmemr, SECTOR_SIZE * 3), 0);    
}

TEST(stm32fsTest, DeleteFile) {
    Stm32fsConfig_t cfg;
    InitFS(cfg, 0xff);
    Stm32fs fs{cfg};
    
    uint8_t testmem[SECTOR_SIZE] = {0};
    uint8_t testmemr[SECTOR_SIZE] = {0};
    std::memset(testmem, 0xab, sizeof(testmem));
    std::memset(testmemr, 0xab, sizeof(testmemr));

    ASSERT_TRUE(fs.WriteFile("testfile", StdData, sizeof(StdData)));
    ASSERT_EQ(fs.FileLength("testfile"), sizeof(StdData));
    
    ASSERT_TRUE(fs.DeleteFile("testfile"));
    
    ASSERT_FALSE(fs.FileExist("testfile"));
    ASSERT_TRUE(fs.FileLength("testfile") < 0);
    
    size_t rxlength = 0;
    ASSERT_FALSE(fs.ReadFile("testfile", testmem, &rxlength, sizeof(StdData)));
    
    ASSERT_EQ(rxlength, 0);
    ASSERT_EQ(std::memcmp(testmem, testmemr, sizeof(testmem)), 0);
    
    Stm32FSFileVersion *version = (Stm32FSFileVersion *)&vmem[32 + 16];
    ASSERT_EQ(version->FileState, fsDeleted);
    ASSERT_EQ(version->FileID, 1);
    ASSERT_EQ(version->FileAddress, 0);
    ASSERT_EQ(version->FileSize, 0);
}

TEST(stm32fsTest, NeedsOptimize) {
    Stm32fsConfig_t cfg;
    InitFS(cfg, 0xff);
    Stm32fs fs{cfg};
    
    uint8_t testmem[SECTOR_SIZE * 4] = {0};
    std::memset(testmem, 0xab, sizeof(testmem));

    ASSERT_FALSE(fs.isNeedsOptimization());
    
    ASSERT_TRUE(fs.WriteFile("file1", testmem, SECTOR_SIZE * 2));
    ASSERT_TRUE(fs.FileExist("file1"));
    ASSERT_FALSE(fs.isNeedsOptimization());

    ASSERT_TRUE(fs.WriteFile("file2", testmem, SECTOR_SIZE));
    ASSERT_TRUE(fs.FileExist("file2"));
    ASSERT_FALSE(fs.isNeedsOptimization());

    ASSERT_FALSE(fs.WriteFile("file3", testmem, 1));
    ASSERT_FALSE(fs.FileExist("file3"));
    ASSERT_TRUE(fs.isNeedsOptimization());
    
    ASSERT_TRUE(fs.DeleteFile("file1"));
    ASSERT_TRUE(fs.DeleteFile("file2"));
    ASSERT_TRUE(fs.isNeedsOptimization());
}
