#include <gtest/gtest.h>
 
#include <string>
#include <cstring>
#include <array>
#include "../libs/stm32fs/stm32fs.h"

#define SECTOR_SIZE 2048

static uint8_t StdHeader[] = {0x55, 0xaa, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xaa, 0x55};
static uint8_t StdData[] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10};
static uint8_t vmem[SECTOR_SIZE * 14] = {0};

void InitFS(Stm32fsConfig_t &cfg, uint8_t defaultVal) {
    std::memset(vmem, defaultVal, sizeof(vmem));
    
    cfg.BaseBlockAddress = (size_t)&vmem;
    cfg.SectorSize = SECTOR_SIZE;
    cfg.Blocks = {{{0,1}, {2,3,4}}};
    cfg.fnEraseFlashBlock = [](uint8_t blockNo){std::memset(&vmem[SECTOR_SIZE * blockNo], 0xff, SECTOR_SIZE);return true;};
    cfg.fnWriteFlash = [](uint32_t address, uint8_t *data, size_t len){std::memcpy(&vmem[address], data, len);return true;};
    cfg.fnReadFlash = [](uint32_t address, uint8_t *data, size_t len){std::memcpy(data, &vmem[address], len);return true;};
}

void InitFS2(Stm32fsConfig_t &cfg, uint8_t defaultVal) {
    std::memset(vmem, defaultVal, sizeof(vmem));
    
    cfg.BaseBlockAddress = (size_t)&vmem;
    cfg.SectorSize = SECTOR_SIZE;
    cfg.Blocks = {{{0,1}, {2,3,4}}, {{5,6}, {7,8,9}}};
    cfg.fnEraseFlashBlock = [](uint8_t blockNo){std::memset(&vmem[SECTOR_SIZE * blockNo], 0xff, SECTOR_SIZE);return true;};
    cfg.fnWriteFlash = [](uint32_t address, uint8_t *data, size_t len){std::memcpy(&vmem[address], data, len);return true;};
    cfg.fnReadFlash = [](uint32_t address, uint8_t *data, size_t len){std::memcpy(data, &vmem[address], len);return true;};
}

void InitFS3(Stm32fsConfig_t &cfg, uint8_t defaultVal) {
    std::memset(vmem, defaultVal, sizeof(vmem));
    
    cfg.BaseBlockAddress = (size_t)&vmem;
    cfg.SectorSize = SECTOR_SIZE;
    cfg.Blocks = {{{0}, {1,2}}, {{3}, {4,5}}, {{6}, {7,8}}};
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

void FillMem(uint8_t *data, uint32_t size) {
    for (size_t i = 0; i < size; i++)
        data[i] = (i & 0xffU) ^ ((i >> 8) & 0xffU) ^ 0x5A;
}

void dump_memory(void* data, size_t len) {
    size_t i;
    for (i=0;i<len;i++) {
        printf("%02X ", ((unsigned char*)data)[i] );
        if ((i + 1) % 16 == 0)
            printf("\n");
    }
    printf("\n");
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
    ASSERT_EQ(fs.GetFreeMemory(), SECTOR_SIZE * 3);
    ASSERT_EQ(fs.GetFreeFileDescriptors(), (SECTOR_SIZE / 16) * 2 - 1);
} 

TEST(stm32fsTest, Create2Blocks) {
    Stm32fsConfig_t cfg;
    InitFS2(cfg, 0x00);
    
    Stm32fs fs{cfg};
    ASSERT_TRUE(fs.isValid());
    ASSERT_FALSE(fs.isNeedsOptimization());
    
    ASSERT_EQ(fs.GetCurrentFsBlockSerial(), 1);
  
    AssertArrayEQ(vmem, StdHeader, sizeof(StdHeader));
    AssertArrayEQConst(vmem + 16, SECTOR_SIZE * 5 - 16, 0xff); // 5 sectors of filesystem
    AssertArrayEQConst(vmem + SECTOR_SIZE * 5, SECTOR_SIZE * 5, 0x00); // 2nd block of filesystem
    
    ASSERT_EQ(fs.GetSize(), SECTOR_SIZE * 3);
    ASSERT_EQ(fs.GetFreeMemory(), SECTOR_SIZE * 3);
    ASSERT_EQ(fs.GetFreeFileDescriptors(), (SECTOR_SIZE / 16) * 2 - 1);
} 

TEST(stm32fsTest, Create3Blocks) {
    Stm32fsConfig_t cfg;
    InitFS3(cfg, 0x00);
    
    Stm32fs fs{cfg};
    ASSERT_TRUE(fs.isValid());
    ASSERT_FALSE(fs.isNeedsOptimization());
    
    ASSERT_EQ(fs.GetCurrentFsBlockSerial(), 1);
  
    AssertArrayEQ(vmem, StdHeader, sizeof(StdHeader));

    ASSERT_EQ(fs.GetSize(), SECTOR_SIZE * 2);
    ASSERT_EQ(fs.GetFreeMemory(), SECTOR_SIZE * 2);
    ASSERT_EQ(fs.GetFreeFileDescriptors(), (SECTOR_SIZE / 16) - 1);
} 

TEST(stm32fsTest, FindFs) {
    Stm32fsConfig_t cfg;
    InitFS3(cfg, 0x00);
    
    Stm32fs fs{cfg};
    ASSERT_TRUE(fs.isValid());    
    ASSERT_EQ(fs.GetCurrentFsBlockSerial(), 1);

    // SearchLast current fs
    Stm32fsConfigBlock_t *blk0 = fs.GetFlash().SearchLastFsBlockInFlash();
    ASSERT_NE(blk0, nullptr);
    ASSERT_EQ(fs.GetFlash().GetFsSerial(*blk0), 1);
    
    // create block 2
    Stm32fsConfigBlock_t *blk1 = fs.GetFlash().SearchNextFsBlockInFlash();
    ASSERT_NE(blk1, nullptr);
    ASSERT_EQ(fs.GetFlash().GetFsSerial(*blk1), 0);
    ASSERT_TRUE(fs.GetFlash().CreateFsBlock(*blk1, 3));
    ASSERT_EQ(fs.GetFlash().GetFsSerial(*blk1), 3);

    // search last block 2
    Stm32fsConfigBlock_t *blkr1 = fs.GetFlash().SearchLastFsBlockInFlash();
    ASSERT_NE(blkr1, nullptr);
    ASSERT_EQ(fs.GetFlash().GetFsSerial(*blkr1), 3);
    
    // create block 3
    Stm32fsConfigBlock_t *blk2 = fs.GetFlash().SearchNextFsBlockInFlash();
    ASSERT_NE(blk2, nullptr);
    ASSERT_TRUE(fs.GetFlash().CreateFsBlock(*blk2, 2));
    ASSERT_EQ(fs.GetFlash().GetFsSerial(*blk2), 2);
    
    // search last block 2. 2nd try
    Stm32fsConfigBlock_t *blkr2 = fs.GetFlash().SearchLastFsBlockInFlash();
    ASSERT_NE(blkr2, nullptr);
    ASSERT_EQ(fs.GetFlash().GetFsSerial(*blkr2), 3);
    
    // now next block should point to block 1
    Stm32fsConfigBlock_t *blkn = fs.GetFlash().SearchNextFsBlockInFlash();
    ASSERT_NE(blkn, nullptr);
    ASSERT_EQ(fs.GetFlash().GetFsSerial(*blkn), 1);
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
    
    AssertArrayEQ(vmem + 2 * SECTOR_SIZE, StdData, sizeof(StdData));
    
    ASSERT_TRUE(fs.FileExist("testfile"));

    ASSERT_EQ(fs.GetSize(), SECTOR_SIZE * 3);
    ASSERT_EQ(fs.GetFreeMemory(), SECTOR_SIZE * 3 - sizeof(StdData));
    ASSERT_EQ(fs.GetFreeFileDescriptors(), (SECTOR_SIZE / 16) * 2 - 1 - 2);
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
    AssertArrayEQ(testmem, StdData, sizeof(StdData));
    
    ASSERT_TRUE(fs.ReadFile("testfile", testmem, nullptr, sizeof(StdData)));
    
    std::memset(testmem, 0xab, sizeof(testmem));
    rxlength = 0;
    ASSERT_TRUE(fs.ReadFile("testfile", testmem, &rxlength, 5));
    ASSERT_EQ(rxlength, 5);
    AssertArrayEQ(testmem, StdData, 5);
    ASSERT_NE(std::memcmp(testmem, StdData, sizeof(StdData)), 0);
}

TEST(stm32fsTest, ReadFileMaxLen) {
    Stm32fsConfig_t cfg;
    InitFS(cfg, 0xff);
    Stm32fs fs{cfg};
    
    uint8_t testmem[SECTOR_SIZE * 4] = {0};
    uint8_t testmemr[SECTOR_SIZE * 4] = {0};
    FillMem(testmem, sizeof(testmem));
    std::memset(testmemr, 0x00, sizeof(testmemr));

    ASSERT_TRUE(fs.WriteFile("file_6kb", testmem, SECTOR_SIZE * 3));

    size_t rxlength = 0;
    ASSERT_TRUE(fs.ReadFile("file_6kb", testmemr, &rxlength, sizeof(testmemr)));
    
    ASSERT_EQ(rxlength, SECTOR_SIZE * 3);
    AssertArrayEQ(testmem, testmemr, SECTOR_SIZE * 3);    
}

TEST(stm32fsTest, WriteFileBadFS) {
    Stm32fsConfig_t cfg;
    InitFS(cfg, 0xff);
    Stm32fs fs{cfg};
    
    uint8_t testmem[SECTOR_SIZE] = {0};
    std::memset(testmem, 0x00, sizeof(testmem));

    // flash bad blocks
    // 8b border
    vmem[SECTOR_SIZE * 2 + 5] = 0x00;
    
    uint32_t restmem = fs.GetFreeMemory();
    ASSERT_TRUE(fs.WriteFile("file", StdData, 1));
    ASSERT_TRUE(fs.WriteFile("file", StdData, sizeof(StdData) - 1));

    size_t rxlength = 0;
    ASSERT_TRUE(fs.ReadFile("file", testmem, &rxlength, sizeof(testmem)));
    
    ASSERT_EQ(rxlength, sizeof(StdData) - 1);
    AssertArrayEQ(testmem, StdData, rxlength);
    ASSERT_EQ(restmem - 24, fs.GetFreeMemory());
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
    AssertArrayEQ(testmem, testmemr, sizeof(testmem));
    
    Stm32FSFileVersion *version = (Stm32FSFileVersion *)&vmem[32 + 16];
    ASSERT_EQ(version->FileState, fsDeleted);
    ASSERT_EQ(version->FileID, 1);
    ASSERT_EQ(version->FileAddress, 0);
    ASSERT_EQ(version->FileSize, 0);

    ASSERT_EQ(fs.GetFreeFileDescriptors(), (SECTOR_SIZE / 16) * 2 - 1 - 3);
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

TEST(stm32fsTest, FindFirst) {
    Stm32fsConfig_t cfg;
    InitFS(cfg, 0xff);
    Stm32fs fs{cfg};
    
    ASSERT_TRUE(fs.WriteFile("file1", StdData, 1));
    ASSERT_TRUE(fs.WriteFile("file2", StdData, 1));
    ASSERT_TRUE(fs.WriteFile("file3", StdData, 1));
    ASSERT_TRUE(fs.WriteFile("file4", StdData, 1));
    
    Stm32File_t srecm;
    Stm32File_t *rc = nullptr;
    
    rc = fs.FindFirst("xfile", &srecm);
    ASSERT_EQ(rc, nullptr);
    
    rc = fs.FindFirst("filez", &srecm);
    ASSERT_EQ(rc, nullptr);

    rc = fs.FindFirst("file1?", &srecm);
    ASSERT_EQ(rc, nullptr);
    
    rc = fs.FindFirst("file1", &srecm);
    ASSERT_NE(rc, nullptr);
    ASSERT_TRUE(rc->FileName == "file1");
    ASSERT_EQ(rc->FileSize, 1);
    ASSERT_EQ(rc->FileID, 1);
    ASSERT_EQ(rc->FileAddress, SECTOR_SIZE * 2);
    
    rc = fs.FindFirst("file4", &srecm);
    ASSERT_NE(rc, nullptr);
    ASSERT_TRUE(rc->FileName == "file4");

    rc = fs.FindFirst("file?", &srecm);
    ASSERT_NE(rc, nullptr);
    ASSERT_TRUE(rc->FileName == "file1");
    
    rc = fs.FindFirst("file*", &srecm);
    ASSERT_NE(rc, nullptr);
    ASSERT_TRUE(rc->FileName == "file1");
    
    rc = fs.FindFirst("*", &srecm);
    ASSERT_NE(rc, nullptr);
    ASSERT_TRUE(rc->FileName == "file1");
}

TEST(stm32fsTest, FindNext) {
    Stm32fsConfig_t cfg;
    InitFS(cfg, 0xff);
    Stm32fs fs{cfg};
    
    ASSERT_TRUE(fs.WriteFile("file1", StdData, 1));
    ASSERT_TRUE(fs.WriteFile("file2", StdData, 2));
    ASSERT_TRUE(fs.WriteFile("file3", StdData, 3));
    ASSERT_TRUE(fs.WriteFile("file4", StdData, 4));
    
    Stm32File_t srecm;
    Stm32File_t *rc = nullptr;
    
    rc = fs.FindFirst("file?", &srecm);
    ASSERT_NE(rc, nullptr);
    ASSERT_TRUE(rc->FileName == "file1");
    ASSERT_EQ(rc->FileSize, 1);
    
    rc = fs.FindNext(rc);
    ASSERT_NE(rc, nullptr);
    ASSERT_TRUE(rc->FileName == "file2");
    ASSERT_EQ(rc->FileSize, 2);
    
    rc = fs.FindNext(rc);
    ASSERT_NE(rc, nullptr);
    ASSERT_TRUE(rc->FileName == "file3");
    ASSERT_EQ(rc->FileSize, 3);
    
    rc = fs.FindNext(rc);
    ASSERT_NE(rc, nullptr);
    ASSERT_TRUE(rc->FileName == "file4");
    ASSERT_EQ(rc->FileSize, 4);
    
    rc = fs.FindNext(rc);
    ASSERT_EQ(rc, nullptr);
    
    rc = fs.FindFirst("file*", &srecm);
    ASSERT_NE(rc, nullptr);
    ASSERT_TRUE(rc->FileName == "file1");
    
    rc = fs.FindNext(rc);
    ASSERT_NE(rc, nullptr);
    ASSERT_TRUE(rc->FileName == "file2"); 

    rc = fs.FindFirst("*", &srecm);
    ASSERT_NE(rc, nullptr);
    ASSERT_TRUE(rc->FileName == "file1");
    
    rc = fs.FindNext(rc);
    ASSERT_NE(rc, nullptr);
    ASSERT_TRUE(rc->FileName == "file2"); 

    rc = fs.FindFirst("?????", &srecm);
    ASSERT_NE(rc, nullptr);
    ASSERT_TRUE(rc->FileName == "file1");
    
    rc = fs.FindNext(rc);
    ASSERT_NE(rc, nullptr);
    ASSERT_TRUE(rc->FileName == "file2"); 
}

TEST(stm32fsTest, DeleteFiles) {
    Stm32fsConfig_t cfg;
    InitFS(cfg, 0xff);
    Stm32fs fs{cfg};
    
    ASSERT_TRUE(fs.WriteFile("file1", StdData, 1));
    ASSERT_TRUE(fs.WriteFile("file2", StdData, 2));
    ASSERT_TRUE(fs.WriteFile("file3", StdData, 3));
    ASSERT_TRUE(fs.WriteFile("file4", StdData, 4));
    
    uint32_t restmem = fs.GetFreeMemory();
    
    ASSERT_TRUE(fs.DeleteFiles("file1"));
    
    ASSERT_FALSE(fs.FileExist("file1"));

    ASSERT_TRUE(fs.DeleteFiles("*"));
    
    ASSERT_FALSE(fs.FileExist("file2"));
    ASSERT_FALSE(fs.FileExist("file3"));
    ASSERT_FALSE(fs.FileExist("file4"));
    
    ASSERT_EQ(restmem, fs.GetFreeMemory());
}

TEST(stm32fsTest, OptimizeEmpty) {
    Stm32fsConfig_t cfg;
    InitFS(cfg, 0xff);
    Stm32fs fs{cfg};
    
    ASSERT_TRUE(fs.WriteFile("file1", StdData, 1));
    ASSERT_TRUE(fs.WriteFile("file2", StdData, 2));
    ASSERT_TRUE(fs.WriteFile("file3", StdData, 3));
    ASSERT_TRUE(fs.WriteFile("file4", StdData, 4));
    
    uint32_t restmem = fs.GetFreeMemory();
    
    ASSERT_TRUE(fs.DeleteFiles("*"));
    ASSERT_FALSE(fs.FileExist("file1"));
    ASSERT_EQ(restmem, fs.GetFreeMemory());
        
    ASSERT_EQ(fs.GetCurrentFsBlockSerial(), 1);

    ASSERT_TRUE(fs.Optimize());
    
    ASSERT_EQ(fs.GetCurrentFsBlockSerial(), 2);
    
    ASSERT_FALSE(fs.FileExist("file1"));
    ASSERT_FALSE(fs.FileExist("file2"));
    ASSERT_FALSE(fs.FileExist("file3"));
    ASSERT_FALSE(fs.FileExist("file4"));
    
    ASSERT_NE(restmem, fs.GetFreeMemory());
    ASSERT_EQ(fs.GetFreeMemory(), SECTOR_SIZE * 3);
}

TEST(stm32fsTest, OptimizeSimple) {
    Stm32fsConfig_t cfg;
    InitFS(cfg, 0xff);
    Stm32fs fs{cfg};
    
    uint32_t startmem = fs.GetFreeMemory();
    
    ASSERT_TRUE(fs.WriteFile("file1", StdData, 1));
    ASSERT_TRUE(fs.WriteFile("file2", StdData, 2));
    ASSERT_TRUE(fs.WriteFile("file3", StdData, 3));
    ASSERT_TRUE(fs.WriteFile("file4", StdData, 4));
    
    ASSERT_TRUE(fs.DeleteFile("file3"));
    ASSERT_FALSE(fs.FileExist("file3"));
        
    ASSERT_EQ(fs.GetCurrentFsBlockSerial(), 1);

    ASSERT_TRUE(fs.Optimize());
    
    //dump_memory(vmem, 128);
    //dump_memory(&vmem[4096], 128);
    
    ASSERT_EQ(fs.GetCurrentFsBlockSerial(), 2);
    
    ASSERT_TRUE(fs.FileExist("file1"));
    ASSERT_TRUE(fs.FileExist("file2"));
    ASSERT_FALSE(fs.FileExist("file3"));
    ASSERT_TRUE(fs.FileExist("file4"));
    
    // all the data inside 1 flash block
    ASSERT_EQ(startmem - 8, fs.GetFreeMemory());
}

TEST(stm32fsTest, OptimizeBigFiles) {
    Stm32fsConfig_t cfg;
    InitFS(cfg, 0xff);
    Stm32fs fs{cfg};
    
    // init arrays
    uint8_t testmem[SECTOR_SIZE * 3] = {0};
    FillMem(testmem, sizeof(testmem));
    uint8_t testmemr[SECTOR_SIZE * 3] = {0};
    std::memset(testmemr, 0xab, sizeof(testmemr));
    
    uint32_t startmem = fs.GetFreeMemory();
    
    ASSERT_TRUE(fs.WriteFile("file1", StdData, 15));
    ASSERT_TRUE(fs.WriteFile("file2", testmem, 3100));
    ASSERT_EQ(fs.FileLength("file2"), 3100);
    ASSERT_TRUE(fs.WriteFile("file3", testmem, 2500));
    ASSERT_EQ(fs.FileLength("file3"), 2500);
    
    ASSERT_TRUE(fs.DeleteFile("file1"));
    ASSERT_FALSE(fs.FileExist("file1"));
        
    ASSERT_EQ(fs.GetCurrentFsBlockSerial(), 1);

    ASSERT_TRUE(fs.Optimize());
    
    //dump_memory(vmem, 128);
    //dump_memory(&vmem[4096], 128);
    
    ASSERT_EQ(fs.GetCurrentFsBlockSerial(), 2);
    
    ASSERT_FALSE(fs.FileExist("file1"));
    ASSERT_TRUE(fs.FileExist("file2"));
    ASSERT_TRUE(fs.FileExist("file3"));

    size_t rxlength = 0;
    ASSERT_TRUE(fs.ReadFile("file2", testmemr, &rxlength, sizeof(testmemr)));
    ASSERT_EQ(rxlength, 3100);
    AssertArrayEQ(testmem, testmemr, rxlength);
    
    std::memset(testmemr, 0xab, sizeof(testmemr));
    rxlength = 0;
    ASSERT_TRUE(fs.ReadFile("file3", testmemr, &rxlength, sizeof(testmemr)));
    ASSERT_EQ(rxlength, 2500);
    AssertArrayEQ(testmem, testmemr, rxlength);
    
    ASSERT_EQ(startmem - (3100 + 2500), fs.GetFreeMemory());
}

TEST(stm32fsTest, Optimize2BlocksEmpty) {
    Stm32fsConfig_t cfg;
    InitFS2(cfg, 0xff);
    Stm32fs fs{cfg};
    
    ASSERT_TRUE(fs.WriteFile("file1", StdData, 1));
    ASSERT_TRUE(fs.WriteFile("file2", StdData, 2));
    ASSERT_TRUE(fs.WriteFile("file3", StdData, 3));
    ASSERT_TRUE(fs.WriteFile("file4", StdData, 4));
    
    uint32_t restmem = fs.GetFreeMemory();
    
    ASSERT_TRUE(fs.DeleteFiles("*"));
    ASSERT_FALSE(fs.FileExist("file1"));
    ASSERT_EQ(restmem, fs.GetFreeMemory());
        
    ASSERT_EQ(fs.GetCurrentFsBlockSerial(), 1);

    ASSERT_TRUE(fs.Optimize());
    
    ASSERT_EQ(fs.GetCurrentFsBlockSerial(), 2);
    
    ASSERT_FALSE(fs.FileExist("file1"));
    ASSERT_FALSE(fs.FileExist("file2"));
    ASSERT_FALSE(fs.FileExist("file3"));
    ASSERT_FALSE(fs.FileExist("file4"));
    
    ASSERT_NE(restmem, fs.GetFreeMemory());
    ASSERT_EQ(fs.GetFreeMemory(), SECTOR_SIZE * 3);
}

TEST(stm32fsTest, Optimize2Blocks) {
    Stm32fsConfig_t cfg;
    InitFS2(cfg, 0x00);
    
    Stm32fs fs{cfg};
    ASSERT_TRUE(fs.isValid());

    ASSERT_EQ(fs.GetSize(), SECTOR_SIZE * 3);
    ASSERT_EQ(fs.GetFreeMemory(), SECTOR_SIZE * 3);
    
    // init arrays
    uint8_t testmem[SECTOR_SIZE * 3] = {0};
    FillMem(testmem, sizeof(testmem));
    uint8_t testmemr[SECTOR_SIZE * 3] = {0};
    std::memset(testmemr, 0xab, sizeof(testmemr));
    
    uint32_t startmem = fs.GetFreeMemory();

    ASSERT_TRUE(fs.WriteFile("file1", StdData, 15));
    ASSERT_TRUE(fs.WriteFile("file2", testmem, 3100));
    ASSERT_EQ(fs.FileLength("file2"), 3100);
    ASSERT_TRUE(fs.WriteFile("file3", testmem, 2500));
    ASSERT_EQ(fs.FileLength("file3"), 2500);
    
    ASSERT_TRUE(fs.DeleteFile("file1"));
    ASSERT_FALSE(fs.FileExist("file1"));
        
    ASSERT_EQ(fs.GetCurrentFsBlockSerial(), 1);

    ASSERT_TRUE(fs.Optimize());
    
    dump_memory(vmem, 128);
    dump_memory(&vmem[2048 * 5], 128);

    dump_memory(&vmem[2048 * 2], 128);
    dump_memory(&vmem[2048 * 7], 128);
    //dump_memory(&vmem[4096], 128);
    
    ASSERT_EQ(fs.GetCurrentFsBlockSerial(), 2);
    
    ASSERT_FALSE(fs.FileExist("file1"));
    ASSERT_TRUE(fs.FileExist("file2"));
    ASSERT_TRUE(fs.FileExist("file3"));

    size_t rxlength = 0;
    ASSERT_TRUE(fs.ReadFile("file2", testmemr, &rxlength, sizeof(testmemr)));
    ASSERT_EQ(rxlength, 3100);
    AssertArrayEQ(testmem, testmemr, rxlength);
    
    std::memset(testmemr, 0xab, sizeof(testmemr));
    rxlength = 0;
    ASSERT_TRUE(fs.ReadFile("file3", testmemr, &rxlength, sizeof(testmemr)));
    ASSERT_EQ(rxlength, 2500);
    AssertArrayEQ(testmem, testmemr, rxlength);
    
    ASSERT_EQ(startmem - (3100 + 2500), fs.GetFreeMemory());
} 

/*
TEST(stm32fsTest, Create3Blocks) {
    Stm32fsConfig_t cfg;
    InitFS3(cfg, 0x00);
    
    Stm32fs fs{cfg};
    ASSERT_TRUE(fs.isValid());
    ASSERT_FALSE(fs.isNeedsOptimization());
    
    ASSERT_EQ(fs.GetCurrentFsBlockSerial(), 1);
  
    AssertArrayEQ(vmem, StdHeader, sizeof(StdHeader));

    ASSERT_EQ(fs.GetSize(), SECTOR_SIZE * 2);
    ASSERT_EQ(fs.GetFreeMemory(), SECTOR_SIZE * 2);
    ASSERT_EQ(fs.GetFreeFileDescriptors(), (SECTOR_SIZE / 16) - 1);
} 
*/


