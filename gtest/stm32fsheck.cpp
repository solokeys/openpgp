#include <gtest/gtest.h>
 
#include <string>
#include <cstring>
#include <array>
#include "../libs/stm32fs/stm32fs.h"

#define SECTOR_SIZE 2048

static uint8_t StdHeader[] = {0x55, 0xaa, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xaa, 0x55};
//static uint8_t StdData[] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10};
static uint8_t vmem[SECTOR_SIZE * 10] = {0};

void InitFS(Stm32fsConfig_t &cfg) {
    std::memset(vmem, 0xff, sizeof(vmem));
    
    cfg.BaseBlockAddress = 0;
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
    InitFS(cfg);
    
    Stm32fs fs{cfg};
    ASSERT_TRUE(fs.isValid());
    
    ASSERT_EQ(fs.GetCurrentFsBlockSerial(), 1);
  
    AssertArrayEQ(vmem, StdHeader, sizeof(StdHeader));
    AssertArrayEQConst(vmem + 16, sizeof(vmem) - 16, 0xff);
} 

TEST(stm32fsTest, WriteFile) {
    Stm32fsConfig_t cfg;
    InitFS(cfg);
    
    Stm32fs fs{cfg};
    EXPECT_TRUE(fs.isValid());

    //EXPECT_TRUE(fs.WriteFile("testfile", StdData, sizeof(StdData)));
} 
