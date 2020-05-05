#include <gtest/gtest.h>
 
#include <string>
#include <cstring>
#include <array>
#include "../libs/stm32fs/stm32fs.h"

TEST(stm32fsTest, Create) {
    uint8_t vmem[2048 * 10];
    std::memset(vmem, 0xff, sizeof(vmem));
    
    Stm32fsConfig_t cfg;
    cfg.BaseBlockAddress = 0;
    cfg.SectorSize = 2048;
    cfg.Blocks = {{{0,1}, {2,3,4}}};
    cfg.fnEraseFlashBlock = [&vmem](uint8_t blockNo){std::memset(&vmem[2048 * blockNo], 0xff, 2048);return true;};
    cfg.fnWriteFlash = [&vmem](uint32_t, uint8_t *data, size_t len){return true;};
    cfg.fnReadFlash = [&vmem](uint32_t, uint8_t *data, size_t *len){return true;};
    
    Stm32fs fs{cfg};
    EXPECT_TRUE(fs.isValid());
} 
