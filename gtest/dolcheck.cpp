#include <gtest/gtest.h>
 
#include "../src/tlv.h"
#include "../src/errors.h"

using namespace Util;

TEST(dolTest, Constructor) {
    auto data = "\x81\x02\x82\x01"_bstr;
    DOL dol;
    
    auto err = dol.Init(""_bstr);
    EXPECT_TRUE(err != Error::NoError);
    
    err = dol.Init(data);
    EXPECT_TRUE(err == Error::NoError);
    EXPECT_TRUE(dol.GetData() == data);
    
    EXPECT_EQ(dol.CurrentElm().Length(), 2);
    EXPECT_EQ(dol.CurrentElm().Tag(), 0x81);
} 

