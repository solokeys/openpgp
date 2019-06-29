#include <gtest/gtest.h>
 
#include "../src/tlv.h"
#include "../src/errors.h"

using namespace Util;

TEST(tlvTest, Constructor) {
    TLVTree tlv;
    
    auto err = tlv.Init(""_bstr);
    EXPECT_TRUE(err != Error::NoError);
    
    err = tlv.Init("\x81\x02\x01\x02"_bstr);
    EXPECT_TRUE(err == Error::NoError);
    EXPECT_EQ(tlv.CurrentElm().Length(), 2);
    EXPECT_EQ(tlv.CurrentElm().Tag(), 0x81);
    EXPECT_EQ(tlv.CurrentElm().GetData()[0], 0x01);
    EXPECT_TRUE(tlv.CurrentElm().GetData() == "\x01\x02"_bstr);
} 
