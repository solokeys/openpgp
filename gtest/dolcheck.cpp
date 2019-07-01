#include <gtest/gtest.h>
 
#include "../src/tlv.h"
#include "../src/errors.h"

using namespace Util;

const auto testdata = "\x81\x02\x7f\x49\x01\x82\x82\x01\x02\x7f\x66\x81\xaa"_bstr;

TEST(dolTest, Constructor) {
    DOL dol;
    
    auto err = dol.Init(""_bstr);
    EXPECT_TRUE(err != Error::NoError);
    
    err = dol.Init(testdata);
    EXPECT_TRUE(err == Error::NoError);
    EXPECT_TRUE(dol.GetData() == testdata);
    
    EXPECT_EQ(dol.CurrentElm().Length(), 2);
    EXPECT_EQ(dol.CurrentElm().Tag(), 0x81);
} 

TEST(dolTest, DecodeAndNavigate) {
    DOL dol;
    auto err = dol.Init(testdata);
    EXPECT_TRUE(err == Error::NoError);
    
    EXPECT_EQ(dol.CurrentElm().Tag(), 0x81);
    EXPECT_EQ(dol.CurrentElm().Length(), 0x02);
    
    EXPECT_TRUE(dol.GoNext());
    EXPECT_EQ(dol.CurrentElm().Tag(), 0x7f49);
    EXPECT_EQ(dol.CurrentElm().Length(), 0x01);
    
    EXPECT_TRUE(dol.GoNext());
    EXPECT_EQ(dol.CurrentElm().Tag(), 0x82);
    EXPECT_EQ(dol.CurrentElm().Length(), 0x0102);

    EXPECT_TRUE(dol.GoNext());
    EXPECT_EQ(dol.CurrentElm().Tag(), 0x7f66);
    EXPECT_EQ(dol.CurrentElm().Length(), 0xaa);

    EXPECT_FALSE(dol.GoNext()); // no next
    EXPECT_EQ(dol.CurrentElm().Tag(), 0x7f66);

    EXPECT_TRUE(dol.GoFirst());
    EXPECT_EQ(dol.CurrentElm().Tag(), 0x81);
}

TEST(dolTest, Search) {
    DOL dol;
    auto err = dol.Init(testdata);
    EXPECT_TRUE(err == Error::NoError);
    
    size_t offset = 0xaa;
    size_t length = 0xbb;
    
    EXPECT_TRUE(dol.Search(0x81, offset, length) == Error::NoError);
    EXPECT_EQ(offset, 0x00);
    EXPECT_EQ(length, 0x02);

    EXPECT_TRUE(dol.Search(0x7f66, offset, length) == Error::NoError);
    EXPECT_EQ(offset, 0x02 + 0x01 + 0x0102);
    EXPECT_EQ(length, 0xaa);
}
