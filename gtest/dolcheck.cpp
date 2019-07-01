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

TEST(dolTest, AddRoot) {
    uint8_t _data[50] = {0};
    auto data = bstr(_data, 0, sizeof(_data));
    
    DOL dol;
    auto err = dol.Init(data);
    EXPECT_FALSE(err == Error::NoError);

    dol.AddRoot(0x7f49, 0x010203);

    EXPECT_TRUE(dol.GetData() == "\x7f\x49\x83\x01\x02\x03"_bstr);
}

TEST(dolTest, AddNext) {
    uint8_t _data[50] = {0};
    auto data = bstr(_data, 0, sizeof(_data));
    
    DOL dol;
    auto err = dol.Init(data);
    EXPECT_FALSE(err == Error::NoError);

    dol.AddRoot(0x7f49, 0x010203);
    
    dol.AddNext(0x81, 0x01);
    dol.AddNext(0x82, 0x0102);
    dol.AddNext(0x83);

    EXPECT_TRUE(dol.GetData() == "\x7f\x49\x83\x01\x02\x03\x81\x01\x82\x82\x01\x02\x83\x00"_bstr);
}

TEST(dolTest, AddNextWithData) {
    uint8_t _data[50] = {0};
    auto data = bstr(_data, 0, sizeof(_data));
    
    DOL dol;
    auto err = dol.Init(data);
    EXPECT_FALSE(err == Error::NoError);

    dol.AddRoot(0x7f49);
    
    dol.AddNextWithData(0x81, 0x00);
    dol.AddNextWithData(0x82, 0x01);

    EXPECT_TRUE(dol.GetData() == "\x7f\x49\x00\x82\x01"_bstr);
}

TEST(dolTest, CheckEncodeDecode) {
    uint8_t _data[50] = {0};
    auto data = bstr(_data, 0, sizeof(_data));
    
    DOL dol;
    auto err = dol.Init(data);
    EXPECT_FALSE(err == Error::NoError);

    dol.AddRoot(0x7f49);
    dol.AddNext(0x81, 0xaa);
    dol.AddNext(0x82, 0x01ff);
    dol.AddNext(0x83, 0x0101ff);
    dol.AddNext(0x7f66, 0xffffff);
    dol.AddNext(0xdfee25, 0xfefeff);
    
    EXPECT_TRUE(dol.GetData() == "\x7f\x49\x00\x81\x81\xaa\x82\x82\x01\xff\x83\x83\x01\x01\xff\x7f\x66\x83\xff\xff\xff\xdf\xee\x25\x83\xfe\xfe\xff"_bstr);

    ASSERT_TRUE(dol.GoFirst());
    EXPECT_EQ(dol.CurrentElm().Tag(), 0x7f49);
    EXPECT_EQ(dol.CurrentElm().Length(), 0x00);

    ASSERT_TRUE(dol.GoNext());
    EXPECT_EQ(dol.CurrentElm().Tag(), 0x81);
    EXPECT_EQ(dol.CurrentElm().Length(), 0xaa);

    ASSERT_TRUE(dol.GoNext());
    EXPECT_EQ(dol.CurrentElm().Tag(), 0x82);
    EXPECT_EQ(dol.CurrentElm().Length(), 0x01ff);

    ASSERT_TRUE(dol.GoNext());
    EXPECT_EQ(dol.CurrentElm().Tag(), 0x83);
    EXPECT_EQ(dol.CurrentElm().Length(), 0x0101ff);

    ASSERT_TRUE(dol.GoNext());
    EXPECT_EQ(dol.CurrentElm().Tag(), 0x7f66);
    EXPECT_EQ(dol.CurrentElm().Length(), 0xffffff);

    ASSERT_TRUE(dol.GoNext());
    EXPECT_EQ(dol.CurrentElm().Tag(), 0xdfee25);
    EXPECT_EQ(dol.CurrentElm().Length(), 0xfefeff);
}
