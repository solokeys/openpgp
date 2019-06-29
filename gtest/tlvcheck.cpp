#include <gtest/gtest.h>
 
#include "../src/tlv.h"
#include "../src/errors.h"

using namespace Util;

/* tree:
 * --f4
 * ----81 0102
 * ----82 0304
 * ----7f49
 * ------85 0405
 * ------86 06
 * ------87 07
 * ----83 08090a
 * ----84 aa
 * 
 */
const auto sampletree = "\xf4\x1d\x81\x02\x01\x02\x82\x02\x03\x04\x7f\x49\x0a\x85\x02\x04\x05\x86\x01\x06\x87\x01\x07\x83\x03\x08\x09\x0a\x84\x01\xaa"_bstr;

TEST(tlvTest, Constructor) {
    auto data = "\x81\x02\x01\x02"_bstr;
    TLVTree tlv;
    
    auto err = tlv.Init(""_bstr);
    EXPECT_TRUE(err != Error::NoError);
    
    err = tlv.Init(data);
    EXPECT_TRUE(err == Error::NoError);
    EXPECT_TRUE(tlv.GetDataLink() == data);
    
    EXPECT_EQ(tlv.CurrentElm().GetPtr(), data.uint8Data());
    EXPECT_EQ(tlv.CurrentElm().Length(), 2);
    EXPECT_EQ(tlv.CurrentElm().Tag(), 0x81);
    EXPECT_EQ(tlv.CurrentElm().GetData()[0], 0x01);
    EXPECT_TRUE(tlv.CurrentElm().GetData() == "\x01\x02"_bstr);
} 

TEST(tlvTest, TreeMove) {
    TLVTree tlv;
    auto err = tlv.Init(sampletree);
    EXPECT_TRUE(err == Error::NoError);
    
    EXPECT_EQ(tlv.CurrentElm().Tag(), 0xf4);
    
    EXPECT_FALSE(tlv.GoNext()); // no next
    EXPECT_EQ(tlv.CurrentElm().Tag(), 0xf4);
    
    EXPECT_FALSE(tlv.GoParent()); // no parent
    EXPECT_EQ(tlv.CurrentElm().Tag(), 0xf4);
    
    EXPECT_TRUE(tlv.GoChild());
    EXPECT_EQ(tlv.CurrentElm().Tag(), 0x81);
    
    EXPECT_FALSE(tlv.GoChild()); // cant
    EXPECT_EQ(tlv.CurrentElm().Tag(), 0x81);
    
    EXPECT_TRUE(tlv.GoNext()); 
    EXPECT_EQ(tlv.CurrentElm().Tag(), 0x82);
    
    EXPECT_TRUE(tlv.GoNext()); 
    EXPECT_EQ(tlv.CurrentElm().Tag(), 0x7f49);
    
    EXPECT_TRUE(tlv.GoChild());
    EXPECT_EQ(tlv.CurrentElm().Tag(), 0x85);
    
    EXPECT_TRUE(tlv.GoParent());
    EXPECT_EQ(tlv.CurrentElm().Tag(), 0x7f49);
    
    EXPECT_TRUE(tlv.GoChild());
    EXPECT_EQ(tlv.CurrentElm().Tag(), 0x85);
    
    EXPECT_TRUE(tlv.GoNext()); 
    EXPECT_EQ(tlv.CurrentElm().Tag(), 0x86);
    
    EXPECT_TRUE(tlv.GoNext()); 
    EXPECT_EQ(tlv.CurrentElm().Tag(), 0x87);
    EXPECT_FALSE(tlv.CurrentElmIsLast());
    
    EXPECT_TRUE(tlv.GoParent());
    EXPECT_EQ(tlv.CurrentElm().Tag(), 0x7f49);
    
    EXPECT_TRUE(tlv.GoFirst());
    EXPECT_EQ(tlv.CurrentElm().Tag(), 0xf4);
}

TEST(tlvTest, TreeMoveNextTreeElm) {
    TLVTree tlv;
    auto err = tlv.Init(sampletree);
    EXPECT_TRUE(err == Error::NoError);
    EXPECT_EQ(tlv.CurrentElm().Tag(), 0xf4);
    
    EXPECT_FALSE(tlv.CurrentElmIsLast());
    
    EXPECT_TRUE(tlv.GoNextTreeElm());
    EXPECT_EQ(tlv.CurrentElm().Tag(), 0x81);
    
    EXPECT_TRUE(tlv.GoNextTreeElm()); 
    EXPECT_EQ(tlv.CurrentElm().Tag(), 0x82);
    
    EXPECT_TRUE(tlv.GoNextTreeElm()); 
    EXPECT_EQ(tlv.CurrentElm().Tag(), 0x7f49);
    
    EXPECT_TRUE(tlv.GoNextTreeElm()); 
    EXPECT_EQ(tlv.CurrentElm().Tag(), 0x85);

    EXPECT_TRUE(tlv.GoParent());
    EXPECT_EQ(tlv.CurrentElm().Tag(), 0x7f49);

    EXPECT_TRUE(tlv.GoNext()); 
    EXPECT_EQ(tlv.CurrentElm().Tag(), 0x83);

    EXPECT_TRUE(tlv.GoNextTreeElm()); 
    EXPECT_EQ(tlv.CurrentElm().Tag(), 0x84);
    EXPECT_TRUE(tlv.CurrentElmIsLast());

    EXPECT_FALSE(tlv.GoNextTreeElm()); // end of tree 
    EXPECT_EQ(tlv.CurrentElm().Tag(), 0x84);
}

TEST(tlvTest, TreeSearch) {
    TLVTree tlv;
    auto err = tlv.Init(sampletree);
    EXPECT_TRUE(err == Error::NoError);
    
    TLVElm *elm = tlv.Search(0x86);
    ASSERT_NE(elm, nullptr);
    EXPECT_EQ(elm->Tag(), 0x86);
    EXPECT_EQ(tlv.CurrentElm().Tag(), 0x86);

    elm = tlv.Search(0x7f49);
    ASSERT_NE(elm, nullptr);
    EXPECT_EQ(elm->Tag(), 0x7f49);
    EXPECT_EQ(tlv.CurrentElm().Tag(), 0x7f49);

    elm = tlv.Search(0x99);
    ASSERT_EQ(elm, nullptr);
    EXPECT_EQ(tlv.CurrentElm().Tag(), 0xf4);
}
