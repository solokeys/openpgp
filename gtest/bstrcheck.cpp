#include <gtest/gtest.h>
 
#include "../src/opgputil.h"

TEST(bstrTest, UserDefinedStringLiteral) {
    bstr teststring = "12345678"_bstr;
    EXPECT_EQ(teststring.length(), 8);
    EXPECT_EQ(teststring.max_length(), 8);
    EXPECT_EQ(teststring[0], 0x31);
    EXPECT_EQ(teststring.uint8Data()[0], 0x31);
}

TEST(bstrTest, Clear) {
    bstr teststring = "12345678"_bstr;
    teststring.clear();
    EXPECT_EQ(teststring.length(), 0);
    EXPECT_EQ(teststring.max_length(), 8);
}

TEST(bstrTest, GetUintBe) {
    bstr teststring = "\x01\x02\x03\x04\xaa\xff"_bstr;
    EXPECT_EQ(teststring.get_uint_be(0, 1), 0x01);
    EXPECT_EQ(teststring.get_uint_be(0, 2), 0x0102);
    EXPECT_EQ(teststring.get_uint_be(0, 3), 0x010203);
    EXPECT_EQ(teststring.get_uint_be(0, 4), 0x01020304);
    EXPECT_EQ(teststring.get_uint_be(1, 4), 0x020304aa);
    EXPECT_EQ(teststring.get_uint_be(2, 4), 0x0304aaff);
}

TEST(bstrTest, GetUintLe) {
    bstr teststring = "\x01\x02\x03\x04\xaa\xff"_bstr;
    EXPECT_EQ(teststring.get_uint_le(0, 4), 0x04030201);
    EXPECT_EQ(teststring.get_uint_le(1, 1), 0x02);
    EXPECT_EQ(teststring.get_uint_le(1, 2), 0x0302);
    EXPECT_EQ(teststring.get_uint_le(1, 3), 0x040302);
    EXPECT_EQ(teststring.get_uint_le(1, 4), 0xaa040302);
    EXPECT_EQ(teststring.get_uint_le(2, 4), 0xffaa0403);
}

TEST(bstrTest, SetUintBe) {
    uint8_t data[10] = {0};
    bstr teststring = bstr(data, 6, sizeof(data));
    
    teststring.set_uint_be(0, 4, 0x01020304);
    EXPECT_EQ(teststring.get_uint_be(0, 4), 0x01020304);
    
    teststring.set_uint_be(2, 4, 0x01020304);
    EXPECT_EQ(teststring.get_uint_be(2, 4), 0x01020304);
    
    teststring.set_uint_be(3, 2, 0xbabb);
    EXPECT_EQ(teststring.get_uint_be(3, 2), 0xbabb);
}

TEST(bstrTest, SetLength) {
    bstr teststring = "12345678"_bstr;
    EXPECT_EQ(teststring.length(), 8);
    
    teststring.set_length(2);
    EXPECT_EQ(teststring.length(), 2);
    EXPECT_TRUE(teststring == "12"_bstr);
}

TEST(bstrTest, MaxLengthConstructors) {
    uint8_t data[15] = {0};
    
    bstr teststring = bstr(data, 0, sizeof(data));    
    EXPECT_EQ(teststring.max_length(), sizeof(data));

    bstr teststring1 = bstr(data, sizeof(data));    
    EXPECT_EQ(teststring1.max_length(), sizeof(data));
    
    bstr teststring2 = bstr("123"_bstr);    
    EXPECT_EQ(teststring2.max_length(), 3);

    bstr teststring3 = bstr("123"_bstr, 4);    
    EXPECT_EQ(teststring3.max_length(), 4);

    auto teststring4 = bstr(data, 0, sizeof(data));
    auto teststring5 = teststring4;    
    EXPECT_EQ(teststring5.max_length(), sizeof(data));
}

TEST(bstrTest, Append) {
    uint8_t data[15] = {0};
    bstr teststring = bstr(data, 0, sizeof(data));
    
    teststring.append(0x01);
    teststring.appendAPDUres(0x0203);
    uint8_t cn[] = {0x04, 0x05, 0x06};
    teststring.append(cn, sizeof(cn));
    teststring.append("\x07\x08\x09"_bstr);
    EXPECT_TRUE(teststring == "\x01\x02\x03\x04\x05\x06\x07\x08\x09"_bstr);
}

TEST(bstrTest, Set) {
    uint8_t data[15] = {0};
    bstr teststring = bstr(data, 0, sizeof(data));
    
    teststring.setAPDURes(0x9101);
    EXPECT_TRUE(teststring == "\x91\x01"_bstr);

    
    teststring.set("1234567"_bstr);
    EXPECT_TRUE(teststring == "1234567"_bstr);
}

TEST(bstrTest, Del) {
    uint8_t data[15] = {0};
    bstr teststring = bstr(data, 0, sizeof(data));
    
    teststring.set("123456789"_bstr);
    teststring.del(0, 2);
    EXPECT_TRUE(teststring == "3456789"_bstr);
    
    teststring.set("123456789"_bstr);
    teststring.del(3, 4);
    EXPECT_TRUE(teststring == "12389"_bstr);

    teststring.set("123456789"_bstr);
    teststring.del(7, 2);
    EXPECT_TRUE(teststring == "1234567"_bstr);
    
    teststring.set("123456789"_bstr);
    teststring.del(7, 20);
    EXPECT_TRUE(teststring == "1234567"_bstr);

    teststring.set("123456789"_bstr);
    teststring.del(0, 20);
    EXPECT_EQ(teststring.length(), 0);
}

TEST(bstrTest, MoveTaiNegativel) {
    uint8_t data[15] = {0};
    bstr teststring = bstr(data, 0, sizeof(data));
    
    teststring.set("123456789"_bstr);
    teststring.moveTail(5, -3);
    EXPECT_TRUE(teststring == "126789"_bstr);

    teststring.set("123456789"_bstr);
    teststring.moveTail(2, -5);
    EXPECT_TRUE(teststring == "6789"_bstr);
    
    teststring.set("123456789"_bstr);
    teststring.moveTail(8, -8);
    EXPECT_TRUE(teststring == "9"_bstr);
}

TEST(bstrTest, MoveTailPositive) {
    uint8_t data[15] = {0};
    bstr teststring = bstr(data, 0, sizeof(data));
    
    teststring.set("123456789"_bstr);
    teststring.moveTail(3, 2);
    teststring.uint8Data()[3] = 0x30; // correct undefined behavior
    teststring.uint8Data()[4] = 0x30;
    EXPECT_TRUE(teststring == "12300456789"_bstr);

    teststring.set("123456789"_bstr);
    teststring.moveTail(0, 2);
    teststring.uint8Data()[0] = 0x30; // correct undefined behavior
    teststring.uint8Data()[1] = 0x30;
    EXPECT_TRUE(teststring == "00123456789"_bstr);

    teststring.set("123456789"_bstr);
    teststring.moveTail(8, 2);
    teststring.uint8Data()[8] = 0x30; // correct undefined behavior
    teststring.uint8Data()[9] = 0x30;
    EXPECT_TRUE(teststring == "12345678009"_bstr);
}

TEST(bstrTest, MaxLengthMoving) {
    uint8_t data[15] = {0};
    
    bstr teststring = bstr(data, 0, sizeof(data));
    teststring.set_length(2);    
    EXPECT_EQ(teststring.max_length(), sizeof(data));

    // TODO: add MaxLength move between strings like get subsring and etc
}

// TODO: add MaxLength checks in append, movetail, etc (not implemented in code now!) 
