#include <gtest/gtest.h>

int main(int argc, char **argv) {
    ::testing::InitGoogleTest(&argc, argv); 
    auto ret = RUN_ALL_TESTS();
    if (ret == 0)
        printf("[TestsOk]\n");
    else
        printf("[TestsError]\n");
    return ret;
}
