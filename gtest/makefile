GOOGLE_TEST_LIB = gtest
GOOGLE_TEST_INCLUDE = /usr/local/include

G++ = g++
G++_FLAGS = -c -Wall -std=c++17 -I $(GOOGLE_TEST_INCLUDE)
LD_FLAGS = -L /usr/local/lib -l $(GOOGLE_TEST_LIB) -l pthread

OBJECTS = ptest.o bstrcheck.o tlvcheck.o dolcheck.o stm32fscheck.o
TARGET = ptest

all: $(TARGET)

$(TARGET): $(OBJECTS)
	$(G++) -o $(TARGET) $(OBJECTS) $(LD_FLAGS)

%.o : %.cpp
	$(G++) $(G++_FLAGS) $<

clean:
	rm -f $(TARGET) $(OBJECTS)

test: all
	./ptest

.PHONY: all clean test

