CC = gcc
CFLAGS = -Wall -Wextra -Werror -std=c11 -Iinclude
LDFLAGS =

SRC_DIR = src
INC_DIR = include
BUILD_DIR = build
TEST_DIR = tests

SRCS = $(SRC_DIR)/main.c \
       $(SRC_DIR)/sniffer.c \
       $(SRC_DIR)/parser.c \
       $(SRC_DIR)/filters.c \
       $(SRC_DIR)/analyzer.c \
       $(SRC_DIR)/output.c \
       $(SRC_DIR)/stats.c

# Object files for main target (all sources)
OBJS = $(patsubst $(SRC_DIR)/%.c, $(BUILD_DIR)/%.o, $(SRCS))

# Library objects (everything except main.c) for tests
LIB_SRCS = $(filter-out $(SRC_DIR)/main.c, $(SRCS))
LIB_OBJS = $(patsubst $(SRC_DIR)/%.c, $(BUILD_DIR)/%.o, $(LIB_SRCS))

TARGET = sniffer
TEST_TARGET = test_parser

.PHONY: all clean test

all: $(BUILD_DIR) $(TARGET)

$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

$(BUILD_DIR)/%.o: $(SRC_DIR)/%.c
	$(CC) $(CFLAGS) -c $< -o $@

# Unit tests
test: $(BUILD_DIR) $(LIB_OBJS) $(TEST_DIR)/test_parser.c
	$(CC) $(CFLAGS) -o $(TEST_TARGET) $(TEST_DIR)/test_parser.c $(LIB_OBJS) $(LDFLAGS)
	./$(TEST_TARGET)

clean:
	rm -rf $(BUILD_DIR) $(TARGET) $(TEST_TARGET)
