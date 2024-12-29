CC = gcc
CFLAGS = -DHMAC_TEST_VECS -Wno-incompatible-pointer-types -I../

COMMON_PATH = ../common
SHA512_PATH = ../sha512

SHA512_OBJS = $(SHA512_PATH)/sha512.o \
              $(SHA512_PATH)/sha512_x64_avx.o \
              $(SHA512_PATH)/sha512_x64_avx2.o \
              $(SHA512_PATH)/sha512_x64_avx512.o

COMMON_SRCS = $(COMMON_PATH)/mem.c $(COMMON_PATH)/memzero.c

HMAC_SRCS = hmac.c
HMAC_OBJS = hmac.o

TARGET = hmac_test

all: $(TARGET)

$(TARGET): $(COMMON_SRCS) $(SHA512_OBJS) $(HMAC_OBJS)
	$(CC) $(CFLAGS) $^ -o $@

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

.PHONY: clean
clean:
	rm -f $(COMMON_OBJS) $(HMAC_OBJS) $(TARGET)
