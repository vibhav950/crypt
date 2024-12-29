CC = gcc
CFLAGS = -march=native -mtune=native -I../
COMMON_DIR = ../common

.PHONY: all
all: sha512.o

sha512_x64_avx.o: sha512_x64_avx.c $(COMMON_DIR)/mem.c $(COMMON_DIR)/memzero.c
	$(CC) $(CFLAGS) -c $< -o $@

sha512_x64_avx2.o: sha512_x64_avx2.c $(COMMON_DIR)/mem.c $(COMMON_DIR)/memzero.c
	$(CC) $(CFLAGS) -c $< -o $@

sha512_x64_avx512.o: sha512_x64_avx512.c $(COMMON_DIR)/mem.c $(COMMON_DIR)/memzero.c
	$(CC) $(CFLAGS) -mavx512bw -c $< -o $@

sha512.o: sha512.c sha512_x64_avx.o sha512_x64_avx2.o sha512_x64_avx512.o $(COMMON_DIR)/mem.c $(COMMON_DIR)/memzero.c
	$(CC) $(CFLAGS) -c $< -o $@

.PHONY: clean
clean:
	rm -f *.o
