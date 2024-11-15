CC = gcc
CFLAGS = -O3 -maes -mavx -DAESNI_TEST_VECS

aesni.o: aesni.c
	$(CC) $(CFLAGS) -c aesni.c -o aesni.o

.PHONY: clean
clean:
	rm -f aesni.o