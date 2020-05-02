all: scan

scan: scan.c brute.h hashfuncs.h uthash.h
	gcc -g -Wall scan.c -o scan -lpthread -lresolv -lm -lssh2 -DHASH_FUNCTION=HASH_FNV -O3

valgrind: scan
	valgrind --leak-check=full --show-leak-kinds=all ./scan 36.246.68.0/24 23

test24: scan
	./scan 36.246.68.0/24 23

test16: scan
	./scan 36.246.0.0/16 23

test8: scan
	./scan 36.0.0.0/8 23

clean: scan
	rm scan
