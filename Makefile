CC = clang
CPP = g++
CFLAGS = -Wall -Wextra -Wno-unused-parameter -g -O2 -I$(HOME)/.local/include
LDFLAGS = -L$(HOME)/workspace/OpenPACE/trunk/openssl/ -lcrypto -L$(HOME)/.local/lib -lntl -lm -lpthread

all: shoup_fu.c
	$(CPP) $(CFLAGS) shoup_fu.c -o shoup_fu $(LDFLAGS)

valgrind:
	LD_LIBRARY_PATH=$(HOME)/workspace/OpenPACE/trunk/openssl/ valgrind --leak-check=full --track-origins=yes ./shoup_fu

clean:
	rm -rf shoup_fu
