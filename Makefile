CC = clang
CPP = clang++
CFLAGS = -Wall -Wextra -Wno-unused-parameter -g -O2 -I$(HOME)/.local/include
LDFLAGS = -L$(HOME)/workspace/OpenPACE/trunk/openssl/ -lcrypto -L$(HOME)/.local/lib -lntl -lm

all: shoup_fu.cpp
	$(CPP) $(CFLAGS) shoup_fu.cpp -o shoup_fu $(LDFLAGS)

valgrind:
	LD_LIBRARY_PATH=$(HOME)/workspace/OpenPACE/trunk/openssl/ valgrind --leak-check=full --track-origins=yes ./shoup_fu

clean:
	rm -rf shoup_fu
