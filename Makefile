all: transockproxy

transockproxy: transockproxy.c
	$(CC) -m32 -O2 -Wall -Werror -o transockproxy transockproxy.c -lpthread
