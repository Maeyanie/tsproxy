all: transockproxy transockproxyd

transockproxy: transockproxy.c
	$(CC) -m32 -O2 -Wall -Werror -o transockproxy transockproxy.c -lpthread

transockproxyd: transockproxy.c
	$(CC) -m32 -O2 -Wall -Werror -DDAEMON -o transockproxyd transockproxy.c -lpthread
