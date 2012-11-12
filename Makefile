all: transockproxy transockproxys transockproxyd

transockproxy: transockproxy.c
	$(CC) -m32 -g -Wall -Werror -o $@ $< -lpthread

transockproxys: transockproxy.c gnutls.c
	$(CC) -g -Wall -Werror -DGNUTLS -o $@ $< gnutls.c -lpthread -lgnutls

transockproxyd: transockproxy.c
	$(CC) -m32 -g -Wall -Werror -DDAEMON -o $@ $< -lpthread
