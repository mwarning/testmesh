
.PHONY: main clean

main: main.c net.c log.c utils.c unix.c clean
	$(CC) $(CFLAGS) -DDEBUG -g -O2 -o geomesh main.c net.c log.c utils.c unix.c

clean:
	rm -f geomesh
