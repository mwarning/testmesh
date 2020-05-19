

main: main.c net.c log.c utils.c unix.c other.c
	$(CC) $(CFLAGS) -DDEBUG -g -O0 -o geomesh main.c net.c log.c utils.c unix.c other.c

clean:
	rm geomesh
