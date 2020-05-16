

main: main.c net.c log.c utils.c unix.c
	$(CC) $(CFLAGS) -DDEBUG -o main main.c net.c log.c utils.c unix.c

clean:
	rm main
