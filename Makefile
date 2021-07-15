DEBUG := 1

#########

FILES := src/main.c \
		 src/log.c \
		 src/utils.c \
		 src/traffic.c \
		 src/console.c \
		 src/unix.c \
		 src/net.c \
		 src/client.c \
		 src/interfaces.c

.PHONY: all clean

# add all routing protocols
FILES += $(wildcard src/*/*.c)

ifdef DEBUG
  CFLAGS += -g -O0 -DDEBUG
endif

OBJS=$(FILES:.c=.o)

%.o : %.c
	$(CC) $(CFLAGS) -c -o $@ $<

all: $(OBJS)
	$(CC) $(CFLAGS) $(OBJS) $(LDFLAGS) -lm -o build/geomesh
	ln -s geomesh build/geomesh-ctl 2> /dev/null || true

clean:
	rm -f build/* $(OBJS)
