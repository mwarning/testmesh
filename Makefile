PROTOCOLS ?= dsr-bloom-0 dsr-bloom-1 flood-0 flood-1
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

# add routing protocols
FILES += $(wildcard src/dsr-bloom-0/*.c)
FILES += $(wildcard src/dsr-bloom-1/*.c)
FILES += $(wildcard src/flood-0/*.c)
FILES += $(wildcard src/flood-1/*.c)
FILES += $(wildcard src/vivaldi-0/*.c)

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
