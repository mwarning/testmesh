CFLAGS += -Wall
DEBUG := 1

#########

FILES := src/main.c \
		 src/conf.c \
		 src/log.c \
		 src/utils.c \
		 src/traffic.c \
		 src/console.c \
		 src/unix.c \
		 src/tun.c \
		 src/net.c \
		 src/client.c \
		 src/interfaces.c

.PHONY: all clean install src/protocols.h

# add all routing protocols
FILES += $(wildcard src/*/*.c)

ifdef DEBUG
  CFLAGS += -g -O0 -DDEBUG
endif

OBJS=$(FILES:.c=.o)

%.o : %.c
	$(CC) $(CFLAGS) -c -o $@ $<

all: src/protocols.h $(OBJS)
	mkdir -p build
	$(CC) $(CFLAGS) $(OBJS) $(LDFLAGS) -lm -o build/geomesh
	ln -s geomesh build/geomesh-ctl 2> /dev/null || true

# generate this file
src/protocols.h:
	@echo "// this file is auto-generated" > src/protocols.h
	@awk 'FNR == 1{printf("#include \"%s\"\n", substr(FILENAME, 5))}' src/*/routing.h >> src/protocols.h
	@echo >> src/protocols.h
	@echo "void register_all_protocols()" >> src/protocols.h
	@echo "{" >> src/protocols.h
	@awk '/_register/{printf("    %s\n", $$2)}' src/*/routing.h >> src/protocols.h
	@echo "}" >> src/protocols.h

clean:
	rm -f build/* $(OBJS) src/protocols.h

install:
	cp build/geomesh $(DESTDIR)/usr/bin/ 2> /dev/null || true
	cp build/geomesh-ctl $(DESTDIR)/usr/bin/ 2> /dev/null || true
