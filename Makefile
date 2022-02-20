CFLAGS += -Wall
DEBUG := 1

#########

.PHONY: all clean install src/protocols.h

# add all C files
FILES += $(wildcard src/*.c) $(wildcard src/*/*.c)

ifdef DEBUG
  CFLAGS += -g -O0 -DDEBUG
endif

OBJS=$(FILES:.c=.o)

%.o : %.c
	$(CC) $(CFLAGS) -c -o $@ $<

all: src/protocols.h $(OBJS)
	mkdir -p build
	$(CC) $(CFLAGS) $(OBJS) $(LDFLAGS) -lm -o build/testmesh
	ln -s testmesh build/testmesh-ctl 2> /dev/null || true

# generate this file
src/protocols.h:
	@echo "Create src/protocols.h"
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
	cp build/testmesh $(DESTDIR)/usr/bin/ 2> /dev/null || true
	cp build/testmesh-ctl $(DESTDIR)/usr/bin/ 2> /dev/null || true
