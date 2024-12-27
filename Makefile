#
# CAMI -- C Asterisk Manager Interface
#
# Copyright (C) 2022, Naveen Albert
#
# Naveen Albert <asterisk@phreaknet.org>
#

CC		= gcc
CFLAGS = -Wall -Werror -Wno-unused-parameter -Wextra -Wstrict-prototypes -Wmissing-prototypes -Wdeclaration-after-statement -Wmissing-declarations -Wmissing-format-attribute -Wformat=2 -Wshadow -std=gnu99 -pthread -O3 -g -Wstack-protector -fno-omit-frame-pointer -D_FORTIFY_SOURCE=2 -I.
EXE		= cami
SAMPEXES = simpleami amicli
LIBNAME	= lib$(EXE).so
LIBS	= -lm -ldl
RM		= rm -f
INSTALL	= install

all : library examples

%.o: %.c
	$(CC) $(CFLAGS) -fPIC -c $^

$(LIBNAME): $(EXE).o
	@echo "== Linking $@"
	$(CC) -shared -fPIC -o $(LIBNAME) $^ $(LIBS)

library: $(LIBNAME)
	@if [ ! -d /usr/include/$(EXE) ]; then \
		ln -f -s include $(EXE);           \
	fi

install:
	$(INSTALL) -m 755 $(LIBNAME) "/usr/lib"
	mkdir -p /usr/include/$(EXE)
	$(INSTALL) -m 644 include/*.h "/usr/include/$(EXE)/"

simpleami: simpleami.o $(LIBNAME)
	$(CC) $(CFLAGS) -o $@ $@.o -L. -Wl,-rpath,. -l$(EXE) $(LIBS)

amicli: amicli.o $(LIBNAME)
	$(CC) $(CFLAGS) -o $@ $@.o -L. -Wl,-rpath,. -l$(EXE) $(LIBS)

examples: $(SAMPEXES)

clean:
	$(RM) *.i *.o $(EXE) $(SAMPEXES) $(LIBNAME)

uninstall:
	$(RM) /usr/lib/$(EXE).so
	$(RM) /usr/include/$(EXE)/*.h
	rm -rf /usr/include/$(EXE)

.PHONY: all
.PHONY: library
.PHONY: install
.PHONY: examples
.PHONY: clean

# vim: set noexpandtab shiftwidth=4 tabstop=4:
