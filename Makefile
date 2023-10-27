#
# CAMI -- C Asterisk Manager Interface
#
# Copyright (C) 2022, Naveen Albert
#
# Naveen Albert <asterisk@phreaknet.org>
#

CC		= gcc
CFLAGS = -Wall -Werror -Wno-unused-parameter -Wextra -Wstrict-prototypes -Wmissing-prototypes -Wdeclaration-after-statement -Wmissing-declarations -Wmissing-format-attribute -Wformat=2 -Wshadow -std=gnu99 -pthread -O3 -g -Wstack-protector -fno-omit-frame-pointer -D_FORTIFY_SOURCE=2
EXE		= cami
LIBNAME = libcami
LIBS	= -lm
RM		= rm -f
INSTALL = install

all : library

%.o: %.c
	$(CC) $(CFLAGS) -fPIC -c $^

library: $(EXE).o
	@echo "== Linking $@"
	$(CC) -shared -fPIC -o $(LIBNAME).so $^ $(LIBS)

install:
	$(INSTALL) -m  755 $(LIBNAME).so "/usr/lib"
	mkdir -p /usr/include/$(EXE)
	$(INSTALL) -m 755 include/*.h "/usr/include/$(EXE)/"

example : library install simpleami.o
	$(CC) $(CFLAGS) -o simpleami simpleami.o -l$(EXE) $(LIBS) -ldl

clean :
	$(RM) *.i *.o $(EXE)

uninstall:
	$(RM) /usr/lib/$(EXE).so
	$(RM) /usr/include/$(EXE)/*.h
	rm -rf /usr/include/$(EXE)

.PHONY: all
.PHONY: library
.PHONY: install
.PHONY: example
.PHONY: clean
