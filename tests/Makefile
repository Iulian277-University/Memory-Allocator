CC=gcc
CPPFLAGS=-I../utils
CFLAGS=-fPIC -Wall -Wextra -g
LDFLAGS=-L../allocator
LDLIBS=-losmem

SOURCEDIR=src
BUILDDIR=bin
SRCS=$(sort $(wildcard $(SOURCEDIR)/*.c))
BINS=$(patsubst $(SOURCEDIR)/%.c, $(BUILDDIR)/%, $(SRCS))

.PHONY: all clean

all: $(BUILDDIR) $(BINS)

$(BUILDDIR):
	mkdir -p $(BUILDDIR)

$(BUILDDIR)/%: $(SOURCEDIR)/%.c
	$(CC) $(CPPFLAGS) $(CFLAGS) -o $@ $^ $(LDFLAGS) $(LDLIBS)

clean:
	rm -f $(BINS)
