#Stephen Bangs
#Lab 3 Makefile - PSargon
#5/18/25 
#Makefile for the psargon program for CS333 - reading, verifying, cracking(?) argon2 passwords from files.
#Also cleans, and tars files using make clean and make tar commands.
#added a git lazy command for source control, though I mostly still commit manually.

#DEBUG = -g3 -O0

CFLAGS = -Wall -Wextra -Wshadow -Wunreachable-code -Wredundant-decls \
	 -Wmissing-declarations -Wold-style-definition -Wmissing-prototypes \
	 -Wdeclaration-after-statement -Wno-return-local-addr -Wunsafe-loop-optimizations \
	 -Wuninitialized -Werror -Wno-unused-parameter -Wno-string-compare -Wno-stringop-overflow \
	 -Wno-stringop-overread -Wno-stringop-truncation

LOCAL_INCLUDES = -I ~rchaney/argon2/include
LOCAL_LIBS = -L ~rchaney/argon2/lib/x86_64-linux-gnu -largon2

CFLAGS += $(LOCAL_INCLUDES)
#LDFLAGS = 
#LDFLAGS += $(DEBUG)

CC = gcc

psargon = psargon

TARGETS = $(psargon)
CSRCS = $(psargon).c
COBJS = $(psargon).o

all: ${TARGETS}

.PHONY: clean tar

$(COBJS): $(CSRCS)
	$(CC) $(CFLAGS) -c $(@:.o=.c) 

$(TARGETS): $(COBJS)
	$(CC) $(@).o -o $(@) $(LOCAL_LIBS)

clean:
	rm -f $(COBJS) $(TARGETS) *~ *.err *.dat *.out *.h *.time

LAB = 03
TAR_FILE = stbangs_Lab$(LAB).tar.gz

tar:
	rm -f $(TAR_FILE)
	tar cvfa $(TAR_FILE) ?akefile *.c
	tar tvaf $(TAR_FILE)

git lazy:
	git add *.[ch] ?akefile
	git commit -m "lazy make git commit"
