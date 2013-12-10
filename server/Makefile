#
# Makefile
#

INCLUDEDIR = ../include
COMMONDIR = ../common
SRCS = glives.c $(COMMONDIR)/link.c
OUTNAME = glives
OBJS = $(SRCS:.c*=.o)

# Target Cross Tools
CC ?= $(CROSS_COMPILE)gcc
PKG_CFG_STRING=$(shell pkg-config --cflags --libs gstreamer-0.10)
CFLAGS += -I$(INCLUDEDIR)

# Debugging
ifdef DEBUG
CFLAGS += -DDEBUG -O0 -g
endif

all: $(OUTNAME)
	
$(OUTNAME) : $(OBJS) Makefile
	$(CC) $(CFLAGS) $(SRCS) -o $(OUTNAME) $(PKG_CFG_STRING) $(LDFLAGS)

.PHONY : clean
	
clean:
	@rm -f $(OUTNAME)
