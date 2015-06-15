#
# Makefile
#

SRCS =  link.c
SERVER = glive-server
OBJS = $(SRCS:.c*=.o)
PREFIX ?= /usr/bin

# Target Cross Tools
CC ?= $(CROSS_COMPILE)gcc

ifdef GST0.10
PKG_CFG_STRING = $(shell pkg-config --cflags --libs gstreamer-0.10 gst-rtsp-server-0.10)
else
PKG_CFG_STRING = $(shell pkg-config --cflags --libs gstreamer-1.0 gstreamer-rtsp-server-1.0)
endif

CFLAGS += -Wall

# Debugging
ifdef DEBUG
CFLAGS += -DDEBUG -DGST_DEBUG=3 -O0 -g
endif

all: $(SERVER)
	
$(SERVER) : $(OBJS) Makefile glive-server.c
	$(CC) $(CFLAGS) $(SRCS) glive-server.c -o $(SERVER) $(PKG_CFG_STRING) $(LDFLAGS)

.PHONY : install clean

install:
	install -d $(DESTDIR)$(PREFIX)
	install -m 0755 $(SERVER) $(DESTDIR)$(PREFIX)
clean:
	@rm -f $(SERVER)  *.o
