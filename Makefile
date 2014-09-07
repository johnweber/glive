#
# Makefile
#

SRCS =  link.c
CLIENT = glive-client
RTSP_CLIENT = glive-rtsp-client
SERVER = glive-server
OBJS = $(SRCS:.c*=.o)
PREFIX ?= /usr/bin

# Target Cross Tools
CC ?= $(CROSS_COMPILE)gcc
PKG_CFG_STRING=$(shell pkg-config --cflags --libs gstreamer-0.10 gst-rtsp-server-0.10)

CFLAGS += -Wall

# Debugging
ifdef DEBUG
CFLAGS += -DDEBUG -DGST_DEBUG=3 -O0 -g
endif

all: $(SERVER) $(CLIENT) $(RTSP_CLIENT)
	
$(SERVER) : $(OBJS) Makefile glive-server.c
	$(CC) $(CFLAGS) $(SRCS) glive-server.c -o $(SERVER) $(PKG_CFG_STRING) $(LDFLAGS)

$(CLIENT) : $(OBJS) Makefile glive-client.c
	$(CC) $(CFLAGS) $(SRCS) glive-client.c -o $(CLIENT) $(PKG_CFG_STRING) $(LDFLAGS)

$(RTSP_CLIENT) : $(OBJS) Makefile glive-rtsp-client.c
	$(CC) $(CFLAGS) $(SRCS) glive-rtsp-client.c -o $(RTSP_CLIENT) $(PKG_CFG_STRING) $(LDFLAGS)

.PHONY : install clean

install:
	install -d $(DESTDIR)$(PREFIX)
	install -m 0755 $(SERVER) $(DESTDIR)$(PREFIX)
	install -m 0755 $(CLIENT) $(DESTDIR)$(PREFIX)
clean:
	@rm -f $(SERVER) $(CLIENT) $(RTSP_CLIENT) *.o
