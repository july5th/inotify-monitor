CC=gcc
CFLAGS=-Wall -g
SRCS=inotify_monitor.c inotify_utils.c event_queue.c
OBJS=inotify_monitor.o inotify_utils.o event_queue.o

.c.o:
	$(CC) $(CFLAGS) -c $<

all: inotify_monitor

inotify_monitor: $(OBJS)
	$(CC) $(CFLAGS) inotify_utils.o inotify_monitor.o event_queue.o -o inotify_monitor -L/usr/lib/mysql/ -lmysqlclient -lcrypto

clean:
	rm -f $(OBJS) *.bak inotify_monitor
