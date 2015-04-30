#ifndef __INOTIFY_UTILS_H
#define __INOTIFY_UTILS_H

#include "event_queue.h"

struct __file_hash_table
{
	struct __file_hash_table * next;
	char * file_name;
	unsigned char md5[16];
};

struct __inotify_struct
{
	char * dir_name;
	int file_number;
	struct __file_hash_table * file_hash_table;
	
};

void handle_event (queue_entry_t event, int fd);
int read_event (int fd, struct inotify_event *event);
int event_check (int fd);
int process_inotify_events (queue_t q, int fd);
int watch_dir (int fd, char *dirname, unsigned long mask);
int ignore_wd (int fd, int wd);
int close_inotify_fd (int fd);
int open_inotify_fd ();
void stor_file_hash(char *path, int wd);
//void md5_file(char *filename, struct __file_hash_table * file_hash_table);
void md5_file(char *filename, unsigned char * md5);
void print_inotify_struct(int wd);
void init_inotify_struct();
int check_md5_file(char * filename, int wd);
void delete_file_hash(char *filename, int wd);
void add_file_hash(char *filename, int wd);

#endif
