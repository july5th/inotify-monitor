#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>
#include <sys/select.h>
#include <sys/inotify.h>
#include <mysql/mysql.h>
#include <time.h>
#include <dirent.h>
#include <sys/stat.h>
#include <openssl/md5.h>

#include "event_queue.h"
#include "inotify_utils.h"

extern MYSQL  mysql;
extern char host_name[255];
extern int keep_running;
extern int pid;
extern unsigned long max_file_len;

char *file_suf = ".php";

static int watched_items;

//static int max_fd = 0;

#define MAX_MONITOR_FD 65535

struct __inotify_struct inotify_struct[MAX_MONITOR_FD];

/* Create an inotify instance and open a file descriptor
   to access it */
int open_inotify_fd()
{
	int fd;
	watched_items = 0;
	fd = inotify_init();
	if(fd < 0){
		perror("inotify_init() = ");
	}
	return fd;
}


/* Close the open file descriptor that was opened with inotify_init() */
int close_inotify_fd(int fd)
{
	int r;
	if((r = close(fd)) < 0){
		perror("close (fd) = ");
	}
	watched_items = 0;
	return r;
}

/* This method does the work of determining what happened,
   then allows us to act appropriately
 */
void handle_event(queue_entry_t event, int fd)
{
	/* If the event was associated with a filename, we will store it here */
	char *cur_event_filename = NULL;
	char *cur_event_file_or_dir = NULL;
	/* This is the watch descriptor the event occurred on */
	int cur_event_wd = event->inot_ev.wd;
	int cur_event_cookie = event->inot_ev.cookie;
	unsigned long flags;
	time_t t;
	struct tm *tmptr; 

	char query[69535];
	char time_str[80];
	char filename[1024];
	char file_content[65535];

	int len;
	char * end;

	FILE *fp; 

	time(&t);
	tmptr = localtime(&t);
	strftime(time_str, sizeof(time_str), "%F %T", tmptr);

	if(event->inot_ev.len){
		cur_event_filename = event->inot_ev.name;
	}
	if(event->inot_ev.mask & IN_ISDIR){
		cur_event_file_or_dir = "Dir";
	} else {
		cur_event_file_or_dir = "File";
		sprintf(filename, "%s/%s", inotify_struct[cur_event_wd].dir_name, cur_event_filename);
	}
	sprintf(filename, "%s/%s", inotify_struct[cur_event_wd].dir_name, cur_event_filename); 
	flags = event->inot_ev.mask & ~(IN_ALL_EVENTS | IN_UNMOUNT | IN_Q_OVERFLOW | IN_IGNORED );

	/* Perform event dependent handler routines */
	/* The mask is the magic that tells us what file operation occurred */
	switch (event->inot_ev.mask & (IN_ALL_EVENTS | IN_UNMOUNT | IN_Q_OVERFLOW | IN_IGNORED)) {
		/* File was accessed */
		case IN_ACCESS:
			printf ("ACCESS: %s \"%s\" on WD #%i\n", cur_event_file_or_dir, filename, cur_event_wd);
			//syslog(LOG_INFO, "ACCESS: %s \"%s\"\n", cur_event_file_or_dir, filename);
			break;
			/* File was modified */
		case IN_MODIFY:
			printf ("MODIFY: %s \"%s\" on WD #%i\n", cur_event_file_or_dir, filename, cur_event_wd); 
			char *p = strrchr(filename, '.');
			if(p && (strcmp(p, file_suf) == 0) && check_md5_file(filename, cur_event_wd)){
				if (!(fp = fopen(filename,"rb"))) {
					printf("Can not open %s this file!\n",filename);
				}
				len = fread(file_content, 1, 65535, fp);
				fclose(fp);
				memset(query, '\0', 1024); 
				sprintf(query, "insert into file (hostname, pid, file_name, file_type, action, time, content) values ('%s', %d, '%s', '%s', '%s', '%s', ", host_name, pid, filename, cur_event_file_or_dir, "MODIFY", time_str);
				end = query;
				end += strlen(query);
				*end++ = '\'';
				end += mysql_real_escape_string(&mysql, end, file_content, len);
				*end++ = '\'';
				*end++ = ')';
				*end++ = ';';
				mysql_real_query(&mysql, query, (unsigned int)(end - query));
				printf("%s\n",query);
			} else {
				sprintf(query, "insert into file (hostname, pid, file_name, file_type, action, time) values ('%s', %d, '%s', '%s', '%s', '%s')", host_name, pid, filename, cur_event_file_or_dir, "MODIFY", time_str);
				printf("%s\n",query);
				mysql_query(&mysql, query);
			}
			//print_inotify_struct(cur_event_wd);
			break;

			/* File changed attributes */
		case IN_ATTRIB:
			printf("ATTRIB: %s \"%s\" on WD #%i\n", cur_event_file_or_dir, filename, cur_event_wd);
			break;

			/* File open for writing was closed */
		case IN_CLOSE_WRITE:
			printf("CLOSE_WRITE: %s \"%s\" on WD #%i\n", cur_event_file_or_dir, filename, cur_event_wd);
			break;

			/* File open read-only was closed */
		case IN_CLOSE_NOWRITE:
			printf("CLOSE_NOWRITE: %s \"%s\" on WD #%i\n", cur_event_file_or_dir, filename, cur_event_wd);
			break;

			/* File was opened */
		case IN_OPEN:
			printf ("OPEN: %s \"%s\" on WD #%i\n", cur_event_file_or_dir, filename, cur_event_wd);
			break;

			/* File was moved from X */
		case IN_MOVED_FROM:
			printf ("MOVED_FROM: %s \"%s\" on WD #%i. Cookie=%d\n", cur_event_file_or_dir, filename, cur_event_wd, cur_event_cookie);
			sprintf(query, "insert into file (hostname, pid, file_name, file_type, action, time, cookie) values ('%s', %d, '%s', '%s', '%s', '%s', %d);", host_name, pid, filename, cur_event_file_or_dir, "MOVE_FROM", time_str, cur_event_cookie);
			mysql_query(&mysql, query);

			if( event->inot_ev.mask & IN_ISDIR ){
			} else {
				char *p = strrchr(filename, '.');
				if(p && (strcmp(p, file_suf) == 0)){
					delete_file_hash(filename, cur_event_wd);
					//print_inotify_struct(cur_event_wd);
				}
			} 
			break;

			/* File was moved to X */
		case IN_MOVED_TO:
			printf ("MOVED_TO: %s \"%s\" on WD #%i. Cookie=%d\n", cur_event_file_or_dir, filename, cur_event_wd, cur_event_cookie);
			sprintf(query, "insert into file (hostname, pid, file_name, file_type, action, time, cookie) values ('%s', %d, '%s', '%s', '%s', '%s', %d);", host_name, pid, filename, cur_event_file_or_dir, "MOVE_TO", time_str, cur_event_cookie);
			mysql_query(&mysql, query);
			if ( event->inot_ev.mask & IN_ISDIR ){ 
			} else {
				char *p = strrchr(filename, '.');
				if(p && (strcmp(p, file_suf) == 0)){
					add_file_hash(filename, cur_event_wd);
					//print_inotify_struct(cur_event_wd);
				}
			}
			break;

			/* Subdir or file was deleted */
		case IN_DELETE:
			printf ("DELETE: %s \"%s\" on WD #%i\n", cur_event_file_or_dir, filename, cur_event_wd);
			sprintf(query, "insert into file (hostname, pid, file_name, file_type, action, time) values ('%s', %d, '%s', '%s', '%s', '%s');", host_name, pid, filename, cur_event_file_or_dir, "DELETE", time_str);
			mysql_query(&mysql, query);

			if(event->inot_ev.mask & IN_ISDIR){
			} else {
				char *p = strrchr(filename, '.');
				if(p && (strcmp(p, file_suf) == 0)){
					delete_file_hash(filename, cur_event_wd);
					//print_inotify_struct(cur_event_wd);
				}
			}
			break;

			/* Subdir or file was created */
		case IN_CREATE:
			printf ("CREATE: %s \"%s\"\n", cur_event_file_or_dir, filename);	

			if ( event->inot_ev.mask & IN_ISDIR ){       
				watch_dir (fd, filename, IN_MODIFY | IN_MOVE | IN_CREATE | IN_DELETE );
			} else {
				char *p = strrchr(filename, '.');
				if(p && (strcmp(p, file_suf) == 0)){
					add_file_hash(filename, cur_event_wd);
					print_inotify_struct(cur_event_wd);
					if (!(fp = fopen(filename,"rb"))) {
						printf("Can not open %s this file!\n",filename);
					}
					len = fread(file_content, 1, 65535, fp);
					fclose(fp);
					memset(query, '\0', 1024); 
					sprintf(query, "insert into file (hostname, pid, file_name, file_type, action, time, content) values ('%s', %d, '%s', '%s', '%s', '%s', ", host_name, pid, filename, cur_event_file_or_dir, "CREATE", time_str);
					end = query;
					end += strlen(query);
					*end++ = '\'';
					end += mysql_real_escape_string(&mysql, end, file_content, len);
					*end++ = '\'';
					*end++ = ')';
					mysql_real_query(&mysql, query, (unsigned int)(end - query));
					printf("%s\n",query);
					break;
				}  
			}
			sprintf(query, "insert into file (hostname, pid, file_name, file_type, action, time) values ('%s', %d, '%s', '%s', '%s', '%s');", host_name, pid, filename, cur_event_file_or_dir, "CREATE", time_str);
			mysql_query(&mysql, query);

			break;

			/* Watched entry was deleted */
		case IN_DELETE_SELF:
			printf ("DELETE_SELF: %s \"%s\" on WD #%i\n",cur_event_file_or_dir, filename, cur_event_wd);
			break;

			/* Watched entry was moved */
		case IN_MOVE_SELF:
			printf ("MOVE_SELF: %s \"%s\" on WD #%i\n",cur_event_file_or_dir, filename, cur_event_wd);
			break;

			/* Backing FS was unmounted */
		case IN_UNMOUNT:
			printf ("UNMOUNT: %s \"%s\" on WD #%i\n",cur_event_file_or_dir, filename, cur_event_wd);
			break;

			/* Too many FS events were received without reading them
			   some event notifications were potentially lost.  */
		case IN_Q_OVERFLOW:
			printf ("Warning: AN OVERFLOW EVENT OCCURRED: \n");
			break;

			/* Watch was removed explicitly by inotify_rm_watch or automatically
			   because file was deleted, or file system was unmounted.  */
		case IN_IGNORED:
			watched_items--;
			printf ("IGNORED: WD #%d\n", cur_event_wd);
			printf("Watching = %d items\n",watched_items); 
			break;

			/* Some unknown message received */
		default:
			printf ("UNKNOWN EVENT \"%X\" OCCURRED for file \"%s\" on WD #%i\n",
					event->inot_ev.mask, cur_event_filename, cur_event_wd);
			break;
	}
	/* If any flags were set other than IN_ISDIR, report the flags */
	if (flags & (~IN_ISDIR))
	{
		flags = event->inot_ev.mask;
		printf ("Flags=%lX\n", flags);
	}
}

void handle_events(queue_t q, int fd)
{
	queue_entry_t event;
	while(!queue_empty(q))
	{
		event = queue_dequeue (q);
		handle_event (event, fd);
		free (event);
	}
}

int read_events(queue_t q, int fd)
{
	char buffer[16384];
	size_t buffer_i;
	struct inotify_event *pevent;
	queue_entry_t event;
	ssize_t r;
	size_t event_size, q_event_size;
	int count = 0;

	r = read (fd, buffer, 16384);
	if (r <= 0)
		return r;
	buffer_i = 0;
	while (buffer_i < r)
	{
		/* Parse events and queue them. */
		pevent = (struct inotify_event *) &buffer[buffer_i];
		event_size =  offsetof (struct inotify_event, name) + pevent->len;
		q_event_size = offsetof (struct queue_entry, inot_ev.name) + pevent->len;
		event = malloc (q_event_size);
		memmove (&(event->inot_ev), pevent, event_size);
		queue_enqueue (event, q);
		buffer_i += event_size;
		count++;
	}
	printf ("\n%d events queued\n", count);
	return count;
}

int event_check (int fd)
{
	fd_set rfds;
	FD_ZERO (&rfds);
	FD_SET (fd, &rfds);
	/* Wait until an event happens or we get interrupted 
	   by a signal that we catch */
	return select (FD_SETSIZE, &rfds, NULL, NULL, NULL);
}

int process_inotify_events (queue_t q, int fd)
{
	while (keep_running && (watched_items > 0)){
		if (event_check (fd) > 0){
			int r;
			r = read_events (q, fd);
			if (r < 0){
				break;
			} else {
				handle_events (q, fd);
			}
		}
	}
	return 0;
}

int watch_dir(int fd, char *dirname, unsigned long mask)
{
	int wd;
	wd = inotify_add_watch(fd, dirname, mask);
	if (wd < 0) {
		printf ("Cannot add watch for \"%s\" with event mask %lX", dirname, mask);
		fflush (stdout);
		perror (" ");
	} else {
		watched_items++;

		if(dirname[strlen(dirname) - 1] == '/'){
			dirname[strlen(dirname) - 1] = '\0';
		}
		inotify_struct[wd].dir_name = strdup(dirname);
		stor_file_hash(dirname, wd);
		printf ("Watching %s WD=%d\n", dirname, wd);
		printf ("Watching = %d items\n", watched_items); 
	}
	return wd;
}

int ignore_wd(int fd, int wd)
{
	int r;
	r = inotify_rm_watch (fd, wd);
	if (r < 0)
	{
		perror ("inotify_rm_watch(fd, wd) = ");
	}
	else 
	{
		watched_items--;
	}
	return r;
}

void delete_file_hash(char *filename, int wd)
{
	struct __file_hash_table * file_hash_table;
	struct __file_hash_table * front_hash_table;
	int i;

	char * file_name = strrchr(filename, '/');
	file_name++; 

	file_hash_table = inotify_struct[wd].file_hash_table;

	printf("find : %s\n",file_hash_table -> file_name);

	if( strcmp(file_hash_table -> file_name, file_name) == 0){

		inotify_struct[wd].file_hash_table = file_hash_table ->next;
		free(file_hash_table -> file_name);
		free(file_hash_table);		
		inotify_struct[wd].file_number--;
	} else {
		for(i = 1; i < inotify_struct[wd].file_number; i++){

			front_hash_table = file_hash_table;
			file_hash_table = file_hash_table -> next;

			if( strcmp(file_hash_table -> file_name, file_name) == 0){
				printf("find!\n");

				front_hash_table -> next = file_hash_table -> next;
				free(file_hash_table -> file_name);
				free(file_hash_table);
				inotify_struct[wd].file_number--;
				break;
			}
		}	
	}    	
}

void add_file_hash(char *filename, int wd)
{
	struct __file_hash_table * file_hash_table;

	char * file_name = strrchr(filename, '/');
	file_name++; 

	file_hash_table = malloc(sizeof(struct __file_hash_table));
	file_hash_table -> next = inotify_struct[wd].file_hash_table;
	file_hash_table -> file_name = strdup(file_name);
	inotify_struct[wd].file_hash_table = file_hash_table;
	inotify_struct[wd].file_number++;

	md5_file(filename, file_hash_table->md5);

}

void stor_file_hash(char *path, int wd)
{
	struct dirent* ent = NULL;
	DIR *pDir;
	char dir[512];
	char filename[1024];
	struct stat statbuf;
	struct __file_hash_table * file_hash_table;

	if((pDir = opendir(path)) == NULL)
	{
		fprintf( stderr, "Cannot open directory:%s\n", path );
		return;
	}
	while((ent = readdir(pDir)) != NULL)
	{
		//得到读取文件的绝对路径名
		snprintf(dir, 512,"%s/%s", path, ent->d_name );
		//得到文件信息
		lstat(dir, &statbuf);
		//判断是目录还是文件
		if(S_ISDIR(statbuf.st_mode)){
			continue;
		} else {
			char *p = strrchr(ent->d_name, '.');
			if(p && (strcmp(p, file_suf) == 0)){
				sprintf(filename, "%s/%s", path ,ent->d_name);

				file_hash_table = malloc(sizeof(struct __file_hash_table));
				file_hash_table -> next = inotify_struct[wd].file_hash_table;
				file_hash_table -> file_name = strdup(ent->d_name);
				inotify_struct[wd].file_hash_table = file_hash_table;
				inotify_struct[wd].file_number++;

				//printf("Match :　%s\n", filename);
				md5_file(filename, file_hash_table->md5);

			} else {
				//printf( "Not match %s\n", ent->d_name );
			}
		}
	}
	closedir(pDir);
	print_inotify_struct(wd);
}


unsigned long get_file_size(const char *path)  
{  
    unsigned long filesize = -1;      
    struct stat statbuff;  
    if(stat(path, &statbuff) < 0){  
        return filesize;  
    }else{  
        filesize = statbuff.st_size;  
    }  
    return filesize;  
}  

void md5_file(char * filename, unsigned char * md5)
{
	FILE *fp;
	MD5_CTX ctx;
	int i=0; 
	char x[1024];
	unsigned long file_size;
	
	file_size = get_file_size(filename);
	
	if (file_size <= 0 || file_size > max_file_len) {
		printf("File %s is large then %lu\n", filename, max_file_len);
		memset(md5, '\0', 8);
		return;
	}

	if (!(fp = fopen(filename,"rb"))) {
		printf("Can not open %s this file!\n",filename);
		memset(md5, '\0', 8);
		return;
	}
	
	MD5_Init(&ctx);

	while (( i = fread(x, 1, 1024, fp)) >0)
	{
		MD5_Update(&ctx, x, i);
	}   

	MD5_Final(md5, &ctx);

	fclose(fp);
}


int check_md5_file(char * filename, int wd)
{
	unsigned char md5[16] = {0};
	struct __file_hash_table * file_hash_table;
	int i,j;

	char * file_name = strrchr(filename, '/');
	file_name++;

	md5_file(filename, md5);

	file_hash_table = inotify_struct[wd].file_hash_table;

	for(i = 0; i < inotify_struct[wd].file_number && file_hash_table != NULL; i++){
		if( strcmp(file_hash_table -> file_name, file_name) == 0){
			if (strncmp( (const char *)(file_hash_table -> md5), (const char *)md5, 16) == 0){
				return(0);
			} else{
				for(j = 0; j < 16; j++)
					file_hash_table -> md5[j] = md5[j];
				return(1);
			}
		}

		file_hash_table = file_hash_table -> next;
	}
	return(1);
}

void init_inotify_struct()
{
	int i;
	for(i = 0; i < MAX_MONITOR_FD; i++){
		inotify_struct[i].file_number = 0;
		inotify_struct[i].file_hash_table = NULL;
	}		
}

void print_inotify_struct(int wd)
{
	int i,j;
	struct __file_hash_table * file_hash_table;

	file_hash_table = inotify_struct[wd].file_hash_table;

	printf("DIR: %s\n", inotify_struct[wd].dir_name);
	for(i = 0; i < inotify_struct[wd].file_number; i++){
		printf("\tFILE: %s \tMD5: ", file_hash_table -> file_name);
		for(j = 0; j < 16; j++)
			printf("%02x", file_hash_table -> md5[j]);
		printf("\n");
		file_hash_table = file_hash_table -> next;
	}
}
