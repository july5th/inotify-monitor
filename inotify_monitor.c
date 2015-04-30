#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/select.h>
#include <sys/inotify.h>
#include <signal.h>
#include <mysql/mysql.h>
#include "event_queue.h"
#include "inotify_utils.h"

char * config_filename = "inotify.conf";

int keep_running;
MYSQL  mysql;
char host_name[255];
int pid;
unsigned long max_file_len;

/* This program will take as arguments one or more directory 
   or file names, and monitor them, printing event notifications 
   to the console. It will automatically terminate if all watched
   items are deleted or unmounted. Use ctrl-C or kill to 
   terminate otherwise.
*/

/* Signal handler that simply resets a flag to cause termination */
void signal_handler(int signum)
{
	keep_running = 0;
}

void init_daemon(void)
{
	int pid;
	int i;
	pid = fork();

	if(pid)
		exit(0);//是父进程，结束父进程
	else if(pid< 0)
		exit(1);//fork失败，退出
	//是第一子进程，后台继续执行
	setsid();//第一子进程成为新的会话组长和进程组长
	//并与控制终端分离

	pid = fork();
	if(pid)
		exit(0);//是第一子进程，结束第一子进程
	else if (pid < 0)
		exit(1);//fork失败，退出
	//是第二子进程，继续
	//第二子进程不再是会话组长

	for (i = 0; i < sysconf(_SC_OPEN_MAX); ++i)//关闭打开的文件描述符
		close(i);
	//chdir("/tmp");//改变工作目录到/tmp
	umask(0);//重设文件创建掩模
	return;
}

int main (int argc, char **argv)
{
	/* This is the file descriptor for the inotify watch */
	int inotify_fd;
	char c;
	char *file_name = NULL;
	FILE *fp;
	//char *user = "monitor", *pwd = "!QAZ2wsx", *dbname = "record", *host="10.2.10.144"; 
	char *user, *passwd, *dbname, *host; 
	char arr[256], tmp[256];
	keep_running = 1;
	int running_bg = 0, p;
	/*read config file*/
	fp = fopen(config_filename, "r");
	if(fp <= 0){
		printf("Open config file：%s faild\n", config_filename);
		return(0);
	}

	while ((fgets (arr, 254, fp)) != NULL){
		arr[strlen(arr) - 1] = '\0';
		printf("\n%s\n", arr);
		for(p = 0; p < strlen(arr); p++){
			if(*(arr + p) != ' ' && *(arr + p) != '\t' && *(arr + p) != '='){
				tmp[p] = arr[p];
			} else {
				break;
			}
		}
		tmp[p] = '\0';
		if (strcmp(tmp, "host") == 0){
			while(*(arr + p) == ' ' || *(arr + p) == '\t' || *(arr + p) == '=')
				p++;
			host = strdup(arr + p);
			printf("host : %s", host);
		}else if(strcmp(tmp, "dbname") == 0){
			while(*(arr + p) == ' ' || *(arr + p) == '\t' || *(arr + p) == '=')
				p++;
			dbname = strdup(arr + p);
			printf("dbname : %s", dbname);
		}else if(strcmp(tmp, "user") == 0){
			while(*(arr + p) == ' ' || *(arr + p) == '\t' || *(arr + p) == '=')
				p++;
			user = strdup(arr + p);
			printf("user : %s", user);
		}else if(strcmp(tmp, "passwd") == 0){
			while(*(arr + p) == ' ' || *(arr + p) == '\t' || *(arr + p) == '=')
				p++;
			passwd = strdup(arr + p);
			printf("passwd : %s", passwd);
		}else if(strcmp(tmp, "max_file_len") == 0){
			while(*(arr + p) == ' ' || *(arr + p) == '\t' || *(arr + p) == '=')
				p++;
			max_file_len = atoi(strdup(arr + p));
			printf("max_file_len : %lu", max_file_len);
		}
	}
	fclose(fp);
	while((c = getopt(argc, argv, "dc:")) != -1) {
		switch(c) {
			case 'c':
				file_name = strdup(optarg);
				break;
			case 'd':
				running_bg = 1;
				break;
		}
	}
	if(file_name == NULL){
		printf("please use [ -c filename ] to set monitor file list!\n");
		return(0);
	}
	if(running_bg)
		init_daemon();
	gethostname(host_name, sizeof(host_name));
	pid = getpid();
	mysql_init(&mysql);
	if (!mysql_real_connect(&mysql,host,user,passwd,dbname,0,NULL,0)){
		printf("ERROR: connet mysql.\n");
		return(1);
	}
	fp = fopen(file_name ,"r");
	if(fp <= 0){
		printf("Open file：%s faild\n", file_name);
		return(0);
	}
	/* Set a ctrl-c signal handler */
	if (signal(SIGINT, signal_handler) == SIG_IGN){
		/* Reset to SIG_IGN (ignore) if that was the prior state */
		signal (SIGINT, SIG_IGN);
	}
	init_inotify_struct();
	/* First we open the inotify dev entry */
	inotify_fd = open_inotify_fd();
	if (inotify_fd > 0){
		/* We will need a place to enqueue inotify events,
		   this is needed because if you do not read events
		   fast enough, you will miss them. This queue is 
		   probably too small if you are monitoring something
		   like a directory with a lot of files and the directory 
		   is deleted.
		 */
		queue_t q;
		q = queue_create(256);
		/* This is the watch descriptor returned for each item we are 
		   watching. A real application might keep these for some use 
		   in the application. This sample only makes sure that none of
		   the watch descriptors is less than 0.
		 */
		int wd = 0;
		/* Watch all events (IN_ALL_EVENTS) for the directories and 
		   files passed in as arguments.
		   Read the article for why you might want to alter this for 
		   more efficient inotify use in your app.      
		 */
		printf("\n");

		while ((fgets (arr, 254, fp)) != NULL) {
			arr[strlen(arr) - 1] = '\0';
			wd = watch_dir(inotify_fd, arr, IN_MODIFY | IN_MOVE | IN_CREATE | IN_DELETE);
			if (wd < 0 ) break;
		}

		if (wd > 0) {
			/* Wait for events and process them until a 
			   termination condition is detected
			 */
			process_inotify_events(q, inotify_fd);
		}
		printf ("\nTerminating\n");

		/* Finish up by closing the fd, destroying the queue,
		   and returning a proper code
		 */
		close_inotify_fd(inotify_fd);
		queue_destroy(q);
	}
	return 0;
}

