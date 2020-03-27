#include <stdio.h>
#include <unistd.h>
#include <arpa/inet.h>
#include "transform.h"
#define buffersize 0x10000
#include <dirent.h>
#include <sys/types.h>
#include <string.h>
#include <stdlib.h>
#include <regex.h>
void transform(int x,char *argv[]){


FILE *fp;	
FILE *fp2;
fp = fopen("/proc/net/tcp","r");
fp2 =fopen("/proc/net/udp","r");/*read file*/

char line_buffer[buffersize];
int num;
unsigned int sl;
unsigned int local_add_ip;
unsigned int rem_add_ip;
unsigned int local_add_port;
unsigned int rem_add_port;
unsigned int inode;
unsigned int stxx;

unsigned int txqueue;
unsigned int rxqueue;
unsigned int tr;
unsigned int tm;
unsigned int retrnsmt;
unsigned int uid;
unsigned int timeout;
unsigned int useless;
/*read file*/
char path[] ="/proc";
/**/
DIR *dir;
DIR *dir2;
DIR *dir3;
struct dirent *sd;//connect dir number
struct dirent *sd2;//connect file number
char *pid;
if (x==0)/*tcp connect*/
{
	printf("List of TCP connectionns:\n");
	if(fgets(line_buffer,buffersize-1,fp)!=NULL){
	printf("Proto      Local Address             Foreign Address              PID   /Program name and arguments\n");
	}	
	while(fgets(line_buffer,buffersize-1,fp))
	{
	num = sscanf(line_buffer,"%d: %X:%X %X:%X %X %X:%X %X:%X %X %d %d %d %d",&sl,&local_add_ip,&local_add_port,&rem_add_ip,&rem_add_port,&stxx,&txqueue,&rxqueue,&tr,&tm,&retrnsmt,&uid,&timeout,&inode,&useless);
	/*print connect info*/
/*find dir*/
	dir =opendir(path);
//	printf("第一%s\n@@@><",path);

	while((sd=readdir(dir)) != NULL){
		char path2[50]="/proc/";
		pid= sd->d_name;	
		strcat(path2,sd->d_name);
		strcat(path2,"/fd");
//		printf("第二%s\n",path2);	
		dir3 =opendir(path2);
		if(dir3){
			while((sd2 =readdir(dir3))!=NULL)
			{		
			FILE *cmdlf;//cmdline file
			char cmdr[500];//cmd read
			char path3[50] ="";//path in file fd
			strcat(path3,path2);
			strcat(path3,"/");
			strcat(path3,sd2->d_name);
			char *buffer;
			ssize_t bufsiz;
			bufsiz = PATH_MAX;
			buffer = malloc(bufsiz);
			readlink(path3,buffer,bufsiz);
//			printf("第三%s\n",path3);
			unsigned int sylink=-1;
			sscanf(buffer,"socket:[%d]",&sylink);//read data from buffer
			if(inode==sylink)
			{
			//	printf("%dxxx",sylink);	
			//	printf("%s\n",sd->d_name);	
			
			//	FILE *cmdlf;//cmdline file
			//	char cmdr[500];//cmd read
				FILE *state;
				char name[30];
				char cmds[50]="/proc/";
				char st[50]="/proc/";
				char st_name[50];
				//cmdline file  path
				strcat(cmds,pid);
				strcat(cmds,"/cmdline");
				//process name path
				strcat(st,pid);
				strcat(st,"/status");

				//start tp read /proc/[pid]/status name
				state = fopen(st,"r");
				fgets(st_name,30,state);
				sscanf(st_name,"Name:	%s",name);
				fclose(state);
				// read correct /proc/[pid]/cmdline
				
				struct in_addr local_ip4;
				char local_ipv4[200] ="";
				local_ip4.s_addr=local_add_ip;
				inet_ntop(AF_INET,&(local_ip4.s_addr),local_ipv4,INET_ADDRSTRLEN);
				struct in_addr rem_ip4;
				char rem_ipv4[200] ="";
				rem_ip4.s_addr=rem_add_ip;
				inet_ntop(AF_INET,&(rem_ip4.s_addr),rem_ipv4,INET_ADDRSTRLEN);
				// read correct /proc/[pid]/cmdline
				cmdlf =fopen(cmds,"r");
				
				while(fgets(cmdr,500,cmdlf)!= NULL){	}
				//reg
				int status, i;
				int cflags =REG_EXTENDED;
				regmatch_t pmatch[1];
				const size_t nmatch=1;
				regex_t reg;
				if(argv[1]==NULL){
				
				printf("\ntcp	%-15s:%-4X	%-15s:%-4X	%s/%s	cmdline=%s\n\n",local_ipv4,local_add_port,rem_ipv4,rem_add_port,pid,name,cmdr);
				fclose(cmdlf);
				break;
				}
				if(argv[2]!=NULL){
				const char *pattern =argv[2];
				//cmdr
				regcomp(&reg, pattern, cflags);
				status =regexec(&reg,cmdr,nmatch,pmatch,0);}
				if (status==REG_NOMATCH)
				{//	printf("NO  MATCH\n");
					break;}
				else if(status==0)
				{
				printf("\ntcp	%-15s:%-4X	%-15s:%-4X	%s/%s	cmdline=%s\n\n",local_ipv4,local_add_port,rem_ipv4,rem_add_port,pid,name,cmdr);
				fclose(cmdlf);
				break;
				}
				}			
	
			
			}
		closedir(dir3);

			}

		}
	closedir(dir);
	}
}


else if(x==1)/*udp connect*/
{


	printf("List of UDP connectionns:\n");
	if(fgets(line_buffer,buffersize-1,fp2)!=NULL){
	printf("Proto      Local Address             Foreign Address          PID   /Program name and arguments\n");
	}	
	while(fgets(line_buffer,buffersize-1,fp2))
	{
	num = sscanf(line_buffer,"%d: %X:%X %X:%X %X %X:%X %X:%X %X %d %d %d %d",&sl,&local_add_ip,&local_add_port,&rem_add_ip,&rem_add_port,&stxx,&txqueue,&rxqueue,&tr,&tm,&retrnsmt,&uid,&timeout,&inode,&useless);
	/*print connect info*/
/*find dir*/
	dir =opendir(path);
//	printf("第一%s\n@@@><",path);

	while((sd=readdir(dir)) != NULL){
		char path2[50]="/proc/";
		pid= sd->d_name;	
		strcat(path2,sd->d_name);
		strcat(path2,"/fd");
//		printf("第二%s\n",path2);	
		dir3 =opendir(path2);
		if(dir3){
			while((sd2 =readdir(dir3))!=NULL)
			{		
			FILE *cmdlf;//cmdline file
			char cmdr[500];//cmd read
			char path3[50] ="";//path in file fd
			strcat(path3,path2);
			strcat(path3,"/");
			strcat(path3,sd2->d_name);
			char *buffer;
			ssize_t bufsiz;
			bufsiz = PATH_MAX;
			buffer = malloc(bufsiz);
			readlink(path3,buffer,bufsiz);
//			printf("第三%s\n",path3);
			unsigned int sylink=-1;
			sscanf(buffer,"socket:[%d]",&sylink);//read data from buffer
			if(inode==sylink)
			{
			//	printf("%dxxx",sylink);	
			//	printf("%s\n",sd->d_name);	
			
			//	FILE *cmdlf;//cmdline file
			//	char cmdr[500];//cmd read
				FILE *state;
				char name[30];
				char cmds[50]="/proc/";
				char st[50]="/proc/";
				char st_name[50];
				//cmdline file  path
				strcat(cmds,pid);
				strcat(cmds,"/cmdline");
				//process name path
				strcat(st,pid);
				strcat(st,"/status");

				//start tp read /proc/[pid]/status name
				state = fopen(st,"r");
				fgets(st_name,30,state);
				sscanf(st_name,"Name:	%s",name);
				fclose(state);
				//convert to ipv4
				struct in_addr local_ip4;
				char local_ipv4[200] ="";
				local_ip4.s_addr=local_add_ip;
				inet_ntop(AF_INET,&(local_ip4.s_addr),local_ipv4,INET_ADDRSTRLEN);
				struct in_addr rem_ip4;
				char rem_ipv4[200] ="";
				rem_ip4.s_addr=rem_add_ip;
				inet_ntop(AF_INET,&(rem_ip4.s_addr),rem_ipv4,INET_ADDRSTRLEN);
				// read correct /proc/[pid]/cmdline
				cmdlf =fopen(cmds,"r");
				while(fgets(cmdr,500,cmdlf)!= NULL){	}
				int status, i;
				int cflags =REG_EXTENDED;
				regmatch_t pmatch[1];
				const size_t nmatch=1;
				regex_t reg;
				if(argv[1]==NULL){
				
				printf("\nudp	%-15s:%-5X	%-15s:%-5X	%s/%s	cmdline=%s\n\n",local_ipv4,local_add_port,rem_ipv4,rem_add_port,pid,name,cmdr);
				fclose(cmdlf);
				break;
				}
				if(argv[2]!=NULL){
				const char *pattern =argv[2];
				//cmdr
				regcomp(&reg, pattern, cflags);
				status =regexec(&reg,cmdr,nmatch,pmatch,0);}
				if (status==REG_NOMATCH)
				{//	printf("NO  MATCH\n");
					break;}
				else if(status==0)
				{
				printf("\nudp	%-15s:%-5X	%-15s:%-5X	%s/%s	cmdline=%s\n\n",local_ipv4,local_add_port,rem_ipv4,rem_add_port,pid,name,cmdr);
				fclose(cmdlf);
				break;
				}		
				}	
			
			}
		closedir(dir3);

			}

		}
	closedir(dir);
	}


}



fclose(fp);
fclose(fp2);


}
