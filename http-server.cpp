#include<unistd.h>
#include<time.h>
#include<stdio.h>
#include<stdlib.h>
#include<stdio.h>
#include<string.h>
#include<sys/types.h>
#include<sys/socket.h>
#include<netdb.h>
#include<arpa/inet.h>
#include<signal.h>
#include<errno.h>
#include<queue>
#include <iostream>
#include <deque>
#include <list>
#include<utility>
#include<fcntl.h>
#include<sys/types.h>
#include<sys/time.h>
#include<unistd.h>
#include <dirent.h>
#include <netinet/in.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <sys/wait.h>
#include "smartalloc.h"

#define MAXBUF 2500
#define BACKLOGSIZE 10
#define INITBUFSIZE 500
#define BUFL 1000

SSL_CTX *ctx;


char ok[] = "OK";
char notfound[] = "Not Found";
char forbidden[] = "Forbidden";
char http11[] = "HTTP/1.1";

char http_404_msg[] = "<HTML><HEAD><TITLE>HTTP ERROR 404</TITLE></HEAD><BODY>404 Not Found.  Your request could not be completed due to encountering HTTP error number 404.</BODY></HTML>";

char http_403_msg[] = "<HTML><HEAD><TITLE>HTTP ERROR 403</TITLE></HEAD><BODY>403 Forbidden.  Your request could not be completed due to encountering HTTP error number 403.</BODY></HTML>";

char http_dir_begin[] = "<HTML>\n<HEAD>\n<TITLE>Directory Listing</TITLE>\n</HEAD>\n<BODY>\n<H2>Directory Listing</H2><BR>\n<UL>\n";

char http_dir_end[] = "</UL>\n</BODY>\n</HTML>\n";
char http_status_start[] = "<HTML>\n<HEAD>\n<TITLE>Server Status</TITLE>\n</HEAD>\n<BODY>\n";
char http_status_end[] = "<BR>\n<FORM METHOD=\"GET\" ACTION=\"quit\">\n<INPUT TYPE=\"submit\" VALUE=\"Quit Server\"/>\n<INPUT TYPE=\"HIDDEN\" NAME=\"confirm\" VALUE=\"1\"/>\n</FORM>\n</BODY>\n</HTML>\n";


static int httpsport = 0;
static int httpport = 0;
char v6check[12];

char texttype[] = "text/html";
char pdftype[] = "application/pdf";
char giftype[] = "image/gif";
char jpgtype[] = "image/jpeg";
char pngtype[] = "image/png";
char txttype[] = "text/plain";





int getport(struct sockaddr *sa);
void accept_stage(int sfd, bool ssl);
void read_stage();
void ssl_stage();
void parse_stage();
void write_stage();
char *create_header(double version, int number, char *command, char *type, int length);

void freestuff();


void createCTX(void);
void loadCerts(void);

using namespace std;
enum ParseState {
   NOTHING,
   START,
   MORE,
   NEXT,
   DONE,
   CR
};
struct connection{
   int fd;
   char *buffer;
   int buffersize;
   int pos;
   char *writebuffer;
   int writepos;
   int writesize;
   ParseState state;
   ParseState prevstate;
   SSL *ssl;
};

typedef struct connection connection;

void freeconn(connection *conn);
int servefile(connection *currconn, char *fullpath, char *version);
char *decodeurl(char *path);

bool getout = false;
bool ipv6 = false;

void sigint_handler(int sig)
{
   getout = true;
}


list<connection *> ssl_q;
list<connection *> read_q;
list<connection *> parse_q;
list<connection *> write_q;

int main(int argc, char **argv)
{

   struct sigaction sa;
   int sfd, ssld, status;
   char *iparg;


   if (argc == 2) {
      iparg = argv[1];
   }
   else {
      iparg = NULL;
   }


   createCTX();
   loadCerts();

   if( (ssld = socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP)) == -1 ){
      perror("invalid socket");
      exit(1);
   }

   if( (sfd = socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP)) == -1 ){
      perror("invalid socket");
      exit(1);
   }

   struct sockaddr_in6 mainsock;
   memset(&mainsock, 0, sizeof(struct sockaddr_in6));
   mainsock.sin6_family = AF_INET6;

   if(!iparg){
      mainsock.sin6_addr= in6addr_any;

   } 
   else {
      status = inet_pton(AF_INET6, iparg, &(mainsock.sin6_addr));
      ipv6 = true;

      if(!status){
         ipv6 = false;
         int arglen = strlen(iparg);
         char v6str[] = "::FFFF:";
         char *newarg = (char *)malloc(arglen + 8);

         strcpy(newarg, v6str);
         strcat(newarg, iparg);

         status = inet_pton(AF_INET6, newarg, &(mainsock.sin6_addr));
         if(!status){
            fprintf(stderr, "invalid argument\n");
            free(newarg);
            exit(1);
         }
         
         free(newarg);

      }
         
   }

   memset(v6check, 0, 12);
   v6check[10] = (char)0xFF;
   v6check[11] = (char)0xFF;


   int socketflags = fcntl(sfd, F_GETFL);

   socketflags |= O_NONBLOCK;
   fcntl(sfd, F_SETFL, socketflags);
   
 
   int sslsocketflags = fcntl(ssld, F_GETFL);

   sslsocketflags |= O_NONBLOCK;
   fcntl(ssld, F_SETFL, sslsocketflags);
   
   if( (bind(sfd, (struct sockaddr *)&mainsock, sizeof(mainsock))) == -1 ){
      perror("error binding");
      exit(1);
   }

   
   struct sockaddr_in6 sslsock;
   memcpy(&sslsock, &mainsock, sizeof(sockaddr_in6));
 
   if( (bind(ssld, (struct sockaddr *)&sslsock, sizeof(sslsock))) == -1 ){
      perror("error ssl binding");
      exit(1);
   }



   if( listen(sfd, BACKLOGSIZE) < 0){
     perror("listen");
   }

   if( listen(ssld, BACKLOGSIZE) < 0){
     perror("ssl listen");
   }


   struct sockaddr portnum;
   socklen_t socklen  = sizeof(portnum);
   getsockname(sfd, &portnum, &socklen);
   
   struct sockaddr sslportnum;
   socklen_t sslsocklen  = sizeof(sslportnum);
   getsockname(ssld, &sslportnum, &sslsocklen);


   httpport = getport(&portnum);
   httpsport = getport(&sslportnum);

   printf("HTTP server is using TCP port %d\n", getport(&portnum));
   printf("HTTPS server is using TCP port %d\n", getport(&sslportnum));
   fflush(stdout);

 
  // freeaddrinfo(serverinfo); // free the linked-list

   /* Install the signal handler */
   sa.sa_handler = sigint_handler;
   sigfillset(&sa.sa_mask);
   sa.sa_flags = 0;

   if (-1 == sigaction(SIGINT, &sa, NULL))
   {
      perror("Couldn't set signal handler for SIGINT");
      return 2;
   }


    
 
   fd_set read_set;
   fd_set write_set;
   int maxfd;
   connection *currconn;
   list<connection *>::iterator itr;

   //main event loop
   for( ; ; ){
      if(getout){
         break;
      }
      while(parse_q.size() != 0)
         parse_stage();

      

      FD_ZERO(&read_set);
      FD_ZERO(&write_set);      

      FD_SET(sfd, &read_set);
      maxfd = sfd;

      FD_SET(ssld, &read_set);
      if(ssld > maxfd)
         maxfd = ssld;


      for(itr = read_q.begin(); itr != read_q.end(); itr++){
         currconn = (*itr);
         FD_SET(currconn->fd, &read_set);
         if(maxfd < currconn->fd)
            maxfd = currconn->fd;
      }
      for(itr = ssl_q.begin(); itr != ssl_q.end(); itr++){
         currconn = (*itr);
         FD_SET(currconn->fd, &read_set);
         if(maxfd < currconn->fd)
            maxfd = currconn->fd;
      }


      for(itr = write_q.begin(); itr != write_q.end(); itr++){
         currconn = (*itr);
         FD_SET(currconn->fd, &write_set);
         if(maxfd < currconn->fd)
            maxfd = currconn->fd;
      }

      select(maxfd + 1, &read_set, &write_set, NULL, NULL);



      accept_stage(sfd, false);
      accept_stage(ssld, true);
      ssl_stage();
      read_stage();
      write_stage();
   }
   
   freestuff();
   printf("Server exiting cleanly.\n");

   return 0;

}

void accept_stage(int sfd, bool ssl){


   sockaddr_in clientaddr;
   int connfd;
   socklen_t len = sizeof(clientaddr);

   connfd = accept(sfd, (sockaddr *)&clientaddr, &len);


   if(connfd != -1){ 

#ifdef DEBUG
      printf("accepted new connection\n");
      fflush(stdout);
#endif

      connection *newconn = (connection *)malloc(sizeof(connection));

      newconn->fd = connfd;
      newconn->buffer = (char *)malloc(INITBUFSIZE);
      newconn->buffersize = INITBUFSIZE;
      newconn->pos = 0;
      newconn->writebuffer = NULL;

      newconn->state = NOTHING;
      newconn->prevstate = NOTHING;
      
      if(ssl){

         newconn->ssl = SSL_new(ctx);
         SSL_set_fd(newconn->ssl, connfd);

/*
       int socketflags = fcntl(connfd, F_GETFL);

         socketflags |= O_NONBLOCK;
         fcntl(connfd, F_SETFL, socketflags);
*/

         if(SSL_accept(newconn->ssl) == -1){

            while( SSL_get_error(newconn->ssl, -1) == SSL_ERROR_WANT_READ){
               SSL_accept(newconn->ssl);
            }
         }

         read_q.push_back(newconn);
         //ssl_q.push_back(newconn);
         

         }
      else {
         newconn->ssl = NULL;
         read_q.push_back(newconn);
      }

   }
}


void ssl_stage(){
   if( ssl_q.size() == 0){
      return;
   }

   connection *currconn;

   //create new socket set to observe
   fd_set read_set;
   FD_ZERO(&read_set);
   list<connection *>::iterator itr;

   int maxfd = 0;
   for(itr = ssl_q.begin(); itr != ssl_q.end(); itr++){
      currconn = (*itr);
      FD_SET(currconn->fd, &read_set);
      if(maxfd < currconn->fd)
         maxfd = currconn->fd;
   }

   //use zero timeout for polling
   struct timeval timeout;
   timeout.tv_sec = 0;
   timeout.tv_usec = 0;
   
   int status = select(maxfd + 1, &read_set, NULL, NULL, &timeout);
   if(status <= 0){
      return;
   }

   int readfrom;

   for(itr = ssl_q.begin(); itr != ssl_q.end(); itr++){
      currconn = (*itr);
      if (FD_ISSET(currconn->fd, &read_set)){
         readfrom = currconn->fd;
         break;
      }
   }


   if(SSL_accept(currconn->ssl) == -1){
      ERR_print_errors_fp(stderr);
      close(currconn->fd);
      ssl_q.remove(currconn);

      freeconn(currconn);
   }
   else {

      fprintf(stderr, "ssl connection accepted\n");
      ssl_q.remove(currconn);
      fprintf(stderr, "ssl_q size %d\n", ssl_q.size());
      read_q.push_back(currconn);
   }


}

void read_stage(){
   if( read_q.size() == 0){
      return;
   }   

   int n;
   connection *currconn;


   //create new socket set to observe
   fd_set read_set;
   FD_ZERO(&read_set);
   list<connection *>::iterator itr;

   int maxfd = 0;
   for(itr = read_q.begin(); itr != read_q.end(); itr++){
      currconn = (*itr);

      FD_SET(currconn->fd, &read_set);
      if(maxfd < currconn->fd)
         maxfd = currconn->fd;
   }

   //use zero timeout for polling
   struct timeval timeout;
   timeout.tv_sec = 0;
   timeout.tv_usec = 0;
   
   int status = select(maxfd + 1, &read_set, NULL, NULL, &timeout);
   if(status <= 0){
      return;
   }

   int readfrom;

   for(itr = read_q.begin(); itr != read_q.end(); itr++){

      currconn = (*itr);
      if (FD_ISSET(currconn->fd, &read_set)){
         readfrom = currconn->fd;
         break;
      }
   }

   if(currconn->buffersize < (currconn->pos + 2)){
      currconn->buffer = (char *)realloc(currconn->buffer, currconn->buffersize + INITBUFSIZE);
      currconn->buffersize += INITBUFSIZE;
   }

   #ifdef DEBUG
         printf("ready to readfrom to %d\n", readfrom);
   #endif


   if(currconn->ssl){
      n = SSL_read(currconn->ssl, currconn->buffer + currconn->pos, MAXBUF);
      currconn->pos += n;
      currconn->buffer[currconn->pos] = '\0';
      char *crlf = strstr(currconn->buffer, "\r\n\r\n");
      if(crlf != NULL){
         currconn->state = DONE;
      }

   }
   else{
      n = recv(currconn->fd, currconn->buffer + currconn->pos, 1, 0);

   if ( n > 0){


      if( currconn->state == NOTHING ){

         if(currconn->buffer[currconn->pos] == '\r'){
            currconn->buffer[currconn->pos] = '\0';
            currconn->state = CR;
            currconn->prevstate = NOTHING;
         }    
         else {
            currconn->state = START;
            currconn->pos += n;
         }
      } 

      else if(currconn->state == START){

         if(currconn->buffer[currconn->pos] == '\r'){
            currconn->buffer[currconn->pos] = '\0';
            currconn->state = CR;
            currconn->prevstate = START;
         }
         else {
            currconn->pos += n;
         }
      }

      else if(currconn->state == NEXT){

         if(currconn->buffer[currconn->pos] == '\r'){
            currconn->buffer[currconn->pos] = '\0';
            currconn->state = CR;
            currconn->prevstate = NEXT; 
         }
         else {
            currconn->state = MORE;
            currconn->buffer[currconn->pos] = '\0';
         }

      }
 
      else if(currconn->state == MORE) {

         if(currconn->buffer[currconn->pos] == '\r'){
            currconn->buffer[currconn->pos] = '\0';
            currconn->state = CR;
            currconn->prevstate = MORE; 
         }
         else {
            currconn->state = MORE;
            currconn->buffer[currconn->pos] = '\0';
         }

      }
 
      else if(currconn->state == CR){

         if(currconn->buffer[currconn->pos] == '\n'){
            currconn->buffer[currconn->pos] = '\0';

            if(currconn->prevstate == NEXT)
               currconn->state = DONE;
            else if(currconn->prevstate == START)
               currconn->state =  NEXT;
            else if(currconn->prevstate == MORE)
               currconn->state =  NEXT;
            else 
               currconn->state = currconn->prevstate;
         }
         else {
            fprintf(stderr, "expected LF after CR\n");
         }
 
      } 

   }
   }

   if(n == 0){
      //the client closed the connection
      if(currconn->ssl)
         SSL_shutdown(currconn->ssl);
 
      close(currconn->fd);
      read_q.remove(currconn);
      freeconn(currconn);
   } else if(currconn->state == DONE){
      read_q.remove(currconn); 
      parse_q.push_back(currconn);
   } else {
#ifdef DEBUG
      printf("not done yet\n");
#endif
   }
}



void parse_stage(){
   if ( parse_q.size() == 0){
      return;
   }

   connection *currconn = parse_q.front();
   char curr_buff[currconn->pos + 1];
   memcpy(curr_buff, currconn->buffer, currconn->pos);
   curr_buff[currconn->pos] = '\0';

#ifdef DEBUG
   printf("%s\n", curr_buff);
#endif

   char command[MAXBUF];
   char path[MAXBUF];
   char version[MAXBUF];


   //just making sure it doesnt have http/1.1
   version[0] = 'p';


   int numargs = sscanf(curr_buff, "%s %s %s\n", command, path, version);
   char *header;





   char *decoded;

   if( strstr(path, "://") != NULL){
     char *http = strstr(path, "://");
     http += 3;
     http = strstr(http, "/");
     decoded = decodeurl(http);
     strcpy(path, decoded);
     free(decoded);
   } else {
     decoded = decodeurl(path);
     strcpy(path, decoded);
     free(decoded);
   }

   char cgipath[MAXBUF];
   strcpy(cgipath, path);
   char *binname = strtok(cgipath, "/");

   if(!binname){
      binname = ok;
   }

   
   FILE *tempfile;

   if(numargs < 2 || strcmp(command, "GET") ){
      
      if(strcmp(http11, version))
         header = create_header(1.0, 404, notfound, texttype, strlen(http_404_msg));
      else
         header = create_header(1.1, 404, notfound, texttype, strlen(http_404_msg));


#ifdef DEBUG
      printf("%s", header);
#endif

      currconn->writebuffer = (char *)malloc(MAXBUF);
      sprintf(currconn->writebuffer, "%s%s", header, http_404_msg);



#ifdef DEBUG
      printf("%s", currconn->writebuffer);
#endif
      
      currconn->writepos = 0;
      currconn->writesize = strlen(header) + strlen(http_404_msg);
      
      free(header);
   }
   else if(!strcmp(binname,"cgi-bin")){
      binname = strtok(NULL, "/");

      if(binname == NULL)
         binname = http_404_msg;


      char cwdpath[BUFL];
  
      if( !getcwd(cwdpath,BUFL) ){
         perror("cwd");
      }
     

      char binname2[MAXBUF];
      strcpy(binname2, binname);
 
      char *scriptname = strtok(binname2, "?");
      char *querystring = NULL;
        
      if(scriptname == NULL){
         scriptname = ok;
      }
      else {
         querystring = strtok(NULL, "?");
      }


      strcat(cwdpath, "/cgi/");
      strcat(cwdpath, scriptname);

      if(!strcmp(binname, "status")){
         char *statusstuff = (char *)malloc(MAXBUF);
         time_t thetime = time(NULL); 
         int wrote = sprintf(statusstuff, "%sAuthor: Kareem Nassar<BR>\nServer Process ID: %d<BR>\nCurrent Time: %s%s", 
                             http_status_start, (int)getpid(), ctime(&thetime), http_status_end);
        
         

         if(strcmp(http11, version))
            header = create_header(1.0, 200, ok, texttype, wrote);
         else
            header = create_header(1.1, 200, ok, texttype, wrote);

         
         currconn->writepos = 0;
         currconn->writesize = strlen(header) + wrote;

         currconn->writebuffer = (char *)malloc(MAXBUF);
         sprintf(currconn->writebuffer, "%s%s", header, statusstuff);

         free(header);
         free(statusstuff);
      }
      else if(!strcmp(binname, "quit?confirm=1")){
         currconn->writebuffer = (char *)malloc(MAXBUF);
         char goodbye[] = "Goodbye!";  
         if(strcmp(http11, version))
            header = create_header(1.0, 200, ok, txttype, strlen(goodbye));
         else
            header = create_header(1.1, 200, ok, txttype, strlen(goodbye));

         sprintf(currconn->writebuffer, "%s%s", header, goodbye);
         currconn->writepos = 0;
         currconn->writesize = strlen(header) + strlen(goodbye);
         free(header);

         getout = true;
      }
      else {



         if(!strcmp(scriptname, "quit")){
            currconn->writebuffer = (char *)malloc(MAXBUF);
            char badparams[] = "Bad Params!";  

            if(strcmp(http11, version))
               header = create_header(1.0, 200, ok, txttype, strlen(badparams));
            else
               header = create_header(1.1, 200, ok, txttype, strlen(badparams));

            sprintf(currconn->writebuffer, "%s%s", header, badparams);
            currconn->writepos = 0;
            currconn->writesize = strlen(header) + strlen(badparams);
            free(header);
         }
         else if( (tempfile = fopen(cwdpath, "r") ) ){
            fclose(tempfile);
            
            tempfile = tmpfile();
            int tempfd = fileno(tempfile);

            //let's fork and pipe the output to the currconn writebuffer


           char envval[MAXBUF];
           
           struct sockaddr_in6 servername;
           memset(&servername, 0, sizeof(struct sockaddr_in6));
           socklen_t serverlen = sizeof(servername);
 
           getsockname(currconn->fd, (struct sockaddr *)&servername, &serverlen);
  

           bool ipv4 = true;

           for(int i = 0; i < 12; i++){
              if( (char)(servername.sin6_addr.s6_addr[i]) != v6check[i] ){
                 ipv4 = false;
              }

           }
           char *iparg = envval;
           if(ipv4){
            //not sure about print format
              inet_ntop(AF_INET6, &servername.sin6_addr, envval,MAXBUF);
              iparg = strtok(envval, ":");
              iparg = strtok(NULL, ":");
           } else {
              char tempval[MAXBUF];
              inet_ntop(AF_INET6, &servername.sin6_addr, tempval,MAXBUF);
              sprintf(envval, "[%s]", tempval);
 
           }

           setenv("SERVER_NAME", iparg, 1);







           struct sockaddr_in6 peername;
           memset(&peername, 0, sizeof(struct sockaddr_in6));
           socklen_t peerlen = sizeof(peername);
 
           getpeername(currconn->fd, (struct sockaddr *)&peername, &peerlen);
  

           ipv4 = true;

           for(int i = 0; i < 12; i++){
              if( (char)(peername.sin6_addr.s6_addr[i]) != v6check[i] ){
                 ipv4 = false;
              }

           }
          
           iparg = envval;
           if(ipv4){
            //not sure about print format
              inet_ntop(AF_INET6, &peername.sin6_addr, envval,MAXBUF);
              iparg = strtok(envval, ":");
              iparg = strtok(NULL, ":");
           } else {
              char tempval[MAXBUF];
              inet_ntop(AF_INET6, &peername.sin6_addr, tempval,MAXBUF);
              sprintf(envval, "[%s]", tempval);
 
           }

           setenv("REMOTE_ADDR", iparg, 1);


           if(querystring == NULL){
              unsetenv("QUERY_STRING");
           }
           else {
              sprintf(envval, "%s", querystring);
              setenv("QUERY_STRING", envval,1);
           } 

           sprintf(envval, "CGI/1.1");
           setenv("GATEWAY_INTERFACE", envval, 1);

           sprintf(envval, "/cgi-bin/%s", scriptname);
           setenv("SCRIPT_NAME", envval, 1);

           sprintf(envval, "GET");
           setenv("REQUEST_METHOD", envval, 1);



           if(currconn->ssl)
              sprintf(envval, "%d", httpsport);
           else
              sprintf(envval, "%d", httpport);

           setenv("SERVER_PORT", envval, 1);



           if(strcmp(http11, version))
               sprintf(envval, "HTTP/1.0");
           else
               sprintf(envval, "HTTP/1.1");

           setenv("SERVER_PROTOCOL", envval, 1);

           

            pid_t thePid;
            int status;
            int pfd[2];
            
            if(pipe(pfd))
               perror("pipe");


            if( (thePid = fork()) == -1 ){
               perror("fork");
            }
            if(thePid == 0){

               if( dup2(tempfd,STDOUT_FILENO) == -1){
                     perror("dup2");
                     exit(EXIT_FAILURE);
               }
               
               char patharg[MAXBUF];
               sprintf(patharg, "%s", cwdpath);
               char *argvp[2];
               argvp[0] = patharg;
               argvp[1] = NULL; 

               execvp(cwdpath, argvp);
               fprintf(stderr, "cwd path is %s\n", cwdpath);
               perror("execvp");
               exit(EXIT_FAILURE);

            }
            close(pfd[0]);
            close(pfd[1]);

            while(waitpid(thePid,&status,0) == -1){
               if(errno != EINTR){
                  perror("waitpid1");
                  exit(EXIT_FAILURE);
               }
            }

            
           fseek(tempfile, 0, SEEK_END);
           int filesize = ftell(tempfile);

           rewind(tempfile);
           currconn->writebuffer = (char *)malloc(MAXBUF + filesize);

           char *filestuff = (char *)malloc(filesize + 5);

           fread(filestuff, 1, filesize, tempfile);
           filestuff[filesize] = '\0';


           if(strcmp(http11, version))
             header = create_header(1.0, 200, ok, NULL, 0);
           else
             header = create_header(1.1, 200, ok, NULL, 0);


           memcpy(currconn->writebuffer, header, strlen(header) - 2);  //without last crlf
           memcpy(currconn->writebuffer + strlen(header) - 2, filestuff, filesize);

           currconn->writepos = 0;
           currconn->writesize = filesize + strlen(header) - 2;
 
           free(filestuff);
           free(header);
           close(tempfd);
            
         } 
         else {

            currconn->writebuffer = (char *)malloc(MAXBUF);
            if(strcmp(http11, version))
               header = create_header(1.0, 404, notfound, texttype, strlen(http_404_msg));
            else
               header = create_header(1.1, 404, notfound, texttype, strlen(http_404_msg));

            sprintf(currconn->writebuffer, "%s%s", header, http_404_msg);

            currconn->writepos = 0;
            currconn->writesize = strlen(header) + strlen(http_404_msg);

            free(header);
         }

      }
      
   }
   else {

      struct stat currstat;
      char cwdpath[BUFL];
  
      if( !getcwd(cwdpath,BUFL) ){
         perror("cwd");
      }

      strcat(cwdpath, "/docs");
      strcat(cwdpath, path);
      

      if( stat(cwdpath, &currstat) ) {

         if(strcmp(http11, version))
            header = create_header(1.0, 404, notfound, texttype, strlen(http_404_msg));
         else
            header = create_header(1.1, 404, notfound, texttype, strlen(http_404_msg));

         currconn->writebuffer = (char *)malloc(MAXBUF);
         sprintf(currconn->writebuffer, "%s%s", header, http_404_msg);

         currconn->writepos = 0;
         currconn->writesize = strlen(header) + strlen(http_404_msg);
         
         free(header);

      } 
      //the stat worked! it must be  file or directory
      else {

         
         DIR *cwdir;
         if( (cwdir = opendir(cwdpath)) ) {
            //hey mama we gotta directory in herrrrreee!
            //let's see if there' an index file

            char indexpath[BUFL];
            strcpy(indexpath, cwdpath);
            int indexlen = strlen(indexpath);

            if(indexpath[indexlen - 1] == '/'){
               strcat(indexpath, "index.html");
            }
            else {
               strcat(indexpath, "/index.html");
            }
 
            if(!servefile(currconn, indexpath, version) ){
               //ok no index let's serve a dir page
               struct dirent *currentfile;
               int pos = 0;
               char *dirstuff = (char *)malloc(MAXBUF);
               int currentsize = MAXBUF;

               int wrote= sprintf(dirstuff, "%s", http_dir_begin);

               pos += wrote;

               while ( (currentfile = readdir(cwdir)) ){
                   if(pos + 500 > currentsize){
                      dirstuff = (char *)realloc(dirstuff, currentsize + MAXBUF);
                      currentsize += MAXBUF;
                   }

                   if(strcmp(".", currentfile->d_name) && strcmp("..",currentfile->d_name)){
                      wrote = sprintf(dirstuff + pos, "<LI><A HREF=\"%s/%s\">%s</A></LI>\n", path, currentfile->d_name, currentfile->d_name);
                      pos += wrote;
                   }
                   
               }

               
               sprintf(dirstuff + pos, "%s", http_dir_end);
               
               int dirstufflen = strlen(dirstuff);

               if(strcmp(http11, version))
                  header = create_header(1.0, 200, ok, texttype, dirstufflen);
               else
                  header = create_header(1.1, 200, ok, texttype, dirstufflen);

               currconn->writebuffer = (char *)malloc(currentsize + MAXBUF);

               sprintf(currconn->writebuffer, "%s%s", header, dirstuff);
               currconn->writesize = strlen(header) + dirstufflen;
               currconn->writepos = 0;
               
               free(header);
               free(dirstuff);
            }


         }
         else {
            //must be a file
            if(!servefile(currconn, cwdpath, version) ){
               if(strcmp(http11, version))
                  header = create_header(1.0, 403, forbidden, texttype, strlen(http_403_msg));
               else
                  header = create_header(1.1, 403, forbidden, texttype, strlen(http_403_msg));

               currconn->writebuffer = (char *)malloc(MAXBUF);
               sprintf(currconn->writebuffer, "%s%s", header, http_403_msg);

               currconn->writepos = 0;
               currconn->writesize = strlen(header) + strlen(http_403_msg);
               free(header);
            }

         }

      }


   }

#ifdef DEBUG
   printf("command: %s\npath: %s\nversion: %s\n", command, path, version);
#endif

   parse_q.pop_front();
   write_q.push_back(currconn);
   
}

void write_stage(){
   if(write_q.size() == 0){ 
      return;
   }
   
   int n;
   connection *currconn;


   //create new socket set to observe
   fd_set write_set;
   FD_ZERO(&write_set);
   list<connection *>::iterator itr;
   int maxfd = 0;

   for(itr = write_q.begin(); itr != write_q.end(); itr++){
      currconn = (*itr);
      FD_SET(currconn->fd, &write_set);
      if(maxfd < currconn->fd)
         maxfd = currconn->fd;
   }

   //use zero timeout for polling
   struct timeval timeout;
   timeout.tv_sec = 0;
   timeout.tv_usec = 0;
   
   int status = select(maxfd + 1, NULL, &write_set, NULL, &timeout);
   if(status <= 0){
      return;
   }

   int writeto;

   for(itr = write_q.begin(); itr != write_q.end(); itr++){
      currconn = (*itr);
      if ( FD_ISSET(currconn->fd, &write_set) ){
         writeto = currconn->fd;
         break;
      }
   }

   #ifdef DEBUG
         printf("ready to write to %d\n", writeto);
   #endif
   if(currconn->ssl)
      n = SSL_write(currconn->ssl, currconn->writebuffer + currconn->writepos, currconn->writesize - currconn->writepos);
   else
      n = write(currconn->fd, currconn->writebuffer + currconn->writepos, currconn->writesize - currconn->writepos);

   currconn->writepos += n;

   if(currconn->writepos >=  currconn->writesize){
      if(currconn->ssl)
         SSL_shutdown(currconn->ssl);

      close(currconn->fd);
      write_q.remove(currconn);
      freeconn(currconn);
   }  
}

int getport(struct sockaddr *sa) {
   if (sa->sa_family == AF_INET) {
      return ntohs(((struct sockaddr_in*)sa)->sin_port);
   }
   else {
      return ntohs(((struct sockaddr_in6*)sa)->sin6_port);
   } 
}

char *create_header(double version, int number, char *command, char *type, int length){
   char *header = (char *)malloc(MAXBUF);
   

   if(length == 0 && type == NULL){
      sprintf(header, "HTTP/%.1f %d %s\r\n\r\n", 
         version, number, command);

   }
   else if(length == 0){
      sprintf(header, "HTTP/%.1f %d %s\r\nContent-Type: %s\r\n\r\n", 
         version, number, command, type);
   }
   else if(type == NULL) {

      sprintf(header, "HTTP/%.1f %d %s\r\nContent-Length: %d\r\n\r\n", 
         version, number, command, length);
   } 
   else {
      sprintf(header, "HTTP/%.1f %d %s\r\nContent-Type: %s\r\nContent-Length: %d\r\n\r\n", 
         version, number, command, type, length);
   }

   return header;


}

void freeconn(connection *conn){
   if(conn->buffer)
      free(conn->buffer);
   if(conn->writebuffer)
      free(conn->writebuffer);
   if(conn->ssl)
      SSL_free(conn->ssl);
   free(conn);
}


void freestuff(){
   connection *currconn;

   while(read_q.size() != 0){
      currconn = read_q.front();
      freeconn(currconn);
      read_q.pop_front();
   }

   while(parse_q.size() != 0){
      currconn = parse_q.front();
      freeconn(currconn);
      parse_q.pop_front();
   }
   while(write_q.size() != 0){
      currconn = write_q.front();
      freeconn(currconn);
      write_q.pop_front();
   }
   while(ssl_q.size() != 0){
      currconn = ssl_q.front();
      freeconn(currconn);
      ssl_q.pop_front();
   }
}






int servefile(connection *currconn, char *fullpath, char *version){

   char *header;
   FILE *fp = fopen(fullpath, "r");
 
   char parsepath[BUFL];

   strcpy(parsepath, fullpath);
   char *parsetype = strtok(parsepath, ".");
   parsetype = strtok(NULL, ".");
   if(parsetype ==NULL)
      parsetype = ok;
   char *type;


   if(!strcmp(parsetype, "html") || !strcmp(parsetype, "htm")){
      type = texttype;
   }
   else if(!strcmp(parsetype, "txt")){
      type = txttype;
   }
   else if (!strcmp(parsetype, "pdf")){
      type = pdftype;
   } 
   else if(!strcmp(parsetype, "gif")){
      type = giftype;
   }
   else if(!strcmp(parsetype, "jpg") || !strcmp(parsetype, "jpeg")){
      type = jpgtype;
   }
   else if(!strcmp(parsetype, "png") ){
      type = pngtype;
   }
   else {
      type = NULL;
   }


   if(!fp){
      return 0;
   }

   fseek(fp, 0, SEEK_END);
   int filesize = ftell(fp);

   rewind(fp);
   currconn->writebuffer = (char *)malloc(MAXBUF + filesize);
                
   if(strcmp(http11, version))
      header = create_header(1.0, 200, ok, type, filesize);
   else
      header = create_header(1.1, 200, ok, type, filesize);

   char *filestuff = (char *)malloc(filesize + 5);

   fread(filestuff, 1, filesize, fp);


   filestuff[filesize] = '\0';


   sprintf(currconn->writebuffer, "%s", header);
   memcpy(currconn->writebuffer + strlen(header), filestuff, filesize);

   currconn->writepos = 0;
   currconn->writesize = strlen(header) + filesize;

   free(filestuff);
   free(header);
 

   return 1;
}


char *decodeurl(char *path){
   char decode[MAXBUF];
   strcpy(decode, path);

   
   char *http = decode;
   
   char *retval = (char *)malloc(MAXBUF);
   char *curr = retval;
   char hexcode[3] = {0};
   unsigned long ascii = 0;

   while(*http){
      if(*http == '%'){
         http++;
         memcpy(hexcode, http, 2);
         ascii = strtoul(hexcode, NULL, 16);
         *curr++ = (char)ascii;
         http += 2;
      } else {
         *curr++ = *http++;
      }

   }
   *curr = '\0';
   return retval;
}


void createCTX(void) {
   SSL_METHOD *method;
   // Load algorithms and error strings.
//   OpenSSL_add_all_algorithms();

   SSL_library_init();
   SSL_load_error_strings();
   
   // Compatible with SSLv2, SSLv3 and TLSv1
   method = SSLv23_server_method();

   // Create new context from method.
   ctx = SSL_CTX_new(method);

   if(ctx == NULL) {
      ERR_print_errors_fp(stderr);
      exit(1);
   }
}

void loadCerts(void){
   char fname[] = "ssl.pem";
   if( SSL_CTX_use_certificate_chain_file(ctx, fname) <= 0){
      ERR_print_errors_fp(stderr);
      exit(1);
   }
  
   if(SSL_CTX_use_RSAPrivateKey_file(ctx, fname, SSL_FILETYPE_PEM) <= 0){
      ERR_print_errors_fp(stderr);
      exit(1);

   }

   if ( !SSL_CTX_check_private_key(ctx) ) {
      fprintf(stderr, "Private key is invalid.\n");
      exit(1);
   }

}
