#include "uthash.h"
#include "libssh2.h"

pthread_rwlock_t rwlock;

struct hash_struct {
	struct args* arguments;
	LIBSSH2_SESSION* session;
        char* source_ip;
	pthread_t threadID;
	time_t start_time;
	u_int8_t attempts;
	u_int8_t done;
        UT_hash_handle hh;
};

struct hash_struct *done_ips = NULL;

void add_ip(char* source_ip, void* arguments) {

        pthread_rwlock_wrlock(&rwlock);

        struct hash_struct *hs;

        hs = malloc(sizeof(struct hash_struct));

	hs->arguments = arguments;
	hs->source_ip = malloc(strlen(source_ip) + 1);
	strcpy(hs->source_ip, source_ip);
	hs->threadID = 0;
	hs->start_time = time(NULL);
	hs->attempts = 0;
	hs->done = 0;
	hs->session = NULL;

        HASH_ADD_STR(done_ips, source_ip, hs);

        pthread_rwlock_unlock(&rwlock);

}

int update_pid(char* source_ip) {

	pthread_rwlock_wrlock(&rwlock);

        struct hash_struct *hs;

	HASH_FIND_STR(done_ips, source_ip, hs);

	if(hs) {
                hs->threadID = pthread_self();
                pthread_rwlock_unlock(&rwlock);
                return hs->start_time;
	} else {
		pthread_rwlock_unlock(&rwlock);
                return 0;
        }
}

int update_session(char* source_ip, LIBSSH2_SESSION *session) {

        pthread_rwlock_wrlock(&rwlock);

        struct hash_struct *hs;

        HASH_FIND_STR(done_ips, source_ip, hs);

        if(hs) {
                hs->session = session;
                pthread_rwlock_unlock(&rwlock);
                return 1;
        } else {
                pthread_rwlock_unlock(&rwlock);
                return 0;
        }
}

int update_done(char* source_ip) {

	pthread_rwlock_wrlock(&rwlock);

        struct hash_struct *hs;

        HASH_FIND_STR(done_ips, source_ip, hs);

        if(hs) {
                hs->done = 1;
                pthread_rwlock_unlock(&rwlock);
                return 1;
        } else {
                pthread_rwlock_unlock(&rwlock);
                return 0;
        }
}

int update_entry(char* source_ip) {

	pthread_rwlock_wrlock(&rwlock);

        struct hash_struct *hs;

        HASH_FIND_STR(done_ips, source_ip, hs);

        if(hs) {
		hs->start_time = time(NULL);
		hs->attempts++;
		pthread_rwlock_unlock(&rwlock);
                return hs->start_time;
        } else {
                pthread_rwlock_unlock(&rwlock);
                return 0;
        }
}

int find_ip(char* source_ip) {

        pthread_rwlock_wrlock(&rwlock);

        struct hash_struct *hs;

        HASH_FIND_STR(done_ips, source_ip, hs);

        if(hs) {
                pthread_rwlock_unlock(&rwlock);
                return hs->start_time;
        } else {
                pthread_rwlock_unlock(&rwlock);
                return 0;
        }
}
