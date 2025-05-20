//Stephen Bangs
//5/18/25
//CS333 - Jesse Chaney
//PSargon (Portand State Argon) program to process and crack (kind of) argon two passwords and hashes.

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <getopt.h>
#include <sys/time.h>
#include <stdarg.h>
#include <sys/stat.h>
#include <pthread.h>
//TODO
#include <errno.h>
//TODO
#include <argon2.h>
#include <fcntl.h>

#define MAX_THREADS 16

//global for dyn load balancing
static size_t next_hash = 0;
static pthread_mutex_t hash_lock = PTHREAD_MUTEX_INIT

//per thread stats
struct thread_stats{
	size_t cracked;
	size_t failed;
};

//args for each thread
struct thread_args {
	size_t thread_id;
	size_t total_hashes;
	char **hashes;
	char **passwords;
	size_t num_passwords;
	FILE *out_fp;
	struct thread_stats *stats;
};

//verbose control
static int verbose = 0;
static FILE *log_fp = NULL;

//timing for -v
static struct timeval tv_start, tv_end;

static long elapsed_us(void) {
	struct timeval diff;
	timersub(&tv_end, &tv_start, &diff);
	return diff.tv_sec * 1000000L + diff.tv_usec;
}

//capture time, print formatted time
static void vlog(const char *fmt, ...) {
	if (!verbose) {
		return;
	}
	gettimeofday(&tv_end, NULL);
	long us = elapsed_us();

	fprintf(log_fp, "%ld: ", us);
	va_list ap;
	va_start(ap, fmt);
	vfprintf(log_fp, fmt, ap);
	va_end(ap);
	fputc('\n', log_fp);
}

static void print_help(const char *prog) {
	printf("Usage: %s -h hashes-file -p passwords-file [options]\n", prog);
	exit(EXIT_SUCCESS);
}

int main(int argc, char *argv[]) {

	//path to hashes
	char *hfile = NULL;
	//path to passwords
	char *pfile = NULL;
	//path to output
	char *ofile = NULL;
	//# threads
	int nthreads = 1;
	FILE *out_fp = stdout;
	log_fp = stderr;

	int opt;

	while ((opt = getopt(argc, argv, "h:p:o:l:t:vH")) != -1) {
		switch(opt) {
			case 'h':
				fprintf(stderr, "case h\n");
				hfile = optarg;
				break;
			case 'p':
				fprintf(stderr, "case p\n");
				pfile = optarg;
				break;
			case 'o':
				fprintf(stderr, "case o\n");
				ofile = optarg;
				break;
			//TODO
			case 'l':
				fprintf(stderr, "case l\n");
				break;
			case 't':
				fprintf(stderr, "case t\n");
				nthreads = atoi(optarg);
				if (nthreads < 1 || nthreads > MAX_THREADS) {
					fprintf(stderr, "Please enter a thread value from 1 to 16.\n");
					EXIT(EXIT_FAILURE);				
				}
				break;
			case 'v':
				fprintf(stderr, "case v\n");
				verbose = 1;
				break;
			case 'H':
				print_help(argv[0]);
				break;
			default:
				print_help(argv[0]);
				break;
		}
	}

	if (!hfile || !pfile) {
		print_help(argv[0]);
	}

	if(ofile) {
		out_fp = fopen(ofile, "w");
		if(!out_fp) {
			perror("fopen");
			exit(EXIT_FAILURE);
		}
	}

	//TODO REMOVE
	argc++;
	argc--;
	argv++;
	argv--;
	return EXIT_SUCCESS;
}
