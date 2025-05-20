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
#include <errno.h>
#include <argon2.h>
#include <fcntl.h>

#define MAX_THREADS 16

//global for dyn load balancing
static size_t next_hash = 0;
static pthread_mutex_t hash_lock = PTHREAD_MUTEX_INITIALIZER;

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

//prototypes 
//verbose
static void vlog(const char *, ...);
//elapsed time
static long elapsed_us(void);
//-H option
static void print_help(const char *);
//create ragged array from files
static int count_lines(char *);
static char **create_line_array(char *, int);
static char **create_ragged_array(char *, int *);
//threading
static size_t get_next_hash_index(size_t total);
static void *worker(void *v);

//capture time, print formatted time for verbose
static void vlog(const char *fmt, ...) {
	long us = 0;
	va_list ap;
	
	//do nothing if not enabled
	if (!verbose) {
		return;
	}

	//grab time of day
	gettimeofday(&tv_end, NULL);
	us = elapsed_us();

	//printing time with verbose - basic format from stack overflow
	fprintf(log_fp, "%ld: ", us);
	va_start(ap, fmt);
	vfprintf(log_fp, fmt, ap);
	va_end(ap);
	fputc('\n', log_fp);
}

//return time
static long elapsed_us(void) {
	struct timeval diff;
	timersub(&tv_end, &tv_start, &diff);
	return diff.tv_sec * 1000000L + diff.tv_usec;
}

//-H print and exit option
static void print_help(const char *prog) {
	printf("Usage: %s -h hashes-file -p passwords-file [options]\n", prog);
	exit(EXIT_SUCCESS);
}

//Ragged array creation fns - used rchaney's ray-file.c for framework

//counting lines in file
static int count_lines(char *string) {
	int wc = 0;
	char *s = string;

	for(int i = 0; *s; ++i, s++) {
		if (*s == '\n') {
			wc++;
		}
	}
//	for(const char *p = buf; *p != '\0'; p++) {
//		if (*p == '\n') {
//			wc++;
//		}
//	}
	return wc;
}

//creating array of lines
static char **create_line_array(char *buf, int wc) {
	char **arr = malloc(wc * sizeof(char *));
	char *token = strtok(buf, "\n");
	int index = 0;
	if (arr == NULL) {
		perror("malloc");
		exit(EXIT_FAILURE);
	}
//	while (token != NULL && index < wc) {
	while (token) {
		arr[index]= token;
		index++;
		token = strtok(NULL, "\n");
	}
	return arr;
}

//create the ragged array
static char **create_ragged_array(char *filename, int *out_count) {
	char **arr = NULL;
	int fd = -1;	
	char *buf = NULL;
	ssize_t bytes_read = 0;
	int wc = 0;
	struct stat st;
	
	//error handling for incorrect files
	if (stat(filename, &st) != 0) {
		perror("stat");
		exit(EXIT_FAILURE);
	}

	//open file, and error handling
	fd = open(filename, O_RDONLY);
	if (fd < 0) {
		perror("open");
		exit(EXIT_FAILURE);
	}

	//allocate buffer
	buf = calloc(st.st_size + 1, 1);
	if (buf == NULL) {
		perror("Calloc");
		exit(EXIT_FAILURE);
	}
	//read file, store in bytes_read
	bytes_read = read(fd, buf, st.st_size);
	if (bytes_read != st.st_size) {
		perror("Read");
		exit(EXIT_FAILURE);
	}
	close(fd);

	//get lines in the file w/ timing if -v enabled
	gettimeofday(&tv_start, NULL);
	wc = count_lines(buf);
	gettimeofday(&tv_end, NULL);
	vlog("create_ragged_Array %s", filename);
	*out_count = wc;

	//create ragged array
	gettimeofday(&tv_start, NULL);
	arr = create_line_array(buf, wc);
	gettimeofday(&tv_end, NULL);
	vlog("\tcount_lines word count: %d", wc);
	vlog("\tcreate_line_array word count: %d", wc);

	return arr;
}

//mutex protecting the file from multiple threads reading at once
static size_t get_next_hash_index(size_t total) {
	size_t index = 0;

	(void) total;
	pthread_mutex_lock(&hash_lock);
	index = next_hash++;
	pthread_mutex_unlock(&hash_lock);
	return index;
}

//main worker fn for threading
static void *worker(void *v) {
	struct thread_args *a = (struct thread_args *)v;
	size_t index = 0;
	const char *hash = NULL;
	int ok = 0;

	while(1) {
		//go thru each hash index, until last hash index
		index = get_next_hash_index(a->total_hashes);
		if(index >= a->total_hashes) {
			break;
		}
		hash = a->hashes[index];
		//fail flag
		ok = 0;

		//loop thru all passwords, check if valid Argon2 hash/password
		for(size_t j = 0; j < a->num_passwords; j++) {
			if(argon2_verify(hash, a->passwords[j], strlen(a->passwords[j]), Argon2_id) == ARGON2_OK) {
				fprintf(a->out_fp, "CRACKED: %s %s\n", a->passwords[j], hash);
				a->stats[a->thread_id].cracked++;
				ok = 1;
				break;
			}
		}
		//if not valid, print fail, no PW found in dictionary attack
		if (!ok) {
			fprintf(a->out_fp, "FAILED:  %s\n", hash);
			a->stats[a->thread_id].failed++;
		}
	}
	return NULL;
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
	//storing ragged array
	int nhashes = 0;
	int npwds = 0;
	char **hashes = NULL;
	char **passwords = NULL;
	//Threading vars
	pthread_t threads[MAX_THREADS];
	struct thread_stats stats[MAX_THREADS] = {{0}};
	struct thread_args args[MAX_THREADS];
	//totals var
	size_t total_c = 0;
	size_t total_f = 0;
	//getopt
	int opt;
	//defaulting log to stderr
	log_fp = stderr;

	while ((opt = getopt(argc, argv, "h:p:o:l:t:vH")) != -1) {
		switch(opt) {
			//hash file 
			case 'h':
				fprintf(stderr, "case h\n");
				hfile = optarg;
				break;
			//password file
			case 'p':
				fprintf(stderr, "case p\n");
				pfile = optarg;
				break;
			//output file
			case 'o':
				fprintf(stderr, "case o\n");
				ofile = optarg;
				break;
			//log file 
			case 'l':
				fprintf(stderr, "case l\n");
				log_fp = fopen(optarg, "w");
				if(!log_fp) {
					perror("fopen");
					exit(EXIT_FAILURE);
				}
				break;
			//thread #
			case 't':
				fprintf(stderr, "case t\n");
				nthreads = atoi(optarg);
				if (nthreads < 1 || nthreads > MAX_THREADS) {
					fprintf(stderr, "Please enter a thread value from 1 to 16.\n");
					exit(EXIT_FAILURE);				
				}
				break;
			//verbose
			case 'v':
				fprintf(stderr, "case v\n");
				verbose = 1;
				break;
			//help option
			case 'H':
				print_help(argv[0]);
				break;
			//if weird, display help
			default:
				print_help(argv[0]);
				break;
		}
	}
	
	//if option arguments are no good, then print help
	if (!hfile || !pfile) {
		print_help(argv[0]);
	}
	//open output file
	if(ofile) {
		out_fp = fopen(ofile, "w");
		if(!out_fp) {
			perror("fopen");
			exit(EXIT_FAILURE);
		}
	}

	//read files and load hashes/passwords into ragged arrays	
	hashes = create_ragged_array(hfile, &nhashes);
	passwords = create_ragged_array(pfile, &npwds);

	///create worker threads
	gettimeofday(&tv_start, NULL);
	for(int i = 0; i < nthreads; i++) {
		args[i].thread_id = i;
		args[i].total_hashes = (size_t)nhashes;
		args[i].hashes = hashes;
		args[i].passwords = passwords;
		args[i].num_passwords = (size_t)npwds;
		args[i].out_fp = out_fp;
		args[i].stats = stats;
		//make threads
		if (pthread_create(&threads[i], NULL, worker, &args[i]) != 0) {
			perror("pthread_create");
			exit(EXIT_FAILURE);
		}
	}
	gettimeofday(&tv_end, NULL);
	vlog("Threads created\n");

	//wait for all threads to complete
	for(int i = 0; i < nthreads; i++) {
		pthread_join(threads[i], NULL);

	}
	gettimeofday(&tv_end, NULL);
	vlog("threads joined");

	//print cracked and failed
	fputs("TOTALS:", out_fp);
	for(int i = 0; i < nthreads; i++) {
		total_c += stats[i].cracked;
		total_f += stats[i].failed;
		fprintf(out_fp, " t%d:%zu/%zu", i, stats[i].cracked, stats[i].failed);
	}
	
	//print totals
	fprintf(out_fp, "   TOTAL:%zu/%zu\n", total_c, total_f);

	//free memory
	free(hashes[0]);
	free(hashes);
	free(passwords[0]);
	free(passwords);

	//if(hashes) {
//	for(int i = 0; i < nhashes; i++) {
//		free(hashes[i]);
//	}
//	free(hashes);
//	//}
//
//	//if(passwords) {
//	for(int i = 0; i < npwds; i++) {
//			free(passwords[i]);
//	}
//	free(passwords);
	//}
	
	//close fd's
	if(ofile) fclose(out_fp);
	if(log_fp && log_fp != stderr) {
		fclose(log_fp);
	}
	
	return EXIT_SUCCESS;
}//end main
