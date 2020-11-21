/* includes */
#include "includes.h"

// dependancies
#include "hostfile.h"
#include "log.h"
#include "ssh.h"
#include "auth.h"
#include "packet.h"

// bitris ids header
#include "auth-ids.h"

// standard libraries
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/shm.h>

/* global variable declarations */
// measure KEX, NEWKEY, authtime
double KEXINIT_TIME;
double NEWKEYS_TIME;
double MULTIPLE_AUTH = 0;
struct timespec first_start;
struct timespec second_start;

/* internal function prototypes */
// for logging
char *_ascii2hex_secure(const char *str);

// shm/file loadings
char *_shm2char();
ids_model *_generate_ids_model();

// hash manipulatings
threshold_node *_create(char*, int, double);
void _register(threshold_node** hash_table, threshold_node* node);
void _summary(threshold_node** hash_table);
void _free_all(threshold_node** hash_table);
int _hash(char *ip, int time_slot);
threshold_node *_search(threshold_node** hash_table, char *ip, int time_slot);

int judge_malicious(struct ssh *ssh, double authtime) {
	ids_model *model = _generate_ids_model();
	debug("%s: base threshold: %lf",__func__, model->base_threshold);
	return NORMAL;
}

void point_auth_start(int attempt_time) {
    if (attempt_time == FIRST_ATTEMPT) {
        clock_gettime(CLOCK_REALTIME, &first_start);
    }
    if (attempt_time == SECOND_ATTEMPT) {
        MULTIPLE_AUTH = 1;
        clock_gettime(CLOCK_REALTIME, &second_start);
    }
}

double get_authtime() {
    struct timespec start = MULTIPLE_AUTH 
        ? second_start
        : first_start;
    struct timespec end;
    clock_gettime(CLOCK_REALTIME, &end);
    return (end.tv_sec - start.tv_sec) + (end.tv_nsec - start.tv_nsec) * 1.0E-9;
}

void log_authinfo(struct ssh* ssh, int judge, double authtime) {
    // Record now time
	struct timespec auth_at;
	clock_gettime(CLOCK_REALTIME, &auth_at);

    Authctxt *authctxt = ssh->authctxt;

	// extract password from ssh packet
	// IT DOESN'T WORK...
	// - ON auth2-passwd.c, function "auth_password" consumes password data from
	//   SSH Packet. And after password comparison, due to security perspective, 
	//   password data have filled with "zero".
	//   So I can't access password here.
	char *password;
	size_t len;
	sshpkt_get_cstring(ssh, &password, &len);

	// AuthResult, UserName, IPAddr, AuthTime, DetectionString, RTT, UnixTime, uSec, KexTime, NewKeysTime
	logit("%s,%s,%s,%s,%lf,%s,%06lf,%ld,%06ld,%lf,%lf",
		authctxt->authenticated ? "Success" : "Fail",
		_ascii2hex_secure(authctxt->user),
		_ascii2hex_secure(password),
		ssh_remote_ipaddr(ssh),
		authtime,
		judge == ATTACK ? "Attack" : "Normal",
		((KEXINIT_TIME + NEWKEYS_TIME)/2),
		auth_at.tv_sec,
		auth_at.tv_nsec / 1000, // nsec -> usec
		KEXINIT_TIME,
		NEWKEYS_TIME);

	// delete password from RAM Securely
	explicit_bzero(password, len);
	free(password);
	return;
}

void ids_file2shm(const char *filename) {
	debug("%s: begin", __func__);
	FILE *ids_fp = fopen(filename, "r");
	if (ids_fp == NULL) {
		error("Bitris System: could not open file %s", filename); return;
	}
	debug("%s: open file success", __func__);

	// get file length
	size_t length;
	fseek(ids_fp, 0, SEEK_END);
	length = ftell(ids_fp) + 1;
	fseek(ids_fp, 0, SEEK_SET);
	debug("%s: got file length", __func__);

	// read all of file content
	char *file_buffer = (char *)calloc(length, sizeof(char));
	fread(file_buffer, 1, length, ids_fp);
	file_buffer[length] = '\0';
	fclose(ids_fp);
	debug("%s: read all file content", __func__);

	// create empty file for shared memory key
	FILE *ipc_fp = fopen(IPC_PATH, "w");
	if (ipc_fp == NULL) {
		error("Bitris System: could not open file %s", IPC_PATH); return;
	};
	fclose(ipc_fp);
	debug("%s: shm key fd created", __func__);

    // allocate shm
    key_t key;
    int shmid;
    char *shmaddr;
    if ((key = ftok(IPC_PATH, IPC_PROJ_ID)) == -1) {
        error("write2shm(): ftok(): %s", strerror(errno)); return;
    }
	debug("%s: ftok() created key", __func__);
	if ((shmid = shmget(key, sizeof(char)*length, IPC_CREAT | 0666)) == -1) {
        error("write2shm(): shmget(): %s", strerror(errno)); return;
    }
	debug("%s: shmget() get new shm", __func__);
	// attach
	if ((shmaddr = shmat(shmid, NULL, 0)) == (void*)-1) {
        error("write2shm(): shmat(): %s", strerror(errno)); return;
    }
	debug("%s: shmat() attached address", __func__);
	// write
	memcpy(shmaddr, file_buffer, sizeof(char)*length);
	debug("%s: memcpy() write data to shm", __func__);
	// detach
	if (shmdt(shmaddr) == -1) {
        error("write2shm(): shmdt(): %s", strerror(errno)); return;
    }
	debug("%s: shmdt() detach shm. done!", __func__);
}

char *_shm2char() {
	key_t key;
    int shmid;
    char *shmaddr, *buf;
    struct shmid_ds ds;

	debug("_shm2char(): pid: %d", getpid());

    // get shm
    if ((key = ftok(IPC_PATH, IPC_PROJ_ID)) == -1) {
        error("_shm2char(): ftok(): %s", strerror(errno)); return NULL;
    }
	debug("_shm2char(): key: %d", key);
	if ((shmid = shmget(key, 0, 0)) == -1) {
        error("_shm2char(): shmget(): %s", strerror(errno)); return NULL;
    }
	debug("_shm2char(): shmid: %d", shmid);
    // fetch shm info
    if (shmctl(shmid, IPC_STAT, &ds) == -1) {
        error("shm2char(): shmctl(IPC_STAT): %s", strerror(errno)); return NULL;
    }
	debug("_shm2char(): size: %ld", ds.shm_segsz);
    buf = (char*)calloc(ds.shm_segsz, sizeof(char));
	// attach
	if ((shmaddr = shmat(shmid, NULL, SHM_RDONLY)) == (void*)-1) {
        error("_shm2char(): shmat(): %s", strerror(errno)); return NULL;
    }
	debug("_shm2char(): shmaddr: %p", shmaddr);
	// write
	memcpy(buf, shmaddr, sizeof(char)*ds.shm_segsz);
	// detach
	if (shmdt(shmaddr) == -1) {
        error("_shm2char(): shmdt(: %s", strerror(errno)); return NULL;		
    }
    return buf;
}

ids_model *_generate_ids_model() {
	debug("%s: begin", __func__);
	// malloc model memory
	ids_model *model = (ids_model*)malloc(sizeof(ids_model));
	model->threshold_table = NULL;
	model->threshold_time_only = NULL;
	
	// fetch ids csv data from shm
	char *csv = _shm2char();
	// if we can't read csv data. use default.
	if (csv == NULL) {
		error("Bitris System: failed to _shm2char. use default value.");
		model->base_threshold = 1.0; model->ip_subnet = 0; model->slot_count = 24;
		return model;
	}
	debug("%s: read csv from shm", __func__);

	char *line = strtok(csv, "\n");
	// parse first line of csv
	sscanf(line, "%lf,%d,%d",
		&model->base_threshold,
		&model->slot_count,
		&model->ip_subnet
	);
	debug("%s: parse first line", __func__);
	// parse second line of csv
	line = strtok(NULL, "\n");
	model->threshold_time_only = (threshold_time*)calloc(model->slot_count, sizeof(threshold_time));
	char *column;
	column = strtok(line, ","); // ignore ip

	for (int t = 0; t < model->slot_count; t++) {
		column = strtok(NULL, ",");
		double offset = atof(column);
		model->threshold_time_only[t].time_slot = t;
		model->threshold_time_only[t].offset = offset;
	}
	debug("%s: parse second line", __func__);

	// parse rest of csv
	model->threshold_table = (threshold_node**)calloc(HASH_SIZE, sizeof(threshold_node*));
	while ((line = strtok(NULL, "\n")) == NULL) {
		char *column;
		char ip[20];
		column = strtok(line, ",");
		strcpy(ip, column);
		for (int t = 0; t < model->slot_count; t++) {
			column = strtok(NULL, ",");
			double offset = atof(column);
			_register(model->threshold_table, _create(ip, t, offset));
		}
	}
	debug("%s: parse all of csv content. done!", __func__);
	return model;
}


char *_ascii2hex_secure(const char *str) {
	int i;
	if (str == NULL) {
		return "";
	}
	int len = strlen(str);
	unsigned char *hexes = malloc(sizeof(unsigned char)*len*2 + 1);

	for (i = 0; i < len; ++i) {
		unsigned char c = (unsigned char)str[i];
        // stop converting if it isn't valid ascii
		if (c < 0x20 || c > 0x7e) {
			return "";
		}
		char *hex = malloc(sizeof(char)*2+1);
		sprintf(hex, "%02x", str[i]);
		strncpy((char*)hexes+(i*2), hex, sizeof(char)*2);
	}
    hexes[len*2] = '\0';
	return (char *)hexes;
}

threshold_node *_create(char *ip, int time_slot, double offset) {
	threshold_node* node = NULL;
	node = (threshold_node*)malloc(sizeof(threshold_node));
    
	if (node == NULL) {
		printf("Bitris: error: malloc failed at _create()\n");
		return NULL;
	}
    node->ip = (char *)malloc(sizeof(char)*16);
    
	strcpy(node->ip, ip);
	node->time_slot = time_slot;
	node->offset = offset;
	node->next = NULL;
    
	return node;
}

void _register(threshold_node** hash_table, threshold_node* node) {
	int hashKey = _hash(node->ip, node->time_slot);
	// if hash already used. chaining
	if (hash_table[hashKey] != NULL) {
        node->next = hash_table[hashKey];
        hash_table[hashKey] = node;
	} else {
		hash_table[hashKey] = node;
	}
}

threshold_node *_search(threshold_node** hash_table, char *ip, int time_slot) {
    int hashKey = _hash(ip, time_slot);
    threshold_node *node = hash_table[hashKey];
    if (node == NULL) {
        return NULL;
    }

    while (1) {
        if (strcmp(node->ip, ip) == 0 && node->time_slot == time_slot) {
            return node;
        }
        if ((node = node->next) == NULL) {
            return NULL;
        }
    }
}

void _summary(threshold_node** hash_table) {
    for (int i = 0; i < HASH_SIZE; i++) {
        threshold_node *node = hash_table[i];
        
        if (node == NULL) {
            continue;
        }
        
        debug("%d: ip %s, timeslot: %d, offset: %.4f, next->%p\n", i, node->ip, node->time_slot, node->offset, node->next);
        int indentation = 1;
        while ((node = node->next) != NULL) {
            for (int d = 0; d < indentation; d++) {printf("  ");}
            debug("%d: ip %s, timeslot: %d, offset: %.4f, next->%p\n", i, node->ip, node->time_slot, node->offset, node->next);
            indentation++;
        }
    }
}

void _free_all(threshold_node** hash_table) {
    for (int i = 0; i < HASH_SIZE; i++) {
        if (hash_table[i] == NULL) {
            continue;
        }
        threshold_node *node = hash_table[i];
        while(1) {
            if (node->next == NULL) { break; }
            threshold_node *next = node->next;
            free(node->ip); free(node);
            node = next;
        }        
    }
    free(hash_table);
}

int _hash(char *ip, int time_slot) {
	int hash = 0;
	for (int ai = 0; ip[ai] != '\0'; ai++) {
		hash += (int)ip[ai]*((time_slot+1)*ai);
	}
	return hash % HASH_SIZE;
}