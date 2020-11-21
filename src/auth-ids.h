/* This module created by hiragi-gkuth on Kansai Univ. Kobayashi Lab. */

#ifndef AUTH_IDS_H
#define AUTH_IDS_H

#include <time.h>
#include "ssh.h"

#define FIRST_ATTEMPT 1
#define SECOND_ATTEMPT 0

#define ATTACK 1
#define NORMAL 0

#define HASH_SIZE (1024*16)
#define LINE_MAX 4096

#define IPC_PATH "/tmp/sshd3.ipc"
#define IPC_PROJ_ID 624204

// bitris ids model type difinition
typedef struct node {
    int time_slot; // 0 ~ (slot_count - 1)
    char *ip;
    double offset;
    struct node* next;
} threshold_node;

typedef struct {
    int time_slot;
    double offset;
} threshold_time;

typedef struct {
    double base_threshold;
    threshold_node **threshold_table;
    threshold_time *threshold_time_only;
    int slot_count;
    int ip_subnet;
} ids_model;

struct timespec first_start;    // store the beginning of the time for password input
struct timespec second_start;   // store to this variable if there are several attempts in
                                //   one connection.
double MULTIPLE_AUTH;

// the variables for storing the RTT when exchanging the keys
double KEXINIT_TIME;
double NEWKEYS_TIME;

// ids function prototypes
int judge_malicious(struct ssh* ssh, double authtime);
double get_authtime();
void point_auth_start(int attempt_kind);
void log_authinfo(struct ssh* ssh, int judge, double authtime);
void ids_file2shm(const char *filename);


#endif