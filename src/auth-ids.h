/* This module created by hiragi-gkuth on Kansai Univ. Kobayasi seminor */

#ifndef AUTH_IDS_H
#define AUTH_IDS_H

#include <time.h>
#include "ssh.h"

#define FIRST_ATTEMPT 1
#define SECOND_ATTEMPT 0

#define ATTACK 1
#define NORMAL 0

struct timespec first_start;    // store the beginning of the time for password input
struct timespec second_start;   // store to this variable if there are several attempts in
                                //   one connection.
double MULTIPLE_AUTH;

// the variables for storing the RTT when exchanging the keys
double KEXINIT_TIME;
double NEWKEYS_TIME;

/**
 * judge_malicious returns
 *   - ATTACK 1 when looks attack
 *   - NORMAL 0 when looks normal
 */
int judge_malicious(struct ssh* ssh, double authtime);
double get_authtime();
void point_auth_start(int attempt_kind);
void log_authinfo(struct ssh* ssh, int judge, double authtime);

#endif