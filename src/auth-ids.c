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
#include <stdlib.h>
#include <string.h>

// global variables
double KEXINIT_TIME;
double NEWKEYS_TIME;
double MULTIPLE_AUTH = 0;
struct timespec first_start;
struct timespec second_start;

// function prototypes 
char *_ascii2hex_secure(const char *str);
double _fetch_base_threshold();
char *_extract_environ();

// type definitions
typedef struct {
	int begin_unix;
	int end_unix;
} timeslot;

typedef struct {
    char *ip;
    unsigned short mask;
	timeslot slot;
    double threshold;
} threshold_map;


int judge_malicious(struct ssh *ssh, double authtime) {
	double baseThreshold = _fetch_base_threshold();

	if (authtime < baseThreshold) {
		return ATTACK;
	}
    return NORMAL;
}

double get_authtime() {
    struct timespec start = MULTIPLE_AUTH 
        ? second_start
        : first_start;
    struct timespec end;
    clock_gettime(CLOCK_REALTIME, &end);
    return (end.tv_sec - start.tv_sec) + (end.tv_nsec - start.tv_nsec) * 1.0E-9;
}

// logging authinfo, int authenticated is other than 0, then it means success.
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

/**
 * point_auth_start add point for start authentication.
 * if login isn't first attempt, flag up MULTIPLE_AUTH, and change 
 * variable for store time.
 */
void point_auth_start(int attempt_time) {
    if (attempt_time == FIRST_ATTEMPT) {
        clock_gettime(CLOCK_REALTIME, &first_start);
    }
    if (attempt_time == SECOND_ATTEMPT) {
        MULTIPLE_AUTH = 1;
        clock_gettime(CLOCK_REALTIME, &second_start);
    }
}

/**
 * _fetch_base_threshold returns authtime threshold
 * from environment variable named "SSH_THRESHOLD_BASE"
 * if it doesn't set, use 1.0 as default threshold.
 * if it is invalid, use 1.0 as default threshold.
 */
double _fetch_base_threshold() {
    char *baseThresholdStr = getenv("SSH_THRESHOLD_BASE");
	if (baseThresholdStr == NULL) {
		return 1.0;
	}
	double baseThreshold = atof(baseThresholdStr);
	// atof returns 0 if not convertible. 
	if (baseThreshold < 0.01) {
		return 1.0;
	}
    return baseThreshold;
}

char *_extract_environ() {
    // char *envStr = getenv("SSH_THRESHOLD_MAP");
	char *envStr = "dummy";
	return envStr;
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