#include "auth-ids.h"
#include "ssh.h"
#include <stdlib.h>


typedef struct {
    char ip;
    unsigned short subnet_mask;
    double threshold;
} ThresholdMap;

int is_acceptable(struct ssh *ssh, double authtime) {
    return 1;
}

double _fetch_base_threshold() {
    char *baseThresholdStr = getenv("SSH_THRESHOLD_BASE");
    return (double)atof(baseThresholdStr);
}

char *_extract_environ() {
    char *envStr = getenv("SSH_THRESHOLD_MAP");
}