/* This module created by hiragi-gkuth on Kansai Univ. Kobayasi seminor */

#ifndef AUTH_IDS_H
#define AUTH_IDS_H

#include "ssh.h"

/**
 * is_acceptable returns
 *   - not 0, when login attempt is Normal
 *   - 0, when login attempt is Attack
 */
int is_acceptable(struct ssh *, double);


#endif