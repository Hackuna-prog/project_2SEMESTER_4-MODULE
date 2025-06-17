#pragma once

#include "stdlib.h"
#include "stdio.h"
#include "ap_config.h"
#include "apr_dbd.h"
#include "apr_strings.h"
#include "openssl/sha.h"

apr_status_t sha256(apr_pool_t *pool, const char *str, char **result);