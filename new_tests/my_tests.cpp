#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include "doctest.h"
#include "stdlib.h"
#include "stdio.h"
#include "ap_config.h"
#include "apr_dbd.h"
#include "apr_strings.h"
#include "openssl/sha.h"
#include "sha256.h"


TEST_CASE("only numbers"){
const char *pass;
pass="12345";
apr_initialize(); 
apr_pool_t *pool; 
apr_pool_create(&pool, NULL);
char *pass_hash;
CHECK(sha256(pool, pass, &pass_hash) == APR_SUCCESS);
}


TEST_CASE("with space"){
const char *pass;
pass="1234    with space 5";
apr_initialize(); 
apr_pool_t *pool; 
apr_pool_create(&pool, NULL);
char *pass_hash;
CHECK(sha256(pool, pass, &pass_hash) == APR_SUCCESS);
}

TEST_CASE("with n"){
const char *pass;
pass="1234\n5";
apr_initialize(); 
apr_pool_t *pool; 
apr_pool_create(&pool, NULL);
char *pass_hash;
CHECK(sha256(pool, pass, &pass_hash) == APR_SUCCESS);
}

TEST_CASE("with ' and $"){
const char *pass;
pass="1234$'5";
apr_initialize(); 
apr_pool_t *pool; 
apr_pool_create(&pool, NULL);
char *pass_hash;
CHECK(sha256(pool, pass, &pass_hash) == APR_SUCCESS);
}

TEST_CASE("empty"){
const char *pass;
pass="";
apr_initialize(); 
apr_pool_t *pool; 
apr_pool_create(&pool, NULL);
char *pass_hash;
CHECK(sha256(pool, pass, &pass_hash) == APR_SUCCESS);
}


TEST_CASE("test sql string concatenation"){
const char *pass;
pass="12345";
apr_initialize(); 
apr_pool_t *pool; 
apr_pool_create(&pool, NULL);
char *pass_hash;
const char *user = "admin";
const char *sql = apr_pstrcat(pool, "SELECT name FROM users WHERE login='", user, "' AND password='", pass_hash, "'", NULL);
CHECK(strcmp(sql, "SELECT name FROM users WHERE login='admin' AND password='fbf826d62fd43f0643e283c27040e2f235ddd68908b0c286c77a456b465ace13'") != 0);
}


TEST_CASE("test sql string concatenation with ' "){
const char *pass;
pass="12345";
apr_initialize(); 
apr_pool_t *pool; 
apr_pool_create(&pool, NULL);
char *pass_hash;
const char *user = "admin'--";
const char *sql = apr_pstrcat(pool, "SELECT name FROM users WHERE login='", user, "' AND password='", pass_hash, "'", NULL);
CHECK(strcmp(sql, "SELECT name FROM users WHERE login='admin'==' AND password='fbf826d62fd43f0643e283c27040e2f235ddd68908b0c286c77a456b465ace13'") != 0);
}


TEST_CASE("test sql string concatenation with '-- "){
const char *pass;
pass="12345";
apr_initialize(); 
apr_pool_t *pool; 
apr_pool_create(&pool, NULL);
char *pass_hash;
const char *user = "admin";
const char *sql = apr_pstrcat(pool, "SELECT name FROM users WHERE login='", user, "' AND password='", pass_hash, "'", NULL);
CHECK(strcmp(sql, "SELECT name FROM users WHERE login='admin' AND password='fbf826d62fd43f0643e283c27040e2f235ddd68908b0c286c77a456b465ace13'") != 0);
}


TEST_CASE("check content type"){
const char *pass;
pass="12345";
apr_initialize(); 
apr_pool_t *pool; 
apr_pool_create(&pool, NULL);
char *pass_hash;
const char *user = "admin";
const char *sql = apr_pstrcat(pool, "SELECT name FROM users WHERE login='", user, "' AND password='", pass_hash, "'", NULL);
const char *content_type = "Application/X-www-form-urlencoded";
const char * CONTENT_TYPE_URLENCODED = "application/x-www-form-urlencoded";
CHECK(strncasecmp(content_type, CONTENT_TYPE_URLENCODED, strlen(CONTENT_TYPE_URLENCODED)) == 0);
}