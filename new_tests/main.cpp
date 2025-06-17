#include "stdlib.h"
#include "stdio.h"
#include "ap_config.h"
#include "apr_dbd.h"
#include "apr_strings.h"
#include "openssl/sha.h"
#include "sha256.h"




int main()
{
  apr_initialize();
 
  apr_pool_t *pool;
 
  apr_pool_create(&pool, NULL);
 

  if (!pool)
    {
    printf("Ошибка создания пула для работы с памятью\n");
    exit(1);
    }

  const char *pass;

  char *pass_hash;
  return 0;

}