#include "sha256.h"

#include "stdlib.h"
#include "stdio.h"
#include "ap_config.h"
#include "apr_dbd.h"
#include "apr_strings.h"
#include "openssl/sha.h"


apr_status_t sha256(apr_pool_t *pool, const char *str, char **result)
{
  if (!pool || !str || !result)
  {
    return APR_EGENERAL;
  }
  // Вычислим SHA256-хеш от строки str
  unsigned char hash[SHA256_DIGEST_LENGTH];

  SHA256((const unsigned char *)str, strlen(str), hash);

  // Преобразуем двоичное значение в hash в HEX-строку вида AB2481EF...
  char *s = (char *)apr_pcalloc(pool, SHA256_DIGEST_LENGTH * 2 + 1);
  *result = s;


  for (int i=0; i < SHA256_DIGEST_LENGTH; i++)
    {

    char b = hash[i];
    char c = (b >> 4) & 0x0f;
    *(s++) = c > 9 ? c + ('a' - 10) : c + '0';
    c = b & 0x0f;
    *(s++) = c > 9 ? c + ('a' - 10) : c + '0';
    }
  *s = 0;

  return APR_SUCCESS;
}