#include "httpd.h"
#include "http_config.h"
#include "http_protocol.h"
#include "http_log.h"
#include "ap_config.h"
#include "apr_dbd.h"
#include "apr_strings.h"
#include "mod_dbd.h"
#include "apreq.h"
#include "apreq_parser.h"
#include "apreq_param.h"
#include "apreq_util.h"
#include "openssl/sha.h"

static APR_OPTIONAL_FN_TYPE(ap_dbd_acquire) *mod_dbd_acquire_fn = NULL;

static int app_handler(request_rec *r);

#define CONTENT_TYPE_URLENCODED "application/x-www-form-urlencoded"

apr_status_t get_params(request_rec *r, apr_table_t *params)
{
  if (!r || !params)
    return APR_EGENERAL;

  apreq_initialize(r->pool);

  // Создадим структуру, в которую парсер библиотеки apreq помещает распарсенные данные в своем формате
  apr_table_t *ap = apr_table_make(r->pool, 25);

  // Если есть параметры, переданные в URL-строке, распарсим их
  if (r->args)
    apreq_parse_query_string(r->pool, ap, r->args);

  // В HTTP-методе POST данные также могут передаваться как тело запроса. Обработаем и его тоже
  const char *content_type = apr_table_get(r->headers_in, "Content-Type");
  if (r->method_number == M_POST && content_type &&
      strncasecmp(content_type, CONTENT_TYPE_URLENCODED, strlen(CONTENT_TYPE_URLENCODED)) == 0)
    {
    apreq_parser_t *parser = apreq_parser_make(r->pool, r->connection->bucket_alloc, content_type, apreq_parse_urlencoded, 65000, "/tmp", NULL, NULL);
    // Создадим структуру, в которой парсер библиотеки apreq будет обрабатывает содержимое тела POST-запроса
    apr_bucket_brigade *bb = apr_brigade_create(r->pool, r->connection->bucket_alloc);

    int end = false;
    do
      {
      // Последовательно будем читать входные данные и помещать их в цепочку apr_bucket_brigade
      ap_get_brigade(r->input_filters, bb, AP_MODE_READBYTES, APR_BLOCK_READ, 65000);
      // Распарсим порцию входных данных
      apreq_parser_run(parser, ap, bb);
      // Проверим, содержит ли цепочка признак завершения входных данных
      for (apr_bucket *b = APR_BRIGADE_FIRST(bb); b != APR_BRIGADE_SENTINEL(bb); b = APR_BUCKET_NEXT(b))
        {
        if (APR_BUCKET_IS_EOS(b))
          { // если входных данных больше нет, завершаем цикл
          end = true;
          break;
          }
        }
      }
    while (!end);
    }

  if (apr_is_empty_table(ap))
    return APR_SUCCESS; // входных параметров нет

  // Преобазуем входные параметры из внутренней структуры библиотеки apreq в структуру типа apr_table_t
  const apr_array_header_t *a = apr_table_elts(ap);
  apr_table_entry_t *elts = (apr_table_entry_t *) a->elts;
  for (int i = 0; i < a->nelts; i++)
    {
    apreq_param_t *p = apreq_value_to_param(elts[i].val);
    const char *value = p->v.data;
    if (!value)
      value = "";
    apr_table_addn(params, p->v.name, value);
    }

  return APR_SUCCESS;
}

apr_status_t sha256(apr_pool_t *pool, const char *str, char **result)
{
  if (!pool || !str || !result)
    return APR_EGENERAL;

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

extern "C" {
// Код, который должен быть оформлен с extern C, т.к. apache этого требует

static int app_post_config(apr_pool_t *pconf, apr_pool_t *plog, apr_pool_t *ptemp, server_rec *s)
{
  mod_dbd_acquire_fn = APR_RETRIEVE_OPTIONAL_FN(ap_dbd_acquire);

  return OK;
}

static void app_register_hooks(apr_pool_t *p)
{
  ap_hook_handler(app_handler, NULL, NULL, APR_HOOK_MIDDLE);
  ap_hook_post_config(app_post_config, NULL, NULL, APR_HOOK_MIDDLE);
}

AP_DECLARE_MODULE(app) = {
    STANDARD20_MODULE_STUFF,
    NULL,                  /* create per-dir    config structures */
    NULL,                  /* merge  per-dir    config structures */
    NULL,                  /* create per-server config structures */
    NULL,                  /* merge  per-server config structures */
    NULL,                  /* table of config file commands       */
    app_register_hooks  /* register hooks                      */
};
};

// функция отправки SQL-запроса в базу данных
apr_status_t dbd_select(request_rec *r, ap_dbd_t *dbd, apr_dbd_results_t **res, const char *sql)
{
  if (!r || !dbd || !res || !sql || !sql[0])
    return APR_EGENERAL;

  *res = NULL;

  int sql_err = 0;

  apr_dbd_prepared_t *st = NULL;
  sql_err = apr_dbd_prepare(dbd->driver, r->pool, dbd->handle, sql, NULL, &st);
  if (!sql_err)
    sql_err = apr_dbd_pselect(dbd->driver, r->pool, dbd->handle, res, st, 1, 0, NULL);

  if (sql_err)
    {
    ap_log_rerror(APLOG_MARK, LOG_ERR, APR_EGENERAL, r, "DBD error for sql '%s': %s", sql,
                  apr_dbd_error(dbd->driver, dbd->handle, sql_err));
    return APR_EGENERAL;
    }

  return APR_SUCCESS;
}

// основной обработчик запросов Apache
static int app_handler(request_rec *r)
{
  if (strcmp(r->handler, "app_handler") != 0)
    return DECLINED;

  r->content_type = "text/html; charset=UTF-8";

  if (r->header_only)
    return OK;

  ap_dbd_t *dbd = mod_dbd_acquire_fn(r);
  if (!dbd)
    return HTTP_INTERNAL_SERVER_ERROR;

  apr_table_t *params = apr_table_make(r->pool, 25);
  if (get_params(r, params) != APR_SUCCESS)
    return HTTP_INTERNAL_SERVER_ERROR;

  const char *user = apr_table_get(params, "user");
  const char *pass = apr_table_get(params, "pass");

  ap_log_rerror(APLOG_MARK, LOG_INFO, APR_SUCCESS, r, "user=%s pass=%s", user, pass);

  char *pass_hash;
  if (sha256(r->pool, pass, &pass_hash) != APR_SUCCESS)
    return HTTP_INTERNAL_SERVER_ERROR;

  apr_dbd_results_t *res;
  apr_dbd_row_t *row = NULL;

  // Сформируем SQL-запрос для проверки корректности логина и пароля
  const char *sql = apr_pstrcat(r->pool, "SELECT name FROM users WHERE login='", user, "' AND password='", pass_hash, "'", NULL);
  ap_log_rerror(APLOG_MARK, LOG_INFO, APR_SUCCESS, r, "SQL=%s", sql);

  // Получим имя пользователя с указанным логином и паролем. Если name останется NULL, значит, логин или пароль некорректны
  const char *name = NULL;

  if (dbd_select(r, dbd, &res, sql) != APR_SUCCESS)
    return HTTP_INTERNAL_SERVER_ERROR;
  while(res && apr_dbd_get_row(dbd->driver, r->pool, res, &row, -1) == 0 && row)
    {
    name = apr_pstrdup(r->pool, apr_dbd_get_entry(dbd->driver, row, 0));
    }


  if (!name)
    {
    ap_log_rerror(APLOG_MARK, LOG_WARNING, APR_SUCCESS, r, "Name not found");
    return HTTP_FORBIDDEN;
    }
  else
    ap_log_rerror(APLOG_MARK, LOG_INFO, APR_SUCCESS, r, "Name=%s", name);

  ap_rprintf(r, "<p>Добро пожаловать, %s</p>\n\n", name);

  return OK;
}
