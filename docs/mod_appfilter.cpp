/**
 *  @file mod_appfilter.cpp
 *  @brief Apache модуль, который блокирует sql инъекции, используя сигнатурный метод выявления атак.
 *
 *  Модуль можно включать и отключать в конфигурационных настройках Apache
 *  в файле httpd.conf.
 *
 *  Также в настройках можно указывать сигнатуры для определения SQL инъекций.
 *
 *  Данная программа работает с Postgresql в качестве базы данных о запросах пользователей.
 */


#include "httpd.h"
#include "http_config.h"
#include "http_protocol.h"
#include "http_log.h"
#include "http_request.h"
#include "ap_config.h"
#include "apr_dbd.h"
#include "apr_strings.h"
#include "mod_dbd.h"
#include "apreq.h"
#include "apreq_parser.h"
#include "apreq_param.h"
#include "apreq_util.h"
#include "openssl/sha.h"

/**
  * @brief Alias типа структуры со списком плохих строк. В данном случае ' и %27
 */
typedef struct {
  int enabled;            // true, если модуль активирован опцией appfilter_enable true
  apr_table_t *badstr;    // apache таблица со списком плохих строк
} config_t;


// опция C требуется, т.к. Apache требует оформления наименований по стандарту C
/**
  * @brief Объявление модуля
 */
extern "C" module AP_MODULE_DECLARE_DATA appfilter_module;

// Заголовки описаний функций, описанных после AP_DECLARE_MODULE, чтобы скомпилировался код
static const char *option_enable(cmd_parms *cmd, void *doof, const char *value);
static const char *option_str(cmd_parms *cmd, void *doof, const char *value);
static int input_fixup(request_rec *r);

/**
  * @brief Функция выделяет память для хранения параметров модуля, указанных в httpd.conf.
  * В данном примере есть 3 параметра: 
  *
  * appfilter_enable true
  *
  * appfilter_str "'"
  *
  * appfilter_str "%27"
  */
static void *create_server_conf(apr_pool_t *pool, server_rec *s)
{
  // apr_pcalloc возвращает выделенную память, заполненную 0 
  config_t *config = (config_t *)apr_pcalloc(pool, sizeof(config_t));
  // apr_table_make создает таблицу со списком плохих строк
  // Apache умеет автоматически расширятьт размер таблицы, но всё же создадим минимум - 5 параметров
  config->badstr = apr_table_make(pool, 5);

  return config;
}
/**
  * @brief Функция регистрации обработчиков модуля-фильтра SQL запросов.
  */
static void appfilter_register_hooks(apr_pool_t *p)
{
  // это фильтр запросов, не сервесный модуль или служебный модуль
  ap_hook_fixups(input_fixup, NULL, NULL, APR_HOOK_MIDDLE);
}


extern "C" {
// Код, который должен быть оформлен с extern C, т.к. apache этого требует
// функция, которая принимает значения из конфигурационного файла
// значения appfilter_enable и appfilter_str прописаны в файле httpd.conf (строки 69 - 73)
/**
  * @brief Функция которая задает опции обработчику.
  * Первая опция - включить/отключить модуль
  *
  * Вторая опция - добавление сигнутур в файле конфигурации
  */
static const command_rec appfilter_options[] =
{
  // AP_INIT_TAKE1 - функция принимает 1 параметр
  // "appfilter_enable" - название директивы
  // option_enable - название функции на С для парсинга директивы
  // RSRC_CONF - описание директивы находится вне строк <Directory> или <Location>
  // "Enable/disable filtering") - краткое описание директивы
  AP_INIT_TAKE1("appfilter_enable", option_enable, NULL, RSRC_CONF, "Enable/disable filtering"),
  AP_INIT_TAKE1("appfilter_str", option_str, NULL, RSRC_CONF, "String to filter"),
  {NULL}
};


/**
  * @brief Функция определения модуля mod_appfilter.so
  * @param create_server_conf память для хранения параметров модуля 
  * @param appfilter_options опции модуля
  * @param appfilter_register_hooks фильтр модуля
  */
AP_DECLARE_MODULE(appfilter) = {
    STANDARD20_MODULE_STUFF,
    NULL,                  /* create per-dir    config structures */
    NULL,                  /* merge  per-dir    config structures */
    create_server_conf,    /* create per-server config structures */
    NULL,                  /* merge  per-server config structures */
    appfilter_options,             /* table of config file commands       */
    appfilter_register_hooks       /* register hooks                      */
};
};


/**
  * @brief Обработчик опции appfilter_enable конфигурационного файла Apache.
  * @param *cmd отвечает за местоположение директивы, нужно вне <Directory>
  * @param *doof не нужен, но должен быть прописан
  * @param *value принимает на вход значение value , указанное в файле httpd.conf
  * Опции модуля должны быть прописаны в файле httpd.conf вне <Directory> и 
  * принимать значения только true либо false
  * @return error или NULL
  */

static const char *option_enable(cmd_parms *cmd, void *doof, const char *value)
{
  // Убедимся, что данная опция указана не внутри опции Directory
  const char *error = ap_check_cmd_context(cmd, GLOBAL_ONLY);
  if (error)
    return error;

  config_t *config = ap_get_module_config(cmd->server->module_config, &appfilter_module);

  if (strcasecmp(value, "true") == 0)
    config->enabled = true;
  else if (strcasecmp(value, "false") == 0)
    config->enabled = false;
  else
    return "Possible values for appfilter_enable option are true or false";

  return NULL;
}




/**
  * @brief Обработчик опции appfilter_str конфигурационного файла Apache.
  * @param *cmd отвечает за местоположение директивы, нужно вне <Directory>
  * @param *doof не нужен, но должен быть указан
  * @param *value принимает на вход значение value , указанное в файле httpd.conf
  * Функция добавляет указанные в конфигурации сигнатуры в структуру config
  * @return error или NULL
  */
static const char *option_str(cmd_parms *cmd, void *doof, const char *value)
{
  // Убедимся, что данная опция указана не внутри опции Directory
  const char *error = ap_check_cmd_context(cmd, GLOBAL_ONLY);
  if (error)
    return error;

  config_t *config = ap_get_module_config(cmd->server->module_config, &appfilter_module);

  apr_table_addn(config->badstr, "1", value);

  return NULL;
}



/**
  * @brief Фильтр входного запроса.
  * @param *r структура URL-запросов.
  * Функция проверяет статус включенного модуля и наличие сигнатур.
  *
  * Затем ищет вхождения сигнатур в запросы, если находит, возвращает 403 ошибку.

  * @return статус OK - успешное соединение, если не удалось - внутренняя ошибка сервера.
  */
static int input_fixup(request_rec *r)
{
  config_t *config = ap_get_module_config(r->server->module_config, &appfilter_module);
  if (!config)
    return HTTP_INTERNAL_SERVER_ERROR;

  // Если опция appfilter_enable не true, выходим
  if (!config->enabled)
    return OK;

  // Если не указана ни одна опция appfilter_str, выходим
  if (apr_is_empty_table(config->badstr))
    return OK;

  // Если нет параметров, выходим
  if (!r->args)
    return OK;

  // В цикле проверим наличие в URL плохой строки
  const apr_array_header_t *a = apr_table_elts(config->badstr);
  apr_table_entry_t *elts = (apr_table_entry_t *) a->elts;
  for (int i = 0; i < a->nelts; i++)
    {
    const char *str = elts[i].val;
    ap_log_rerror(APLOG_MARK, LOG_INFO, APR_SUCCESS, r, "testing string %s in args %s", str, r->args);
    // ищем подстроку str SQL запроса в r->args, 
    // функция возвращает указатель на место первого 
    // символа первого вхождения (tесли такого нет - NULL, возвращаем 403 ошибку)
    if (strstr(r->args, str))
      {
      ap_log_rerror(APLOG_MARK, LOG_WARNING, APR_SUCCESS, r, "Bad string %s found in URI %s", str, r->args);
      return HTTP_FORBIDDEN;
      }
    }

  return OK;
}
