/**
 *  @file mod_app.cpp
 *  @brief Apache модуль авторизации пользователя в системе. 
 *
 *  Данная программа парсит полученные данные: логин + пароль в виде sha хэша; 
 *
 *  проверяет логин и пароль на корректность; 
 *
 *  работает с postgres sql; 
 *
 *  формирует страницу html и отправляет её Apache. 
 */



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

/**
  * @brief Cтатическое определение типа данных опциональной библиотеки для работы с Postgresql. 
 */
static APR_OPTIONAL_FN_TYPE(ap_dbd_acquire) *mod_dbd_acquire_fn = NULL;

/**
  * @brief Определение функции обработчика HTTP-запросов.
 */
static int app_handler(request_rec *r);

/**
  * @brief Макрос, определяющий тип кодировки URL. 
  * 
  * Кодировка "application/x-www-form-urlencoded" происходит в формате ключ=значение.
  * 
  * Например, login=smith&password=12345678 
 */
#define CONTENT_TYPE_URLENCODED "application/x-www-form-urlencoded"


/**
  * @brief Функция парсинга.
  * @param *r Указатель на структуру данных об HTTP-запросе. Тип структуры - стандартный для Apache.
  * @param *params Указатель на структуру данных об HTTP-запросе. Тип структуры - Apache Portable Runtime таблица.
  *
  * Сначала проверим наличие данных внутри входных параметров.
  *
  * Если запрос внутри стандартной структуры Apache пустой или 
  * пустой запрос внутри таблицы APR, то возвращаем ошибку.
  *
  * Данные URL-строки парсим с помощью стандартной функции apreq_parse_query_string.
  *
  * Данные из тела POST-запроса, у которых Content-type = "application/x-www-
  * form-urlencoded"  парсим построчно и добавляем в bucket brigade.
  *
  * Полученные данные порционно будем помещать в структуру типа Apache, а 
  * затем преобразуем в таблицу APR.
  * @return Код состояния APR_SUCCESS в случае успеха, иначе APR_EGENERAL.

  */
apr_status_t get_params(request_rec *r, apr_table_t *params)
{
  if (!r || !params)
    return APR_EGENERAL; //General failure (specific information not available)

  // функция инициализации
  apreq_initialize(r->pool);


  // Создадим таблицу, в которую парсер библиотеки apreq помещает распарсенные данные в своем формате
  // В таблице по указателю *ap будут храниться данные запроса из пула pool 
  // изначально зададим размер таблицы - 25 параметров
  apr_table_t *ap = apr_table_make(r->pool, 25);


  // Если есть параметры, переданные в URL-строке, распарсим их
  // данные r->pool из пула помещаем в таблицу ap
  if (r->args)
    apreq_parse_query_string(r->pool, ap, r->args);



  // В HTTP-методе POST данные также могут передаваться в теле запроса. 
  // Это нужно, так как URL данные Apache хранит в логах, а
  // хранить пароли в открытом виде небезопастно.
  // Обработаем и его тоже.
  // Принимаем значение Content-type из таблицы
  const char *content_type = apr_table_get(r->headers_in, "Content-Type");

  // если метод запроса POST, и данные в Content-Type есть, 
  // и Content-type  это "application/x-www-form-urlencoded"
  if (r->method_number == M_POST && content_type &&
      strncasecmp(content_type, CONTENT_TYPE_URLENCODED, strlen(CONTENT_TYPE_URLENCODED)) == 0)
    {
    // Структура-парсер временная.
    // функция apreq_parser_make создает новый объект парсера.
    // она использует текущий пул памяти r->pool с результатами http запроса.
    // тип кодирования content_type - application/x-www-form-urlencoded
    // использует метод apreq_parse_urlencoded чтобы распарсить данные. 
    // максимальный размер данных 65000 байтов.
    // в директории /tmp будут храниться временные файлы.
    apreq_parser_t *parser = apreq_parser_make(r->pool, r->connection->bucket_alloc, content_type, apreq_parse_urlencoded, 65000, "/tmp", NULL, NULL);

    // Создадим структуру, в которой парсер библиотеки apreq будет обрабатывает содержимое тела POST-запроса
    // Bucket brigades represent a complex data stream that can be passed through 
    // a layered IO system without unnecessary copying.
    // Так как сервер харанее не знает размер данных внутри тела запроса, Apache помещает данные порционно в bucket brigade
    apr_bucket_brigade *bb = apr_brigade_create(r->pool, r->connection->bucket_alloc);

    int end = false;
    do
      {
      // Последовательно будем читать входные данные и помещать их в цепочку apr_bucket_brigade
      ap_get_brigade(r->input_filters, bb, AP_MODE_READBYTES, APR_BLOCK_READ, 65000);
      // Распарсим порцию входных данных
      apreq_parser_run(parser, ap, bb);
      
      // Проверим, содержит ли цепочка признак завершения входных данных
      // APR_BRIGADE_FIRST указатель на первую корзину в bb brigade
      // APR_BRIGADE_SENTINEL указатель на последнюю корзину в bb brigade
      // APR_BUCKET_NEXT указатель на следующую корзину в bb brigade
      for (apr_bucket *b = APR_BRIGADE_FIRST(bb); b != APR_BRIGADE_SENTINEL(bb); b = APR_BUCKET_NEXT(b))
        {
        if (APR_BUCKET_IS_EOS(b))
          { // если входных данных больше нет, завершаем цикл
          // EOS (End Of Stream) bucket - последняя корзина 
          end = true;
          break;
          }
        }
      }
    while (!end);
    }


  if (apr_is_empty_table(ap))
    return APR_SUCCESS; // входных параметров нет

  // Преобазуем входные параметры из внутренней структуры библиотеки apreq в таблицу типа apr_table_t
  // Таблица содеержит ключ и значение, например параметр Content-type будет иметь значение "application/x-www-form-urlencoded"
  // функция apr_table_elts вернет массив из данных таблицы ap 
  const apr_array_header_t *a = apr_table_elts(ap);
  // структура *elts содержит ключ, значение и checksum
  apr_table_entry_t *elts = (apr_table_entry_t *) a->elts;
  // проходимся по всем элементам структуры a
  for (int i = 0; i < a->nelts; i++)
    {
    // функция apreq_value_to_param преобразует значения аргументов в данные структуры типа apreq_param_t
    apreq_param_t *p = apreq_value_to_param(elts[i].val);
    const char *value = p->v.data;
    if (!value)
      value = "";
    apr_table_addn(params, p->v.name, value);
    }

  return APR_SUCCESS;
}





/**
  * @brief Функция преобразования пароля в хеш.
  * @param *pool Указатель на пул памяти.
  * @param *str Пароль в виде строки.
  * @param **result Результат - хеш пароля.
  * @return Код состояния APR_SUCCESS в случае успеха, иначе APR_EGENERAL.
  */
apr_status_t sha256(apr_pool_t *pool, const char *str, char **result)
{
  if (!pool || !str || !result)
    return APR_EGENERAL;

  // Вычислим SHA256-хеш от строки str
  // длина массива SHA256_DIGEST_LENGTH - стандартная 32 байта, их openssl библиотеки (не утилиты с тем же названием)
  unsigned char hash[SHA256_DIGEST_LENGTH];

  // openssl функция 
  // принимает указатель на массив из char 
  // возвращает массив с хешем в бинарном виде 
  // SHA256 возвращает хеш в двоичном значении
  SHA256((const unsigned char *)str, strlen(str), hash);


  // Преобразуем двоичное значение в hash в HEX-строку вида AB2481EF...
  // Выделяем пул памяти длиной 65 байт - один байт - это 2 буквы + 1 символ - конец массива
  char *s = (char *)apr_pcalloc(pool, SHA256_DIGEST_LENGTH * 2 + 1);
  *result = s;

  // Берется 1 байт, сдвигается на 4 бита.
  // Если число от 0 до 9, то добавляется '0'. 
  //  Если число от 10 до 15, то от него удаляется 10 и добавляется 'a', (например, 15 -> 'f')
  // & 0x0f - побитовая операция И с числом 0x0f (bin = 0000 1111). Эта операция оставляет только 4 младших бита результата сдвига, обнуляя все остальные биты.
  for (int i=0; i < SHA256_DIGEST_LENGTH; i++)
    {
    char b = hash[i];
    char c = (b >> 4) & 0x0f;
    *(s++) = c > 9 ? c + ('a' - 10) : c + '0';
    c = b & 0x0f;
    *(s++) = c > 9 ? c + ('a' - 10) : c + '0';
    }
  // Признак конца массива  
  *s = 0;

  return APR_SUCCESS;
}



// оформление в формате внешнего связывания (external linkage) по стандарту "C"
// функция будет доступна другим модулям apache
// https://en.cppreference.com/w/cpp/language/language_linkage.html
// https://en.cppreference.com/w/cpp/language/storage_duration.html
// это нужно, так как программа написана на С++ , а Apache на С
// во время компиляции C++ программ происходит замангливание (обратно декорирование) функций ,
// так apache не увидит название функций без extern "C"
extern "C" {
// Код, который должен быть оформлен с extern C, т.к. apache этого требует

/**
  * @brief Функция получения статуса соединения с продолжительностью = времени жизни запроса.
  * @param *pconf Указатель на пул памяти конфигурации.
  * @param *plog Указатель на пул памяти логирования.
  * @param *ptemp Указатель на временный пул памяти.
  * @param *s Указатель на пул памяти, где лежит SQL запрос в виде хеша.
  * Функция нужна будут в будущем для проверки работы сервера
  * @return OK
  */
static int app_post_config(apr_pool_t *pconf, apr_pool_t *plog, apr_pool_t *ptemp, server_rec *s)
{
  // опциональная библиотека для работы с Postgresql
  mod_dbd_acquire_fn = APR_RETRIEVE_OPTIONAL_FN(ap_dbd_acquire);
  return OK;
}


/**
  * @brief Функция регистрации обработчиков модуля mod_app.so
  * @param *p Указатель на пул памяти .
  * Каждый модуль Apache отвечает на запросы сервера с помощью hook - 
  * сообщения о том, будут он обрабатывать это запрос или отклонит его.
  */
static void app_register_hooks(apr_pool_t *p)
{
  ap_hook_handler(app_handler, NULL, NULL, APR_HOOK_MIDDLE);
  ap_hook_post_config(app_post_config, NULL, NULL, APR_HOOK_MIDDLE);
}


/**
  * @brief Функция определения модуля mod_app.so
  * @param app_register_hooks Обработчики модуля.
  * Данный модуль имеет стандартный вид и принимает только hooks параметры.
  */
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




/**
  * @brief Функция отправки SQL-запроса в базу данных.
  * @param *r Указатель на структуру, которая содержит информацию о HTTP-запросе.
  * @param *dbd Указатель на структуру, которая содержит информацию о драйвере, обработчике (handler), пуле и хеше
  * @param **res Указатель на указатель на структуру для взаимодействия в Postgresql.
  * @param *sql SQL запрос в виде массива из char.  
  * SQL является одним из стандартов работы с базами данных. Процесс имеет 3 стадии:
  *
  * 1 - Компиляция
  *
  * 2 - Выполнение
  *
  * 3 - Чтение
  *
  * В данной функции происходят первые два этапа обработки SQL запроса - подготовка и выполнение
  * @return Код состояния APR_SUCCESS в случае успеха, иначе APR_EGENERAL.
  */
apr_status_t dbd_select(request_rec *r, ap_dbd_t *dbd, apr_dbd_results_t **res, const char *sql)
{
  if (!r || !dbd || !res || !sql || !sql[0])
    return APR_EGENERAL;

  *res = NULL;

  int sql_err = 0;
  // *st - statemant указатель на  структуру с хешем SQL запросов типа apr_dbd_prepared_t
  apr_dbd_prepared_t *st = NULL;

  // подготавливаем запрос к проверке
  // sql_err будет возвращать 0 в случае успеха или код ошибки
  sql_err = apr_dbd_prepare(dbd->driver, r->pool, dbd->handle, sql, NULL, &st);
  // если запрос SQL верный , то возвращаем APR_SUCCESS;
  if (!sql_err)
    sql_err = apr_dbd_pselect(dbd->driver, r->pool, dbd->handle, res, st, 1, 0, NULL);
  
  // если запрос не верный, формируем сообщение об ошибке 
  // и направляем его в файл error_log
  // возвращаем ошибку APR_EGENERAL
  if (sql_err)
    {
    ap_log_rerror(APLOG_MARK, LOG_ERR, APR_EGENERAL, r, "DBD error for sql '%s': %s", sql,
                  apr_dbd_error(dbd->driver, dbd->handle, sql_err));
    return APR_EGENERAL;
    }

  return APR_SUCCESS;
}



/**
  * @brief Основной обработчик запросов Apache.
  * @param *r Указатель на структуру, которая содержит распарсенные данные о HTTP-запросах.
  *
  * Для того чтобы произвести авторизацию пользователя в системе нужно:
  *
  * проверить, что этот запрос обрабатывается модулем mod_app.so;
  * 
  * получить данные о POST-запросе в хэдере или теле запроса с кодировкой application/x-www-form-urlencoded;
  *
  * поменять URL кодировку на UTF-8 кодировку для формирования HTML страницы;
  *
  * убедиться, что время запроса не превосходит его продолжительности жизни;
  *
  * преобразовать пароль в хеш SHA256;
  *
  * сформировать SQL-запрос, который уже был проверен на наличие инъекций модулем mod_appfilter.so
  * @return Код состояния OK в случае успеха, иначе HTTP_INTERNAL_SERVER_ERROR.
  */
static int app_handler(request_rec *r)
{
  // убедимся, что этот запрос должен обрабатываться этим модулем,
  // иначе handler вернет Apache отказ и не станет обрабатывать запрос 
  if (strcmp(r->handler, "app_handler") != 0)
    return DECLINED;

  // до этого content-type был application/x-www-form-urlencoded, он использовался, 
  // когда браузер отправлял серверу POST запрос 
  // был указан формат для парсинга типа ключ-значение
  // теперь content-type text/html; charset=UTF, 
  // будем использовать его для ответа брузеру
  // ответ будет содержать html страничку с кодировкой UTF-8
  r->content_type = "text/html; charset=UTF-8";


  // если запрос пустой, завершаем функцию обработки со статусом OK 
  if (r->header_only)
    return OK;


  //  в начале файла определяли static функцию APR_OPTIONAL_FN_TYPE(ap_dbd_acquire) 
  // с указателем *mod_dbd_acquire_fn на NULL 
  // в extern "C" была функция static int app_post_config, 
  // которая проверяла установлено ли соединение c Postgresql
  // в данной функции проверяется смог ли обработчик получить 
  // статус OK - успешное соединение, если не удалось - внутренняя ошибка сервера

  // mod_app вызывает mod_dbd_acquire_fn, затем ждет сообщение от 
  // модуля mod_dbd.so о том, можно ли дальше продолжать
  // работать с бд
  ap_dbd_t *dbd = mod_dbd_acquire_fn(r);
  if (!dbd)
    return HTTP_INTERNAL_SERVER_ERROR;


  // проверяем удалось ли распарсить данные, 
  // добавить их в цепочку apr_bucket_brigade, 
  // а затем преобразовать в структуру типа apr_table_t
  // если нет - внутренняя ошибка сервера
  apr_table_t *params = apr_table_make(r->pool, 25);
  if (get_params(r, params) != APR_SUCCESS)
    return HTTP_INTERNAL_SERVER_ERROR;

  const char *user = apr_table_get(params, "user");
  const char *pass = apr_table_get(params, "pass");

  // помещаем в файл ошибок  error_log информацию о запросе
  ap_log_rerror(APLOG_MARK, LOG_INFO, APR_SUCCESS, r, "user=%s pass=%s", user, pass);

  // если вычислить SHA256 хеш не удалось - внутренняя ошибка сервера
  char *pass_hash;
  if (sha256(r->pool, pass, &pass_hash) != APR_SUCCESS)
    return HTTP_INTERNAL_SERVER_ERROR;

  // нужны будут для функции apr_dbd_get_row
  apr_dbd_results_t *res;
  apr_dbd_row_t *row = NULL;

  // 3 стадия работы SQL стандарта
  // Сформируем SQL-запрос для проверки корректности логина и пароля
  const char *sql = apr_pstrcat(r->pool, "SELECT name FROM users WHERE login='", user, "' AND password='", pass_hash, "'", NULL);
  ap_log_rerror(APLOG_MARK, LOG_INFO, APR_SUCCESS, r, "SQL=%s", sql);


  // Получим имя пользователя с указанным логином и паролем. Если name останется NULL, значит, логин или пароль некорректны
  const char *name = NULL;
  // объединяем строки из пула r->pool
  if (dbd_select(r, dbd, &res, sql) != APR_SUCCESS)
    return HTTP_INTERNAL_SERVER_ERROR;
  while(res && apr_dbd_get_row(dbd->driver, r->pool, res, &row, -1) == 0 && row)
    {
    name = apr_pstrdup(r->pool, apr_dbd_get_entry(dbd->driver, row, 0));
    }


  if (!name)
    {
    ap_log_rerror(APLOG_MARK, LOG_WARNING, APR_SUCCESS, r, "Name not found");
    // если такого пользователя нет 
    // помещаем информацию об sql запросе в файл error_log
    return HTTP_FORBIDDEN;
    }
  else
    ap_log_rerror(APLOG_MARK, LOG_INFO, APR_SUCCESS, r, "Name=%s", name);

  ap_rprintf(r, "<p>Добро пожаловать, %s</p>\n\n", name);

  return OK;
}



/**
 * @mainpage Web application firewall в виде модулей Apache mod_app.so и mod_appfilter.so
 *
 * Краткое описание работы двух модулей Apache.
 *
 * HTTP-запрос клиента хранится в виде структуры request_req.
 * Сначала сервер направляет запрос фильтру mod_appfilter.so, если 
 * SQLi не найдена, то запрос передаётся серверному модулю mod_app.so.
 * Затем запрос парсится.
 * Далее в базе данных Postgresql модуль проверяет наличие sha256 
 * хеша по логину и далее сообщает серверу статус кода OK либо
 * Forbidden.
 */