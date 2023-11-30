
#ifndef _LOG_H_
#define _LOG_H_

#include <syslog.h>
#include "main.h"

#define MAX_LOG_LEVEL 7

#define log_error(...)                             \
  do {                                             \
    if (gstate.log_level > 0)                      \
      log_print(LOG_ERR, __VA_ARGS__);             \
  } while (0)

#define log_warning(...)                           \
  do {                                             \
    if (gstate.log_level > 1)                      \
      log_print(LOG_WARNING, __VA_ARGS__);         \
  } while (0)

#define log_info(...)                              \
  do {                                             \
    if (gstate.log_level > 2)                      \
      log_print(LOG_INFO, __VA_ARGS__);            \
  } while (0)

#define log_verbose(...)                           \
  do {                                             \
    if (gstate.log_level > 3)                      \
      log_print(LOG_INFO, __VA_ARGS__);            \
  } while (0)

#ifdef DEBUG
#define log_debug(...)                             \
  do {                                             \
    if (gstate.log_level > 4)                      \
      log_print(LOG_DEBUG, __VA_ARGS__);           \
  } while (0)
#else
#define log_debug(...)
#endif

#ifdef DEBUG
#define log_trace(...)                            \
  do {                                             \
    if (gstate.log_level > 5)                      \
      log_print(LOG_DEBUG, __VA_ARGS__);           \
  } while (0)
#else
#define log_trace(...)
#endif

// Print a log message
void log_print(int priority, const char format[], ...);

uint8_t log_level_parse(const char *level);
const char *log_level_str(uint8_t level);

#endif // _LOG_H_
