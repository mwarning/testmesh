
#ifndef _LOG_H_
#define _LOG_H_

#include <syslog.h>
#include "main.h"


// verbosity levels
enum {
  VERBOSITY_QUIET,
  VERBOSITY_VERBOSE,
  VERBOSITY_DEBUG
};

#define log_error(...) \
  log_print(LOG_ERR, __VA_ARGS__);

#define log_info(...)                              \
  do {                                             \
    if (gstate.log_verbosity != VERBOSITY_QUIET)   \
      log_print(LOG_INFO, __VA_ARGS__);            \
  } while (0)

#define log_warning(...)                           \
  do {                                             \
    if (gstate.log_verbosity != VERBOSITY_QUIET)   \
      log_print(LOG_WARNING, __VA_ARGS__);         \
  } while (0)

#define log_debug(...)                             \
  do {                                             \
    if (gstate.log_verbosity == VERBOSITY_DEBUG)   \
      log_print(LOG_DEBUG, __VA_ARGS__);           \
  } while (0)

// Print a log message
void log_print(int priority, const char format[], ...);

#endif // _LOG_H_
