
#include <stdio.h>
#include <stdlib.h>
#include <syslog.h>
#include <stdarg.h>
#include <time.h>
#include <string.h>

#include "main.h"
#include "console.h"
#include "log.h"


// program start time
static struct timespec g_log_start = { 0, 0 };

const char *g_log_levels[MAX_LOG_LEVEL] = {"mute", "error", "warning", "info", "verbose", "debug", "trace"};

const char *log_level_str(uint8_t level)
{
	if (level < MAX_LOG_LEVEL) {
		return g_log_levels[level];
	}

	return NULL;
}

uint8_t log_level_parse(const char *level)
{
	// try to parse as mnemonic
	for (size_t i = 0; i < MAX_LOG_LEVEL; ++i) {
		if (0 == strcmp(level, g_log_levels[i])) {
			return i;
		}
	}

	// try to parse as number - fallback
	char *ptr = NULL;
	const char *end = level + strlen(level);
	uint32_t log_level = strtoul(level, &ptr, 10);
	if (ptr == end && log_level < MAX_LOG_LEVEL) {
		return log_level;
	}

	// return invalid log level
	return MAX_LOG_LEVEL;
}

static const char *log_get_time(char* buf)
{
	struct timespec now = { 0, 0 };

	clock_gettime(CLOCK_MONOTONIC, &now);

	// Initialize clock
	if (g_log_start.tv_sec == 0 && g_log_start.tv_nsec == 0) {
		clock_gettime(CLOCK_MONOTONIC, &g_log_start);
	}

	uint64_t ms = (1000UL * now.tv_sec + now.tv_nsec / 1000000UL)
		- (1000UL * g_log_start.tv_sec + g_log_start.tv_nsec / 1000000UL);
	sprintf(buf, "[%4u.%03u] ", (unsigned) (ms / 1000UL), (unsigned) (ms % 1000UL));

	return buf;
}

void log_print(int priority, const char format[], ...)
{
	char buf[500];
	char buf2[524];
	char time_buf[16];
	const char *time;
	va_list vlist;

	va_start(vlist, format);
	vsnprintf(buf, sizeof(buf), format, vlist);
	va_end(vlist);

	if (gstate.log_time) {
		time = log_get_time(time_buf);
	} else {
		time = "";
	}

	if (gstate.log_to_syslog) {
		// Write messages to e.g. /var/log/syslog
		openlog(PROGRAM_NAME, LOG_PID | LOG_CONS, LOG_USER | LOG_PERROR);
		syslog(priority, "%s%s", time, buf);
		closelog();
	}

	if (gstate.log_to_terminal) {
		FILE *out = (priority == LOG_ERR) ? stderr : stdout;
		fprintf(out, "%s%s\n", time, buf);
	}

	if (gstate.log_to_socket) {
		snprintf(buf2, sizeof(buf2), "%s%s\n", time, buf);
		console_log_message(buf2);
	}

	if (gstate.log_to_file) {
		fprintf(gstate.log_to_file, "%s%s\n", time, buf);
		fflush(gstate.log_to_file);
	}
}
