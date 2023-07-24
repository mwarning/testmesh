#include <string.h>
#include <stdbool.h>
#include <stdlib.h>
#include <time.h>

#include "../main.h"
#include "../log.h"
#include "packet_trace.h"


#define MARKER_MIN_LENGTH 3
#define MARKER_MAX_LENGTH 30
#define MARKER_CUT_OFF true


struct DebugData {
    uint32_t src;
    uint32_t dst;
    time_t time;
    char *marker;
    char *message;
};

static struct DebugData g_debug_data = {
    .src = 0,
    .dst = 0,
    .time = 0,
    .marker = NULL,
    .message = NULL,
};

static void packet_trace_clear()
{
    g_debug_data.time = 0;

    if (g_debug_data.marker != NULL) {
        free(g_debug_data.marker);
        g_debug_data.marker = NULL;
    }

    if (g_debug_data.message != NULL) {
        free(g_debug_data.message);
        g_debug_data.message = NULL;
    }
}

void packet_trace_set(const char *action, const void* data, size_t data_length)
{
    packet_trace_clear();

    g_debug_data.time = gstate.time_now;
    g_debug_data.message = strdup(action);

    // get first printable string
    char marker[MARKER_MAX_LENGTH + 1];
    size_t j = 0;
    for (size_t i = 0; i < data_length; i += 1) {
        const char c = ((uint8_t*) data)[i];
        if ((c >= 'a' && c <= 'z')
                || (c >= 'A' && c <= 'Z')
                || (c >= '0' && c <= '9')
                || c == '-' || c == '_') {
            // printable ASCII character
            marker[j++] = c;
            if (j >= MARKER_MAX_LENGTH) {
                if (MARKER_CUT_OFF) {
                    // string too long, take it thus far
                    break;
                } else {
                    // too long => find next string
                    j = 0;
                }
            }
        } else if (j > 0 && j >= MARKER_MIN_LENGTH) {
            // found string that matches requirement
            break;
        } else {
            // too short => find next string
            j = 0;
        }
    }
    marker[j] = 0;

    log_trace("found marker: %s", marker);

    g_debug_data.marker = strdup(marker);
}

static const char *str(const char *s)
{
    return s ? s : "";
}

void packet_trace_json(FILE* fp)
{
    fprintf(fp, "{\"marker\": \"%s\", \"message\": \"%s\", \"time\": %zu}",
        str(g_debug_data.marker), str(g_debug_data.message), (size_t) g_debug_data.time);
}
