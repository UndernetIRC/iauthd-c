/* log.h - logging subsystem
 *
 * Copyright 2004, 2011 Michael Poole <mdpoole@troilus.org>
 *
 * Permission is hereby granted, free of charge, to any person
 * obtaining a copy of this software and associated documentation
 * files (the "Software"), to deal in the Software without
 * restriction, including without limitation the rights to use, copy,
 * modify, merge, publish, distribute, sublicense, and/or sell copies
 * of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#if !defined(LOG_H_b32c7845_d03f_4dab_80b7_56b9f85190e2)

/** Multiple-inclusion guard for "src/log.h". */
#define LOG_H_b32c7845_d03f_4dab_80b7_56b9f85190e2

struct log_type;

extern struct log_type *log_core;

enum log_severity {
    LOG_DEBUG,   /* 0 */
    LOG_COMMAND,
    LOG_INFO,
    LOG_WARNING,
    LOG_ERROR,
    LOG_FATAL,   /* 5 */
    LOG_NUM_SEVERITIES
};

struct log_destination
{
    char *name;
    struct log_destination_vtable *vtbl;
    int refcnt;
};

struct log_destination_vtable
{
    const char *type_name;
    struct log_destination* (*open)(const char *args);
    void (*reopen)(struct log_destination *self_);
    void (*close)(struct log_destination *self_);
    void (*log)(struct log_destination *self_, struct log_type *type, enum log_severity sev, const char *message);
};

struct log_type *log_type_register(const char *name, const char *default_target);
void log_vmessage(struct log_type *type, enum log_severity sev, const char *format, va_list args);
void log_message(struct log_type *type, enum log_severity sev, const char *format, ...) PRINTF_LIKE(3, 4);

void log_reopen(void);
void log_set_verbosity(int level);
void log_destination_vtable_register(const struct log_destination_vtable *orig);

#endif /* !defined(LOG_H_b32c7845_d03f_4dab_80b7_56b9f85190e2) */
