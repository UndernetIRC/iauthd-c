/* log.c - logging subsystem
 *
 * Copyright 2004, 2005, 2011 Michael Poole <mdpoole@troilus.org>
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

#include "src/common.h"

DECLARE_VECTOR(log_destination_vector, struct log_destination *);
DECLARE_BITSET(severity_bitset, LOG_NUM_SEVERITIES);

struct log_type {
    const char *name;
    char *default_target;
    struct severity_bitset specified;
    struct log_destination_vector logs[LOG_NUM_SEVERITIES];
};

DEFINE_VECTOR(log_destination_vector, struct log_destination *)

static const char *log_severity_names[LOG_NUM_SEVERITIES] = {
    "debug",
    "command",
    "info",
    "warning",
    "error",
    "fatal"
};
static struct set log_vtables; /* contains log_destination_vtable */
static struct set log_destinations; /* contains log_destination */
static struct set log_types; /* contains log_type */
static int log_verbosity = 1;
struct log_type *log_core;
struct log_type *log_default;
static struct {
    struct conf_node_object *root;
    struct conf_node_string *verbose_timestamp;
} conf;

static void log_init(void);

void log_destination_vtable_register(const struct log_destination_vtable *orig)
{
    struct set_node *sn;

    if (!log_vtables.compare)
        log_init();
    if (set_find(&log_vtables, orig))
        return;
    sn = set_node_alloc(sizeof(*orig));
    memcpy(set_node_data(sn), orig, sizeof(*orig));
    set_insert(&log_vtables, sn);
}

static void log_destination_cleanup(void *data)
{
    struct log_destination *ld = data;
    ld->vtbl->close(ld);
    xfree(ld->name);
}

static struct log_destination *log_destination_open(const char *name)
{
    struct log_destination_vtable *vtbl;
    struct log_destination *ld;
    char *sep, type_name[32], *tmp;

    ld = set_find(&log_destinations, &name);
    if (ld) {
        ld->refcnt++;
        return ld;
    }
    sep = strchr(name, ':');
    if (sep) {
        memcpy(type_name, name, sep - name);
        type_name[sep - name] = '\0';
    } else {
        strcpy(type_name, name);
    }
    tmp = type_name;
    vtbl = set_find(&log_vtables, &tmp);
    if (!vtbl) {
        log_message(log_core, LOG_FATAL, "Unknown vtable type %s", type_name);
        return NULL;
    }
    ld = vtbl->open(sep ? sep + 1 : NULL);
    if (!ld) {
        log_message(log_core, LOG_FATAL, "Log open failed for %s:%s",
            type_name, sep ? sep + 1 : "(null)");
        return NULL;
    }
    if (!ld->vtbl)
        ld->vtbl = vtbl;
    ld->name = xstrdup(name);
    set_insert(&log_destinations, set_node(ld));
    return ld;
}

struct log_type *log_type_register(const char *name, const char *default_target)
{
    struct log_type *lt;
    struct set_node *sn;
    enum log_severity sev;

    if (!log_vtables.compare)
        log_init();
    lt = set_find(&log_types, &name);
    if (!lt) {
        sn = set_node_alloc(sizeof(*lt) + strlen(name) + 1);
        lt = set_node_data(sn);
        lt->name = strcpy((char*)(lt + 1), name);
        set_insert(&log_types, sn);
    }
    if (default_target && !lt->default_target) {
        lt->default_target = xstrdup(default_target);
        for (sev = LOG_WARNING; sev < LOG_NUM_SEVERITIES; ++sev)
            if (!BITSET_GET(lt->specified, sev))
                log_destination_vector_append(&lt->logs[sev], log_destination_open(default_target));
    }
    return lt;
}

void log_vmessage(struct log_type *type, enum log_severity sev, const char *format, va_list args)
{
    va_list args_2;
    struct char_vector cv;
    char *message, buff[1024];
    unsigned int ii, count;
    int res;

    assert(type != NULL || sev == LOG_FATAL);
    assert(format != NULL);
    assert(sev < LOG_NUM_SEVERITIES);

    /* Get the formatted string. */
    va_copy(args_2, args);
    res = vsnprintf(buff, sizeof(buff), format, args);
    memset(&cv, 0, sizeof(cv));
    if (res < 0) {
        char_vector_append_vprintf(&cv, format, args_2);
        message = cv.vec;
    } else
        message = buff;

    if (type) {
        /* Call each backend for that log severity. */
        for (ii = count = 0; ii < type->logs[sev].used; ++ii, ++count) {
            struct log_destination *ld = type->logs[sev].vec[ii];
            ld->vtbl->log(ld, type, sev, message);
        }
        for (ii = 0; ii < log_default->logs[sev].used; ++ii, ++count) {
            struct log_destination *ld = log_default->logs[sev].vec[ii];
            ld->vtbl->log(ld, type, sev, message);
        }
    }

    /* Also print to stdout if appropriate. */
    if ((log_verbosity > 1)
        || ((log_verbosity == 1) && (sev >= LOG_WARNING))) {
        char ts[32];

        if (conf.verbose_timestamp->parsed.p_boolean) {
            struct tm local;
            time_t now;

            time(&now);
            localtime_r(&now, &local);
            strftime(ts, sizeof(ts), "[%H:%M:%S %m/%d/%Y] ", &local);
        } else
            ts[0] = '\0';
        fprintf(stdout, "%s%s: %s\n", ts, type->name, message);
    }

    xfree(cv.vec);

    /* Terminate the process if it's a fatal error. */
    if (sev == LOG_FATAL)
        _exit(1);
}

void log_message(struct log_type *type, enum log_severity sev, const char *format, ...)
{
    va_list args;

    va_start(args, format);
    log_vmessage(type, sev, format, args);
    va_end(args);
}

void log_reopen(void)
{
    struct set_node *it;

    for (it = set_first(&log_destinations); it; it = set_next(it)) {
        struct log_destination *ld = set_node_data(it);
        ld->vtbl->reopen(ld);
    }
}

static void log_type_cleanup(void *lt_)
{
    struct log_type *lt = lt_;
    struct log_destination *ld;
    unsigned int ii;
    enum log_severity sev;

    for (sev = 0; sev < LOG_NUM_SEVERITIES; ++sev) {
        for (ii = 0; ii < lt->logs[sev].used; ++ii) {
            ld = lt->logs[sev].vec[ii];
            if (!ld)
                continue;
            assert(ld->refcnt >= 0);
            if (!ld->refcnt--)
                set_remove(&log_destinations, ld, 0);
        }
        log_destination_vector_clear(&lt->logs[sev]);
    }
    xfree(lt->default_target);
}

static void log_format_timestamp(time_t when, struct char_vector *buf)
{
    struct tm local;
    int size;

    localtime_r(&when, &local);
    if (buf->used + 24 >= buf->size)
        char_vector_reserve(buf, buf->used + 24);
    size = sprintf(buf->vec + buf->used, "[%02d:%02d:%02d %02d/%02d/%04d]",
                   local.tm_hour, local.tm_min, local.tm_sec, local.tm_mon+1,
                   local.tm_mday, local.tm_year + 1900);
    if (size < 1)
        return;
    buf->used += size;
}

void log_set_verbosity(int level)
{
    log_verbosity = level;
}

struct log_destination_file
{
    struct log_destination base;
    char *fname;
    FILE *stream;
};

static struct log_destination *log_file_open(const char *args)
{
    struct log_destination_file *self;
    struct set_node *sn;

    sn = set_node_alloc(sizeof(*self));
    self = set_node_data(sn);
    self->fname = xstrdup(args);
    self->stream = fopen(self->fname, "a");
    if (!self->stream) {
        xfree(self->fname);
        xfree(sn);
        return NULL;
    }
    return &self->base;
}

static void log_file_reopen(struct log_destination *self_)
{
    struct log_destination_file *self = (struct log_destination_file*)self_;
    FILE *new_stream = freopen(self->fname, "a", self->stream);
    if (new_stream)
        self->stream = new_stream;
}

static void log_file_close(struct log_destination *self_)
{
    struct log_destination_file *self = (struct log_destination_file*)self_;
    if (!self->stream)
        return;
    fclose(self->stream);
    xfree(self->fname);
    self->stream = NULL;
    self->fname = NULL;
}

static void log_file_log(struct log_destination *self_, struct log_type *type, enum log_severity sev, const char *message)
{
    struct char_vector buf;
    struct log_destination_file *self = (struct log_destination_file*)self_;
    time_t now;

    memset(&buf, 0, sizeof(buf));
    time(&now);
    log_format_timestamp(now, &buf);
    fprintf(self->stream, "%s (%s:%s) %s\n", buf.vec, type->name, log_severity_names[sev], message);
    fflush(self->stream);
    xfree(buf.vec);
}

static struct log_destination_vtable log_file_vtable = {
    "file",
    log_file_open,
    log_file_reopen,
    log_file_close,
    log_file_log
};

static void log_cleanup(void)
{
    set_clear(&log_types);
    set_clear(&log_destinations);
    set_clear(&log_vtables);
}

static int log_parse_type_sevset(struct log_type **type, struct severity_bitset *sevset, const char *str_)
{
    char *str, *sev_str, *sep;
    int res, op;
    enum log_severity sev_val;

    str = xstrdup(str_);
    *type = NULL;
    BITSET_ZERO(*sevset);

    /* Split off and parse the log type name. */
    if (!(sep = strchr(str, '.'))) {
        res = 1;
        goto out;
    }
    *sep++ = '\0';
    *type = set_find(&log_types, &str);
    if (!*type)
        *type = log_type_register(str, NULL);
    if (!strcmp(sep, "*")) {
        for (sev_val = 0; sev_val < LOG_NUM_SEVERITIES; ++sev_val)
            BITSET_SET(*sevset, sev_val);
    } else while (sep && ((sev_str = sep)[0] != '\0')) {
        sep = strchr(sev_str, ',');
        if (sep)
            *sep++ = '\0';
        /* Figure out whether to use the literal severity, or if it is
         * a greater/less[-than-or-equal] range.
         */
        if (sev_str[0] == '>') {
            if (*++sev_str == '=') {
                op = 1;
                ++sev_str;
            } else
                op = 2;
        } else if (sev_str[0] == '<') {
            if (*++sev_str == '=') {
                op = 3;
                ++sev_str;
            } else
                op = 4;
        } else if (sev_str[0] == '=') {
            ++sev_str;
            op = 0;
        } else
            op = 0;
        /* Look up the severity value. */
        for (sev_val = 0; sev_val < LOG_NUM_SEVERITIES; ++sev_val)
            if (!strcasecmp(sev_str, log_severity_names[sev_val]))
                break;
        if (sev_val == LOG_NUM_SEVERITIES) {
            res = 3;
            goto out;
        }
        /* Set the appropriate bits in the severity mask. */
        switch (op) {
        case 0:
            BITSET_SET(*sevset, sev_val);
            break;
        case 1:
            BITSET_SET(*sevset, sev_val);
        case 2:
            while (++sev_val < LOG_NUM_SEVERITIES)
                BITSET_SET(*sevset, sev_val);
            break;
        case 3:
            BITSET_SET(*sevset, sev_val);
        case 4:
            while (sev_val-- > 0)
                BITSET_SET(*sevset, sev_val);
            break;
        }
    }
    res = 0;
out:
    xfree(str);
    return res;
}

static void log_attach_destinations(struct log_type *type, enum log_severity sev, struct conf_node_base *node_)
{
    if (node_->type == CONF_STRING) {
        struct conf_node_string *node;

        node = ENCLOSING_STRUCT(node_, struct conf_node_string, base);
        if (node->value) {
            log_message(log_core, LOG_INFO, "Attaching %s to %s.%s.", node->value, type->name, log_severity_names[sev]);
            log_destination_vector_append(&type->logs[sev], log_destination_open(node->value));
        }
    } else if (node_->type == CONF_STRING_LIST) {
        struct conf_node_string_list *node;
        unsigned int ii;

        node = ENCLOSING_STRUCT(node_, struct conf_node_string_list, base);
        for (ii = 0; ii < node->value.used; ++ii) {
            log_message(log_core, LOG_INFO, "Attaching %s to %s.%s.", node->value.vec[ii], type->name, log_severity_names[sev]);
            log_destination_vector_append(&type->logs[sev], log_destination_open(node->value.vec[ii]));
        }
    }
}

static CONF_UPDATE_HOOK(log_rescan_type);

/** Handle a change to the log configuration section. */
static CONF_UPDATE_HOOK(log_rescan_conf)
{
    struct severity_bitset sevset;
    struct conf_node_base *child;
    struct log_destination *dest;
    struct set_node *it, *next;
    struct log_type *type;
    enum log_severity sev;

    assert(node_ == &conf.root->base);

    /* Clear all log destinations' reference counts. */
    for (it = set_first(&log_destinations); it; it = set_next(it)) {
        dest = set_node_data(it);
        dest->refcnt = -1;
    }

    /* Mark all type/severity pairs as unspecified and empty. */
    for (it = set_first(&log_types); it; it = set_next(it)) {
        type = set_node_data(it);
        for (sev = 0; sev < LOG_NUM_SEVERITIES; ++sev) {
            BITSET_CLEAR(type->specified, sev);
            type->logs[sev].used = 0;
        }
    }

    /* Walk over the contents of the config node. */
    for (it = set_first(&conf.root->contents); it; it = set_next(it)) {
        child = set_node_data(it);

        /* Make sure it has an update hook. */
        if (!child->hook)
            child->hook = log_rescan_type;

        /* Figure out log type and severity set. */
        if (log_parse_type_sevset(&type, &sevset, child->name) || !type)
            continue;

        /* For each specified severity, attach the specified destinations. */
        for (sev = 0; sev < LOG_NUM_SEVERITIES; ++sev) {
            if (BITSET_GET(sevset, sev)) {
                log_attach_destinations(type, sev, child);
                BITSET_SET(type->specified, sev);
            }
        }
    }

    /* For each type, attach the default destination to unspecified
     * severities of LOG_WARNING and above. */
    for (it = set_first(&log_types); it; it = set_next(it)) {
        type = set_node_data(it);
        if (!type->default_target)
            continue;
        for (sev = LOG_WARNING; sev < LOG_NUM_SEVERITIES; ++sev) {
            if (BITSET_GET(type->specified, sev))
                continue;
            log_message(log_core, LOG_INFO, "Attaching %s to %s.%s.", type->default_target, type->name, log_severity_names[sev]);
            log_destination_vector_append(&type->logs[sev], log_destination_open(type->default_target));
        }
    }

    /* Close any still-unreferenced destinations. */
    for (it = set_first(&log_destinations); it; it = next) {
        next = set_next(it);
        dest = set_node_data(it);
        if (dest->refcnt < 0) {
            log_message(log_core, LOG_INFO, "Releasing unreferenced log destination %s after config rescan.", dest->name);
            set_remove(&log_destinations, dest, 0);
        }
    }
}

/** Handle updates of a configuration node inside the log section. */
static CONF_UPDATE_HOOK(log_rescan_type)
{
    /* Any particular log type/severity pair may be specified in more
     * than one entry, so it is not worth it to update the destination
     * list here.  We do that all log_rescan_conf().
     */
    log_rescan_conf(&node_->parent->base);
}

static void log_init(void)
{
    reg_exit_func(log_cleanup);
    log_destinations.compare = set_compare_charp;
    log_destinations.cleanup = log_destination_cleanup;
    log_vtables.compare = set_compare_charp;
    log_types.compare = set_compare_charp;
    log_types.cleanup = log_type_cleanup;
    log_destination_vtable_register(&log_file_vtable);
    log_core = log_type_register("core", NULL);
    log_default = log_type_register("*", NULL);
    conf.root = conf_register_object(NULL, "logs");
    conf.verbose_timestamp = conf_register_string(conf.root, CONF_STRING_BOOLEAN, "verbose_timestamp", "true");
    conf.root->base.hook = log_rescan_conf;
    log_rescan_conf(&conf.root->base);
}
