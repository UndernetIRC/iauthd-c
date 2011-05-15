/* config.c - configuration file reader
 *
 * Copyright 2004-2005, 2011 Michael Poole <mdpoole@troilus.org>
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

#include <setjmp.h>

#ifdef HAVE_SYS_STAT_H
# include <sys/stat.h>
#endif

#define PARSE_PREMATURE_EOF      -1
#define PARSE_EXPECTED_STRING    -2
#define PARSE_EXPECTED_COMMA     -3
#define PARSE_EXPECTED_SEMICOLON -4

static struct conf_node_object conf_root;
static struct log_type *conf_log;
static const char *conf_string_subtype_names[] = {
    "string",
    "boolean",
    "integer",
    "float",
    "interval",
    "volume",
    "IP address",
    NULL
};

struct conf_parse {
    struct conf_node_object root;
    jmp_buf env;
    const char *data;
    const char *curr;
    const char *line_start;
    int line_num;
};

static void config_init(void);

static int conf_object_cmp(const void *a_, const void *b_)
{
    const struct conf_node_base *a = a_;
    const struct conf_node_base *b = b_;
    int res = strcasecmp(a->name, b->name);
    if (res)
        return res;
    return a->type - b->type;
}

static void conf_object_cleanup(void *base_)
{
    struct conf_node_base *base = base_;
    switch (base->type) {
    case CONF_STRING:
        xfree(ENCLOSING_STRUCT(base, struct conf_node_string, base)->value);
        break;
    case CONF_INADDR: {
        struct conf_node_inaddr *node;
        node = ENCLOSING_STRUCT(base, struct conf_node_inaddr, base);
        xfree(node->hostname);
        xfree(node->service);
        sar_abort(node->req);
        sar_free(node->addr);
        break;
    }
    case CONF_STRING_LIST: {
        struct conf_node_string_list *node;
        node = ENCLOSING_STRUCT(base, struct conf_node_string_list, base);
        string_vector_clear_int(&node->value);
        string_vector_clear_int(&node->def_value);
        break;
    }
    case CONF_OBJECT:
        set_clear(&ENCLOSING_STRUCT(base, struct conf_node_object, base)->contents);
        break;
    }
    xfree(base->name);
}

static void *conf_register_node(struct conf_node_object *parent, const char *name, enum conf_node_type type, size_t size)
{
    struct set_node *snode;
    struct conf_node_base *cnode;
    struct conf_node_base *existing;

    if (!parent)
        parent = &conf_root;
    assert(size >= sizeof(*cnode));
    snode = set_node_alloc(size);
    cnode = set_node_data(snode);
    cnode->name = xstrdup(name);
    cnode->type = type;
    existing = set_find(&parent->contents, cnode);
    if (existing) {
        xfree(cnode->name);
        xfree(snode);
        cnode = existing;
        snode = set_node(cnode);
    } else {
        cnode->parent = parent;
        set_insert(&parent->contents, snode);
    }
    cnode->specified = 1;
    return cnode;
}

int conf_parse_boolean(const char *value, int *success)
{
    int result = 0;
    int valid = 1;

    if (!strcmp(value, "0") || !strcmp(value, "false") || !strcmp(value, "off") || !strcmp(value, "disabled") || !strcmp(value, "no")) {
        /* Do nothing; result is already 0. */
    } else if (!strcmp(value, "1") || !strcmp(value, "true") || !strcmp(value, "on") || !strcmp(value, "enabled") || !strcmp(value, "yes")) {
        result = 1;
    } else {
        valid = 0;
    }

    if (success)
        *success = valid;
    return result;
}

int conf_parse_integer(const char *value, int *success)
{
    char *eov;
    unsigned long ul;

    ul = strtoul(value, &eov, 0);
    if (success)
        *success = !*eov;
    return *eov ? 0 : ul;
}

double conf_parse_float(const char *value, int *success)
{
    char *eov;
    double d;

    d = strtod(value, &eov);
    if (success)
        *success = !*eov;
    return *eov ? 0 : d;
}

unsigned int conf_parse_interval(const char *value, int *success)
{
    const char *pos = value;
    unsigned int total = 0;
    unsigned int partial = 0;
    unsigned int seen_colon = 0;

    while (*pos) switch (*pos++) {
    case '0': case '1': case '2': case '3': case '4':
    case '5': case '6': case '7': case '8': case '9':
        partial = partial * 10 + pos[-1] - '0';
        break;
    case 'd':
        total += partial * 24 * 60 * 60;
        partial = 0;
        break;
    case 'h':
        total += partial * 60 * 60;
        partial = 0;
        break;
    case 'm':
        total += partial * 60;
        partial = 0;
        break;
    case 's':
        total += partial;
        partial = 0;
        break;
    case 'y':
        total += partial * 365 * 24 * 60 * 60;
        partial = 0;
        break;
    case ':':
        switch (seen_colon++) {
        case 0: total += partial * 60 * 60; break;
        case 1: total += partial * 60; break;
        default: goto out;
        }
        partial = 0;
        break;
    default:
        break;
    }
out:
    if (success)
        *success = !*pos;
    return total + partial;
}

unsigned int conf_parse_volume(const char *value, int *success)
{
    const char *pos = value;
    unsigned int total = 0;
    unsigned int partial = 0;

    while (*pos) switch (*pos++) {
    case '0': case '1': case '2': case '3': case '4':
    case '5': case '6': case '7': case '8': case '9':
        partial = partial * 10 + pos[-1] - '0';
        break;
    case 'B': case 'b':
        total += partial;
        partial = 0;
        break;
    case 'G': case 'g':
        total += partial << 30;
        partial = 0;
        break;
    case 'K': case 'k':
        total += partial << 10;
        partial = 0;
        break;
    case 'M': case 'm':
        total += partial << 20;
        partial = 0;
        break;
    }
    if (success)
        *success = !*pos;
    return total + partial;
}

static void conf_parse_string_value(struct conf_node_string *cnode)
{
    union conf_node_string_value newval;
    char *orig_value;
    int success;
    int res;

    orig_value = cnode->value;
    if (!cnode->value)
        cnode->value = xstrdup(cnode->def_value);
    if (!cnode->value) {
        memset(&cnode->parsed, 0, sizeof(cnode->parsed));
        if (orig_value && cnode->base.hook)
            cnode->base.hook(&cnode->base);
        goto out;
    }
    memset(&newval, 0, sizeof(newval));

    switch (cnode->subtype) {
    default:
    case CONF_STRING_PLAIN:
        success = 1;
        /* String copies are a bit tricky. */
        if (cnode->value)
            res = !cnode->parsed.p_string || strcmp(cnode->value, cnode->parsed.p_string);
        else
            res = cnode->parsed.p_string != NULL;
        cnode->parsed.p_string = cnode->value;
        if (res && cnode->base.hook)
            cnode->base.hook(&cnode->base);
        goto out;

    case CONF_STRING_BOOLEAN:
        newval.p_boolean = conf_parse_boolean(cnode->value, &success);
        break;

    case CONF_STRING_INTEGER:
        newval.p_integer = conf_parse_integer(cnode->value, &success);
        break;

    case CONF_STRING_FLOAT:
        newval.p_double = conf_parse_float(cnode->value, &success);
        break;

    case CONF_STRING_INTERVAL:
        newval.p_interval = conf_parse_interval(cnode->value, &success);
        break;

    case CONF_STRING_VOLUME:
        newval.p_volume = conf_parse_volume(cnode->value, &success);
        break;
    }

    if (!success)
        log_message(conf_log, LOG_WARNING, "Unable to parse '%s' as %s.", cnode->value, conf_string_subtype_names[cnode->subtype]);
    else if (memcmp(&cnode->parsed, &newval, sizeof(newval))) {
        memcpy(&cnode->parsed, &newval, sizeof(newval));
        if (cnode->base.hook)
            cnode->base.hook(&cnode->base);
    }
out:
    if (orig_value != cnode->value)
        xfree(orig_value);
}

struct conf_node_string *conf_register_string(struct conf_node_object *parent, enum conf_node_string_subtype subtype, const char *name, const char *def_value)
{
    struct conf_node_string *cnode;

    cnode = conf_register_node(parent, name, CONF_STRING, sizeof(*cnode));
    cnode->subtype = subtype;
    cnode->def_value = def_value;
    conf_parse_string_value(cnode);
    return cnode;
}

static void conf_inaddr_resolved(void *ctx, struct addrinfo *res, enum sar_errcode errcode)
{
    struct conf_node_inaddr *node = ctx;

    if (errcode != SAI_SUCCESS)
        log_message(conf_log, LOG_ERROR, "Error resolving service [%s]:%s: %s", node->hostname, node->service, sar_strerror(errcode));
    else if (res) {
        node->addr = res;
        node->state = CA_VALID;
    } else {
        node->addr = NULL;
        node->state = CA_FAILED;
    }
}

enum conf_addrinfo_state conf_inaddr_validate(struct conf_node_inaddr *node)
{
    if (!node)
        return CA_UNKNOWN;
    else if (node->state != CA_UNKNOWN)
        return node->state;
    node->state = CA_PENDING;
    node->req = sar_getaddr(node->hostname, node->service, NULL, conf_inaddr_resolved, node);
    return node->state; /* may no longer be pending */
}

struct conf_node_inaddr *conf_register_inaddr(struct conf_node_object *parent, const char *name, const char *hostname, const char *service)
{
    struct conf_node_inaddr *cnode;

    cnode = conf_register_node(parent, name, CONF_INADDR, sizeof(*cnode));
    cnode->def_hostname = hostname;
    cnode->def_service = service;
    cnode->state = CA_UNKNOWN;
    return cnode;
}

struct conf_node_string_list *conf_register_string_list(struct conf_node_object *parent, const char *name, ...)
{
    struct conf_node_string_list *cnode;
    const char *arg;
    va_list args;

    cnode = conf_register_node(parent, name, CONF_STRING_LIST, sizeof(*cnode));
    string_vector_clear_int(&cnode->def_value);

    va_start(args, name);
    while ((arg = va_arg(args, const char *)) != NULL)
        string_vector_append(&cnode->def_value, xstrdup(arg));
    va_end(args);

    if (!cnode->value.size)
        string_vector_copy(&cnode->value, &cnode->def_value);
    return cnode;
}

struct conf_node_string_list *conf_register_string_list_sv(struct conf_node_object *parent, const char *name, const struct string_vector *sv)
{
    struct conf_node_string_list *cnode;

    cnode = conf_register_node(parent, name, CONF_STRING_LIST, sizeof(*cnode));
    string_vector_clear_int(&cnode->def_value);
    string_vector_copy(&cnode->def_value, sv);
    if (!cnode->value.size)
        string_vector_copy(&cnode->value, &cnode->def_value);
    return cnode;
}

struct conf_node_object *conf_register_object(struct conf_node_object *parent, const char *name)
{
    struct conf_node_object *cnode;

    if (!conf_log)
        config_init();
    cnode = conf_register_node(parent, name, CONF_OBJECT, sizeof(*cnode));
    cnode->contents.compare = conf_object_cmp;
    cnode->contents.cleanup = conf_object_cleanup;
    return cnode;
}

static char *conf_read_file(struct conf_parse *parse, const char *filename)
{
    struct stat sbuf;
    FILE *file;
    char *data;
    size_t nbr;
    int res;
    int fd;

    file = fopen(filename, "r");
    if (!file)
        longjmp(parse->env, errno);

    fd = fileno(file);
    if (fd < 0) {
        res = errno;
        fclose(file);
        longjmp(parse->env, res);
    }

    res = fstat(fd, &sbuf);
    if (res < 0) {
        res = errno;
        fclose(file);
        longjmp(parse->env, res);
    }

    data = xmalloc(sbuf.st_size + 1);
    nbr = fread(data, sbuf.st_size, 1, file);
    if (nbr < 1) {
        res = errno;
        xfree(data);
        fclose(file);
        longjmp(parse->env, res);
    }

    data[sbuf.st_size] = '\0';
    fclose(file);
    parse->line_num = 1;
    return data;
}

static int conf_parse_whitespace(struct conf_parse *parse)
{
    while (*parse->curr) {
        int c = *parse->curr++, d;
        if (c == '\n') {
            parse->line_start = parse->curr;
            parse->line_num++;
            continue;
        }
        if (isspace(c))
            continue;
        if (c != '/')
            return c;
        d = *parse->curr++;
        if (d == '*') {
            while (1) {
                do {
                    c = *parse->curr++;
                    if (c == '\n') {
                        parse->line_start = parse->curr;
                        parse->line_num++;
                        continue;
                    }
                } while (c != '\0' && c != '*');
                if (c == '\0')
                    return c;
                c = *parse->curr++;
                if (c == '\0' || c == '/')
                    break;
                if (c == '\n') {
                    parse->line_start = parse->curr;
                    parse->line_num++;
                    continue;
                }
            }
        } else if (d == '/') {
            do {
                c = *parse->curr++;
            } while (c != '\0' && c != '\n');
            if (c == '\n') {
                parse->line_start = parse->curr;
                parse->line_num++;
                continue;
            }
        } else {
            parse->curr--;
            return c;
        }
    }
    return '\0';
}

static char *conf_parse_string(struct conf_parse *parse)
{
    struct char_vector sbuf;
    const char *start;
    const char *end;
    int ch;

    ch = conf_parse_whitespace(parse);
    if (ch == '\0')
        return NULL;
    start = parse->curr - 1;
    memset(&sbuf, 0, sizeof(sbuf));
    if (ch == '"') {
        /* Scan quoted string. */
        for (end = start + 1;
             *end != '\0' && *end != '"';
             ++end)
            if (*end == '\\')
                end++;
        if (*end == '\0')
            longjmp(parse->env, PARSE_PREMATURE_EOF);
        /* Allocate buffer. */
        sbuf.size = end + 1 - start;
        sbuf.used = 0;
        sbuf.vec = xmalloc(sbuf.size);
        /* Populate string. */
        for (end = start + 1;
             *end != '"';
             ++end) {
            if (*end == '\\') {
                switch (end[1]) {
                case 'a':
                    sbuf.vec[sbuf.used++] = '\a';
                    break;
                case 'b':
                    sbuf.vec[sbuf.used++] = '\b';
                    break;
                case 'f':
                    sbuf.vec[sbuf.used++] = '\f';
                    break;
                case 'n':
                    sbuf.vec[sbuf.used++] = '\n';
                    break;
                case 'r':
                    sbuf.vec[sbuf.used++] = '\r';
                    break;
                case 't':
                    sbuf.vec[sbuf.used++] = '\t';
                    break;
                case 'v':
                    sbuf.vec[sbuf.used++] = '\v';
                    break;
                case 'x':
                    if (end[2] == '\0') {
                        /* do nothing */
                    } else if (end[3] == '\0') {
                        end++;
                    } else {
                        sbuf.vec[sbuf.used++] = (ct_xdigit_val(end[2]) << 4)
                            || ct_xdigit_val(end[3]);
                        end += 2;
                    }
                    break;
                default:
                    sbuf.vec[sbuf.used++] = end[1];
                    break;
                }
                end++;
            } else {
                sbuf.vec[sbuf.used++] = *end;
            }
        }
        end++;
    } else if (ct_istoken(ch)) {
        /* Scan bareword and allocate buffer. */
        for (end = start + 1; ct_istoken(*end); ++end) ;
        sbuf.size = end + 1 - start;
        sbuf.used = end - start;
        sbuf.vec = xmalloc(sbuf.size);
        memcpy(sbuf.vec, start, sbuf.used);
    } else
        longjmp(parse->env, PARSE_EXPECTED_STRING);
    parse->curr = end;
    char_vector_append(&sbuf, '\0');
    return sbuf.vec;
}

static void *conf_parse_get_child(struct conf_node_object *parent, char *name, enum conf_node_type type, size_t total)
{
    struct conf_node_base *base;
    struct set_node *snode;
    struct set_node *snode2;

    assert(total >= sizeof(*base));
    snode = set_node_alloc(total);
    base = set_node_data(snode);
    base->name = name;
    base->parent = parent;
    base->type = type;
    snode2 = set_find(&parent->contents, base);
    if (snode2) {
        xfree(snode);
        xfree(name);
        base = set_node_data(snode2);
    } else {
        set_insert(&parent->contents, snode);
    }
    base->present = 1;
    return base;
}

static void conf_set_string_list_value(struct conf_node_string_list *node, const struct string_vector *new_value)
{
    unsigned int differ;
    unsigned int ii;

    for (differ = 0; (differ < node->value.used) && (differ < new_value->used); ++differ)
        if (strcmp(node->value.vec[differ], new_value->vec[differ]))
            break;
    if ((differ == new_value->used) && (differ == node->value.used))
        return;
    for (ii = differ; ii < node->value.used; ++ii)
        xfree(node->value.vec[ii]);
    node->value.used = differ;
    for (ii = differ; ii < new_value->used; ++ii)
        string_vector_append(&node->value, xstrdup(new_value->vec[ii]));
    if (node->base.hook)
        node->base.hook(&node->base);
}

static void conf_parse_entry(struct conf_parse *parse, struct conf_node_object *parent)
{
    struct conf_node_base *base;
    char *name;
    int ch;

    name = conf_parse_string(parse);
    ch = conf_parse_whitespace(parse);
    if (ch == '\0') {
        xfree(name);
        return;
    } else if (ch == '(') {
        struct conf_node_string_list *node;
        struct string_vector new_value;

        node = conf_parse_get_child(parent, name, CONF_STRING_LIST, sizeof(*node));
        memset(&new_value, 0, sizeof(new_value));
        while (1) {
            char *value;
            ch = conf_parse_whitespace(parse);
            if (ch == '\0')
                longjmp(parse->env, PARSE_PREMATURE_EOF);
            if (ch == ')')
                break;
            parse->curr--;
            value = conf_parse_string(parse);
            string_vector_append(&new_value, value);
            ch = conf_parse_whitespace(parse);
            if (ch == '\0')
                longjmp(parse->env, PARSE_PREMATURE_EOF);
            if (ch == ')')
                break;
            if (ch != ',')
                longjmp(parse->env, PARSE_EXPECTED_COMMA);
        }
        conf_set_string_list_value(node, &new_value);
        string_vector_clear_int(&new_value);
        base = &node->base;
    } else if (ch == '{') {
        struct conf_node_object *node;
        char ch;

        node = conf_parse_get_child(parent, name, CONF_OBJECT, sizeof(*node));
        node->contents.compare = conf_object_cmp;
        node->contents.cleanup = conf_object_cleanup;
        while (1) {
            ch = conf_parse_whitespace(parse);
            if (ch == '}')
                break;
            parse->curr--;
            conf_parse_entry(parse, node);
        }
        base = &node->base;
    } else {
        char *string;

        parse->curr--;
        string = conf_parse_string(parse);
        ch = conf_parse_whitespace(parse);
        if (ch == ';') {
            struct conf_node_string *node;

            parse->curr--;
            node = conf_parse_get_child(parent, name, CONF_STRING, sizeof(*node));
            xfree(node->value);
            node->value = string;
            base = &node->base;
        } else {
            struct conf_node_inaddr *node;
            char *service;

            parse->curr--;
            service = conf_parse_string(parse);
            node = conf_parse_get_child(parent, name, CONF_INADDR, sizeof(*node));
            xfree(node->hostname);
            xfree(node->service);
            node->hostname = string;
            node->service = service;
            base = &node->base;
        }
    }
    ch = conf_parse_whitespace(parse);
    if (ch != ';')
        longjmp(parse->env, PARSE_EXPECTED_SEMICOLON);
}

static int conf_replace_value(struct conf_node_base *target_, struct conf_node_base *source_)
{
    assert(target_ != NULL);
    if (source_ && (target_->type != source_->type)) {
        set_remove(&target_->parent->contents, target_, 0);
        return 1;
    }

    switch (target_->type) {
    case CONF_STRING: {
        struct conf_node_string *target;
        char *orig_value;

        target = ENCLOSING_STRUCT(target_, struct conf_node_string, base);
        orig_value = target->value;
        if (source_) {
            struct conf_node_string *source;

            source = ENCLOSING_STRUCT(source_, struct conf_node_string, base);
            target->value = source->value;
            source->value = NULL;
            conf_parse_string_value(target);
        } else {
            target->value = NULL;
            conf_parse_string_value(target);
        }
        xfree(orig_value);
        break;
    }

    case CONF_INADDR: {
        struct conf_node_inaddr *target;
        char *orig_hostname;
        char *orig_service;

        target = ENCLOSING_STRUCT(target_, struct conf_node_inaddr, base);
        orig_hostname = target->hostname;
        orig_service = target->service;
        if (source_) {
            struct conf_node_inaddr *source;

            source = ENCLOSING_STRUCT(source_, struct conf_node_inaddr, base);
            target->hostname = source->hostname;
            target->service = source->service;
        } else {
            target->hostname = NULL;
            target->service = NULL;
        }
        if (!target->hostname)
            target->hostname = xstrdup(target->def_hostname);
        if (!target->service)
            target->service = xstrdup(target->def_service);
        /* If hostname or service changed, invalidate node and call hook. */
        if (!target->hostname != !orig_hostname
            || (target->hostname && orig_hostname
                && strcasecmp(target->hostname, orig_hostname))
            || !target->service != !orig_service
            || (target->service && orig_service
                && strcasecmp(target->service, orig_service))) {
            target->state = CA_UNKNOWN;
            if (target_->hook)
                target_->hook(target_);
        }
        xfree(orig_hostname);
        xfree(orig_service);
        break;
    }

    case CONF_STRING_LIST: {
        struct conf_node_string_list *target;

        target = ENCLOSING_STRUCT(target_, struct conf_node_string_list, base);
        conf_set_string_list_value(target,
                                   source_
                                   ? &ENCLOSING_STRUCT(source_, struct conf_node_string_list, base)->value
                                   : &target->def_value);
        break;
    }

    case CONF_OBJECT: {
        struct conf_node_object *target;
        struct set_node *tnode;
        struct set_node *next;
        int modified = 0;

        target = ENCLOSING_STRUCT(target_, struct conf_node_object, base);
        tnode = set_first(&target->contents);
        if (source_) {
            struct conf_node_object *source;
            struct set_node *snode;

            source = ENCLOSING_STRUCT(source_, struct conf_node_object, base);
            snode = set_first(&source->contents);
            while (tnode || snode) {
                int res;

                if (tnode && snode)
                    res = conf_object_cmp(set_node_data(tnode), set_node_data(snode));
                else if (tnode)
                    res = -1;
                else
                    res = 1;

                if (res > 0) {
                    /* Not currently present: splice it over.  */
                    next = set_next(snode);
                    set_remove(&source->contents, set_node_data(snode), 1);
                    ((struct conf_node_base*)set_node_data(snode))->parent = target;
                    set_insert(&target->contents, snode);
                    snode = next;
                    modified = 1;
                } else if (res < 0) {
                    /* No longer present: revert to default value. */
                    if (conf_replace_value(set_node_data(tnode), NULL))
                        modified = 1;
                    tnode = set_next(tnode);
                } else {
                    /* Present in both: update value. */
                    conf_replace_value(set_node_data(tnode), set_node_data(snode));
                    tnode = set_next(tnode);
                    snode = set_next(snode);
                }
            }
        } else if (target_->present) {
            for (; tnode; tnode = next) {
                next = set_next(tnode);
                if (conf_replace_value(set_node_data(tnode), NULL))
                    modified = 1;
            }
        }

        if (modified && target_->hook)
            target_->hook(target_);
        break;
    }
    }

    target_->present = source_ != NULL;
    if (!target_->present && !target_->specified && target_->parent) {
        set_remove(&target_->parent->contents, target_, 0);
        return 1;
    }
    return 0;
}

char *conf_lookup(const char *node_path, struct conf_node_base **found)
{
    struct conf_parse parse;
    struct char_vector cv;
    struct conf_node_base search;
    struct conf_node_base *child;
    struct conf_node_object *obj;
    struct set_node *node;
    int res;

    *found = NULL;
    if (!conf_log || !node_path)
        return NULL;
    memset(&cv, 0, sizeof(cv));
    parse.data = parse.curr = parse.line_start = node_path;
    res = setjmp(parse.env);
    switch (res) {
    case 0:
        /* Walk through path until we get to the parent object. */
        for (obj = &conf_root, child = NULL, search.type = CONF_OBJECT;
             (search.name = conf_parse_string(&parse)) && (*parse.curr++ == '/');
             obj = ENCLOSING_STRUCT(child, struct conf_node_object, base)) {
            child = set_find(&obj->contents, &search);
            xfree(search.name);
            if (!child) {
                char_vector_append_printf(&cv, "No such configuration object %.*s", (int)(parse.curr - parse.data), parse.data);
                return cv.vec;
            }
        }
        if (!search.name) {
            char_vector_append_printf(&cv, "No such configuration object %.*s", (int)(parse.curr - parse.data), parse.data);
            break;
        }
        search.type = 0;
        node = set_lower(&obj->contents, &search);
        *found = node ? set_node_data(node) : NULL;
        xfree(search.name);
        break;
    case PARSE_PREMATURE_EOF:
        char_vector_append_printf(&cv, "Premature end of string.");
        break;
    case PARSE_EXPECTED_STRING:
        char_vector_append_printf(&cv, "Expected a string or bareword token.");
        break;
    case PARSE_EXPECTED_COMMA:
        char_vector_append_printf(&cv, "Expected a comma or closing parenthesis.");
        break;
    case PARSE_EXPECTED_SEMICOLON:
        char_vector_append_printf(&cv, "Expected a semicolon.");
        break;
    default:
        char_vector_append_printf(&cv, "Unhandled parse error: %s", strerror(res));
        break;
    }
    return cv.vec;
}

char *conf_revert_node(const char *node_path)
{
    struct conf_node_base *cnext;
    struct conf_node_base *base;
    char *msg;

    msg = conf_lookup(node_path, &base);
    if (msg)
        return msg;
    if (!base) {
        struct char_vector cv;
        char_vector_init(&cv, 40);
        char_vector_append_printf(&cv, "No such configuration item %s", node_path);
        return cv.vec;
    }

    for (; base; base = cnext) {
        struct set_node *nnext;

        nnext = set_next(set_node(base));
        cnext = set_node_data(nnext);
        if (!nnext || strcasecmp(base->name, cnext->name))
            cnext = NULL;
        if (base->present)
            conf_replace_value(base, NULL);
    }

    return NULL;
}

char *conf_update_node(const char *node_path_and_value)
{
    struct conf_parse parse;
    struct char_vector cv;
    struct conf_node_base search;
    struct conf_node_base *child;
    struct conf_node_base *new_child;
    struct conf_node_object *obj;
    const char *start;
    int res;

    if (!conf_log || !node_path_and_value)
        return NULL;
    memset(&cv, 0, sizeof(cv));
    memset(&parse, 0, sizeof(parse));
    parse.root.base.type = CONF_OBJECT;
    parse.root.base.present = 1;
    parse.root.contents.compare = conf_object_cmp;
    parse.root.contents.cleanup = conf_object_cleanup;
    parse.data = parse.curr = parse.line_start = node_path_and_value;
    res = setjmp(parse.env);
    switch (res) {
    case 0:
        /* Walk through path until we get to the parent object. */
        for (obj = &conf_root, child = NULL, search.type = CONF_OBJECT;;) {
            start = parse.curr;
            search.name = conf_parse_string(&parse);
            if (!search.name || *parse.curr++ != '/')
                break;
            child = set_find(&obj->contents, &search);
            xfree(search.name);
            if (!child) {
                char_vector_append_printf(&cv, "No such configuration object %.*s", (int)(parse.curr - parse.data), parse.data);
                return cv.vec;
            }
            obj = ENCLOSING_STRUCT(child, struct conf_node_object, base);
        }
        if (!search.name) {
            char_vector_append_printf(&cv, "No such configuration object %.*s", (int)(parse.curr - parse.data), parse.data);
            return cv.vec;
        }
        xfree(search.name);

        /* Parse the child object. */
        parse.curr = start;
        conf_parse_entry(&parse, &parse.root);
        assert(set_size(&parse.root.contents) == 1);
        new_child = set_node_data(set_first(&parse.root.contents));
        child = set_find(&obj->contents, new_child);
        if (child) {
            conf_replace_value(child, new_child);
        } else {
            set_remove(&parse.root.contents, new_child, 1);
            new_child->parent = obj;
            set_insert(&obj->contents, set_node(new_child));
            if (obj->base.hook)
                obj->base.hook(&obj->base);
        }
        set_clear(&parse.root.contents);
        break;
    case PARSE_PREMATURE_EOF:
        char_vector_append_printf(&cv, "Premature end of string.");
        break;
    case PARSE_EXPECTED_STRING:
        char_vector_append_printf(&cv, "Expected a string or bareword token.");
        break;
    case PARSE_EXPECTED_COMMA:
        char_vector_append_printf(&cv, "Expected a comma or closing parenthesis.");
        break;
    case PARSE_EXPECTED_SEMICOLON:
        char_vector_append_printf(&cv, "Expected a semicolon.");
        break;
    default:
        char_vector_append_printf(&cv, "Unhandled parse error: %s", strerror(res));
        break;
    }
    return cv.vec;
}

int conf_read(const char *filename)
{
    struct conf_parse parse;
    int res;

    if (!conf_log)
        config_init();
    memset(&parse, 0, sizeof(parse));
    parse.root.base.name = "";
    parse.root.base.type = CONF_OBJECT;
    parse.root.base.specified = 1;
    parse.root.base.present = 1;
    parse.root.contents.compare = conf_object_cmp;
    parse.root.contents.cleanup = conf_object_cleanup;
    res = setjmp(parse.env);
    switch (res) {
    case 0:
        parse.curr = parse.data = conf_read_file(&parse, filename);
        while (*parse.curr)
            conf_parse_entry(&parse, &parse.root);
        conf_replace_value(&conf_root.base, &parse.root.base);
        break;
    case PARSE_PREMATURE_EOF:
        log_message(conf_log, LOG_ERROR, "Premature end of file on line %d of %s.", parse.line_num, filename);
        break;
    case PARSE_EXPECTED_STRING:
        log_message(conf_log, LOG_ERROR, "Expected a string or bareword token on line %d of %s.", parse.line_num, filename);
        break;
    case PARSE_EXPECTED_COMMA:
        log_message(conf_log, LOG_ERROR, "Expected a comma or closing parenthesis on line %d of %s.", parse.line_num, filename);
        break;
    case PARSE_EXPECTED_SEMICOLON:
        log_message(conf_log, LOG_ERROR, "Expected a semicolon on line %d of %s.", parse.line_num, filename);
        break;
    default:
        if (!parse.line_num)
            log_message(conf_log, LOG_ERROR, "Unhandled error opening %s: %s", filename, strerror(res));
        else
            log_message(conf_log, LOG_ERROR, "Unhandled error on line %d of %s: %s", parse.line_num, filename, strerror(res));
        break;
    }
    set_clear(&parse.root.contents);
    xfree((void*)parse.data);
    return res;
}

struct conf_node_object *conf_get_root(void)
{
    if (!conf_log)
        config_init();
    return &conf_root;
}

void *conf_get_child(struct conf_node_object *parent, const char *name, enum conf_node_type type)
{
    struct conf_node_base idx;
    struct conf_node_base *res;

    assert(parent != NULL);
    memset(&idx, 0, sizeof(idx));
    idx.name = (char*)name;
    idx.type = type;
    res = set_find(&parent->contents, &idx);
    return (res && res->type == type) ? res : NULL;
}

static void config_cleanup(void)
{
    set_clear(&conf_root.contents);
}

static void config_init(void)
{
    reg_exit_func(config_cleanup);
    conf_log = log_type_register("config", NULL);

    /* Initialize root object. */
    conf_root.base.name = "";
    conf_root.base.parent = NULL;
    conf_root.base.type = CONF_OBJECT;
    conf_root.base.specified = 1;
    conf_root.base.present = 0;
    conf_root.contents.compare = conf_object_cmp;
    conf_root.contents.cleanup = conf_object_cleanup;
}
