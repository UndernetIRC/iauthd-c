/* config.h - configuration file reader
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

#if !defined(CONFIG_H_9a26bce3_4913_4be4_8784_6164fb8b2baa)

/** Multiple-inclusion guard for "src/config.h". */
#define CONFIG_H_9a26bce3_4913_4be4_8784_6164fb8b2baa

enum conf_node_type {
    CONF_STRING,
    CONF_INADDR,
    CONF_STRING_LIST,
    CONF_OBJECT
};

struct conf_node_base;

#define CONF_UPDATE_HOOK(NAME) void NAME(struct conf_node_base *node_)
typedef CONF_UPDATE_HOOK(conf_update_hook_f);

struct conf_node_base {
    char *name;
    struct conf_node_object *parent;
    conf_update_hook_f *hook;
    enum conf_node_type type : 2;
    unsigned int specified : 1;
    unsigned int present : 1;
};

enum conf_node_string_subtype {
    CONF_STRING_PLAIN,
    CONF_STRING_BOOLEAN,
    CONF_STRING_INTEGER,
    CONF_STRING_FLOAT,
    CONF_STRING_INTERVAL,
    CONF_STRING_VOLUME
};

union conf_node_string_value {
    const char *p_string;
    int p_boolean;
    int p_integer;
    double p_double;
    unsigned int p_interval;
    unsigned int p_volume;
};

struct conf_node_string {
    struct conf_node_base base;
    const char *def_value;
    char *value;
    enum conf_node_string_subtype subtype;
    union conf_node_string_value parsed;
};

enum conf_addrinfo_state {
    CA_UNKNOWN,
    CA_PENDING,
    CA_FAILED,
    CA_VALID
};

struct conf_node_inaddr {
    struct conf_node_base base;
    const char *def_hostname;
    const char *def_service;
    char *hostname;
    char *service;
    struct sar_request *req;
    struct addrinfo *addr;
    enum conf_addrinfo_state state;
};

struct conf_node_string_list {
    struct conf_node_base base;
    struct string_vector def_value;
    struct string_vector value;
};

struct conf_node_object {
    struct conf_node_base base;
    struct set contents;
};

/* Interface to configuration consumers */
struct conf_node_string *conf_register_string(struct conf_node_object *parent, enum conf_node_string_subtype subtype, const char *name, const char *def_value);
struct conf_node_inaddr *conf_register_inaddr(struct conf_node_object *parent, const char *name, const char *def_hostname, const char *def_service);
struct conf_node_string_list *conf_register_string_list(struct conf_node_object *parent, const char *name, ...);
struct conf_node_string_list *conf_register_string_list_sv(struct conf_node_object *parent, const char *name, const struct string_vector *sv);
struct conf_node_object *conf_register_object(struct conf_node_object *parent, const char *name);

/** Return the root of the configuration hierarchy. */
struct conf_node_object *conf_get_root(void);
/** Returns a pointer to a struct conf_node_<something> of type determined by \a type. */
void *conf_get_child(struct conf_node_object *parent, const char *name, enum conf_node_type type);
/** Find the first configuation node named by the config path. */
char *conf_lookup(const char *node_path, struct conf_node_base **found);
/** Revert a node in the configuration (and, if an object, all children) to the default. */
char *conf_revert_node(const char *node_path);
/** Replace a node with a new value. */
char *conf_update_node(const char *node_path_and_value);
/** If a conf_node_inaddr is not already valid, start its DNS lookup(s). */
enum conf_addrinfo_state conf_inaddr_validate(struct conf_node_inaddr *node);

/* Interface to reuse the string parsers */
int conf_parse_boolean(const char *value, int *success);
int conf_parse_integer(const char *value, int *success);
double conf_parse_float(const char *value, int *success);
unsigned int conf_parse_interval(const char *value, int *success);
unsigned int conf_parse_volume(const char *value, int *success);

/* Interface to main flow of control */
int conf_read(const char *filename);

#endif /* !defined(CONFIG_H_9a26bce3_4913_4be4_8784_6164fb8b2baa) */
