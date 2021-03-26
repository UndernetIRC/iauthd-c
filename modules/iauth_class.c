/* iauth_class.c - IAuth module for assigning users to connection classes
 *
 * Copyright 2015 Michael Poole <mdpoole@troilus.org>
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

/* Intended use cases:
 *
 * Some other module performs iauth-specific functions, then this
 * module decides whether the user should be assigned a particular
 * connection class (cclass).  If no rule matches, this module does
 * nothing to the client -- another module could assign a class, or
 * if no iauth module does that, the ircd will try to assign one.
 *
 * We do not want to duplicate functionality that is already in the
 * ircd, or could be more easily done there.  In particular, few
 * clients support multiple (or interactive) PASS commands, and this
 * makes it hard to use both LoC and PASS as a connection
 * authorization mechanism.  The most likely application for this
 * module is on a restricted server, where LoC-assigned account name
 * (possibly with other factors) is used to select a cclass.
 *
 * The config section for iauth_class contains the rules, one object
 * node per rule.  The following elements may be present in a rule:
 * - "class" (string, default: the object name) names the cclass that
 *   matching clients should be assigned to
 * - "account" (string) must match the assigned account stamp
 * - "address" (string) must match the client's IP address; this
 *   supports netmasks by using syntax like 127.0.0.0/8.
 * - "username" (string) must match the client's trusted username
 * - "hostname" (string) must match the client's resolved hostname
 * - "xreply_ok" (string) must match the name of a service that sends
 *   an XREPLY OK for the client
 * - "trust_username" (boolean) is whether to trust the client's claimed
 *   username, even if they are not running identd
 *
 * Rules are applied in alphabetic (case-insensitive) order of their
 * object names, stopping after the first rule that assigns a class.
 *
 * Further assumptions:
 * - The number of rules used to map clients to cclasses is small
 * enough, or dominated by common cases enough, for linear scan to be
 * reasonable.
 */

#include "modules/iauth.h"

struct iauth_class_rule {
    char *name;
    char *class;
    char *account;
    char *username;
    char *hostname;
    char *xreply_ok;
    irc_inaddr address;
    unsigned int address_bits;
    unsigned int assigned;
    int trust_username;
};

DECLARE_VECTOR(iauth_class_rules, struct iauth_class_rule);

static struct {
    struct conf_node_object *root;
    struct iauth_class_rules rules;
} conf;

static struct iauth_module iauth_class;
static struct log_type *iauth_class_log;
static struct variance iauth_class_assigned;
static struct variance iauth_class_not_assigned;
static unsigned int iauth_class_already_assigned;

#define IAUTH_RULE_FUNC(NAME) int NAME(         \
        struct iauth_class_rule *rule,          \
        UNUSED_ARG(unsigned int idx),           \
        struct iauth_request *req)
typedef IAUTH_RULE_FUNC(iauth_rule_f);

DEFINE_VECTOR(iauth_class_rules, struct iauth_class_rule);

static void iauth_class_free_rules(void)
{
    struct iauth_class_rule *rule;
    unsigned int ii;

    for (ii = 0; ii < conf.rules.used; ++ii) {
        rule = &conf.rules.vec[ii];
        xfree(rule->name);
        xfree(rule->class);
        xfree(rule->account);
        xfree(rule->username);
        xfree(rule->hostname);
        xfree(rule->xreply_ok);
    }

    xfree(conf.rules.vec);
}

CONF_UPDATE_HOOK(iauth_class_conf_changed)
{
    struct iauth_class_rules new_rules;
    struct iauth_class_rule *rule;
    struct conf_node_base *base;
    struct conf_node_object *obj;
    struct conf_node_string *str;
    struct set_node *it;
    unsigned int n_rules;
    unsigned int o_idx = 0;
    int res;

    /* Parse the new rules. */
    n_rules = set_size(&conf.root->contents);
    iauth_class_rules_init(&new_rules, n_rules);
    for (it = set_first(&conf.root->contents);
         it != NULL; it = set_next(it)) {
        /* Only process object config children. */
        base = set_node_data(it);
        if (base->type != CONF_OBJECT)
            continue;
        obj = set_node_data(it);

        /* Load the new rule. */
        rule = &new_rules.vec[new_rules.used];
        rule->name = xstrdup(obj->base.name);
        str = conf_get_child(obj, "class", CONF_STRING);
        if (str)
            rule->class = xstrdup(str->value);
        str = conf_get_child(obj, "account", CONF_STRING);
        if (str)
            rule->account = xstrdup(str->value);
        str = conf_get_child(obj, "address", CONF_STRING);
        if (str)
            irc_pton(&rule->address, &rule->address_bits, str->value, 0);
        str = conf_get_child(obj, "username", CONF_STRING);
        if (str)
            rule->username = xstrdup(str->value);
        str = conf_get_child(obj, "hostname", CONF_STRING);
        if (str)
            rule->hostname = xstrdup(str->value);
        str = conf_get_child(obj, "xreply_ok", CONF_STRING);
        if (str)
            rule->xreply_ok = xstrdup(str->value);
        str = conf_get_child(obj, "trust_username", CONF_STRING);
        if (str)
            rule->trust_username = conf_parse_boolean(str->value, 0);

        /* Increment the number of rules in the new set. */
        new_rules.used++;

        /* Inherit assigned user count from old version. */
        for (res = 1; o_idx < conf.rules.used; ++o_idx) {
            res = strcasecmp(conf.rules.vec[o_idx].name, rule->name);
            if (res >= 0)
                break;
        }
        if (res == 0)
            rule->assigned = conf.rules.vec[o_idx].assigned;
    }

    /* Release the memory used by the old rules. */
    iauth_class_free_rules();

    /* Adopt the new rules. */
    conf.rules = new_rules;
    (void)node_;
}

static void iauth_class_report_config(void)
{
    iauth_report_config(&iauth_class, "%u rules",
                        set_size(&conf.root->contents));
}

static int iauth_class_foreach_rule(iauth_rule_f func, struct iauth_request *req)
{
    unsigned int idx = 0;
    int res = 0;

    for (idx = 0; (idx < conf.rules.used) && (res == 0); ++idx)
        res = func(&conf.rules.vec[idx], idx, req);

    return res;
}

static IAUTH_RULE_FUNC(iauth_class_rule_stats)
{
    if (rule->class) {
        iauth_report_stats(&iauth_class, "%s (class %s): %u hits",
                           rule->name, rule->class, rule->assigned);
    } else {
        iauth_report_stats(&iauth_class, "%s: %u hits",
                           rule->name, rule->assigned);
    }

    return 0; (void)req;
}

static void iauth_class_report_stats(void)
{
    iauth_class_foreach_rule(iauth_class_rule_stats, NULL);

    iauth_report_stats(&iauth_class, "%u clients already had classes, %.0f assigned (in %g+/-%g sec), %.0f unassigned (in %g+/-%g sec)",
                       iauth_class_already_assigned,
                       iauth_class_assigned.n,
                       iauth_class_assigned.mean,
                       variance_stdev(&iauth_class_assigned, 0),
                       iauth_class_not_assigned.n,
                       iauth_class_not_assigned.mean,
                       variance_stdev(&iauth_class_not_assigned, 0));
}

static IAUTH_RULE_FUNC(iauth_class_rule_check)
{
    if (rule->account) {
        char acct[ACCOUNTLEN + 1];
        char *sep = strchr(req->account, ':');
        if (sep) {
            memcpy(acct, req->account, sep - req->account);
            acct[sep - req->account] = '\0';
            sep = acct;
        } else {
            sep = req->account;
        }
        if (fnmatch(rule->account, sep, 0))
            return 0;
    }

    if (rule->address_bits && !irc_check_mask(&req->remote_addr, &rule->address, rule->address_bits))
        return 0;

    if (rule->username && fnmatch(rule->username, req->auth_username, 0))
        return 0;

    if (rule->hostname && fnmatch(rule->hostname, req->hostname, 0))
        return 0;

    if (rule->xreply_ok && (iauth_xreply_ok(req, rule->xreply_ok) <= 0))
        return 0;

    log_message(iauth_class_log, LOG_DEBUG, "Applying rule %s to %d_%d",
        rule->name, req->client, req->serial);

    if (rule->trust_username && (req->auth_username[0] == '~')) {
        int ofs = (req->cli_username[0] == '~');
        iauth_trust_username(req, req->cli_username + ofs);
    }

    strlcpy(req->class, rule->class ? rule->class : rule->name, CLASSLEN);
    ++rule->assigned;
    return 1;
}

static void iauth_class_assign(struct iauth_request *req)
{
    struct timespec a, b;
    double duration;

    /* Early out if a class is already assigned. */
    if (req->class[0] != '\0') {
        ++iauth_class_already_assigned;
        return;
    }

    /* Try to assign to a class. */
    clock_gettime(CLOCK_MONOTONIC, &a);
    iauth_class_foreach_rule(iauth_class_rule_check, req);
    clock_gettime(CLOCK_MONOTONIC, &b);

    /* How long did it take? */
    if (b.tv_nsec < a.tv_nsec) {
        b.tv_sec  -= 1;
        b.tv_nsec += 1000000000;
    }
    duration = b.tv_sec - a.tv_sec + (b.tv_nsec - a.tv_nsec) / 1e9;

    /* Update statistics. */
    variance_tick((req->class[0] == '\0')
                  ? &iauth_class_not_assigned
                  : &iauth_class_assigned,
                  duration);
}

static struct iauth_module iauth_class = {
    .owner = NULL,
    .get_config = iauth_class_report_config,
    .get_stats = iauth_class_report_stats,
    .pre_registered = iauth_class_assign,
};

void module_constructor(const char name[])
{
    iauth_class.owner = name;
    iauth_class_log = log_type_register(name, NULL);
    module_depends("iauth_xquery", NULL);
    conf.root = conf_register_object(NULL, name);
    conf.root->base.hook = iauth_class_conf_changed;
    iauth_class_conf_changed(&conf.root->base);
    iauth_register_module(&iauth_class);
}

void module_destructor(void)
{
    iauth_unregister_module(&iauth_class);
    iauth_class_free_rules();
}
