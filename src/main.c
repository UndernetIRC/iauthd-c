/* main.c - Entry point for iauthd-c.
 *
 * Copyright 2011 Michael Poole <mdpoole@troilus.org>
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
#include <signal.h>

struct argument {
    char *long_arg;
    char short_arg;
    int (*handler)(const char *arg);
    unsigned int takes_arg : 1;
    const char *description;
};

static struct {
    struct conf_node_object *root;
    struct conf_node_string_list *modules;
    struct conf_node_string_list *library_path;
} conf;

static const struct argument args[];
static struct event sighup_evt;
static struct event sigusr1_evt;
static const char *config_filename = SYSCONFDIR "/iauthd-c.conf";
static const char *iauthd_executable;
static int verbose_debug;
static int early_exit;
static int no_chdir;
static int restart;
int clean_exit;

static int do_arg_help(UNUSED_ARG(const char *arg))
{
    const char *pname;
    unsigned int ii;

    pname = strrchr(iauthd_executable, '/');
    pname = pname ? pname + 1 : iauthd_executable;
    fprintf(stdout, PACKAGE_STRING ", revision %s\n", iauthd_version);
    fprintf(stdout, "%s [-?|-v|-k] [-f filename] [-d]\n", pname);
    for (ii = 0; args[ii].handler; ++ii) {
        if (args[ii].short_arg && args[ii].long_arg) {
            fprintf(stdout, "  -%c, --%-10s %s\n", args[ii].short_arg, args[ii].long_arg, args[ii].description);
        } else if (args[ii].long_arg) {
            fprintf(stdout, "  --%-14s %s\n", args[ii].long_arg, args[ii].description);
        } else if (args[ii].short_arg) {
            fprintf(stdout, "  -%c               %s\n", args[ii].short_arg, args[ii].description);
        }
    }
    call_exit_funcs();
    exit(EXIT_SUCCESS);
}

static int do_arg_version(UNUSED_ARG(const char *arg))
{
    fprintf(stdout, PACKAGE_STRING ", revision %s\n", iauthd_version);
    call_exit_funcs();
    exit(EXIT_SUCCESS);
}

static int do_arg_config(const char *arg)
{
    config_filename = arg;
    return 0;
}

static int do_arg_check_config(UNUSED_ARG(const char *arg))
{
    early_exit = 1;
    verbose_debug = 1;
    return 0;
}

static int do_arg_debug(UNUSED_ARG(const char *arg))
{
    verbose_debug = 1;
    return 0;
}

static int do_arg_no_chdir(UNUSED_ARG(const char *arg))
{
    no_chdir = 1;
    return 0;
}

static const struct argument args[] = {
    { "help", '?', do_arg_help, 0, "Show usage information" },
    { "version", 'v', do_arg_version, 0, "Show software version" },
    { "check-config", 'k', do_arg_check_config, 0, "Stop after checking configuration syntax" },
    { "config", 'f', do_arg_config, 1, "Use specific configuration file" },
    { "debug", 'd', do_arg_debug, 0, "Enable verbose debug output" },
    { "no-chdir", 'n', do_arg_no_chdir, 0, "Disable chdir(LOGDIR) at startup" },
    { NULL, '\0', NULL, 0, NULL }
};

static void parse_arguments(int argc, char *argv[])
{
    int res, arg, next_arg, ii, jj;
    size_t len;

    for (arg = 1; arg < argc; arg = next_arg) {
        /* Make sure it's a valid option. */
        if (argv[arg][0] != '-') {
            fprintf(stderr, "Unexpected bare argument '%s'.", argv[arg]);
            exit(EXIT_FAILURE);
        }
        next_arg = arg + 1;

        /* Is it a long option? */
        if (argv[arg][1] == '-') {
            for (jj = 0; args[jj].handler; ++jj) {
                const char *str;

                if (!args[jj].long_arg)
                    continue;
                len = strlen(args[jj].long_arg);
                if (strncmp(argv[arg]+2, args[jj].long_arg, len))
                    continue;
                if (argv[arg][2+len] != '\0' && argv[arg][2 + len] != '=')
                    continue;

                if (args[jj].takes_arg) {
                    if (argv[arg][2 + len] == '=')
                        str = argv[arg] + 3 + len;
                    else if (next_arg < argc)
                        str = argv[next_arg++];
                    else {
                        fprintf(stderr, "Missing parameter for argument '%s'.", argv[arg]);
                        exit(EXIT_FAILURE);
                    }
                } else {
                    if (argv[arg][2 + len] != '\0') {
                        fprintf(stderr, "Argument '%s' should not include a parameter.", argv[arg]);
                        exit(EXIT_FAILURE);
                    }
                    str = NULL;
                }
                res = args[jj].handler(str);
                if (res)
                    exit(EXIT_FAILURE);
                break;
            }
            if (!args[jj].handler) {
                fprintf(stderr, "Unrecognized long argument '%s'.", argv[arg]);
                exit(EXIT_FAILURE);
            }
        } else for (ii = 1; argv[arg][ii]; ++ii) {
            /* Otherwise iterate over each character in the option string. */
            for (jj = 0; args[jj].handler; ++jj) {
                const char *str;

                if (argv[arg][ii] != args[jj].short_arg)
                    continue;
                if (args[jj].takes_arg) {
                    if (next_arg >= argc) {
                        fprintf(stderr, "Missing parameter for argument '-%c'.", argv[arg][ii]);
                        exit(EXIT_FAILURE);
                    }
                    str = argv[next_arg++];
                } else
                    str = NULL;
                res = args[jj].handler(str);
                if (res)
                    exit(EXIT_FAILURE);
                break;
            }
            if (!args[jj].handler) {
                fprintf(stderr, "Unrecognized short argument '-%c'.", argv[arg][ii]);
                exit(EXIT_FAILURE);
            }
        }
    }
}

static void log_for_libevent(int severity, const char msg[])
{
    enum log_severity sev;
    switch (severity)
    {
    case _EVENT_LOG_ERR: sev = LOG_ERROR; break;
    case _EVENT_LOG_WARN: sev = LOG_WARNING; break;
    case _EVENT_LOG_DEBUG: sev = LOG_DEBUG; break;
    default: sev = LOG_INFO; break;
    }
    log_message(log_core, sev, "libevent: %s", msg);
}

static void log_for_evdns(int is_warning, const char msg[])
{
    log_message(log_core, is_warning ? LOG_WARNING : LOG_ERROR, "evdns: %s", msg);
}

static void break_loop(UNUSED_ARG(int fd), UNUSED_ARG(short event), UNUSED_ARG(void *arg))
{
    log_message(log_core, LOG_INFO, "break_loop() called due to signal");
    clean_exit = 1;
    event_loopbreak();
}

static void reload_config(UNUSED_ARG(int fd), UNUSED_ARG(short event), UNUSED_ARG(void *arg))
{
    log_message(log_core, LOG_INFO, "Re-reading config file due to signal");
    conf_read(config_filename);
}

int main(int argc, char *argv[])
{
    iauthd_executable = argv[0];
    parse_arguments(argc, argv);

    setenv("TZ", "UTC", 1);
    /* Attempt to change to the log directory unless started relative
     * to cwd.
     */
    if ((argv[0][0] != '.') && (no_chdir == 0)) {
        if (0 != chdir(LOGDIR))
            fprintf(stderr, "chdir(\"%s\") failed: %s\n", LOGDIR, strerror(errno));
    }

    log_core = log_type_register("core", NULL);
    conf.root = conf_register_object(NULL, "core");
    conf.library_path = conf_register_string_list(conf.root, "library_path", MODULESDIR, NULL);
    conf.modules = conf_register_string_list(conf.root, "modules", NULL);

    /* Initialize libevent. */
    if (!event_init()) {
        fprintf(stderr, "Unable to initialize event library.\n");
        return EXIT_FAILURE;
    }

    /* Initialize libevent's DNS module. */
    if (evdns_init()) {
        fprintf(stderr, "Unable to initialize DNS library.\n");
        return EXIT_FAILURE;
    }
    evdns_search_clear();

    /* Capture libevent's error messages to our own log. */
    event_set_log_callback(log_for_libevent);
    evdns_set_log_fn(log_for_evdns);

    /* Initialize the other iauthd core components. */
    log_set_verbosity(verbose_debug ? 2 : 0);
    ctype_init();
    module_init();
    sar_init();
    if (conf_read(config_filename))
        return EXIT_FAILURE;
    if (module_add_path(&conf.library_path->value))
        return EXIT_FAILURE;
    if (module_load_list(&conf.modules->value))
        return EXIT_FAILURE;

    /* Did the user want us to exit early? */
    if (early_exit) {
        fprintf(stdout, "Configuration file %s appears valid.\n", config_filename);
        return EXIT_SUCCESS;
    }

    /* Handle signals. */
    signal_set(&sighup_evt, SIGHUP, break_loop, NULL);
    if (event_add(&sighup_evt, NULL))
        log_message(log_core, LOG_FATAL, "Unable to handle SIGHUP handler.");
    signal_set(&sigusr1_evt, SIGUSR1, reload_config, NULL);
    if (event_add(&sigusr1_evt, NULL))
        log_message(log_core, LOG_FATAL, "Unable to handle SIGUSR1 handler.");

    /* Run the event loop. */
    event_dispatch();

    if (restart)
    {
        char **restart_argv;

        restart_argv = alloca((argc + 1) * sizeof(restart_argv[0]));
        memcpy(restart_argv, argv, argc * sizeof(restart_argv[0]));
        restart_argv[argc] = NULL;
        execv(argv[0], restart_argv);
        log_message(log_core, LOG_FATAL, "Unable to restart iauthd-c: %s\n", strerror(errno));
    }

    return clean_exit ? EXIT_SUCCESS : EXIT_FAILURE;
}
