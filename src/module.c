/* module.c - loadable module support
 *
 * Copyright 2004, 2007, 2011 Michael Poole <mdpoole@troilus.org>
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

#include <dlfcn.h>

struct module {
    char *name;
    struct const_string_vector depends;
    struct const_string_vector rdepends;
    void *handle;
    int is_backend;
    int visited;
};

static struct set modules;
static struct module *loading_module;
static struct string_vector module_path;

#define STAY_LOADED 1

static void
module_clean(void)
{
    module_close_all();
    assert(set_size(&modules) == 0);
    string_vector_clear(&module_path);
}

static void
module_cleanup(void *module_)
{
    void (*func)(void);
    struct module *module = module_;
    unsigned int ii;

    for (ii = 0; ii < module->depends.used; ++ii) {
        struct module *other = module_get(module->depends.vec[ii]);
        if (!other) {
            log_message(log_core, LOG_WARNING, "Module %s somehow depends on non-existent module %s (during cleanup).", module->name, module->depends.vec[ii]);
            continue;
        }
        const_string_vector_remove(&other->rdepends, module->name);
    }
    const_string_vector_clear(&module->depends);
    const_string_vector_clear(&module->rdepends);
    func = dlsym(module->handle, "module_destructor");
    if (func)
        func();
#if !STAY_LOADED
    if (module->handle)
        dlclose(module->handle);
#endif
}

void module_init(void)
{
    reg_exit_func(module_clean);
    modules.compare = set_compare_charp;
    modules.cleanup = module_cleanup;
}

struct module * module_get(const char *name)
{
    struct module *mod;
    struct set_node *node;

    mod = set_find(&modules, &name);
    if (!mod) {
        node = set_node_alloc(sizeof(*mod) + strlen(name) + 1);
        mod = set_node_data(node);
        mod->name = (char*)(mod + 1);
        strcpy(mod->name, name);
        set_insert(&modules, node);
    }
    return mod;
}

const char* module_get_name(const struct module *mod)
{
    return mod ? mod->name : NULL;
}

static void * module_dlopen(const char *name)
{
    void *handle;
    unsigned int ii;
    int flags = RTLD_GLOBAL | RTLD_LAZY;
    char filename[PATH_MAX];

    for (ii = 0; ii < module_path.used; ++ii)
    {
        snprintf(filename, sizeof(filename), "%s/%s.so", module_path.vec[ii], name);
        handle = dlopen(filename, flags);
        if (handle != NULL)
        {
            return handle;
        }
    }

    return dlopen(name, flags);
}

static struct module *module_load(const char *name)
{
    void (*func)(const char *);
    struct module *mod;
    struct module *prior;

    /* If the module already exists, don't initialize it again. */
    mod = set_find(&modules, &name);
    if (mod) {
        return mod;
    }

    prior = loading_module;
    loading_module = mod = module_get(name);
    if (!loading_module) {
        log_message(log_core, LOG_FATAL, "Unable to allocate memory for module %s", name);
        return NULL;
    }
    loading_module->handle = module_dlopen(name);
    if (!loading_module->handle) {
        log_message(log_core, LOG_FATAL, "Unable to load module %s: %s", name, dlerror());
        return NULL;
    }
    func = dlsym(loading_module->handle, "module_constructor");
    if (func)
        func(name);
    loading_module = prior;
    return mod;
}

void module_depends(const char *name, ...)
{
    va_list args;

    assert(loading_module != NULL);
    va_start(args, name);
    for (; name; name = va_arg(args, const char *)) {
        /* If the module is not loaded yet, try to load it. */
        struct module *other = set_find(&modules, &name);
        if (!other)
            other = module_load(name);
        if (!other)
            log_message(log_core, LOG_FATAL, "Module %s depends on unloadable module %s.", loading_module->name, name);
        const_string_vector_append(&loading_module->depends, name);
    }
    va_end(args);
}

void module_antidepends(const char *name, ...)
{
    va_list args;

    assert(loading_module != NULL);
    va_start(args, name);
    for (; name; name = va_arg(args, const char *)) {
        /* If the module is not loaded yet, try to load it. */
        struct module *other = set_find(&modules, &name);
        if (!other)
            other = module_load(name);
        if (!other)
            log_message(log_core, LOG_FATAL, "Module %s anti-depends on unloadable module %s.", loading_module->name, name);
        const_string_vector_append(&other->depends, loading_module->name);
    }
    va_end(args);
}

void module_is_backend(void)
{
    assert(loading_module != NULL);
    loading_module->is_backend++;
}

static int module_dfs(struct module *module, int visit)
{
    unsigned int ii;
    void (*func)(struct module *self);
    int res;

    if (module->visited && (module->visited < visit))
        return 0;
    module->visited = visit;

    for (ii = 0; ii < module->depends.used; ++ii) {
        struct module *other = module_get(module->depends.vec[ii]);
        if (!other)
            continue;
        if (other->visited == visit)
            return -1;
        res = module_dfs(other, visit);
        if (res == -1)
            log_message(log_core, LOG_FATAL, "Module dependency loop: %s -> %s", module->name, other->name);
        if (res)
            return res;
    }

    if (module->handle
        && (func = dlsym(module->handle, "module_post_init")))
        func(module);
    return 0;
}

int module_add_path(const struct string_vector *list)
{
    unsigned int ii;

    for (ii = 0; ii < list->used; ++ii) {
        string_vector_append(&module_path, list->vec[ii]);
    }
    return 0;
}

int module_load_list(const struct string_vector *list)
{
    struct set_node *node;
    unsigned int ii;
    int visit;

    /* Load modules. */
    for (ii = 0; ii < list->used; ++ii)
        if (!module_load(list->vec[ii]))
            return 1;

    /* Set visit count for previously visited modules (if there were any). */
    for (node = set_first(&modules), visit = 0; node; node = set_next(node)) {
        struct module *module = set_node_data(node);

        if (module->visited) {
            module->visited = visit = 1;
        }
    }

    /* Do a topological sort (depth-first walk) of modules. */
    for (node = set_first(&modules); node; node = set_next(node)) {
        struct module *module = set_node_data(node);
        int res;

        /* If we have already visited the module, skip it. */
        if (module->visited)
            continue;

        /* Update rdepends list for this module's dependencies. */
        for (ii = 0; ii < module->depends.used; ++ii) {
            struct module *other = module_get(module->depends.vec[ii]);
            if (!other) {
                log_message(log_core, LOG_WARNING, "Module %s somehow depends on non-existent module %s (during load).", module->name, module->depends.vec[ii]);
                continue;
            }
            const_string_vector_append(&other->rdepends, module->name);
        }

        /* Try to run the module's post-init function. */
        res = module_dfs(module, ++visit);
        if (res)
            return res;
    }

    return 0;
}

void module_close_all(void)
{
    struct set_node *node;
    struct set_node *next;
    struct module *module;
    int progress;

    /* Iterate over modules as long as we find some to free.  In each
     * iteration, free any that are not dependencies of other loaded
     * modules. */
    do {
        progress = 0;
        for (node = set_first(&modules); node; node = next) {
            next = set_next(node);
            module = set_node_data(node);
            if (module->is_backend || module->rdepends.used)
                continue;
            set_remove(&modules, module, 0);
            progress = 1;
        }
    } while (progress);

    /* Go through and remove any remaining modules. */
    for (node = set_first(&modules); node; node = next) {
        next = set_next(node);
        set_remove(&modules, set_node_data(node), 0);
    }
}
