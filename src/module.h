/* module.h - loadable module support
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

#if !defined(MODULE_H_0a98f550_dbab_4c67_b3c4_bc295ab779a6)

/** Multiple-inclusion guard for "src/module.h". */
#define MODULE_H_0a98f550_dbab_4c67_b3c4_bc295ab779a6

struct module;

/* Interface to main.c */

/** Initialize the dynamic module code. */
void module_init(void);
/** Add paths to the module search path. */
int module_add_path(const struct string_vector *list);
/** Load a list of modules by name. */
int module_load_list(const struct string_vector *list);
/** Unload all modules in preparation for shutdown. */
void module_close_all(void);

/* Interface to modules during module load */

/** Indicates that the currently loading module depends on another,
 *  and should be initialized after (and destroyed before) it. */
void module_depends(const char *name, ...) NULL_SENTINEL;
/** Indicates that the currently loading module is a backend for some
 *  facility in another module (and should be treated as a dependency
 *  of that module). */
void module_antidepends(const char *name, ...) NULL_SENTINEL;
/** Indicates that the currently loading module is a backend for some
 *  facility in the iauthd core. */
void module_is_backend(void);

/* Interfaces to any code at runtime */

/** Find a module by name. */
struct module *module_get(const char *name);
/** Return the name for a module. */
const char *module_get_name(const struct module *mod);

#endif /* !defined(MODULE_H_0a98f550_dbab_4c67_b3c4_bc295ab779a6) */
