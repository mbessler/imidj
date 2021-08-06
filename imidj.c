/*
 * This file is part of the IMIDJ - IMage Incremental Deltafragment Joiner
 * (https://github.com/mbessler/imidj)
 *
 * Copyright (c) 2019-21 Manuel Bessler
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, version 2.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 */

#include "imidj.h"
#include "chidx.h"
#include "analyzer.h"
#include "differ.h"
#include "patcher.h"

gboolean opt_verbose = FALSE;
gboolean opt_version = FALSE;


gboolean version_main(int argc, char **argv)
{
    (void) argc;
    (void) argv;
    g_print(VERSION "\n");
    exit(1);
}

void usage(GOptionContext *context) {
    g_autofree gchar *text = NULL;
    text = g_option_context_get_help(context, FALSE, NULL);
    g_print(COPYRIGHT_STR "\n" \
            LICENSE_STR "\n"                       \
            "\n"                                     \
            "%s", text);
}

static void main_usage(const char * argv0)
{
    g_printerr("imidj - IMage Incremental Deltafragment Joiner\n" \
               COPYRIGHT_STR "\n"         \
               LICENSE_STR "\n"                               \
               "\n");
    g_printerr("Usage:\n");
    g_printerr("  %s <COMMAND> ...\n", argv0);
    g_printerr("\n");
    g_printerr ("List of imidj commands:\n");
    g_printerr ("    index\t\tIndex and Chunk an Image File\n");
    g_printerr ("    patch\t\tCreate/Update an Image File from chunks,\n");
    g_printerr ("         \t\t optionally referencing one or more similar local images\n");
    g_printerr ("    analyze\t\tAnalyze/Dump a .chidx Chunk Index File\n");
    g_printerr ("    diff\t\tDiff two images chunk-by-chunk\n");
    exit(1);
}

int main(int argc, char ** argv) {
    mode_dispatch_handler_t action;

    if (argc < 2) {
        main_usage(argv[0]);
        exit(1);
    }

    if (g_str_equal (argv[1], "index")) {
        action = index_args;
    } else if (g_str_equal (argv[1], "patch")) {
        action = patcher_args;
    } else if (g_str_equal (argv[1], "analyze")) {
        action = analyze_args;
    } else if (g_str_equal (argv[1], "diff")) {
        action = diff_args;
    } else if (g_str_equal(argv[1], "version") || g_str_equal(argv[1], "--version")) {
        action = version_main;
    } else {
        main_usage(argv[0]);
        exit(1);
    }

    argv[1] = argv[0];
    exit( (action) (argc - 1, argv + 1) );
}

