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
#pragma once

#include <glib.h>

#define COPYRIGHT_STR "Copyright (C) 2019-2021 by Manuel Bessler"
#define LICENSE_STR "License: GPLv2"
#define VERSION "0.1.0"

typedef gboolean (*mode_dispatch_handler_t)(int argc, char **argv);

extern gboolean opt_verbose;
extern gboolean opt_version;
extern void usage(GOptionContext *context);
extern gboolean version_main(int argc, char **argv);
