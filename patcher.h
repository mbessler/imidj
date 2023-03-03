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

typedef struct {
    unsigned int chunks_fetched;
    unsigned int chunks_local;
    size_t bytes_fetched;
    size_t bytes_fetched_actual;
    size_t bytes_local;

    unsigned int chunks_already_present;
    size_t bytes_already_present;

    size_t total_retries;
} imidj_patch_stats_t;

int patcher_args(int argc, char ** argv);

