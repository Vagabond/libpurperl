#!/bin/sh

gcc libpurperl.c -o libpurperl -Wall -I/usr/local/include/glib-2.0 -I/usr/local/include/libpurple -L/usr/local/lib -lglib-2.0 -lpurple -g3 -ggdb
