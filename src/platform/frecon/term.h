/*
 * Copyright 2014 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#ifndef TERM_H
#define TERM_H

#include "fb.h"
#include "image.h"

#define TERM_MAX_TERMINALS    12
#define TERM_SPLASH_TERMINAL  0
#define TERM_FIRST_STD_VT     1

#define FRECON_VT_PATH FRECON_RUN_DIR "/vt%u"
#define FRECON_CURRENT_VT FRECON_RUN_DIR "/current"


/* Maximum length of buffer than can be passed to /dev/kmsg as defined in kernel
 * sources. */
#define KMSG_LINE_MAX		(1024 - 32)


extern unsigned int term_num_terminals;

typedef struct _terminal_t terminal_t;

void term_set_num_terminals(unsigned new_num);
terminal_t* term_init(unsigned vt, int pts_fd);
void term_close(terminal_t* terminal);
void term_close(terminal_t* terminal);
void term_key_event(terminal_t* terminal, uint32_t keysym, int32_t unicode);
bool term_is_child_done(terminal_t* terminal);

void term_page_up(terminal_t* terminal);
void term_page_down(terminal_t* terminal);
void term_line_up(terminal_t* terminal);
void term_line_down(terminal_t* terminal);

bool term_is_valid(terminal_t* terminal);
int term_fd(terminal_t* terminal);
void term_dispatch_io(terminal_t* terminal, fd_set* read_set);
bool term_exception(terminal_t*, fd_set* exception_set);
bool term_is_active(terminal_t*);
void term_activate(terminal_t*);
void term_deactivate(terminal_t* terminal);
void term_add_fds(terminal_t* terminal, fd_set* read_set, fd_set* exception_set, int* maxfd);
const char* term_get_ptsname(terminal_t* terminal);
void term_set_background(terminal_t* term, uint32_t bg);
int term_show_image(terminal_t* terminal, image_t* image);
void term_write_message(terminal_t* terminal, char* message);
fb_t* term_getfb(terminal_t* terminal);
terminal_t* term_get_terminal(int num);
void term_set_terminal(int num, terminal_t* terminal);
int term_create_splash_term(int pts_fd);
void term_destroy_splash_term(void);
void term_update_current_link(void);
void term_set_current(uint32_t t);
uint32_t term_get_current(void);
terminal_t *term_get_current_terminal(void);
void term_set_current_terminal(terminal_t* terminal);
void term_set_current_to(terminal_t* terminal);
int term_switch_to(unsigned int vt);
void term_monitor_hotplug(void);
void term_redrm(terminal_t* terminal);
void term_clear(terminal_t* terminal);
void term_zoom(bool zoom_in);
void term_background(bool onetry);
void term_foreground(void);
void term_suspend_done(void*);
void term_input_enable(terminal_t* terminal, bool input_enable);
#endif
