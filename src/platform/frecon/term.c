/*
 * Copyright 2014 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#include <ctype.h>
#include <fcntl.h>
#include <libtsm.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/select.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include "dbus.h"
#include "fb.h"
#include "font.h"
#include "image.h"
#include "input.h"
#include "main.h"
#include "shl_pty.h"
#include "term.h"
#include "util.h"

unsigned int term_num_terminals = 4;
static terminal_t* terminals[TERM_MAX_TERMINALS];
static uint32_t current_terminal = 0;

struct term {
	struct tsm_screen* screen;
	struct tsm_vte* vte;
	struct shl_pty* pty;
	int pty_bridge;
	int pid;
	tsm_age_t age;
	int w_in_char, h_in_char;
};

struct _terminal_t {
	unsigned vt;
	bool active;
	bool input_enable;
	uint32_t background;
	bool background_valid;
	fb_t* fb;
	struct term* term;
	char** exec;
};


static char* interactive_cmd_line[] = {
	"/sbin/agetty",
	"-",
	"9600",
	"xterm",
	NULL
};

static bool in_background = false;
static bool hotplug_occured = false;


static void __attribute__ ((noreturn)) term_run_child(terminal_t* terminal)
{
	/* XXX figure out how to fix "top" for xterm-256color */
	setenv("TERM", "xterm", 1);
	if (terminal->exec) {
		execve(terminal->exec[0], terminal->exec, environ);
		exit(1);
	} else {
		while (1)
			sleep(1000000);
	}
}

static int term_draw_cell(struct tsm_screen* screen, uint32_t id,
			  const uint32_t* ch, size_t len,
			  unsigned int cwidth, unsigned int posx,
			  unsigned int posy,
			  const struct tsm_screen_attr* attr,
			  tsm_age_t age, void* data)
{
	terminal_t* terminal = (terminal_t*)data;
	uint32_t front_color, back_color;
	uint8_t br, bb, bg;
	uint32_t luminance;

	if (age && terminal->term->age && age <= terminal->term->age)
		return 0;

	if (terminal->background_valid) {
		br = (terminal->background >> 16) & 0xFF;
		bg = (terminal->background >> 8) & 0xFF;
		bb = (terminal->background) & 0xFF;
		luminance = (3 * br + bb + 4 * bg) >> 3;

		/*
		 * FIXME: black is chosen on a dark background, but it uses the
		 * default color for light backgrounds
		 */
		if (luminance > 128) {
			front_color = 0;
			back_color = terminal->background;
		} else {
			front_color = (attr->fr << 16) | (attr->fg << 8) | attr->fb;
			back_color = terminal->background;
		}
	} else {
			front_color = (attr->fr << 16) | (attr->fg << 8) | attr->fb;
			back_color = (attr->br << 16) | (attr->bg << 8) | attr->bb;
	}

	if (attr->inverse) {
		uint32_t tmp = front_color;
		front_color = back_color;
		back_color = tmp;
	}

	if (len)
		font_render(terminal->fb, posx, posy, *ch,
					front_color, back_color);
	else
		font_fillchar(terminal->fb, posx, posy,
						front_color, back_color);

	return 0;
}

static void term_redraw(terminal_t* terminal)
{
	if (fb_lock(terminal->fb)) {
		terminal->term->age =
			tsm_screen_draw(terminal->term->screen, term_draw_cell, terminal);
		fb_unlock(terminal->fb);
	}
}

void term_key_event(terminal_t* terminal, uint32_t keysym, int32_t unicode)
{
	if (!terminal->input_enable)
		return;

	if (tsm_vte_handle_keyboard(terminal->term->vte, keysym, 0, 0, unicode))
		tsm_screen_sb_reset(terminal->term->screen);

	term_redraw(terminal);
}

static void term_read_cb(struct shl_pty* pty, char* u8, size_t len, void* data)
{
	terminal_t* terminal = (terminal_t*)data;

	tsm_vte_input(terminal->term->vte, u8, len);

	term_redraw(terminal);
}

static void term_write_cb(struct tsm_vte* vte, const char* u8, size_t len,
				void* data)
{
	struct term* term = data;
	int r;

	r = shl_pty_write(term->pty, u8, len);
	if (r < 0)
		LOG(ERROR, "OOM in pty-write (%d)", r);

	shl_pty_dispatch(term->pty);
}

static void term_esc_show_image(terminal_t* terminal, char* params)
{
	char* tok;
	image_t* image;
	int status;

	image = image_create();
	if (!image) {
		LOG(ERROR, "Out of memory when creating an image.\n");
		return;
	}
	for (tok = strtok(params, ";"); tok; tok = strtok(NULL, ";")) {
		if (strncmp("file=", tok, 5) == 0) {
			image_set_filename(image, tok + 5);
		} else if (strncmp("location=", tok, 9) == 0) {
			uint32_t x, y;
			if (sscanf(tok + 9, "%u,%u", &x, &y) != 2) {
				LOG(ERROR, "Error parsing image location.\n");
				goto done;
			}
			image_set_location(image, x, y);
		} else if (strncmp("offset=", tok, 7) == 0) {
			int32_t x, y;
			if (sscanf(tok + 7, "%d,%d", &x, &y) != 2) {
				LOG(ERROR, "Error parsing image offset.\n");
				goto done;
			}
			image_set_offset(image, x, y);
		} else if (strncmp("scale=", tok, 6) == 0) {
			uint32_t s;
			if (sscanf(tok + 6, "%u", &s) != 1) {
				LOG(ERROR, "Error parsing image scale.\n");
				goto done;
			}
			if (s == 0)
				s = image_get_auto_scale(term_getfb(terminal));
			image_set_scale(image, s);
		}
	}

	status = image_load_image_from_file(image);
	if (status != 0) {
		LOG(WARNING, "Term ESC image_load_image_from_file %s failed: %d:%s.",
	        image_get_filename(image), status, strerror(status));
	} else {
		term_show_image(terminal, image);
	}
done:
	image_destroy(image);
}

static void term_esc_draw_box(terminal_t* terminal, char* params)
{
	char* tok;
	uint32_t color = 0;
	uint32_t w = 1;
	uint32_t h = 1;
	uint32_t locx, locy;
	bool use_location = false;
	int32_t offx, offy;
	bool use_offset = false;
	uint32_t scale = 1;
	fb_stepper_t s;
	int32_t startx, starty;

	for (tok = strtok(params, ";"); tok; tok = strtok(NULL, ";")) {
		if (strncmp("color=", tok, 6) == 0) {
			color = strtoul(tok + 6, NULL, 0);
		} else if (strncmp("size=", tok, 5) == 0) {
			if (sscanf(tok + 5, "%u,%u", &w, &h) != 2) {
				LOG(ERROR, "Error parsing box size.\n");
				goto done;
			}
		} else if (strncmp("location=", tok, 9) == 0) {
			if (sscanf(tok + 9, "%u,%u", &locx, &locy) != 2) {
				LOG(ERROR, "Error parsing box location.\n");
				goto done;
			}
			use_location = true;
		} else if (strncmp("offset=", tok, 7) == 0) {
			if (sscanf(tok + 7, "%d,%d", &offx, &offy) != 2) {
				LOG(ERROR, "Error parsing box offset.\n");
				goto done;
			}
			use_offset = true;
		} else if (strncmp("scale=", tok, 6) == 0) {
			if (sscanf(tok + 6, "%u", &scale) != 1) {
				LOG(ERROR, "Error parsing box scale.\n");
				goto done;
			}
			if (scale == 0)
				scale = image_get_auto_scale(term_getfb(terminal));
		}
	}

	w *= scale;
	h *= scale;
	offx *= scale;
	offy *= scale;

	if (!fb_lock(terminal->fb))
		goto done;

	if (use_offset && use_location) {
		LOG(WARNING, "Box offset and location set, using location.");
		use_offset = false;
	}

	if (use_location) {
		startx = locx;
		starty = locy;
	} else {
		startx = (fb_getwidth(terminal->fb) - w)/2;
		starty = (fb_getheight(terminal->fb) - h)/2;
	}

	if (use_offset) {
		startx += offx;
		starty += offy;
	}

	if (!fb_stepper_init(&s, terminal->fb, startx, starty, w, h))
		goto done_fb;

	do {
		do {
		} while (fb_stepper_step_x(&s, color));
	} while (fb_stepper_step_y(&s));

done_fb:
	fb_unlock(terminal->fb);
done:
	;
}

static void term_esc_input(terminal_t* terminal, char* params)
{
	if (strcmp(params, "1") == 0 ||
	    strcasecmp(params, "on") == 0 ||
	    strcasecmp(params, "true") == 0)
		term_input_enable(terminal, true);
	else if (strcmp(params, "0") == 0 ||
		 strcasecmp(params, "off") == 0 ||
		 strcasecmp(params, "false") == 0)
		term_input_enable(terminal, false);
	else
		LOG(ERROR, "Invalid parameter for input escape.\n");
}

static void term_esc_switchvt(terminal_t* terminal, char* params)
{
	uint32_t vt = (uint32_t)strtoul(params, NULL, 0);
	if (vt >= term_num_terminals || vt >= TERM_MAX_TERMINALS) {
		LOG(ERROR, "Invalid parameter for switchvt escape.");
		return;
	}
	term_switch_to(vt);
}

static void term_esc_drmdropmaster(terminal_t* terminal, char* params)
{
	term_background(true);
}

/*
 * Assume all one or two digit sequences followed by ; are xterm OSC escapes.
 */
static bool is_xterm_osc(char *osc)
{
	if (isdigit(osc[0])) {
		if (osc[1] == ';')
			return true;
		if (isdigit(osc[1]) && osc[2] == ';')
			return true;
	}
	return false;
}

static void term_osc_cb(struct tsm_vte *vte, const uint32_t *osc_string,
			size_t osc_len, void *data)
{
	terminal_t* terminal = (terminal_t*)data;
	size_t i;
	char *osc;

	for (i = 0; i < osc_len; i++)
		if (osc_string[i] >= 128)
			return; /* we only want to deal with ASCII */

	osc = malloc(osc_len + 1);
	if (!osc) {
		LOG(WARNING, "Out of memory when processing OSC.\n");
		return;
	}

	for (i = 0; i < osc_len; i++)
		osc[i] = (char)osc_string[i];
	osc[i] = '\0';

	if (strncmp(osc, "image:", 6) == 0)
		term_esc_show_image(terminal, osc + 6);
	else if (strncmp(osc, "box:", 4) == 0)
		term_esc_draw_box(terminal, osc + 4);
	else if (strncmp(osc, "input:", 6) == 0)
		term_esc_input(terminal, osc + 6);
	else if (strncmp(osc, "switchvt:", 9) == 0)
		term_esc_switchvt(terminal, osc + 9);
	else if (strncmp(osc, "drmdropmaster", 13) == 0)
		term_esc_drmdropmaster(terminal, osc + 13);
	else if (is_xterm_osc(osc))
		; /* Ignore it. */
	else
		LOG(WARNING, "Unknown OSC escape sequence \"%s\", ignoring.", osc);

	free(osc);
}

#ifdef __clang__
__attribute__((__format__ (__printf__, 7, 0)))
#endif
static void log_tsm(void* data, const char* file, int line, const char* fn,
		    const char* subs, unsigned int sev, const char* format,
		    va_list args)
{
	char buffer[KMSG_LINE_MAX];
	int len = snprintf(buffer, KMSG_LINE_MAX, "<%i>frecon[%d]: %s: ", sev,
	                   getpid(), subs);
	if (len < 0)
		return;
	if (len < KMSG_LINE_MAX - 1)
		vsnprintf(buffer+len, KMSG_LINE_MAX - len, format, args);
	fprintf(stderr, "%s\n", buffer);
}

static int term_resize(terminal_t* term, int scaling)
{
	uint32_t char_width, char_height;
	int status;

	if (!scaling)
		scaling = fb_getscaling(term->fb);

	font_init(scaling);
	font_get_size(&char_width, &char_height);

	term->term->w_in_char = fb_getwidth(term->fb) / char_width;
	term->term->h_in_char = fb_getheight(term->fb) / char_height;

	status = tsm_screen_resize(term->term->screen,
				   term->term->w_in_char, term->term->h_in_char);
	if (status < 0) {
		font_free();
		return -1;
	}

	status = shl_pty_resize(term->term->pty, term->term->w_in_char,
				term->term->h_in_char);
	if (status < 0) {
		font_free();
		return -1;
	}

	return 0;
}

void term_set_num_terminals(unsigned new_num)
{
	if (new_num < 1)
		term_num_terminals = 1;
	else if (new_num > TERM_MAX_TERMINALS)
		term_num_terminals = TERM_MAX_TERMINALS;
	else
		term_num_terminals = new_num;
}

static bool term_is_interactive(unsigned int vt)
{
	if (command_flags.no_login)
		return false;

	if (vt == TERM_SPLASH_TERMINAL)
		return command_flags.enable_vt1;

	return true;
}

/*
 * Set the area not covered by any characters, possibly existing on the right
 * side and bottom of the screen, to the background color.
 */
static void term_clear_border(terminal_t* terminal)
{
	fb_stepper_t s;
	uint32_t char_width, char_height;
	font_get_size(&char_width, &char_height);

	if (!fb_lock(terminal->fb))
		return;

	if (fb_stepper_init(&s, terminal->fb,
			    terminal->term->w_in_char * char_width, 0,
			    fb_getwidth(terminal->fb) - terminal->term->w_in_char * char_width, terminal->term->h_in_char * char_height)) {
		do {
			do {
			} while (fb_stepper_step_x(&s, terminal->background));
		} while (fb_stepper_step_y(&s));
	}

	if (fb_stepper_init(&s, terminal->fb,
			    0, terminal->term->h_in_char * char_height,
			    fb_getwidth(terminal->fb), fb_getheight(terminal->fb) - terminal->term->h_in_char * char_height)) {
		do {
			do {
			} while (fb_stepper_step_x(&s, terminal->background));
		} while (fb_stepper_step_y(&s));
	}

	fb_unlock(terminal->fb);
}

static void term_hide_cursor(terminal_t* terminal)
{
	tsm_screen_set_flags(terminal->term->screen, TSM_SCREEN_HIDE_CURSOR);
}

__attribute__ ((unused))
static void term_show_cursor(terminal_t* terminal)
{
	term_write_message(terminal, "\033[?25h");
}

terminal_t* term_init(unsigned vt, int pts_fd)
{
	const int scrollback_size = 200;
	int status;
	terminal_t* new_terminal;
	bool interactive = term_is_interactive(vt);

	new_terminal = (terminal_t*)calloc(1, sizeof(*new_terminal));
	if (!new_terminal)
		return NULL;

	new_terminal->vt = vt;
	new_terminal->background_valid = false;
	new_terminal->input_enable = true;

	new_terminal->fb = fb_init();

	if (!new_terminal->fb) {
		LOG(ERROR, "Failed to create fb on VT%u.", vt);
		term_close(new_terminal);
		return NULL;
	}

	new_terminal->term = (struct term*)calloc(1, sizeof(*new_terminal->term));
	if (!new_terminal->term) {
		term_close(new_terminal);
		return NULL;
	}

	if (interactive)
		new_terminal->exec = interactive_cmd_line;
	else
		new_terminal->exec = NULL;

	status = tsm_screen_new(&new_terminal->term->screen,
			log_tsm, new_terminal->term);
	if (status < 0) {
		LOG(ERROR, "Failed to create new screen on VT%u.", vt);
		term_close(new_terminal);
		return NULL;
	}

	tsm_screen_set_max_sb(new_terminal->term->screen, scrollback_size);

	status = tsm_vte_new(&new_terminal->term->vte, new_terminal->term->screen,
			term_write_cb, new_terminal->term, log_tsm, new_terminal->term);

	if (status < 0) {
		LOG(ERROR, "Failed to create new VT%u.", vt);
		term_close(new_terminal);
		return NULL;
	}

	if (command_flags.enable_osc)
		tsm_vte_set_osc_cb(new_terminal->term->vte, term_osc_cb, (void *)new_terminal);

	new_terminal->term->pty_bridge = shl_pty_bridge_new();
	if (new_terminal->term->pty_bridge < 0) {
		LOG(ERROR, "Failed to create pty bridge on VT%u.", vt);
		term_close(new_terminal);
		return NULL;
	}

	status = shl_pty_open(&new_terminal->term->pty,
			term_read_cb, new_terminal, 1, 1, pts_fd);

	if (status < 0) {
		LOG(ERROR, "Failed to open pty on VT%u.", vt);
		term_close(new_terminal);
		return NULL;
	} else if (status == 0) {
		term_run_child(new_terminal);
		exit(1);
	}

	status = mkdir(FRECON_RUN_DIR, S_IRWXU);
	if (status == 0 || (status < 0 && errno == EEXIST)) {
		char path[32];
		snprintf(path, sizeof(path), FRECON_VT_PATH, vt);
		unlink(path); /* In case it already exists. Ignore return codes. */
		if (symlink(ptsname(shl_pty_get_fd(new_terminal->term->pty)), path) < 0)
			LOG(ERROR, "Failed to symlink pts name %s to %s, %d:%s",
			    path,
			    ptsname(shl_pty_get_fd(new_terminal->term->pty)),
			    errno, strerror(errno));
	}

	status = shl_pty_bridge_add(new_terminal->term->pty_bridge, new_terminal->term->pty);
	if (status) {
		LOG(ERROR, "Failed to add pty bridge on VT%u.", vt);
		term_close(new_terminal);
		return NULL;
	}

	new_terminal->term->pid = shl_pty_get_child(new_terminal->term->pty);

	status = term_resize(new_terminal, 0);

	if (status < 0) {
		LOG(ERROR, "Failed to resize VT%u.", vt);
		term_close(new_terminal);
		return NULL;
	}

	if (!interactive) {
		term_hide_cursor(new_terminal);
		term_input_enable(new_terminal, false);
	}

	return new_terminal;
}

void term_activate(terminal_t* terminal)
{
	term_set_current_to(terminal);
	terminal->active = true;
	fb_setmode(terminal->fb);
	term_redraw(terminal);
}

void term_deactivate(terminal_t* terminal)
{
	if (!terminal->active)
		return;

	terminal->active = false;
}

void term_close(terminal_t* term)
{
	char path[32];
	if (!term)
		return;

	snprintf(path, sizeof(path), FRECON_VT_PATH, term->vt);
	unlink(path);
	if (term->vt == term_get_current())
		unlink(FRECON_CURRENT_VT);

	if (term->fb) {
		fb_close(term->fb);
		term->fb = NULL;
	}

	if (term->term) {
		if (term->term->pty) {
			if (term->term->pty_bridge >= 0) {
				shl_pty_bridge_remove(term->term->pty_bridge, term->term->pty);
				shl_pty_bridge_free(term->term->pty_bridge);
				term->term->pty_bridge = -1;
			}
			shl_pty_close(term->term->pty);
			term->term->pty = NULL;
		}
		free(term->term);
		term->term = NULL;
	}

	font_free();
	free(term);
}

bool term_is_child_done(terminal_t* terminal)
{
	int status;
	int ret;
	ret = waitpid(terminal->term->pid, &status, WNOHANG);

	if ((ret == -1) && (errno == ECHILD)) {
		return false;
	}
	return ret != 0;
}

void term_page_up(terminal_t* terminal)
{
	tsm_screen_sb_page_up(terminal->term->screen, 1);
	term_redraw(terminal);
}

void term_page_down(terminal_t* terminal)
{
	tsm_screen_sb_page_down(terminal->term->screen, 1);
	term_redraw(terminal);
}

void term_line_up(terminal_t* terminal)
{
	tsm_screen_sb_up(terminal->term->screen, 1);
	term_redraw(terminal);
}

void term_line_down(terminal_t* terminal)
{
	tsm_screen_sb_down(terminal->term->screen, 1);
	term_redraw(terminal);
}

bool term_is_valid(terminal_t* terminal)
{
	return ((terminal != NULL) && (terminal->term != NULL));
}

int term_fd(terminal_t* terminal)
{
	if (term_is_valid(terminal))
		return terminal->term->pty_bridge;
	else
		return -1;
}

void term_dispatch_io(terminal_t* terminal, fd_set* read_set)
{
	if (term_is_valid(terminal))
		if (FD_ISSET(terminal->term->pty_bridge, read_set))
			shl_pty_bridge_dispatch(terminal->term->pty_bridge, 0);
}

bool term_exception(terminal_t* terminal, fd_set* exception_set)
{
	if (term_is_valid(terminal)) {
		if (terminal->term->pty_bridge >= 0) {
			return FD_ISSET(terminal->term->pty_bridge,
					exception_set);
		}
	}

	return false;
}

bool term_is_active(terminal_t* terminal)
{
	if (term_is_valid(terminal))
		return terminal->active;

	return false;
}

void term_add_fds(terminal_t* terminal, fd_set* read_set, fd_set* exception_set, int* maxfd)
{
	if (term_is_valid(terminal)) {
		if (terminal->term->pty_bridge >= 0) {
			*maxfd = MAX(*maxfd, terminal->term->pty_bridge);
			FD_SET(terminal->term->pty_bridge, read_set);
			FD_SET(terminal->term->pty_bridge, exception_set);
		}
	}
}

const char* term_get_ptsname(terminal_t* terminal)
{
	return ptsname(shl_pty_get_fd(terminal->term->pty));
}

void term_set_background(terminal_t* terminal, uint32_t bg)
{
	terminal->background = bg;
	terminal->background_valid = true;
}

int term_show_image(terminal_t* terminal, image_t* image)
{
	return image_show(image, terminal->fb);
}

void term_write_message(terminal_t* terminal, char* message)
{
	FILE* fp;

	fp = fopen(term_get_ptsname(terminal), "w");
	if (fp) {
		fputs(message, fp);
		fclose(fp);
	}
}

fb_t* term_getfb(terminal_t* terminal)
{
	return terminal->fb;
}

terminal_t* term_get_terminal(int num)
{
	return terminals[num];
}

void term_set_terminal(int num, terminal_t* terminal)
{
	terminals[num] = terminal;
}

int term_create_splash_term(int pts_fd)
{
	terminal_t* terminal = term_init(TERM_SPLASH_TERMINAL, pts_fd);
	if (!terminal) {
		LOG(ERROR, "Could not create splash term.");
		return -1;
	}
	term_set_terminal(TERM_SPLASH_TERMINAL, terminal);

	return 0;
}

void term_destroy_splash_term(void)
{
	terminal_t *terminal;
	if (command_flags.enable_vt1) {
		return;
	}
	terminal = term_get_terminal(TERM_SPLASH_TERMINAL);
	term_set_terminal(TERM_SPLASH_TERMINAL, NULL);
	term_close(terminal);
}

void term_update_current_link(void)
{
	char path[32];
	unlink(FRECON_CURRENT_VT);
	if (TERM_SPLASH_TERMINAL != current_terminal ||
	    command_flags.enable_vt1) {
		snprintf(path, sizeof(path), FRECON_VT_PATH, current_terminal);
		if (symlink(path, FRECON_CURRENT_VT) < 0)
			LOG(ERROR, "set_current: failed to create current symlink.");
	}
}

void term_set_current(uint32_t t)
{
	if (t >= TERM_MAX_TERMINALS)
		LOG(ERROR, "set_current: larger than array size");
	else
	if (t >= term_num_terminals)
		LOG(ERROR, "set_current: larger than num terminals");
	else {
		current_terminal = t;
		term_update_current_link();
	}
}

uint32_t term_get_current(void)
{
	return current_terminal;
}

terminal_t *term_get_current_terminal(void)
{
	return terminals[current_terminal];
}

void term_set_current_terminal(terminal_t* terminal)
{
	terminals[current_terminal] = terminal;
}

void term_set_current_to(terminal_t* terminal)
{
	if (!terminal) {
		if (terminals[current_terminal])
			term_close(terminals[current_terminal]);
		terminals[current_terminal] = NULL;
		current_terminal = 0;
		return;
	}

	for (unsigned i = 0; i < term_num_terminals; i++) {
		if (terminal == terminals[i]) {
			current_terminal = i;
			return;
		}
	}
	LOG(ERROR, "set_current_to: terminal not in array");
}

int term_switch_to(unsigned int vt)
{
	terminal_t *terminal;
	if (vt == term_get_current()) {
		terminal = term_get_current_terminal();
		if (term_is_valid(terminal)) {
			if (!term_is_active(terminal))
				term_activate(terminal);
			return vt;
		}
	}

	if (vt >= term_num_terminals)
		return -EINVAL;

	terminal = term_get_current_terminal();
	if (term_is_active(terminal))
		term_deactivate(terminal);

	/* Always background the splash terminal, so Chrome can become DRM
	 * master. */
	if (vt == TERM_SPLASH_TERMINAL
	    && !command_flags.enable_vt1) {
		term_set_current(vt);
                /* Returning to Chrome. Splash screen animation may be still
                 * running in background. */
		term_background(true);
		return vt;
	}

	term_foreground();

	term_set_current(vt);
	terminal = term_get_current_terminal();
	if (!terminal) {
		/* No terminal where we are switching to, create new one. */
		term_set_current_terminal(term_init(vt, -1));
		terminal = term_get_current_terminal();
		if (!term_is_valid(terminal)) {
			LOG(ERROR, "Term init failed VT%u.", vt);
			return -1;
		}
		term_activate(terminal);
	} else {
		term_activate(terminal);
	}

	return vt;
}

void term_monitor_hotplug(void)
{
	unsigned int t;

	if (in_background) {
		hotplug_occured = true;
		return;
	}

	if (!drm_rescan())
		return;

	for (t = 0; t < term_num_terminals; t++) {
		if (!terminals[t])
			continue;
		if (!terminals[t]->fb)
			continue;
		fb_buffer_destroy(terminals[t]->fb);
		font_free();
	}

	for (t = 0; t < term_num_terminals; t++) {
		if (!terminals[t])
			continue;
		if (!terminals[t]->fb)
			continue;
		fb_buffer_init(terminals[t]->fb);
		term_resize(terminals[t], 0);
		if (current_terminal == t && terminals[t]->active)
			fb_setmode(terminals[t]->fb);
		terminals[t]->term->age = 0;
		term_redraw(terminals[t]);
	}
}

void term_redrm(terminal_t* terminal)
{
	fb_buffer_destroy(terminal->fb);
	font_free();
	fb_buffer_init(terminal->fb);
	term_resize(terminal, 0);
	terminal->term->age = 0;
	term_redraw(terminal);
}

void term_clear(terminal_t* terminal)
{
	term_clear_border(terminal);
	tsm_screen_erase_screen(terminal->term->screen, false);
	term_redraw(terminal);
}

void term_zoom(bool zoom_in)
{
	int scaling = font_get_scaling();
	if (zoom_in && scaling < 4)
		scaling++;
	else if (!zoom_in && scaling > 1)
		scaling--;
	else
		return;

	unsigned int t;
	for (t = 0; t < term_num_terminals; t++) {
		if (terminals[t])
			font_free();
	}
	for (t = 0; t < term_num_terminals; t++) {
		terminal_t* term = terminals[t];
		if (term) {
			term_resize(term, scaling);
			term->term->age = 0;
			term_redraw(term);
		}
	}
}

/*
 * Put frecon in background. Give up DRM master.
 * onetry - if true, do not retry to notify Chrome multiple times. For use at
 * time when Chrome may be not around yet to receive the message.
 */
void term_background(bool onetry)
{
        terminal_t* terminal = term_get_current_terminal();
	int retry = onetry ? 1 : 5;
	if (in_background)
		return;
	in_background = true;

        /* The terminal also needs to be deactivated so it doesn't consume key
         * presses. */
	if (term_is_active(terminal))
		term_deactivate(terminal);

	drm_dropmaster(NULL);

	if (!dbus_is_initialized()) {
		LOG(WARNING, "Unable to send display ownership DBus message to "
                	"Chrome DisplayService: DBus not initialized");
		return;
	}

	while (!dbus_take_display_ownership() && retry--) {
		if (onetry)
			break;
		LOG(ERROR, "Chrome failed to take display ownership. %s",
		    retry ? "Trying again." : "Giving up, Chrome is probably dead.");
		if (retry > 0)
			usleep(500 * 1000);
	}
}

void term_foreground(void)
{
	int ret;
	int retry = 5;

	if (!in_background)
		return;
	in_background = false;

	/* LOG(INFO, "TIMING: Console switch time start."); */ /* Keep around for timing it in the future. */
	while (!dbus_release_display_ownership() && retry--) {
		LOG(ERROR, "Chrome did not release master. %s",
		    retry ? "Trying again." : "Frecon will steal master.");
		if (retry > 0)
			usleep(500 * 1000);
	}

	/* LOG(INFO, "TIMING: Console switch setmaster."); */
	ret = drm_setmaster(NULL);
	if (ret < 0)
		LOG(ERROR, "Could not set master when switching to foreground %m.");

	if (hotplug_occured) {
		hotplug_occured = false;
		term_monitor_hotplug();
	}
}

void term_suspend_done(void* ignore)
{
	term_monitor_hotplug();
}

void term_input_enable(terminal_t* terminal, bool input_enable)
{
	terminal->input_enable = input_enable;
}
