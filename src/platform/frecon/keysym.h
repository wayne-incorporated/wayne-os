/*
 * Copyright 2014 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#ifndef KEYSYM_H
#define KEYSYM_H

uint8_t keysym_table[] = {
	'?', '?',		// 0
	'?', '?',		// 1
	'1', '!',		// 2
	'2', '@',		// 3
	'3', '#',		// 4
	'4', '$',		// 5
	'5', '%',		// 6
	'6', '^',		// 7
	'7', '&',		// 8
	'8', '*',		// 9
	'9', '(',		// 10
	'0', ')',		// 11
	'-', '_',		// 12
	'=', '+',		// 13
	8, 8,			// 14
	9, 9,			// 15
	'q', 'Q',		// 16
	'w', 'W',		// 17
	'e', 'E',		// 18
	'r', 'R',		// 19
	't', 'T',		// 20
	'y', 'Y',		// 21
	'u', 'U',		// 22
	'i', 'I',		// 23
	'o', 'O',		// 24
	'p', 'P',		// 25
	'[', '{',		// 26
	']', '}',		// 27
	13, 13,			// 28
	'?', '?',		// 29
	'a', 'A',		// 30
	's', 'S',		// 31
	'd', 'D',		// 32
	'f', 'F',		// 33
	'g', 'G',		// 34
	'h', 'H',		// 35
	'j', 'J',		// 36
	'k', 'K',		// 37
	'l', 'L',		// 38
	';', ':',		// 39
	'\'', '\"',		// 40
	'`', '~',		// 41
	'?', '?',		// 42
	'\\', '|',		// 43
	'z', 'Z',		// 44
	'x', 'X',		// 45
	'c', 'C',		// 46
	'v', 'V',		// 47
	'b', 'B',		// 48
	'n', 'N',		// 49
	'm', 'M',		// 50
	',', '<',		// 51
	'.', '>',		// 52
	'/', '?',		// 53
	'?', '?',		// 54
	'*', '*',		// 55
	'?', '?',		// 56
	' ', ' ',		// 57
	'?', '?',		// 58
	'?', '?',		// 59
	'?', '?',		// 60
	'?', '?',		// 61
	'?', '?',		// 62
	'?', '?',		// 63
	'?', '?',		// 64
	'?', '?',		// 65
	'?', '?',		// 66
	'?', '?',		// 67
	'?', '?',		// 68
	'?', '?',		// 69
	'?', '?',		// 70
	'7', '7',		// 71
	'8', '8',		// 72
	'9', '9',		// 73
	'-', '-',		// 74
	'4', '4',		// 75
	'5', '5',		// 76
	'6', '6',		// 77
	'+', '+',		// 78
	'1', '1',		// 79
	'2', '2',		// 80
	'3', '3',		// 81
	'0', '0',		// 82
	'.', '.',		// 83
	'?', '?',		// 84
	'?', '?',		// 85
	'?', '?',		// 86
	'?', '?',		// 87
	'?', '?',		// 88
	'?', '?',		// 89
	'?', '?',		// 90
	'?', '?',		// 91
	'?', '?',		// 92
	'?', '?',		// 93
	'?', '?',		// 94
	'?', '?',		// 95
	13, 13,			// 96
	'?', '?',		// 97
	'/', '/',		// 98
	'?', '?',		// 99
	'?', '?',		// 100
	'?', '?',		// 101
	'?', '?',		// 102
	'?', '?',		// 103
	'?', '?',		// 104
	'?', '?',		// 105
	'?', '?',		// 106
	'?', '?',		// 107
	'?', '?',		// 108
};

#define KEYSYM_ESC	0xff1b
#define KEYSYM_HOME	0xff50
#define KEYSYM_LEFT	0xff51
#define KEYSYM_UP	0xff52
#define KEYSYM_RIGHT	0xff53
#define KEYSYM_DOWN	0xff54
#define KEYSYM_PAGEUP	0xff55
#define KEYSYM_PAGEDOWN	0xff56
#define KEYSYM_END	0xff57
#define KEYSYM_INSERT	0xff63
#define KEYSYM_DELETE	0xffff

#define KEYSYM_F1	0xffbe
#define KEYSYM_F2	0xffbf
#define KEYSYM_F3	0xffc0
#define KEYSYM_F4	0xffc1
#define KEYSYM_F5	0xffc2
#define KEYSYM_F6	0xffc3
#define KEYSYM_F7	0xffc4
#define KEYSYM_F8	0xffc5
#define KEYSYM_F9	0xffc6
#define KEYSYM_F10	0xffc7


#endif
