/* PL/I language support routines for GDB, the GNU debugger.

   Copyright (C) 1992-2014 Free Software Foundation, Inc.

   This file is part of GDB.

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.  */

#if !defined (PLI_LANG_H)
#define PLI_LANG_H 1

struct ui_file;
struct language_arch_info;

#include "value.h"
#include "macroexp.h"
#include "parser-defs.h"

#ifdef _ARC_SPARC
typedef long double __float128;
#endif

/* built-in type */
struct builtin_pli_type {
    struct type* builtin_fixed_dec;
    struct type* builtin_s_8_fixed_bin;
    struct type* builtin_u_8_fixed_bin;
    struct type* builtin_s_16_fixed_bin;
    struct type* builtin_u_16_fixed_bin;
    struct type* builtin_s_32_fixed_bin;
    struct type* builtin_u_32_fixed_bin;
    struct type* builtin_f_float_dec;
    struct type* builtin_f_float_bin;
    struct type* builtin_d_float_dec;
    struct type* builtin_d_float_bin;
    struct type* builtin_e_float_dec;
    struct type* builtin_e_float_bin;
    struct type* builtin_character;
    struct type* builtin_bit;
    struct type* builtin_graphic;
    struct type* builtin_widechar;
    struct type* builtin_picture;
    struct type* builtin_pointer;
    struct type* builtin_entry;
    struct type* builtin_offset;
    struct type* builtin_area;
};

extern const struct builtin_pli_type *builtin_pli_type (struct gdbarch *);

/* PL/I string type character */
enum pli_string_type {
    PLI_CHARACTER = 0,
    PLI_BIT = 1,
    PLI_GRAPHIC = 2,
    PLI_WIDECHAR = 3
};

/* #TODO: need to implement expression parser for PL/I */
extern int pli_parse ();
extern void pli_error (char*);
extern int pli_parse_escape (char**, struct obstack*);

/* Defined in pli-typeprint.c / #TODO: need to implement */
extern void pli_print_type (struct type*, const char*, struct ui_file*, int, int, const struct type_print_options*);
extern void pli_print_typedef (struct type*, struct symbol*, struct ui_file*);
extern void pli_type_print_base (struct type*, struct ui_file*, int, int, const struct type_print_options*);
extern void pli_type_print_varspec_prefix (struct type*, struct ui_file*, int, int, int, const struct type_print_options*);
extern void pli_type_print_varspec_suffix (struct type*, struct ui_file*, int, int, const struct type_print_options*);

/* Defined in pli-valprint.c */
extern void pli_val_print (struct type*, const gdb_byte*, int, CORE_ADDR, struct ui_file*, int, 
                          const struct value*, const struct value_print_options*);
extern void pli_value_print (struct value*, struct ui_file*, const struct value_print_options*);

/* Defined in pli-lang.c */
extern void pli_printchar (int, struct type*, struct ui_file*);
extern void pli_printstr (struct ui_file*, struct type*, const gdb_byte*, unsigned int, const char*, int, const struct value_print_options*);

struct value* value_subscripted_rvalue_pli_bit (struct value*, LONGEST, int, int);
struct value* value_subscript_pli (struct value*, LONGEST);
struct value* evaluate_subexp_pli (struct type*, struct expression*, int*, enum noside);

extern void pli_language_arch_info (struct gdbarch*, struct language_arch_info*);
extern void pli_emit_char (int, struct type*, struct ui_file*, int);

extern const struct exp_descriptor exp_descriptor_pli;
extern const struct op_print pli_op_print_tab[];

#endif /* !defined (PLI_LANG_H) */

