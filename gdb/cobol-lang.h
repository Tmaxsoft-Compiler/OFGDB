/* COB language support definitions for GDB, the GNU debugger.

   Copyright (C) 1992, 1994-1998, 2000, 2002, 2005-2012 Free Software
   Foundation, Inc.

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


#if !defined (COBOL_LANG_H)
#define COBOL_LANG_H 1

struct ui_file;
struct language_arch_info;

#include "value.h"
#include "macroexp.h"
#include "parser-defs.h"


/* The various kinds of C string and character.  Note that these
   values are chosen so that they may be or'd together in certain
   ways.  */
enum cobol_string_type
  {
    /* An ordinary string: "value".  */
    COBOL_STRING = 0,
    /* A wide string: L"value".  */
    COBOL_WIDE_STRING = 1,
    /* A 16-bit Unicode string: u"value".  */
    COBOL_STRING_16 = 2,
    /* A 32-bit Unicode string: U"value".  */
    COBOL_STRING_32 = 3,
    /* An ordinary char: 'v'.  This can also be or'd with one of the
       above to form the corresponding CHAR value from a STRING
       value.  */
    COBOL_CHAR = 4,
    /* A wide char: L'v'.  */
    COBOL_WIDE_CHAR = 5,
    /* A 16-bit Unicode char: u'v'.  */
    COBOL_CHAR_16 = 6,
    /* A 32-bit Unicode char: U'v'.  */
    COBOL_CHAR_32 = 7
  };

/* Defined in c-exp.y.  */

extern int cobol_parse (void);

extern void cobol_error (char *);

extern int cobol_parse_escape (char **, struct obstack *);

/* sylee TODO : cobol-typeprint.c change */

/* Defined in c-typeprint.c */
extern void cobol_print_type (struct type *, const char *,
			  struct ui_file *, int, int);

extern void cobol_print_typedef (struct type *,
			     struct symbol *,
			     struct ui_file *);

extern void cobol_val_print (struct type *, const gdb_byte *,
			int, CORE_ADDR,
			struct ui_file *, int,
			const struct value *,
			const struct value_print_options *);

extern void cobol_value_print (struct value *, struct ui_file *,
			  const struct value_print_options *);

/* These are in c-lang.c: */

extern struct value *evaluate_subexp_cobol (struct type *expect_type,
					struct expression *exp,
					int *pos,
					enum noside noside);

extern void cobol_printchar (int, struct type *, struct ui_file *);

extern void cobol_printstr (struct ui_file * stream,
			struct type *elttype,
			const gdb_byte *string,
			unsigned int length,
			const char *user_encoding,
			int force_ellipses,
			const struct value_print_options *options);

extern void cobol_language_arch_info (struct gdbarch *gdbarch,
				  struct language_arch_info *lai);

extern const struct exp_descriptor exp_descriptor_cobol;

extern void cobol_emit_char (int c, struct type *type,
			 struct ui_file *stream, int quoter);

extern const struct op_print cobol_op_print_tab[];

/* These are in c-typeprint.c: */

extern void cobol_type_print_base (struct type *, struct ui_file *,
			       int, int);


#endif /* !defined (COBOL_LANG_H) */
