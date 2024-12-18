/* Support for printing COBOL values for GDB, the GNU debugger.

   Copyright (C) 1986-2014 Free Software Foundation, Inc.
   Software Foundation, Inc.

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

#include "defs.h"
#include <string.h>
#include "symtab.h"
#include "gdbtypes.h"
#include "gdbcore.h"
#include "expression.h"
#include "value.h"
#include "valprint.h"
#include "language.h"
#include "c-lang.h"
#include "cp-abi.h"
#include "target.h"
#include "cobol-lang.h"
#include <math.h>

/* Temporary storage using circular buffer.  */
static char *
get_cell (void)
{
  static char buf[16][50];
  static int cell = 0;

  if (++cell >= 16)
    cell = 0;
  return buf[cell];
}

char *ptr_string (struct type *type, const gdb_byte *val, CORE_ADDR address);
char *zoned_string (struct type *type, const gdb_byte *val);
char *packed_string (struct type *type, const gdb_byte *val);
char *fixed_string (struct type *type, const gdb_byte *val);
char *flt_string (struct type *type, const gdb_byte *val, DOUBLEST doub, int comp);

struct value *value_cast_cobol (struct type *type, struct value *arg2);

char* cobol_conv_numeric_to_int (struct type *fromType, struct value* from, enum type_code code, int *is_sign);
char* cobol_conv_flt_to_int (struct type *fromType, DOUBLEST doublest);
struct value *cobol_assign_to_numeric (struct type *toType, struct type *fromType, struct value *from, char* buf, int is_sign );
struct value *cobol_assign_to_binary (struct type *toType, struct type *fromType, struct value *from, char* buf, int is_sign, int is_comp5);
struct value *cobol_assign_to_packed (struct type *toType, struct type *fromType, struct value *from, char* buf, int is_sign );
struct value *cobol_assign_to_zoned (struct type *toType, struct type *fromType, struct value *from, char* buf, int is_sign );
struct value *cobol_assign_to_flt (struct type *toType, struct type *fromType, struct value *from, char* buf, int is_sign );
struct value *cobol_assign_to_edited (struct type *toType, struct type *fromType, struct value *from, char* buf );
struct value *cobol_assign_to_alpha_edited (struct type *toType, struct type *fromType, struct value *from, char* pic, char* buf );
void cobol_extend_picture (char *ogn_pic, int digit);


void val_print_type_code_ptr (struct type *type, const gdb_byte *valaddr, struct ui_file *stream, CORE_ADDR address);
void val_print_alpha_string (struct ui_file *stream, const gdb_byte *valaddr, CORE_ADDR address, struct type *type);
void val_print_type_code_zoned (struct type *type, const gdb_byte *valaddr, struct ui_file *stream, CORE_ADDR address);
void val_print_type_code_packed (struct type *type, const gdb_byte *valaddr, struct ui_file *stream, CORE_ADDR address);
void val_print_type_code_edited (struct type *type, const gdb_byte *valaddr, struct ui_file *stream, CORE_ADDR address);
void val_print_type_code_fixed (struct type *type, const gdb_byte *valaddr, struct ui_file *stream, CORE_ADDR address)
;

void print_linkage_address_data (struct gdbarch *gdbarch, CORE_ADDR addr, struct ui_file *stream, int do_demangle, char *leadin);

/* for cobol */
const long long cobexp10LL[19] = {
    1LL,
    10LL,
    100LL,
    1000LL,
    10000LL,
    100000LL,
    1000000LL,
    10000000LL,
    100000000LL,
    1000000000LL,
    10000000000LL,
    100000000000LL,
    1000000000000LL,
    10000000000000LL,
    100000000000000LL,
    1000000000000000LL,
    10000000000000000LL,
    100000000000000000LL,
    1000000000000000000LL
};

const unsigned long long exp10ULL[19] = {
    1ULL,
    10ULL,
    100ULL,
    1000ULL,
    10000ULL,
    100000ULL,
    1000000ULL,
    10000000ULL,
    100000000ULL,
    1000000000ULL,
    10000000000ULL,
    100000000000ULL,
    1000000000000ULL,
    10000000000000ULL,
    100000000000000ULL,
    1000000000000000ULL,
    10000000000000000ULL,
    100000000000000000ULL,
    1000000000000000000ULL
};

void
cobol_val_print (struct type *type, const gdb_byte *valaddr,
         int embedded_offset, CORE_ADDR address,
         struct ui_file *stream, int recurse,
         const struct value *original_value,
         const struct value_print_options *options)
{
    struct gdbarch *gdbarch = get_type_arch (type);
    enum bfd_endian byte_order = gdbarch_byte_order (gdbarch);
    unsigned int i = 0;    /* Number of characters printed.  */
    unsigned len;
    struct type *elttype, *unresolved_elttype;
    struct type *unresolved_type = type;
    unsigned eltlen;

    enum type_code link_code = TYPE_CODE_PTR;

    CORE_ADDR addr;

    CHECK_TYPEDEF (type);

    // for OFCOB linkage section process
    if (TYPE_CODE(type) == TYPE_CODE_PTR && TYPE_COB_LINK(type) != 1) {
        struct type *link_elttype = TYPE_TARGET_TYPE (type);
        struct type *link_type = check_typedef (link_elttype);
        if (TYPE_COB_LINK(link_type) == 1 && TYPE_CODE(link_type) != TYPE_CODE_STRUCT) {
            addr = unpack_pointer (type, valaddr + embedded_offset);
            print_linkage_address_data(gdbarch, addr, stream, demangle, "");
            return;
        }
    }

    switch (TYPE_CODE (type)) {
        case TYPE_CODE_ARRAY:
            unresolved_elttype = TYPE_TARGET_TYPE (type);
            elttype = check_typedef (unresolved_elttype);
            if (TYPE_LENGTH (type) > 0 && TYPE_LENGTH (unresolved_elttype) > 0) {
                LONGEST low_bound, high_bound;

                if (!get_array_bounds (type, &low_bound, &high_bound))
                    error (_("Could not determine the array high bound"));

                eltlen = TYPE_LENGTH (elttype);
                len = high_bound - low_bound + 1;
                if (options->prettyformat_arrays) {
                    print_spaces_filtered (2 + 2 * recurse, stream);
                }

                fprintf_filtered (stream, "{");
                /* If this is a virtual function table, print the 0th
                   entry specially, and the rest of the members
                   normally.  */
                if (cp_is_vtbl_ptr_type (elttype)) {
                    i = 1;
                    fprintf_filtered (stream, _("%d vtable entries"), len - 1);
                } else {
                    i = 0;
                }
                val_print_array_elements (type, valaddr, embedded_offset,
                          address, stream,
                          recurse, original_value, options, i);
                fprintf_filtered (stream, "}");
                break;
            }
            /* Array of unspecified length: treat like pointer to first elt.  */
            addr = address + embedded_offset;
            goto print_unpacked_pointer;

        case TYPE_CODE_PTR:
            if (options->format && options->format != 's') {
                val_print_scalar_formatted (type, valaddr, embedded_offset,
                                original_value, options, 0, stream);
                break;
            }

            if (options->vtblprint && cp_is_vtbl_ptr_type (type)) {
                /* Print the unmangled name if desired.  */
                /* Print vtable entry - we only get here if we ARE using
                   -fvtable_thunks.  (Otherwise, look under
                   TYPE_CODE_STRUCT.)  */
                CORE_ADDR addr = extract_typed_address (valaddr + embedded_offset, type);

                print_function_pointer_address (options, gdbarch, addr, stream);
                break;
            }
            unresolved_elttype = TYPE_TARGET_TYPE (type);
            elttype = check_typedef (unresolved_elttype);
            {
                int want_space;

                addr = unpack_pointer (type, valaddr + embedded_offset);
                val_print_type_code_ptr(type, valaddr + embedded_offset, stream, addr);
                fprintf_filtered (stream, " / ");

                print_unpacked_pointer:
                want_space = 0;

                if (TYPE_CODE (elttype) == TYPE_CODE_FUNC) {
                    /* Try to print what function it points to.  */
                    print_function_pointer_address (options, gdbarch, addr, stream);
                    return;
                }

                // ptr address & ptr name print
                if (options->symbol_print) {
                    // check linkage section data for cobol
                    want_space = print_address_demangle (options, gdbarch, addr,
                                     stream, demangle);
                } else if (options->addressprint) {
                    fputs_filtered (paddress (gdbarch, addr), stream);
                    want_space = 1;
                }

                /* For a pointer to a textual type, also print the string
                   pointed to, unless pointer is null.  */

                if (c_textual_element_type (unresolved_elttype, options->format) && addr != 0) {
                    if (want_space)
                        fputs_filtered (" ", stream);

                    i = val_print_string (unresolved_elttype, NULL,
                              addr, -1,
                              stream, options);
                } else if (cp_is_vtbl_member (type)) {
                    /* Print vtbl's nicely.  */
                    CORE_ADDR vt_address = unpack_pointer (type,
                                       valaddr
                                       + embedded_offset);
                    struct bound_minimal_symbol msymbol = lookup_minimal_symbol_by_pc (vt_address);

                    /* If 'symbol_print' is set, we did the work above.  */
                    if (!options->symbol_print
                    && (msymbol.minsym != NULL)
                    && (vt_address == SYMBOL_VALUE_ADDRESS (msymbol.minsym))) {
                        if (want_space)
                            fputs_filtered (" ", stream);
                        fputs_filtered (" <", stream);
                        fputs_filtered (SYMBOL_PRINT_NAME (msymbol.minsym), stream);
                        fputs_filtered (">", stream);
                        want_space = 1;
                    }

                    if (vt_address && options->vtblprint) {
                        struct value *vt_val;
                        struct symbol *wsym = (struct symbol *) NULL;
                        struct type *wtype;
                        struct block *block = (struct block *) NULL;
                        struct field_of_this_result is_this_fld;

                        if (want_space)
                            fputs_filtered (" ", stream);

                        if (msymbol.minsym != NULL)
                            wsym = lookup_symbol (SYMBOL_LINKAGE_NAME (msymbol.minsym),
                                      block, VAR_DOMAIN,
                                      &is_this_fld);

                        if (wsym) {
                            wtype = SYMBOL_TYPE (wsym);
                        } else {
                            wtype = unresolved_elttype;
                        }
                        vt_val = value_at (wtype, vt_address);
                        common_val_print (vt_val, stream, recurse + 1,
                                  options, current_language);
                        if (options->prettyformat) {
                            fprintf_filtered (stream, "\n");
                            print_spaces_filtered (2 + 2 * recurse, stream);
                        }
                    }
                }
                return;
            }
            break;

        case TYPE_CODE_UNION:
            if (recurse && !options->unionprint) {
                fprintf_filtered (stream, "{...}");
                break;
            }

        /* Fall through.  */
        case TYPE_CODE_STRUCT:
            /*FIXME: Abstract this away.  */
            if (options->vtblprint && cp_is_vtbl_ptr_type (type)) {
                /* Print the unmangled name if desired.  */
                /* Print vtable entry - we only get here if NOT using
                   -fvtable_thunks.  (Otherwise, look under
                   TYPE_CODE_PTR.)  */
                int offset = (embedded_offset
                      + TYPE_FIELD_BITPOS (type,
                                   VTBL_FNADDR_OFFSET) / 8);
                struct type *field_type = TYPE_FIELD_TYPE (type,
                                       VTBL_FNADDR_OFFSET);
                CORE_ADDR addr
                  = extract_typed_address (valaddr + offset, field_type);

                print_function_pointer_address (options, gdbarch, addr, stream);
            } else {
                // for OFCOB linkage section process
                if (TYPE_COB_LINK(TYPE_FIELD_TYPE (type, 0)) == 1) {
                    CORE_ADDR testaddr = unpack_pointer(type, valaddr + embedded_offset);
                    if (embedded_offset == 0)
                        address = testaddr;
                }

                cp_print_value_fields_rtti (type, valaddr,
                        embedded_offset, address,
                        stream, recurse,
                        original_value, options,
                        NULL, 0);
            }
            break;

        case TYPE_CODE_INT:
            if (options->format || options->output_format) {
                struct value_print_options opts = *options;

                opts.format = (options->format ? options->format
                       : options->output_format);
                val_print_scalar_formatted (type, valaddr, embedded_offset,
                                original_value, &opts, 0, stream);
            } else /* sylee test */ {
                val_print_type_code_int (type, valaddr + embedded_offset, stream);
                /* C and C++ has no single byte int type, char is used
                   instead.  Since we don't know whether the value is really
                   intended to be used as an integer or a character, print
                   the character equivalent as well.  */
                if (c_textual_element_type (unresolved_type, options->format)) {
                    fputs_filtered (" ", stream);
                    LA_PRINT_CHAR (unpack_long (type, valaddr + embedded_offset),
                           unresolved_type, stream);
                }
            }
            break;

        case TYPE_CODE_CHAR:
            if (options->format || options->output_format) {
                struct value_print_options opts = *options;
                opts.format = (options->format ? options->format
                       : options->output_format);
                val_print_scalar_formatted (type, valaddr, embedded_offset,
                                original_value, &opts, 0, stream);
            } else {
                /*sylee test*/
                val_print_alpha_string (stream, valaddr + embedded_offset, address, type);
            }
            break;

        case TYPE_CODE_FLT:
            if (options->format) {
                val_print_scalar_formatted (type, valaddr, embedded_offset,
                                original_value, options, 0, stream);
            } else {
                print_floating (valaddr + embedded_offset, type, stream);
            }
            break;

        case TYPE_CODE_ERROR:
            fprintf_filtered (stream, "%s", TYPE_ERROR_NAME (type));
            break;

        case TYPE_CODE_ZONED:
        {
            if (options->format || options->output_format) {
                struct value_print_options opts = *options;

                opts.format = (options->format ? options->format : options->output_format);
                val_print_scalar_formatted (type, valaddr, embedded_offset,
                                original_value, &opts, 0, stream);
            } else {
                /*sylee test*/
                val_print_type_code_zoned (type, valaddr + embedded_offset,
                             stream, address);
                if (c_textual_element_type (unresolved_type, options->format)) {
                    fputs_filtered (" ", stream);
                    LA_PRINT_CHAR (unpack_long (type, valaddr + embedded_offset),
                           unresolved_type, stream);
                }
            }
        }
            break;

        case TYPE_CODE_PACKED:
        {
            if (options->format || options->output_format) {
                struct value_print_options opts = *options;

                opts.format = (options->format ? options->format
                       : options->output_format);
                val_print_scalar_formatted (type, valaddr, embedded_offset,
                                original_value, &opts, 0, stream);
            } else {
                /*sylee test*/
                val_print_type_code_packed (type, valaddr + embedded_offset,
                             stream, address);
                if (c_textual_element_type (unresolved_type, options->format)) {
                    fputs_filtered (" ", stream);
                    LA_PRINT_CHAR (unpack_long (type, valaddr + embedded_offset),
                           unresolved_type, stream);
                }
            }
        }
            break;

        /* sylee test */
        case TYPE_CODE_EDITED:
            if (options->format || options->output_format) {
                struct value_print_options opts = *options;
                opts.format = (options->format ? options->format
                       : options->output_format);
                val_print_scalar_formatted (type, valaddr, embedded_offset,
                                original_value, &opts, 0, stream);
            } else {
                val_print_type_code_edited (type, valaddr + embedded_offset,
                             stream, address);
            }
            break;

        case TYPE_CODE_SIGNED_FIXED:
        case TYPE_CODE_UNSIGNED_FIXED:
        {
            if (options->format || options->output_format) {
                struct value_print_options opts = *options;

                opts.format = (options->format ? options->format
                       : options->output_format);
                val_print_scalar_formatted (type, valaddr, embedded_offset,
                                original_value, &opts, 0, stream);
            } else {
                /*sylee test*/
                val_print_type_code_fixed (type, valaddr + embedded_offset,
                             stream, address);
                if (c_textual_element_type (unresolved_type, options->format)) {
                    fputs_filtered (" ", stream);
                    LA_PRINT_CHAR (unpack_long (type, valaddr + embedded_offset),
                           unresolved_type, stream);
                }
            }
        }
            break;

        case TYPE_CODE_DBCS:
            if (options->format || options->output_format) {
                struct value_print_options opts = *options;

                opts.format = (options->format ? options->format
                       : options->output_format);
                val_print_scalar_formatted (type, valaddr, embedded_offset,
                                original_value, &opts, 0, stream);
            } else {
                /*sylee test*/
                val_print_alpha_string (stream,  valaddr + embedded_offset, address, type);

                if (c_textual_element_type (unresolved_type, options->format)) {
                    fputs_filtered (" ", stream);
                    LA_PRINT_CHAR (unpack_long (type, valaddr + embedded_offset),
                           unresolved_type, stream);
                }
            }
            break;

        case TYPE_CODE_REF:
        case TYPE_CODE_FUNC:
        case TYPE_CODE_METHOD:
        case TYPE_CODE_RANGE:
        default:
          error (_("Invalid COBOL type code %d in symbol table."),
             TYPE_CODE (type));
    }
    gdb_flush (stream);
}

void
cobol_value_print (struct value *val, struct ui_file *stream, 
           const struct value_print_options *options)
{
  struct type *type, *real_type, *val_type;
  int full, top, using_enc;
  struct value_print_options opts = *options;

  opts.deref_ref = 1;

  /* If it is a pointer, indicate what it points to.

     Print type also if it is a reference.

     C++: if it is a member pointer, we will take care
     of that when we print it.  */

  /* Preserve the original type before stripping typedefs.  We prefer
     to pass down the original type when possible, but for local
     checks it is better to look past the typedefs.  */
  val_type = value_type (val);
  type = check_typedef (val_type);

  if (!value_initialized (val))
    fprintf_filtered (stream, " [uninitialized] ");

    /*sylee test : type name print*/
    if (TYPE_CODE(type) == TYPE_CODE_STRUCT ||
        TYPE_CODE(type) == TYPE_CODE_UNION  ||
        TYPE_CODE(type) == TYPE_CODE_ARRAY) {
      /* normal case */
      fprintf_filtered (stream, "(");
      type_print (value_type (val), "", stream, -1);
      fprintf_filtered (stream, ") ");
    }
    else {
      fprintf_filtered (stream, "(USAGE:");
      type_print (value_type (val), "", stream, -1);

      if (TYPE_COB_PIC_STR(type) != NULL)
        fprintf_filtered (stream, "/PIC:%s) ", TYPE_COB_PIC_STR(type));
      else
        fprintf_filtered (stream, ") ");
    }

    /* sylee test */
  //return val_print (val_type, value_contents_for_printing (val),
  val_print (val_type, value_contents_for_printing (val),
            value_embedded_offset (val),
            value_address (val),
            stream, 0,
            val, &opts, current_language);
}

///////////////////////////////////////////////////////////////////////
/* print element value */

/* for linkage */
void print_linkage_address_data (struct gdbarch *gdbarch, CORE_ADDR addr, struct ui_file *stream, int do_demangle, char *leadin)
{
  char *name = NULL;
  char *filename = NULL;
  int unmapped = 0;
  int offset = 0;
  int line = 0;

  //for linkage pointer data
  struct expression *linkage_expr;
  struct value *linkage_val;
  char linkage_format = 0;
  struct value_print_options linkage_opts;
  const gdb_byte *linkage_value;
  CORE_ADDR linkage_addr;
  struct type *linkage_type;

  /* Throw away both name and filename.  */
  struct cleanup *cleanup_chain = make_cleanup (free_current_contents, &name);
  make_cleanup (free_current_contents, &filename);

  if (build_address_symbolic (gdbarch, addr, do_demangle, &name, &offset,
                  &filename, &line, &unmapped))
    {
      do_cleanups (cleanup_chain);
      return 0;
    }

  {
      linkage_expr = parse_expression(name);
      linkage_val = evaluate_expression(linkage_expr);

      linkage_value = value_contents_for_printing(linkage_val);
      linkage_addr = value_address(linkage_val);

      linkage_value = value_contents(linkage_val);
      linkage_value = value_contents_raw(linkage_val);

      linkage_type = value_type(linkage_val);
      if (TYPE_CODE(linkage_type) == TYPE_CODE_ZONED) {
          val_print_type_code_zoned(linkage_type,
                  linkage_value + value_embedded_offset(linkage_val), stream, linkage_addr);
      }
      else if (TYPE_CODE(linkage_type) == TYPE_CODE_PACKED) {
          val_print_type_code_packed (linkage_type,
                  linkage_value + value_embedded_offset(linkage_val), stream, linkage_addr);
      }
      else if(TYPE_CODE(linkage_type) == TYPE_CODE_INT) {
          val_print_type_code_int (linkage_type,
                  linkage_value + value_embedded_offset(linkage_val), stream);
      }
      else if(TYPE_CODE(linkage_type) == TYPE_CODE_FLT) {
          print_floating(linkage_value + value_embedded_offset(linkage_val), linkage_type, stream);
      }
      else if(TYPE_CODE(linkage_type) == TYPE_CODE_CHAR ||
              TYPE_CODE(linkage_type) == TYPE_CODE_DBCS) {
          val_print_alpha_string (stream,
                  linkage_value + value_embedded_offset(linkage_val), linkage_addr, linkage_type);
      }
      else if(TYPE_CODE(linkage_type) == TYPE_CODE_EDITED) {
          val_print_type_code_edited (linkage_type,
                  linkage_value + value_embedded_offset(linkage_val), stream, linkage_addr);
      }
      else if (TYPE_CODE(linkage_type) == TYPE_CODE_SIGNED_FIXED ||
              TYPE_CODE(linkage_type) == TYPE_CODE_UNSIGNED_FIXED) {
          val_print_type_code_fixed (linkage_type,
                  linkage_value + value_embedded_offset(linkage_val), stream, linkage_addr);
      }
      else if(TYPE_CODE(linkage_type) == TYPE_CODE_PTR) {
          val_print_type_code_ptr(linkage_type,
                  linkage_value + value_embedded_offset(linkage_val), stream, linkage_addr);
      }
      else {
            // TODO
            error (_("cobol Not Implemented"));
      }
  }
  do_cleanups (cleanup_chain);
}


/*pointer*/
char *
ptr_string (struct type *type, const gdb_byte *val, CORE_ADDR address)
{
    int display_len = 10;
    char *temp = get_cell ();
    int diff = 0, i = 0;
    char buf[4096];
    char *retval = get_cell();

    xsnprintf (temp, 50, "%ld", address);
    //printf("[sylee debug]temp:[%s][%d]\n", temp, strlen(temp));

    memset (buf, 0x00, 4096);
    memcpy (buf, (char*)temp, strlen(temp));

    if (display_len > strlen(buf)) {
        diff = display_len - strlen(temp);
        memmove(buf+diff, buf, strlen(buf));
        for (i=0; i<diff; i++)
            buf[i] = '0';
    }
    //printf("[sylee debug]buf:[%s][%d]\n",buf,strlen(buf));

    xsnprintf (retval, 50, "%s", buf);

    return retval;
}

void
val_print_type_code_ptr (struct type *type, const gdb_byte *valaddr,
             struct ui_file *stream, CORE_ADDR address)
{
    const char *val;
    val = ptr_string ( type, valaddr, address );
    fputs_filtered (val, stream);
}

/*string*/
void
val_print_alpha_string (struct ui_file *stream, const gdb_byte *valaddr, CORE_ADDR address, struct type *type)
{
    int i;
    const char *val = valaddr;
    char null_char = '\0';

    char* value;
    char buf[4096];
    int size = TYPE_COB_DIGIT(type);

    memset (buf, 0x00, 4096);
    memcpy (buf, (char*)val, size);

    for (i=0; i<size; i++) {
        if (buf[i] != null_char)
            continue;
        else
            buf[i] = ' ';
    }
    value = buf;

    fputs_filtered (value, stream);
}

/*zoned decimal*/
char *
zoned_string (struct type *type, const gdb_byte *val)
{
    int sign = 1;
    int length = 0; //data length
    int display_len = 0; // data length include sign
    int i = 0;
    char null_char = '\0';
    char buf[256];

    ULONGEST temp;
    const unsigned char *p;
    const unsigned char *startaddr = val;
    const unsigned char *endaddr = startaddr + TYPE_LENGTH (type);
    char* retval = get_cell();

    //printf("[sylee debug][val : %s]\n", val);

    memset (buf, 0x00, 256);

    /*{UNKNOWN/unsigned/leading_over/trailing_over/leading_sepa/trailing_sepa}*/
    if ( TYPE_COB_SIGN(type) == 0 || TYPE_COB_SIGN(type) == 1 ){
        display_len = TYPE_COB_DIGIT(type);
        length = TYPE_COB_DIGIT(type);
    }
    else {
        display_len = TYPE_COB_DIGIT(type) + 1;
        if ( TYPE_COB_SIGN(type) == 2 || TYPE_COB_SIGN(type) == 3 )
            length = TYPE_COB_DIGIT(type);
        else if ( TYPE_COB_SIGN(type) == 4 || TYPE_COB_SIGN(type) == 5 )
            length = TYPE_COB_DIGIT(type) + 1;
    }
    memcpy (buf, (char*)val, length);
    //printf("digit:%d/length:%d/ display_len:%d\n", TYPE_COB_DIGIT(type),length, display_len);
    for (i=0; i < length; i++) {
        if (buf[i] != null_char)
            continue;
        else
            buf[i] = '0';
    }

    {
        p = endaddr - 1;
        temp = ((LONGEST) * p ^ 0x80) - 0x80;
        for (--p; p >= startaddr; --p)
            temp = (temp <<8) | *p;
    }

    if ( TYPE_COB_SIGN(type) == 2 ){ /*leading_over*/
        if (buf[0] >= 0x70 && buf[0] <= 0x79){
            sign = -1;
            buf[0] = buf[0] - 0x70 + '0';
        }
    }
    else if ( TYPE_COB_SIGN(type) == 3 ){ /*trailing_over*/
        if (buf[length-1] >= 0x70 && buf[length-1] <= 0x79){
            sign = -1;
            buf[length-1] = buf[length-1] - 0x70 + '0';
        }
    }

    if ( TYPE_COB_SIGN(type) == 2 ){ /*leading_over*/
        memmove(buf+1, buf, strlen(buf));
        if (sign < 0)
            buf[0] = '-';
        else
            buf[0] = '+';
    }
    else if ( TYPE_COB_SIGN(type) == 3 ){ /*trailing_over*/
        if (sign < 0)
            buf[display_len -1] = '-';
        else
            buf[display_len -1] = '+';
    }

    /*check sylee*/
    xsnprintf (retval, 50, "%s", buf);
    return retval;
}

void
val_print_type_code_zoned (struct type *type, const gdb_byte *valaddr,
             struct ui_file *stream, CORE_ADDR address)
{
    const char *val;
    val = zoned_string (type, valaddr); 
    fputs_filtered (val, stream);
}

/*packed decimal*/
char *
packed_string (struct type *type, const gdb_byte *val)
{
    //printf("[sylee debug][[val : %s]]\n", val);

    int sign = 0;
    int length; //data length
    int display_len; // data length include sign
    int i, left, right;
    char buf[256];
    unsigned char* packed = val;
    char* temp;
    int idx, sign_pic = 0;
    char* pic_str = TYPE_COB_PIC_STR(type);
    int diff = 0;
    char* retval = get_cell();

    memset (buf, 0x00, 256);
    temp = buf;

    // sign mode('S') : first
    if (pic_str[0] == 'S')
        sign_pic = 1;

    length = TYPE_COB_DIGIT(type) / 2 + 1;
    if ( TYPE_COB_SIGN(type) == 0 || TYPE_COB_SIGN(type) == 1 ) {
        display_len = length;
    } else {
        display_len = length + 1;
    }

    for (i=0; i<length; i++) {
        left = ( (int)packed[i] & 0xF0 ) >> 4;
        right = ( (int)packed[i] & 0x0F );

        *temp++ = '0' + left;
        if (i == length-1) {
            /* old source */
            /*
            if (right == 0x0C || right == 0x0F || right == 0x00)
                sign = 1;
            else if (right == 0x0D)
                sign = -1;
            */
            if (right == 0x0D || right == 0x0B)
                sign = -1;
            else
                sign = 1;
        }
        else {
            *temp++ = '0' + right;
        }
    }
    *temp++ = 0x00;

    if (strlen(buf) > TYPE_COB_DIGIT(type)){
        diff = strlen(buf) - TYPE_COB_DIGIT(type);
        memmove(buf, buf+diff, strlen(buf)-diff);
        buf[TYPE_COB_DIGIT(type)] = '\0';
    }

    if ( sign_pic == 1 ) {
        memmove(buf+1, buf, strlen(buf));
        if (sign < 0)
            buf[0] = '-';
        else if (sign > 0)
            buf[0] = '+';
    }

    xsnprintf (retval, 50, "%s", buf);
    return retval;
}

void
val_print_type_code_packed (struct type *type, const gdb_byte *valaddr,
             struct ui_file *stream, CORE_ADDR address)
{
    const char *val;
    val = packed_string (type, valaddr);
    fputs_filtered (val, stream);
}

/*edited string*/
void
val_print_type_code_edited (struct type *type, const gdb_byte *valaddr,
             struct ui_file *stream, CORE_ADDR address)
{
    const char *val = valaddr;

    char* value;
    char buf[4096];
    int size = TYPE_COB_DIGIT(type);

    memset (buf, 0x00, 4096);
    memcpy (buf, (char*)val, size);
    value = buf;

    fputs_filtered (value, stream);
}

/*binary*/
char *
fixed_string (struct type *type, const gdb_byte *val)
{
    //printf("[sylee debug][[val : %s]]\n", val);

    int sign = 1, is_comp5 = 0;
    int length; //data length
    int display_len; // data length include sign
    char *buf = get_cell();
    ULONGEST temp;
    const unsigned char *p;
    const unsigned char *startaddr = val;
    const unsigned char *endaddr = startaddr + TYPE_LENGTH (type);

    int diff = 0;
    char *save = get_cell();
    // sign mode('S') : first
    int i = 0, idx = 0, sign_pic = 0;
    char* pic_str = TYPE_COB_PIC_STR(type);
    if (pic_str[0] == 'S' || TYPE_CODE (type) == TYPE_CODE_SIGNED_FIXED)
        sign_pic = 1;

    length = TYPE_COB_DIGIT(type);
    display_len = length;

    // COMP5
    if (strncmp (TYPE_NAME (type), "COMP5", strlen("COMP5")) == 0) {
        is_comp5 = 1;

        p = endaddr - 1;
        temp = ((LONGEST) * p ^ 0x80) - 0x80;
        for (--p; p >= startaddr; --p)
            temp = (temp <<8) | *p;

        switch (TYPE_LENGTH(type)) {
            case 1: //INT8
                display_len = 3;
                break;
            case 2: //INT16
                display_len = 5;
                break;
            case 4: //INT32
                display_len = 10;
                break;
            case 8: //INT64
                display_len = 20;
                break;
        }
    }
    else /*byte order change*/
    {
        if (TYPE_COB_ENDIAN(type) == 1){
            p = startaddr;
            temp = ((LONGEST) * p ^ 0x80) - 0x80;
            for (++p; p < endaddr; ++p)
                temp = (temp << 8) | *p;
        }
    }

    if ((int)temp < 0){
        temp = temp * -1;
        sign = -1;
    }

    //printf("temp:%d\n",temp);

    xsnprintf (save, 50, "%ld", temp);

    if (sign_pic == 1){
        display_len = display_len + 1;

        if (sign > 0)
            buf[0] = '+';
        else if (sign < 0)
            buf[0] = '-';

        if (display_len-1 > strlen(save)){
            diff = (display_len-1) - strlen(save);
            idx = 1;
            for (i=0; i<diff; i++){
                buf[idx] = '0';
                idx++;
            }
        }

        xsnprintf (buf+1+diff, 50, "%ld", temp);
    }
    else {
        if (display_len > strlen(save)){
            diff = (display_len) - strlen(save);
            idx = 0;
            for (i=0; i<diff; i++){
                buf[idx] = '0';
                idx++;
            }
        }

        xsnprintf (buf+diff, 50, "%ld", temp);
    }

    return buf;
}

void
val_print_type_code_fixed (struct type *type, const gdb_byte *valaddr,
             struct ui_file *stream, CORE_ADDR address)
{
    const char *val;
    val = fixed_string (type, valaddr);
    fputs_filtered (val, stream);
}

/*float/double*/
char *
flt_string (struct type *type, const gdb_byte *val, DOUBLEST doub, int comp)
{
    char mentia = ' ', exponent = ' ';
    char mentia_buf[256];
    int i, index = 0;
    int exponent_val;
    long long mentia_val;
    char *buf = get_cell ();

    if (comp == 1)
        xsnprintf (buf, 50, "%.7E",  (double)doub);
    else if (comp == 2)
        xsnprintf (buf, 50, "%.17E", (double)doub);

    //printf("buf:[%s]\n",buf);
    /* get mentia sign */
    if( buf[0] < '0' || buf[0] > '9' ) {
        if(buf[0] == '+')
            mentia = ' ';
        if(buf[0] == '-')
            mentia = '-';
    }

    /* get mentia */
    for( i = 0; buf[i] != 'E'; i++) {
        if( buf[i] == '.' ) {
            continue;
        }
        if(buf[i] < '0' || buf[i] > '9')
            continue;

        mentia_buf[index] = buf[i];
        index++;
    }

    i++;
    if( buf[i] == '+' )
        exponent = ' ';
    if( buf[i] == '-' )
        exponent = '-';
    exponent_val = atoi(&(buf[i]));
    exponent_val++;
    exponent_val = abs(exponent_val);

    mentia_buf[index] = 0x00;
    mentia_val = strtoll(mentia_buf, NULL, 10);

    xsnprintf (buf, 50, "%c.%lldE%c%02d", mentia, mentia_val, exponent, exponent_val);

    return buf;
}

/* print command set */
struct value *
value_cast_cobol (struct type *type, struct value *arg2)
{
/*
    code1 : cobol type_code
    <check TYPE_CODE_ARRAY(2), TYPE_CODE_STRUCT(3), TYPE_CODE_UNION(4)>
    TYPE_CODE_PTR(1),
    TYPE_CODE_INT(8),
    TYPE_CODE_FLT(9),
    TYPE_CODE_CHAR(20),=>(19)
    TYPE_CODE_PACKED(27),
    TYPE_CODE_ZONED(28),=>(32)
    TYPE_CODE_EDITED(29),=>(33)
    TYPE_CODE_SIGNED_FIXED(30),=>(34)
    TYPE_CODE_UNSIGNED_FIXED(31),=>(35)
    TYPE_CODE_DBCS(32) =>(31)
*/
    enum type_code code1;
    enum type_code code2;
    int scalar, is_sign = 0;
    struct type *type2;

    int convert_to_boolean = 0;
    int cob_numeric = 0;

    LONGEST longest;
    DOUBLEST doublest;
    const char *tmpbuf;
    char convbuf[256];
    int digit = 0, scale = 0;

    int ix = 0, idx = 0;
    int from_scale_status = 0;
    char num_buf[4096];

    char* testbuf;

    /* to */
    code1 = TYPE_CODE (check_typedef (type));
    /* from */
    code2 = TYPE_CODE (check_typedef (value_type (arg2)));

    CHECK_TYPEDEF (type);
    code1 = TYPE_CODE (type);
    arg2 = coerce_ref (arg2);
    type2 = check_typedef (value_type(arg2));
    code2 = TYPE_CODE (type2);

    scalar = (code2 == TYPE_CODE_INT || code2 == TYPE_CODE_FLT
        || code2 == TYPE_CODE_DECFLOAT || code2 == TYPE_CODE_ENUM
        || code2 == TYPE_CODE_RANGE
        || code2 == TYPE_CODE_SIGNED_FIXED || code2 == TYPE_CODE_UNSIGNED_FIXED
        || code2 == TYPE_CODE_ZONED || code2 == TYPE_CODE_PACKED);

    cob_numeric = (code2 == TYPE_CODE_SIGNED_FIXED || code2 == TYPE_CODE_UNSIGNED_FIXED
                || code2 == TYPE_CODE_ZONED || code2 == TYPE_CODE_PACKED);

    memset (convbuf, 0x00, 256);

    switch (code1) {
        case TYPE_CODE_INT:
        case TYPE_CODE_SIGNED_FIXED:
        case TYPE_CODE_UNSIGNED_FIXED:
        {
            if (scalar || code2 == TYPE_CODE_PTR) { //code2 == TYPE_CODE_MEMBERPTR
                if (code2 == TYPE_CODE_PTR)
                    longest = extract_unsigned_integer
                        (value_contents (arg2), TYPE_LENGTH (type2),
                         gdbarch_byte_order (get_type_arch (type2)));
                else if (code2 == TYPE_CODE_INT) {
                    longest = value_as_long (arg2);
                }
                else if (code2 == TYPE_CODE_FLT) {
                    doublest = value_as_double(arg2);

                    // set sign of value
                    if (doublest < 0) {
                        is_sign = 1;
                        doublest = (double)doublest * -1;
                    }

                    // convert to int string
                    tmpbuf = cobol_conv_flt_to_int (type2, doublest);
                    memcpy (convbuf, tmpbuf, strlen(tmpbuf));

                    return cobol_assign_to_numeric( type, type2, arg2, convbuf, is_sign );
                }
                else if (cob_numeric) {
                    tmpbuf = cobol_conv_numeric_to_int (type2, arg2, code2, &is_sign);
                    memcpy (convbuf, tmpbuf, strlen(tmpbuf));

                    return cobol_assign_to_numeric( type, type2, arg2, convbuf, is_sign );
                }
                return value_from_longest (type, convert_to_boolean ?
                        (LONGEST) (longest ? 1 : 0) : longest);
            }
            else if (code2 == TYPE_CODE_ARRAY) {
                sprintf (convbuf, "%s", value_contents(arg2));

                ix = 0; 
                idx = 0;
                from_scale_status = 0;
                memset (num_buf, 0x00, 4096);
                for (ix = 0; ix < strlen(convbuf); ix++) {
                    if (convbuf[ix] == '+' || convbuf[ix] == '-') {
                        if (convbuf[ix] == '-')
                            is_sign = 1;
                        continue;
                    }
                    else if (convbuf[ix] >= '0' && convbuf[ix] <= '9') {
                        num_buf[idx] = convbuf[ix];
                        idx++;
                    }
                    else if (convbuf[ix] == '.') {
                        from_scale_status = 1;
                        continue;
                    }
                    else if ((convbuf[ix] >= 'a' && convbuf[ix] <= 'z') ||
                             (convbuf[ix] >= 'A' && convbuf[ix] <= 'Z'))
                        error(_("Not numeric string."));

                    if (from_scale_status)
                        scale++;
                }
                //printf("num_buf[%s]digit[%d]scale[%d]\n", num_buf,strlen(num_buf), scale);
                digit = strlen(num_buf);

                // set digit,scale of TYPE
                if (!TYPE_COB_ATTR(type2)) {
                    TYPE_COB_ATTR(type2) = XMALLOC (struct cobol_attr);
                    TYPE_COB_DIGIT(type2) = digit;
                    TYPE_COB_SCALE(type2) = scale;
                }

                return cobol_assign_to_numeric( type, type2, arg2, num_buf, is_sign );
            }
        }
           break;
        case TYPE_CODE_ZONED:
        case TYPE_CODE_PACKED:
        {
            if (scalar || code2 == TYPE_CODE_PTR) { //code2 == TYPE_CODE_MEMBERPTR
                if (code2 == TYPE_CODE_PTR)
                    longest = extract_unsigned_integer
                        (value_contents (arg2), TYPE_LENGTH (type2),
                         gdbarch_byte_order (get_type_arch (type2)));
                else if (code2 == TYPE_CODE_INT) {
                    longest = value_as_long (arg2);

                    if (longest < 0){
                        is_sign = 1;
                        longest *= -1;
                    }

                    sprintf (convbuf, "%ld", longest);
                    digit = strlen(convbuf);

                    // set digit,scale of TYPE
                    if (!TYPE_COB_ATTR(type2)) {
                        TYPE_COB_ATTR(type2) = XMALLOC (struct cobol_attr);
                    }
                    TYPE_COB_DIGIT(type2) = digit;
                    TYPE_COB_SCALE(type2) = scale;

                    return cobol_assign_to_numeric( type, type2, arg2, convbuf, is_sign );
                }
                else if (code2 == TYPE_CODE_FLT) {
                    doublest = value_as_double(arg2);

                    // set sign of value
                    if (doublest < 0) {
                        is_sign = 1;
                        doublest = (double)doublest * -1;
                    }

                    // convert to int string
                    tmpbuf = cobol_conv_flt_to_int (type2, doublest);
                    memcpy (convbuf, tmpbuf, strlen(tmpbuf));

                    return cobol_assign_to_numeric( type, type2, arg2, convbuf, is_sign );
                }
                else if (cob_numeric) {
                    // SYLEE TODO : pack to pack / zoned to zoned
                    tmpbuf = cobol_conv_numeric_to_int (type2, arg2, code2, &is_sign);
                    memcpy (convbuf, tmpbuf, strlen(tmpbuf));

                    return cobol_assign_to_numeric( type, type2, arg2, convbuf, is_sign );
                }
                return value_from_longest (type, convert_to_boolean ?
                        (LONGEST) (longest ? 1 : 0) : longest);
            }
            else if (code2 == TYPE_CODE_ARRAY) {
                sprintf (convbuf, "%s", value_contents(arg2));

                ix = 0;
                idx = 0;
                from_scale_status = 0;
                memset (num_buf, 0x00, 4096);
                for (ix = 0; ix < strlen(convbuf); ix++) {
                    if (convbuf[ix] == '+' || convbuf[ix] == '-') {
                        if (convbuf[ix] == '-')
                            is_sign = 1;
                        continue;
                    }
                    else if (convbuf[ix] >= '0' && convbuf[ix] <= '9') {
                        num_buf[idx] = convbuf[ix];
                        idx++;
                    }
                    else if (convbuf[ix] == '.') {
                        from_scale_status = 1;
                        continue;
                    }
                    else if ((convbuf[ix] >= 'a' && convbuf[ix] <= 'z') ||
                             (convbuf[ix] >= 'A' && convbuf[ix] <= 'Z'))
                        error(_("Not numeric string."));

                    if (from_scale_status)
                        scale++;
                }
                //printf("num_buf[%s]digit[%d]scale[%d]\n", num_buf,strlen(num_buf), scale);
                digit = strlen(num_buf);

                // set digit,scale of TYPE
                if (!TYPE_COB_ATTR(type2)) {
                    TYPE_COB_ATTR(type2) = XMALLOC (struct cobol_attr);
                    TYPE_COB_DIGIT(type2) = digit;
                    TYPE_COB_SCALE(type2) = scale;
                }

                return cobol_assign_to_numeric( type, type2, arg2, num_buf, is_sign );
            }
        }
           break;
        case TYPE_CODE_PTR:
           break;
        case TYPE_CODE_FLT:
        {
            if (scalar) {
                if (cob_numeric) {
                    tmpbuf = cobol_conv_numeric_to_int (type2, arg2, code2, &is_sign);
                    memcpy (convbuf, tmpbuf, strlen(tmpbuf));

                    return cobol_assign_to_flt( type, type2, arg2, convbuf, is_sign );
                }
                return value_from_double (type, value_as_double(arg2));
            }
            else if (code2 == TYPE_CODE_ARRAY) {
                sprintf (convbuf, "%s", value_contents(arg2));

                ix = 0;
                idx = 0;
                from_scale_status = 0;
                memset (num_buf, 0x00, 4096);
                for (ix = 0; ix < strlen(convbuf); ix++) {
                    if (convbuf[ix] == '+' || convbuf[ix] == '-') {
                        if (convbuf[ix] == '-')
                            is_sign = 1;
                        continue;
                    }
                    else if (convbuf[ix] >= '0' && convbuf[ix] <= '9') {
                        num_buf[idx] = convbuf[ix];
                        idx++;
                    }
                    else if (convbuf[ix] == '.') {
                        from_scale_status = 1;
                        continue;
                    }
                    else if ((convbuf[ix] >= 'a' && convbuf[ix] <= 'z') ||
                             (convbuf[ix] >= 'A' && convbuf[ix] <= 'Z'))
                        error(_("Not numeric string."));

                    if (from_scale_status)
                        scale++;
                }
                //printf("num_buf[%s]digit[%d]scale[%d]\n", num_buf,strlen(num_buf), scale);
                digit = strlen(num_buf);

                // set digit,scale of TYPE
                if (!TYPE_COB_ATTR(type2)) {
                    TYPE_COB_ATTR(type2) = XMALLOC (struct cobol_attr);
                    TYPE_COB_DIGIT(type2) = digit;
                    TYPE_COB_SCALE(type2) = scale;
                }

                return cobol_assign_to_flt( type, type2, arg2, num_buf, is_sign );
            }
        }
            break;
        case TYPE_CODE_CHAR:
        case TYPE_CODE_DBCS:
        {
            return arg2;
        }
            break;
        // SYLEE TODO check numeric/alphanumeric
        case TYPE_CODE_EDITED:
        {
            if (scalar || code2 == TYPE_CODE_PTR) {
                if (code2 == TYPE_CODE_PTR)
                    longest = extract_unsigned_integer
                        (value_contents (arg2), TYPE_LENGTH (type2),
                         gdbarch_byte_order (get_type_arch (type2)));
                else if (code2 == TYPE_CODE_INT) {
                    longest = value_as_long (arg2);

                    if (longest < 0) {
                        is_sign = 1;
                        longest *= -1;
                    }

                    sprintf(convbuf, "%ld", longest);
                    digit = strlen(convbuf);

                    if (!TYPE_COB_ATTR(type2)) {
                        TYPE_COB_ATTR(type2) = XMALLOC (struct cobol_attr);
                    }
                    TYPE_COB_DIGIT(type2) = digit;
                    TYPE_COB_SCALE(type2) = scale;

                    return cobol_assign_to_edited ( type, type2, arg2, convbuf );
                }
                else if (code2 == TYPE_CODE_FLT) {
                    doublest = value_as_double(arg2);

                    // set sign of value
                    if (doublest < 0) {
                        is_sign = 1;
                        doublest = (double)doublest * -1;
                    }

                    // convert to int string
                    tmpbuf = cobol_conv_flt_to_int (type2, doublest);
                    memcpy (convbuf, tmpbuf, strlen(tmpbuf));

                    return cobol_assign_to_edited( type, type2, arg2, convbuf );
                }
                return value_from_longest (type, convert_to_boolean ?
                        (LONGEST) (longest ? 1 : 0) : longest);
            }
            else if (code2 == TYPE_CODE_ARRAY || code2 == code1) {
                sprintf (convbuf, "%s", value_contents(arg2));
                digit = strlen(convbuf);

                // set digit,scale of TYPE
                if (!TYPE_COB_ATTR(type2)) {
                    TYPE_COB_ATTR(type2) = XMALLOC (struct cobol_attr);
                    TYPE_COB_DIGIT(type2) = digit;
                    TYPE_COB_SCALE(type2) = scale;
                }

                //printf("[sylee debug EDITED] convbuf:[%s]\n", convbuf);
                return cobol_assign_to_edited( type, type2, arg2, convbuf );
            }
            return arg2;
        }
            break;
        default:
            error (_("cobol casting type error."));
    } 

    return 0;
}



/* numeric conversion to integer string */
char *cobol_conv_numeric_to_int (struct type *fromType, struct value* from, enum type_code code, int *is_sign)
{
    const char *convbuf;
    int ix = 0, tmp_idx = 0;
    int digit_start = 0;
    static char retbuf[4096];
    static char* tmpbuf;

    switch (code) {
        case TYPE_CODE_SIGNED_FIXED:
        case TYPE_CODE_UNSIGNED_FIXED:
            convbuf = fixed_string (fromType, value_contents(from));
            break;
        case TYPE_CODE_PACKED:
            convbuf = packed_string (fromType, value_contents(from)); 
            break;
        case TYPE_CODE_ZONED:
            convbuf = zoned_string (fromType, value_contents(from));
            break;
        default:
            error (_("cobol conversion type error."));
    }
    //printf("[sylee debug]convbuf:[%s]val[%s]\n", convbuf, value_contents(from));

    memset (retbuf, 0x00, 4096);

    for (ix=0; ix<strlen(convbuf); ix++) {
        if (digit_start == 0 && convbuf[ix] != '0') {
            digit_start = 1;
        }

        if (convbuf[ix] == '+' || convbuf[ix] == '-') {
            if (convbuf[ix] == '-') {
                *is_sign = 1;
                continue;
            }
        }
        else {
            if (digit_start) {
                retbuf[tmp_idx] = convbuf[ix];
                tmp_idx++;
            }
        }
    } 

    //printf("[sylee debug] numeric conversion[%s], is_sign:%d\n", retbuf, *is_sign);
    tmpbuf = retbuf;
    return tmpbuf;
}


/* flt conversion to integer string */
char* cobol_conv_flt_to_int (struct type *fromType, DOUBLEST doublest)
{
    static const char *retbuf = NULL;
    static char convbuf[256];
    char temp[256];

    // get digit, scale of value
    char *dotPtr;
    int dotPos;
    int digit = 0, scale = 0;

    memset (convbuf, 0x00, 256);
    sprintf (convbuf, "%lf", (double)doublest);

    dotPtr = strchr(convbuf,'.');
    dotPos = dotPtr-convbuf;
    scale = strlen(convbuf) - (dotPos+1);
    digit = dotPos + scale;

    //printf("doublest:%lf, convbuf:%s\n", (double)doublest, convbuf);

    // set digit,scale of TYPE
    if (!TYPE_COB_ATTR(fromType)) {
        TYPE_COB_ATTR(fromType) = XMALLOC (struct cobol_attr);
    }

    TYPE_COB_DIGIT(fromType) = digit;
    TYPE_COB_SCALE(fromType) = scale;

    memset (temp, 0x00, 256);
    memcpy (temp, convbuf+dotPos+1, scale);

    convbuf[digit] = '\0';
    memcpy (convbuf+dotPos, temp, scale);

    //printf("temp:[%s] convbuf:[%s]\n", temp, convbuf);

    retbuf = (char*) alloca (strlen(convbuf)+1);
    retbuf = convbuf;

    return retbuf;
}

/* TO: BINARY(COMP=COMP4)/COMP5/COMP3/ZONED */
struct value *
cobol_assign_to_numeric (struct type *toType, struct type *fromType, struct value *from, char* buf, int is_sign)
{
    struct value *retval;

    if (strncmp (TYPE_NAME(toType), "BINARY", strlen("BINARY")) == 0) { //BINARY,COMP,COMP4
        retval = cobol_assign_to_binary(toType, fromType, from, buf, is_sign, 0);
    }else if (strncmp (TYPE_NAME(toType), "COMP5", strlen("COMP5")) == 0) { //COMP5
        retval = cobol_assign_to_binary(toType, fromType, from, buf, is_sign, 1);
    }else if (strncmp (TYPE_NAME(toType), "COMP3", strlen("COMP3")) == 0) { //COMP3
        retval = cobol_assign_to_packed(toType, fromType, from, buf, is_sign);
    }else if (strncmp (TYPE_NAME(toType), "DISPLAY", strlen("DISPLAY")) == 0) { //ZONED
        retval = cobol_assign_to_zoned(toType, fromType, from, buf, is_sign);
    }

    return retval;
}

struct value *
cobol_assign_to_binary (struct type *toType, struct type *fromType, struct value *from, char* buf, int is_sign, int is_comp5)
{
    enum type_code code1;
    enum type_code code2;


    int fromDigit = TYPE_COB_DIGIT(fromType);
    int fromScale = TYPE_COB_SCALE(fromType);
    int toDigit = TYPE_COB_DIGIT(toType);
    int toScale = TYPE_COB_SCALE(toType);
    int diffScale = 0, diffDigit = 0;
    int display_len = toDigit;

    int i = 0;
    LONGEST srcValue;
    char toBuf[4096];
    memset (toBuf, 0x00, 4096);

    code1 = TYPE_CODE (toType);
    code2 = TYPE_CODE (fromType);

    //printf("[sylee debug]assign_to_binary: buf[%s]\n", buf);
    //printf("[to]digit:%d,scale:%d/[from]digit:%d,scale:%d\n", toDigit, toScale, fromDigit, fromScale);

    if (toScale > fromScale){
        diffScale = toScale - fromScale;
        fromDigit = fromDigit + diffScale;

        memset (buf+strlen(buf), '0', diffScale);
        buf[fromDigit] = '\0';
        //printf("[sylee debug]change buf:[%s]\n", buf);
    }
    else if (toScale < fromScale){
        diffScale = fromScale - toScale;
        buf[strlen(buf)-diffScale] = '\0';
        //printf("[sylee debug]trunc buf:[%s]\n", buf);

    }

    // Calculating the number of digits for COMP5
    if (is_comp5) {
        switch (TYPE_LENGTH(toType)) {
            case 1: //INT8
                display_len = 3;
                break;
            case 2: //INT16
                display_len = 5;
                break;
            case 4: //INT32
                display_len = 10;
                break;
            case 8: //INT64
                display_len = 20;
                break;
        }
    }

    srcValue = atoi(buf);
    srcValue %= cobexp10LL[display_len];

    for (i=display_len-1; i>=0; i--) {
        toBuf[i] = (char) (srcValue % 10 + '0');
        srcValue /= 10;
    }

    //printf("toBuf:[%s]\n", toBuf);
    LONGEST longest = atoi(toBuf);

    if (is_sign == 1)
        longest *= -1;

    return value_from_longest (toType, 0 ? (LONGEST) (longest ? 1 : 0) : longest);
}

struct value *
cobol_assign_to_packed (struct type *toType, struct type *fromType, struct value *from, char* buf, int is_sign)
{
    enum type_code code1;
    enum type_code code2;

    int fromDigit = TYPE_COB_DIGIT(fromType);
    int fromScale = TYPE_COB_SCALE(fromType);
    int toDigit = TYPE_COB_DIGIT(toType);
    int toScale = TYPE_COB_SCALE(toType);
    int diffScale = 0, diffDigit = 0;

    char buffer[4096];
    int i, left, right;
    int bytes;
    LONGEST srcValue;

    int sign = 1;
    char toBuf[4096];
    memset (toBuf, 0x00, 4096);

    code1 = TYPE_CODE (toType);
    code2 = TYPE_CODE (fromType);

    //printf("[sylee debug]assign_to_packed: buf[%s] sign[%d]\n", buf, is_sign);
    //printf("[sylee debug][to] digit:%d/scale:%d [from]digit:%d/scale:%d\n", 
    //        toDigit, toScale, fromDigit, fromScale);

    if (toScale > fromScale) {
        diffScale = toScale - fromScale;
        fromDigit = fromDigit + diffScale;
        memset (buf+strlen(buf), '0', diffScale);
        buf[fromDigit] = '\0';
        //printf("[sylee debug] change buf:[%s]\n", buf);
    }
    else if (toScale < fromScale) {
        diffScale = fromScale - toScale;
        buf[strlen(buf)-diffScale] = '\0';
        //printf("[sylee debug]temp buf:[%s]src:[%ld]\n", buf, srcValue);
    }

    srcValue = atoi(buf);
    srcValue %= cobexp10LL[toDigit];

    if (is_sign == 1)
        srcValue = srcValue * (-1);


    if (srcValue == 0)
        sign = 1;
    else if (srcValue < 0) {
        srcValue *= -1;
        sign = -1;
    }

    bytes = toDigit / 2 + 1;

    sprintf(buffer, "%0*lld", bytes*2-1, srcValue);
    //printf("[sylee debug]buffer:[%s] byte:%d\n",buffer, bytes*2-1); 

    for (i=0; i<bytes; i++) {
        left = buffer[2 * i + 0] - '0';
        if (left < 0 || left > 9){
            error(_("Invalid cast.")); 
            return 0;
        }

        if (i == bytes-1) {
            /* old source */
            /*
            if (is_sign == 1)
                right = 0x0D;
            else
                right = 0x0C;
            */
            if (is_sign == 1) {
                if (sign < 0) right = 0x0D;
                else right = 0x0C;
            }
            else
                right = 0x0F;
        }
        else {
            right = buffer[2 * i + 1] - '0';
            if (right < 0 || right > 9){
                error(_("Invalid cast."));
                return 0;
            }
        }

        toBuf[i] = (left << 4) | right;
        fromDigit = fromDigit + diffScale;
    }

    return value_from_contents_and_address(toType, toBuf, value_address(from));
}

struct value *
cobol_assign_to_zoned (struct type *toType, struct type *fromType, struct value *from, char* buf, int is_sign)
{
    enum type_code code1;
    enum type_code code2;

    int fromDigit = TYPE_COB_DIGIT(fromType);
    int fromScale = TYPE_COB_SCALE(fromType);
    int toDigit = TYPE_COB_DIGIT(toType);
    int toScale = TYPE_COB_SCALE(toType);
    int diffScale = 0, diffDigit = 0;

    int i = 0;
    char buffer[4096];
    LONGEST srcValue;

    char toBuf[4096];
    memset (toBuf, 0x00, 4096);

    code1 = TYPE_CODE (toType);
    code2 = TYPE_CODE (fromType);

    //printf("[sylee debug]assign_to_zoned: buf[%s]\n", buf);

    //printf("[sylee debug][to] digit:%d/scale:%d [from]digit:%d/scale:%d\n", 
    //        toDigit, toScale, fromDigit, fromScale);

    if (toScale > fromScale) {
        diffScale = toScale - fromScale;
        fromDigit = fromDigit + diffScale;

        memset(buf+strlen(buf), '0', diffScale);
        buf[fromDigit] = '\0';
        //printf("[sylee debug]change buf:[%s]\n", buf);
    }
    else if (toScale < fromScale) {
        diffScale = fromScale - toScale;
        buf[strlen(buf)-diffScale] = '\0';
        //printf("scale after:[%s]\n", buf);
        fromDigit = fromDigit + diffScale;
    }

    srcValue = atoi(buf);


    srcValue %= cobexp10LL[toDigit];
    //printf("[sylee debug]temp buf:[%s]src:[%ld]\n", buf, srcValue);

    for(i=toDigit-1; i>=0; i--){
        buffer[i] = (char) (srcValue % 10 + '0');
        srcValue /= 10;
    }

    if (TYPE_COB_SIGN(toType) == 2){ //SIGN_INCLUDE_LEADING
        memcpy (toBuf, buffer, toDigit);
        if (is_sign == 1)
            toBuf[0] = toBuf[0] - '0' + 0x70;
    }
    else if (TYPE_COB_SIGN(toType) == 3){ //SIGN_INCLUDE_TRAILING
        memcpy (toBuf, buffer, toDigit);
        if (is_sign == 1)
            toBuf[toDigit - 1] = toBuf[toDigit - 1] - '0' + 0x70;
    }
    else if (TYPE_COB_SIGN(toType) == 4){ //SIGN_SEPERATE_LEADING
        memcpy (toBuf+1, buffer, toDigit);
        if (is_sign == 1)
            toBuf[0] = '-';
        else
            toBuf[0] = '+';
    }
    else if (TYPE_COB_SIGN(toType) == 5){ //SIGN_SEPERATE_TRAILING
        memcpy (toBuf, buffer, toDigit);
        if (is_sign == 1)
            toBuf[toDigit] = '-';
        else
            toBuf[toDigit] = '+';
    }
    else
        memcpy (toBuf, buffer, toDigit);

    //printf("[sylee debug]testbuf:[%s]buflen:[%d]\n", toBuf, strlen(toBuf));
    return value_from_contents_and_address(toType, toBuf, value_address(from));
}


/* TO: COMP1/COMP2 */
struct value *
cobol_assign_to_flt (struct type *toType, struct type *fromType, struct value *from, char* buf, int is_sign)
{
    int fromDigit = TYPE_COB_DIGIT(fromType);
    int fromScale = TYPE_COB_SCALE(fromType);
    int dotPos = 0;
    DOUBLEST srcValue;

    //printf("[cobol_assign_to_flt]buf:%s/buflen:%d\n", buf, strlen(buf));

    if (fromScale > 0) {
        dotPos = strlen(buf)-fromScale;
        memmove (buf+dotPos+1, buf+dotPos, fromScale);
        buf[dotPos] = '.';
    }

    srcValue = atof(buf);

    if (is_sign == 1)
        srcValue *= -1;

    return value_from_double (toType, srcValue);
}

void cobol_extend_picture (char *ogn_pic, int digit) {
    int pic_len = strlen(ogn_pic);
    int pic_idx = 0, tmp_idx = 0, buf_idx = 0;
    int repeatCount = 0;
    char pic;
    char buf[256];
    char modified[4096];

    memset (buf, 0x00, 256);
    memset (modified, 0x00, 4096);

    for (pic_idx = 0; pic_idx < pic_len; pic_idx++) {
        if (ogn_pic[pic_idx] == '('){
            pic = modified[tmp_idx-1];
            pic_idx++;

            while (ogn_pic[pic_idx] != ')') {
                buf[buf_idx] = ogn_pic[pic_idx];
                pic_idx++;
                buf_idx++;
            }

            repeatCount = atoi(buf);
            buf_idx = 0;
            memset (buf, 0x00, 256);
            memset (modified+strlen(modified), pic, repeatCount-1); 
            tmp_idx = strlen(modified);
        } 
        else {
            modified[tmp_idx] = ogn_pic[pic_idx];
            tmp_idx++;
        }
    }
    memcpy (ogn_pic, modified, strlen(modified));
    ogn_pic[strlen(modified)] = '\0';
}

struct value *
cobol_assign_to_edited (struct type *toType, struct type *fromType, struct value *from, char* buf)
{
    enum type_code code1;
    enum type_code code2;

    int fromDigit = TYPE_COB_DIGIT(fromType);
    int fromScale = TYPE_COB_SCALE(fromType);
    int toDigit = TYPE_COB_DIGIT(toType);
    int toScale = TYPE_COB_SCALE(toType);
    int diffScale = 0, diffDigit = 0;

    int ix, add_len, digit_started = 0;
    int idx = 0;
    int src_len;
    int src_sign = TYPE_COB_SIGN(fromType);
    int is_src_zero = 1;

    int pic_len, scale_status = 0;
    int pic_digit = 0;
    int pic_scale = 0;
    int first_sign = 1, first_currency = 1;
    int pic_idx, tmp_idx, target_idx;
    char insert_char;
    char tmp_buf[4096];
    char target_buf[4096];

    int is_alpha = 0;
    int is_all_Z = 1;
    int is_crdb = 0;
    char credit_str[3];
    char pic[4096];

    int from_scale = 0, from_scale_status = 0;
    char num_buf[4096];
    char from_picstr[4096];
    int from_pic_len = fromDigit;
    int from_pic_digit = 0;

    LONGEST srcValue;
    char modified_buf[4096];
    char toBuf[4096];
    memset (toBuf, 0x00, 4096);

    code1 = TYPE_CODE (toType);
    code2 = TYPE_CODE (fromType);
    //printf("[sylee debug]assign_to_edited: buf[%s]\n", buf);

    //printf("[sylee debug][to] digit:%d/scale:%d [from]digit:%d/scale:%d\n", 
    //        toDigit, toScale, fromDigit, fromScale);

    src_len = strlen(buf);
    for (ix=0; ix<src_len; ix++) {
        if (buf[ix] != '0' && buf[ix] != ' ') {
            is_src_zero = 0;
            break;
        }
    }
    strcpy (pic, TYPE_COB_PIC_STR(toType));
    pic_len = toDigit;

    //printf("pic:[%s] pic_len:[%d]/ src:[%s] src_len:[%d]\n", pic, pic_len, buf, src_len);

    memset(modified_buf, 0x00, 4096);
    cobol_extend_picture (&pic, pic_len);
    //printf("pic:[%s]\n", pic);

    for (pic_idx=0; pic_idx < pic_len; pic_idx++) {
        if (pic[pic_idx] == '0' || pic[pic_idx] == ',' ||
            pic[pic_idx] == '/' || pic[pic_idx] == 'B') {
            continue;
        }
        else if (pic[pic_idx] == 'V' || pic[pic_idx] == '.') {
            scale_status = 1;
            continue;
        }
        else if ((pic[pic_idx] == 'C' && pic[pic_idx+1] == 'R') ||
                 (pic[pic_idx] == 'D' && pic[pic_idx+1] == 'B') ) {
            is_crdb = 1;
            credit_str[0] = pic[pic_idx];
            credit_str[1] = pic[pic_idx+1];
            credit_str[2] = 0x00;
            pic[pic_idx] = 0x00;
            pic_len -= 2;

            break;
        }

        pic_digit++;
        if (scale_status)
            pic_scale++;

        if (pic[pic_idx] == '9' || pic[pic_idx] == '*')
            is_all_Z = 0;
        else if (pic[pic_idx] == 'A' || pic[pic_idx] == 'X')
            is_alpha = 1;
    }

    if (pic[pic_len-1] == '+' || pic[pic_len-1] == '-') {
        if (pic[0] != '+' && pic[0] != '-')
            pic_digit--;
    }

    if (is_src_zero && is_all_Z == 1) {
        memset (toBuf, ' ', toDigit);
        return value_from_contents_and_address (toType, toBuf, value_address(from));
    }

    if (is_alpha) {
        return cobol_assign_to_alpha_edited(toType, fromType, from, pic, buf);
    }
    else {
        // Bring only NUMERIC
        idx = 0;
        memset (num_buf, 0x00, 4096);

        strcpy (from_picstr, TYPE_COB_PIC_STR(fromType));

        from_pic_len = fromDigit;
        from_pic_digit = 0;

        for (ix = 0; ix < from_pic_len; ix++) {
            if (from_picstr[ix] == '0' || from_picstr[ix] == ',' ||
                    from_picstr[ix] == '/' || from_picstr[ix] == 'B') {
                continue;
            }
            else if (from_picstr[ix] == 'V' || from_picstr[ix] == '.') {
                continue;
            }
            else if ((from_picstr[ix] == 'C' && from_picstr[ix+1] == 'R') ||
                    (from_picstr[ix] == 'D' && from_picstr[ix+1] == 'B') ) {
                from_pic_len -= 2;

                break;
            }
            from_pic_digit++;
        }

        if (from_picstr[from_pic_len-1] == '+' || from_picstr[from_pic_len-1] == '-') {
            if (from_picstr[0] != '+' && from_picstr[0] != '-')
                from_pic_digit--;
        }

        //printf("from pic digit:%d\n", from_pic_digit);

        for (ix = 0; ix < src_len; ix++) {
            if (buf[ix] == '+' || buf[ix] == '-') {
                if (buf[ix] == '-')
                    src_sign = 1;
                continue;
            }
            else if (buf[ix] >= '0' && buf[ix] <= '9') {
                num_buf[idx] = buf[ix];
                idx++;
            }
            else if (buf[ix] == '.') {
                from_scale_status = 1;
                continue;
            }
            else if ((buf[ix] >= 'a' && buf[ix] <= 'z') ||
                     (buf[ix] >= 'A' && buf[ix] <= 'Z'))
                error(_("Invalid string."));

            if (from_scale_status)
                from_scale++;
        }
    
        memset (buf, 0x00, strlen(buf));
        memcpy (buf, num_buf, strlen(num_buf));
        buf[from_pic_digit] = '\0';

        fromDigit = strlen(buf);
        src_len = strlen(buf);
        fromScale = from_scale;
    }

    if (fromScale < pic_scale) {
        add_len = pic_scale - fromScale;
        for (ix = 0; ix < add_len; ix++) {
            strcat (buf, "0");
            src_len++;
        }
    }
    else if (fromScale > pic_scale) {
        src_len -= fromScale - pic_scale;
        buf[src_len] = 0x00;
    }

    memset (tmp_buf, '0', pic_digit);

    if (pic_digit >= src_len) {
        memcpy (tmp_buf+pic_digit - src_len, buf, src_len);
    }
    else {
        memcpy (tmp_buf, buf+src_len - pic_digit, pic_digit);
    }

    tmp_buf[pic_digit] = 0x00;
    //printf("tmp_buf:[%s]\n", tmp_buf);

    pic_idx = 0;
    tmp_idx = 0;
    target_idx = 0;
    for (; pic_idx < strlen(pic); pic_idx++) {
        if (digit_started == 0 && tmp_buf[tmp_idx] != '0') {
            digit_started = 1;
        }

        switch (pic[pic_idx]) {
            case 'V':
                break;
            case '9':
                target_buf[target_idx] = tmp_buf[tmp_idx];
                tmp_idx++;
                target_idx++;
                break;
            case '0':
            case ',':
            case '.':
            case '/':
            case 'B':
                if (pic[pic_idx] == 'B') {
                    insert_char = ' ';
                }
                else if (pic[pic_idx] == '0') {
                    insert_char = 'O';
                }
                else if (pic[pic_idx] == '.') {
                    insert_char = pic[pic_idx];
                    digit_started = 1;
                }
                else {
                    insert_char = pic[pic_idx];
                }
                target_buf[target_idx] = insert_char;
                target_idx++;
                break;
            case '+':
            case '-':
                if (first_sign) {
                    target_buf[target_idx] = pic[pic_idx];
                    first_sign = 0;
                }
                else if (digit_started) {
                    target_buf[target_idx] = tmp_buf[tmp_idx];
                }
                else {
                    target_buf[target_idx] = pic[pic_idx];
                }
                target_idx++;
                tmp_idx++;
                break;
            case '$':
                if (first_currency) {
                    target_buf[target_idx] = pic[pic_idx];
                    first_currency = 0;
                }
                else if (digit_started) {
                    target_buf[target_idx] = tmp_buf[tmp_idx];
                }
                else {
                    target_buf[target_idx] = pic[pic_idx];
                }
                target_idx++;
                tmp_idx++;
                break;
            case 'Z':
            case '*':
                if (digit_started) {
                    target_buf[target_idx] = tmp_buf[tmp_idx];
                }
                else {
                    target_buf[target_idx] = pic[pic_idx];
                }
                target_idx++;
                tmp_idx++;
                break;
            default:
                error(_("Invalid cast."));
        }
    }
    target_buf[target_idx] = 0x00;
    //printf("target_buf:[%s]\n", target_buf);

    for (ix = 0; ix < target_idx; ix++) {
        switch (target_buf[ix]){
            case '+':
                if( target_buf[ix + 1] == '+' ) {
                    target_buf[ix] = ' ';
                }
                else if( target_buf[ix + 1] == 'B' ||
                         target_buf[ix + 1] == 'O' || //'O'
                         target_buf[ix + 1] == ',' ||
                         target_buf[ix + 1] == '/' ) {

                    target_buf[ix + 1] = '+';
                    target_buf[ix] = ' ';
                }
                else {
                    if( src_sign == 1 )
                        target_buf[ix] = '-';
                    else
                        target_buf[ix] = '+';
                }
                break;
            case '-':
                if( target_buf[ix + 1] == '-' )
                    target_buf[ix] = ' ';
                else if( target_buf[ix + 1] == 'B' ||
                        target_buf[ix + 1] == 'O' || //'O'
                        target_buf[ix + 1] == ',' ||
                        target_buf[ix + 1] == '/' ) {

                    target_buf[ix + 1] = '-';
                    target_buf[ix] = ' ';
                }
                else {
                    if( src_sign == 1 )
                        target_buf[ix] = '-';
                    else
                        target_buf[ix] = ' ';
                }
                break;
            case '$':
                if( target_buf[ix + 1] == '$' )
                    target_buf[ix] = ' ';
                else if( target_buf[ix + 1] == 'B' ||
                        target_buf[ix + 1] == 'O' || //'O'
                        target_buf[ix + 1] == ',' ||
                        target_buf[ix + 1] == '/' ) {

                    target_buf[ix + 1] = '$';
                    target_buf[ix] = ' ';
                }
                break;
            case 'Z':
                if( target_buf[ix + 1] == 'B' ||
                    target_buf[ix + 1] == 'O' || //'O'
                    target_buf[ix + 1] == ',' ||
                    target_buf[ix + 1] == '/' ) {

                    target_buf[ix + 1] = 'Z';
                    target_buf[ix] = ' ';
                }
                else
                    target_buf[ix] = ' ';
                break;
            case '*':
                if( target_buf[ix + 1] == 'B' ||
                    target_buf[ix + 1] == 'O' || //'O'
                    target_buf[ix + 1] == ',' ||
                    target_buf[ix + 1] == '/' ) {

                    target_buf[ix + 1] = '*';
                    target_buf[ix] = '*';
                }
                else
                    target_buf[ix] = '*';
                break;
            case 'O':
                target_buf[ix] = '0';
                break;
            default:
                break;
        }
    }

    if (is_crdb) {
        if (src_sign == 1)
            strcat (target_buf, credit_str);
        else
            strcat (target_buf, "  " );
        target_idx += 2;
    }

    //printf("last target_buf:[%s]\n", target_buf);
    memcpy( toBuf, target_buf, target_idx );

    return value_from_contents_and_address(toType, toBuf, value_address(from));
}

struct value *
cobol_assign_to_alpha_edited (struct type *toType, struct type *fromType, struct value *from, char* pic, char* buf)
{
    int fromDigit = TYPE_COB_DIGIT(fromType);
    int toDigit = TYPE_COB_DIGIT(toType);
    int targetSize = 0;
    int diffDigit = 0;
    int i, j;

    char toBuf[4096];
    char temp_buf[4096];

    memset (toBuf, 0x00, 4096);
    memset (temp_buf, 0x00, 4096);

    for (i = 0; pic[i] != 0x00; i++) {
        if (pic[i] != 'B' && pic[i] != '/' && pic[i] != '0')
            targetSize++;
    }

    //printf("fromDigit:%d/toDigit:%d/targetSize:%d\n", fromDigit, toDigit, targetSize);
    //printf("pic:[%s] buf:[%s]\n", pic, buf);

    if (targetSize == fromDigit) {
        memcpy (temp_buf, buf, targetSize);
    }else if (targetSize > fromDigit) {
        diffDigit = targetSize - fromDigit;
        memcpy (temp_buf, buf, fromDigit);
    }
    else {
        diffDigit = fromDigit - targetSize;
        memcpy (temp_buf, buf, targetSize);
    }

    for (i = 0, j = 0; pic[i] != 0x00; i++) {
        if (pic[i] == 'B')
            toBuf[i] = ' ';
        else if (pic[i] == '/' || pic[i] == '0')
            toBuf[i] = pic[i];
        else {
            toBuf[i] = temp_buf[j];
            j++;
        }
    }
    //printf("toBuf:[%s]/temp_buf:[%s]\n", toBuf, temp_buf);
    return value_from_contents_and_address(toType, toBuf, value_address(from));
}
