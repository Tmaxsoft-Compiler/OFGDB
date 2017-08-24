/* Support for printing PL/I values for GDB, the GNU debugger.

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

#include "defs.h"
#include "symtab.h"
#include "gdbtypes.h"
#include "gdbcore.h"
#include "expression.h"
#include "value.h"
#include "valprint.h"
#include "language.h"
#include "pli-lang.h"
#include "annotate.h"
#include <netinet/in.h>
#include <math.h>
#include <string.h>

#ifdef _ARC_X86
#include <quadmath.h>
#endif

static const struct generic_val_print_decorations pli_decorations =
{
  "",    /* complex_prefix */
  " + ", /* complex_infix */
  "I",   /* complex_suffix */
  "",    /* true_name */
  "",    /* false_name */
  ""     /* void_name */
};

const char overpunch_plus[10] = { '{', 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I' };
const char overpunch_minus[10] = { '}', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R' };

const long long exp10LL[19] = {                
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

const char display_value[10] = {                                                                                         
    '0', '1', '2', '3', '4', '5', '6', '7', '8', '9'                                                               
}; 

void _print_signed_fixed_bin_val (char*, const struct type*, const gdb_byte*);
void _print_unsigned_fixed_bin_val (char*, const struct type*, const gdb_byte*);
void _print_bit_array_elements (struct type*, const gdb_byte*, int, CORE_ADDR, struct ui_file*,
                                int, const struct value*, const struct value_print_options*, unsigned int);
void _val_print_bit_array (struct type*, const gdb_byte*, int, CORE_ADDR, 
                           struct ui_file*, int, const struct value*, const struct value_print_options*);
void _print_value_fields (struct type*, const gdb_byte*, int, CORE_ADDR,
                              struct ui_file*, int, const struct value*, 
                              const struct value_print_options*);

/* print SIGNED FIXED BINARY value */
void
_print_signed_fixed_bin_val (char* buf, const struct type* type, const gdb_byte* valaddr) 
{
    int8_t negative_flag = 0, endian_flag = TYPE_PLI_ENDIAN (type);
    int16_t conv_length = 1 + ceil (TYPE_PLI_DIGIT (type) / 3.32);
    int16_t scale = TYPE_PLI_SCALE (type), shiftbit;
    int mul_idx = 0;
    int32_t index, buflen, scale_count;
    int64_t fixedbin_value, quotient, remainder;

    /* decoding value: consider endianity */
    /* 1: big endian & 2: little endian */
    if (TYPE_LENGTH (type) == 1) {
        const int8_t* fixedbin_val_ptr = valaddr;
        fixedbin_value = (int8_t) *fixedbin_val_ptr;
    }
    else if (TYPE_LENGTH (type) == 2) {
        const int16_t* fixedbin_val_ptr = valaddr;
        int16_t fixedbin_value_org = (int16_t) *fixedbin_val_ptr ;

        if (endian_flag == 1) {
#ifndef _BIG_ENDIAN
            fixedbin_value_org = htons (fixedbin_value_org);
#endif
        }
        else if (endian_flag == 2) {
#ifdef _BIG_ENDIAN
            fixedbin_value_org = htons (fixedbin_value_org);
#endif
        }

        fixedbin_value = (int16_t) fixedbin_value_org;
    }
    else if (TYPE_LENGTH (type) == 4) {
        const int32_t* fixedbin_val_ptr = valaddr;
        int32_t fixedbin_value_org = (int32_t) *fixedbin_val_ptr;

        if (endian_flag == 1) {
#ifndef _BIG_ENDIAN
            fixedbin_value_org = htonl (fixedbin_value_org);
#endif
        }
        else if (endian_flag == 2) {
#ifdef _BIG_ENDIAN
            fixedbin_value_org = htonl (fixedbin_value_org);
#endif
        }

        fixedbin_value = (int32_t) fixedbin_value_org;
    }
    else if (TYPE_LENGTH (type) == 8) {
        const int64_t* fixedbin_val_ptr = valaddr;
        fixedbin_value = (int64_t) *fixedbin_val_ptr;

        if (endian_flag == 1) {
#ifdef _BIG_ENDIAN
            int64_t conv_value = 0x0000000000000000;
            conv_value |= (fixedbin_value & 0xff00000000000000) >> 56;
            conv_value |= (fixedbin_value & 0x00ff000000000000) >> 40;
            conv_value |= (fixedbin_value & 0x0000ff0000000000) >> 24;
            conv_value |= (fixedbin_value & 0x000000ff00000000) >> 8;
            conv_value |= (fixedbin_value & 0x00000000ff000000) << 8;
            conv_value |= (fixedbin_value & 0x0000000000ff0000) << 24;
            conv_value |= (fixedbin_value & 0x000000000000ff00) << 40;
            conv_value |= (fixedbin_value & 0x00000000000000ff) << 56;

            fixedbin_value = conv_value;
#endif
        }
        else if (endian_flag == 2) {
#ifndef _BIG_ENDIAN
            int64_t conv_value = 0x0000000000000000;
            conv_value |= (fixedbin_value & 0xff00000000000000) >> 56;
            conv_value |= (fixedbin_value & 0x00ff000000000000) >> 40;
            conv_value |= (fixedbin_value & 0x0000ff0000000000) >> 24;
            conv_value |= (fixedbin_value & 0x000000ff00000000) >> 8;
            conv_value |= (fixedbin_value & 0x00000000ff000000) << 8;
            conv_value |= (fixedbin_value & 0x0000000000ff0000) << 24;
            conv_value |= (fixedbin_value & 0x000000000000ff00) << 40;
            conv_value |= (fixedbin_value & 0x00000000000000ff) << 56;

            fixedbin_value = conv_value;
#endif
        }
    }
    else {
        error (_("invalid size for FIXED BIN type"));
    }

    if (fixedbin_value < 0) {
        negative_flag = 1;
        fixedbin_value *= -1;
    }

    shiftbit = scale;
    if (scale < 0) {
        scale = ceil (-1 * scale / 3.32) * -1;
        mul_idx = -scale;
        fixedbin_value <<= -shiftbit;
        fixedbin_value /= exp10LL[mul_idx];
    }
    else if (scale > 0) {
        scale = ceil (scale / 3.32);
        mul_idx = scale;
        fixedbin_value *= exp10LL[mul_idx];
        fixedbin_value >>= shiftbit;
    }

    /* XXX: need to insert F+ char for negative precision? */
    if (conv_length >= scale && scale >= 0) {
        buflen = conv_length + 3;
        index = buflen - 1;
        scale_count = 0;
        memset (buf, ' ', 256);

        while (index > 0) {
            quotient = fixedbin_value / 10;
            remainder = fixedbin_value - (quotient << 3) - (quotient << 1);
            buf[index--] = display_value [remainder];

            fixedbin_value = quotient;
            scale_count++;

            if (scale > 0 && scale_count == scale) buf[index--] = '.';
            if (fixedbin_value == 0 && scale_count > scale) break;
        }

        /* insert sign */
        if (negative_flag == 1)
            buf[index] = '-';

        buf[buflen] = 0x00;
    }
    else {
        buflen = conv_length + 1;
        index = buflen - 1;
        memset (buf, ' ', 256);

        while (index > 0) {
            quotient = fixedbin_value / 10;
            remainder = fixedbin_value - (quotient << 3) - (quotient << 1);
            buf[index--] = display_value [remainder];

            fixedbin_value = quotient;

            if (fixedbin_value == 0) break;
        }

        /* insert sign */
        if (negative_flag == 1)
            buf[index] = '-';

        buf[buflen] = 'F';
        /* insert F-nn */
        if (scale > 0) {
            buf[buflen + 1] = 0x00;
            sprintf (buf + buflen + 1, "%d", -scale);
        }
        /* insert F+nn */
        else {
            buf[buflen + 1] = '+';
            buf[buflen + 2] = 0x00;
            sprintf (buf + buflen + 2, "%d", -scale);
        }
    }

}

/* print UNSIGNED FIXED BINARY value */
void
_print_unsigned_fixed_bin_val (char* buf, const struct type *type, const gdb_byte *valaddr) 
{
    int8_t negative_flag = 0, endian_flag = TYPE_PLI_ENDIAN (type);
    int16_t conv_length = 1 + ceil (TYPE_PLI_DIGIT (type) / 3.32);
    int16_t scale = TYPE_PLI_SCALE (type), shiftbit;
    int mul_idx = 0;
    int32_t index, buflen, scale_count;
    uint64_t fixedbin_value, quotient, remainder;

    /* decoding value: consider endianity */
    /* 1: big endian & 2: little endian */
    if (TYPE_LENGTH (type) == 1) {
        const uint8_t* fixedbin_val_ptr = valaddr;
        fixedbin_value = (uint8_t) *fixedbin_val_ptr;
    }
    else if (TYPE_LENGTH (type) == 2) {
        const uint16_t* fixedbin_val_ptr = valaddr;
        uint16_t fixedbin_value_org = (uint16_t) *fixedbin_val_ptr ;

        if (endian_flag == 1) {
#ifndef _BIG_ENDIAN
            fixedbin_value_org = htons (fixedbin_value_org);
#endif
        }
        else if (endian_flag == 2) {
#ifdef _BIG_ENDIAN
            fixedbin_value_org = htons (fixedbin_value_org);
#endif
        }

        fixedbin_value = (uint16_t) fixedbin_value_org;
    }
    else if (TYPE_LENGTH (type) == 4) {
        const uint32_t* fixedbin_val_ptr = valaddr;
        uint32_t fixedbin_value_org = (uint32_t) *fixedbin_val_ptr;

        if (endian_flag == 1) {
#ifndef _BIG_ENDIAN
            fixedbin_value_org = htonl (fixedbin_value_org);
#endif
        }
        else if (endian_flag == 2) {
#ifdef _BIG_ENDIAN
            fixedbin_value_org = htonl (fixedbin_value_org);
#endif
        }

        fixedbin_value = (uint32_t) fixedbin_value_org;
    }
    else if (TYPE_LENGTH (type) == 8) {
        const uint64_t* fixedbin_val_ptr = valaddr;
        fixedbin_value = (uint64_t) *fixedbin_val_ptr;

        if (endian_flag == 1) {
#ifdef _BIG_ENDIAN
            int64_t conv_value = 0x0000000000000000;
            conv_value |= (fixedbin_value & 0xff00000000000000) >> 56;
            conv_value |= (fixedbin_value & 0x00ff000000000000) >> 40;
            conv_value |= (fixedbin_value & 0x0000ff0000000000) >> 24;
            conv_value |= (fixedbin_value & 0x000000ff00000000) >> 8;
            conv_value |= (fixedbin_value & 0x00000000ff000000) << 8;
            conv_value |= (fixedbin_value & 0x0000000000ff0000) << 24;
            conv_value |= (fixedbin_value & 0x000000000000ff00) << 40;
            conv_value |= (fixedbin_value & 0x00000000000000ff) << 56;

            fixedbin_value = conv_value;
#endif
        }
        else if (endian_flag == 2) {
#ifndef _BIG_ENDIAN
            int64_t conv_value = 0x0000000000000000;
            conv_value |= (fixedbin_value & 0xff00000000000000) >> 56;
            conv_value |= (fixedbin_value & 0x00ff000000000000) >> 40;
            conv_value |= (fixedbin_value & 0x0000ff0000000000) >> 24;
            conv_value |= (fixedbin_value & 0x000000ff00000000) >> 8;
            conv_value |= (fixedbin_value & 0x00000000ff000000) << 8;
            conv_value |= (fixedbin_value & 0x0000000000ff0000) << 24;
            conv_value |= (fixedbin_value & 0x000000000000ff00) << 40;
            conv_value |= (fixedbin_value & 0x00000000000000ff) << 56;

            fixedbin_value = conv_value;
#endif
        }
    }
    else {
        error (_("invalid size for FIXED BIN type"));
    }

    shiftbit = scale;
    if (scale < 0) {
        scale = ceil (-1 * scale / 3.32) * -1;
        mul_idx = -scale;
        fixedbin_value <<= -shiftbit;
        fixedbin_value /= exp10LL[mul_idx];
    }
    else if (scale > 0) {
        scale = ceil (scale / 3.32);
        mul_idx = scale;
        fixedbin_value *= exp10LL[mul_idx];
        fixedbin_value >>= shiftbit;
    }

    /* XXX: need to insert F+ char for negative precision? */
    if (conv_length >= scale && scale >= 0) {
        buflen = conv_length + 3;
        index = buflen - 1;
        scale_count = 0;
        memset (buf, ' ', 256);

        while (index > 0) {
            quotient = fixedbin_value / 10;
            remainder = fixedbin_value - (quotient << 3) - (quotient << 1);
            buf[index--] = display_value [remainder];

            fixedbin_value = quotient;
            scale_count++;

            if (scale > 0 && scale_count == scale) buf[index--] = '.';
            if (fixedbin_value == 0 && scale_count > scale) break;
        }

        buf[buflen] = 0x00;
    }
    else {
        buflen = conv_length + 1;
        index = buflen - 1;
        memset (buf, ' ', 256);

        while (index > 0) {
            quotient = fixedbin_value / 10;
            remainder = fixedbin_value - (quotient << 3) - (quotient << 1);
            buf[index--] = display_value [remainder];

            fixedbin_value = quotient;

            if (fixedbin_value == 0) break;
        }

        buf[buflen] = 'F';
        /* insert F-nn */
        if (scale > 0) {
            buf[buflen + 1] = 0x00;
            sprintf (buf + buflen + 1, "%d", -scale);
        }
        /* insert F+nn */
        else {
            buf[buflen + 1] = '+';
            buf[buflen + 2] = 0x00;
            sprintf (buf + buflen + 2, "%d", -scale);
        }
    }

}

/* print BIT type array elements: based on val_print_array_elements function in valprint.c */
void
_print_bit_array_elements (struct type* type, const gdb_byte* valaddr, int embedded_bit_offset, CORE_ADDR address, struct ui_file* stream,
                           int recurse, const struct value* val, const struct value_print_options* options, unsigned int i)
{
    unsigned int things_printed = 0;
    unsigned len;
    struct type *elttype, *index_type;
    unsigned eltlen;
    /* Position of the array element we are examining to see
       whether it is repeated.  */
    unsigned int rep1;
    /* Number of repetitions we have detected so far.  */
    unsigned int reps;
    LONGEST low_bound, high_bound;

    /* for getting the element size by bit unit */
    unsigned int elt_size, elt_offs;
    unsigned int num_of_leaf_elem = 1; 
    struct type* leaf_elttype = elttype;
    struct type* unresolved_elttype;

    elttype = TYPE_TARGET_TYPE (type);
    eltlen = TYPE_LENGTH (check_typedef (elttype));
    index_type = TYPE_INDEX_TYPE (type);

    if (get_array_bounds (type, &low_bound, &high_bound)) {
        if (low_bound > high_bound)
            len = 0;
        else
            len = high_bound - low_bound + 1;
    }
    else {
        warning (_("unable to get bounds of array, assuming null array"));
        low_bound = 0;
        len = 0;
    }

    /* get the element size */
    leaf_elttype = elttype;
    while (TYPE_CODE (leaf_elttype) == TYPE_CODE_ARRAY) {
        LONGEST low_bound, high_bound;
        if (!get_array_bounds (leaf_elttype, &low_bound, &high_bound))
            error (_("Could not determine the array high bound"));

        unresolved_elttype = TYPE_TARGET_TYPE (leaf_elttype);
        leaf_elttype = check_typedef (unresolved_elttype);

        num_of_leaf_elem *= (high_bound - low_bound + 1);
    }
    elt_size = num_of_leaf_elem * TYPE_PLI_BITSIZE (leaf_elttype);

    annotate_array_section_begin (i, elttype);
    for (; i < len && things_printed < options->print_max; i++)
    { 
        elt_offs = elt_size * i;

        if (i != 0)
        { 
            if (options->prettyformat_arrays)
            { 
                fprintf_filtered (stream, ",\n");
                print_spaces_filtered (2 + 2 * recurse, stream);
            }
            else
            { 
                fprintf_filtered (stream, ", ");
            }
        } 
        wrap_here (n_spaces (2 + 2 * recurse));
        maybe_print_array_index (index_type, i + low_bound,
                stream, options);

        rep1 = i + 1;
        reps = 1;
        /* Only check for reps if repeat_count_threshold is not set to UINT_MAX (unlimited).  */
        /* TODO: test is necessary */
        if (options->repeat_count_threshold < UINT_MAX)
        { 
            while (rep1 < len
                    && value_available_contents_eq (val, (embedded_bit_offset + elt_offs) / 8, val,
                       (embedded_bit_offset / 8 + rep1 * eltlen), eltlen))
            { 
                ++reps;
                ++rep1;
            }
        } 


        if (reps > options->repeat_count_threshold)
        {
            if (TYPE_CODE (elttype) == TYPE_CODE_ARRAY)
                _val_print_bit_array (elttype, valaddr, embedded_bit_offset + elt_offs, address, stream, recurse + 1, val, options);
            else {
                unsigned int elt_byte_size;

                /* set offset */
                elt_byte_size = (embedded_bit_offset + elt_offs + elt_size) / 8 - (embedded_bit_offset + elt_offs) / 8 + 1;
                TYPE_LENGTH (elttype) = elt_byte_size;
                TYPE_PLI_BITOFFSET (elttype) = (embedded_bit_offset + elt_offs) % 8;

                pli_val_print (elttype, valaddr, (embedded_bit_offset + elt_offs) / 8, address, stream, recurse + 1, val, options);
            }

            annotate_elt_rep (reps);
            fprintf_filtered (stream, " <repeats %u times>", reps);
            annotate_elt_rep_end ();

            i = rep1 - 1;
            things_printed += options->repeat_count_threshold;
        }
        else
        {
            if (TYPE_CODE (elttype) == TYPE_CODE_ARRAY) {
                _val_print_bit_array (elttype, valaddr, embedded_bit_offset + elt_offs, address, stream, recurse + 1, val, options);
            }
            else {
                unsigned int elt_byte_size;

                /* set offset */
                elt_byte_size = (embedded_bit_offset + elt_offs + elt_size) / 8 - (embedded_bit_offset + elt_offs) / 8 + 1;
                TYPE_LENGTH (elttype) = elt_byte_size;
                TYPE_PLI_BITOFFSET (elttype) = (embedded_bit_offset + elt_offs) % 8;

                pli_val_print (elttype, valaddr, (embedded_bit_offset + elt_offs) / 8, address, stream, recurse + 1, val, options);
            }

            annotate_elt ();
            things_printed++;
        }
    }
    annotate_array_section_end ();
    if (i < len)
    {
        fprintf_filtered (stream, "...");
    }
}

void
_val_print_bit_array (struct type* type, const gdb_byte* valaddr,
                      int embedded_offset, CORE_ADDR address, 
                      struct ui_file* stream, int recurse, const struct value* val, const struct value_print_options* options)
{
    struct type* elttype;
    struct type* unresolved_elttype;

    /* get the element type */
    unresolved_elttype = TYPE_TARGET_TYPE (type);
    elttype = check_typedef (unresolved_elttype);

    if (options->prettyformat_arrays)
        print_spaces_filtered (2 + 2 * recurse, stream);

    fprintf_filtered (stream, "{");
    _print_bit_array_elements (type, valaddr, embedded_offset, address, stream,
                               recurse, val, options, 0);
    fprintf_filtered (stream, "}");
}

void
_print_value_fields (struct type* type, const gdb_byte* valaddr, int offset, CORE_ADDR address,
                         struct ui_file* stream, int recurse, const struct value* val, const struct value_print_options* options)
{
    int i, len, n_baseclasses;

    CHECK_TYPEDEF (type);

    fprintf_filtered (stream, "{");
    len = TYPE_NFIELDS (type);
    n_baseclasses = TYPE_N_BASECLASSES (type);

    if (!len && n_baseclasses == 1)
        fprintf_filtered (stream, "<No data fields>");
    else {
        int fields_seen = 0;

        for (i = n_baseclasses; i < len; i++) {
            if (field_is_static (&TYPE_FIELD (type, i))) {
                const char* name = TYPE_FIELD_NAME (type, i);

                if (!options->static_field_print)
                    continue;
            }
            if (fields_seen)
                fprintf_filtered (stream, ", ");

            fields_seen = 1;

            if (options->prettyformat) {
                fprintf_filtered (stream, "\n");
                print_spaces_filtered (2 + 2 * recurse, stream);
            }
            else {
                wrap_here (n_spaces (2 + 2 * recurse));
            }

            annotate_field_begin (TYPE_FIELD_TYPE (type, i));

            if (field_is_static (&TYPE_FIELD (type, i)))
                fputs_filtered ("static ", stream);

            fputs_filtered (TYPE_FIELD_NAME (type, i), stream);
            annotate_field_name_end ();
            fputs_filtered (": ", stream);
            annotate_field_value ();

            if (!field_is_static (&TYPE_FIELD (type, i)) && TYPE_FIELD_PACKED (type, i)) {
                /* #XXX: may use BIT type members */
            }
            else {
                if (TYPE_FIELD_IGNORE (type, i)) {
                    fputs_filtered ("<optimized out or zero length>", stream);
                }
                else if (field_is_static (&TYPE_FIELD (type, i))) {
                    struct value_print_options opts;
                    struct value *v = value_static_field (type, i);
                    struct type *t = check_typedef (value_type (v));

                    if (TYPE_CODE (t) == TYPE_CODE_STRUCT)
                        v = value_addr (v);
                    opts = *options;
                    opts.deref_ref = 0;
                    common_val_print (v, stream, recurse + 1, &opts, current_language);
                }
                else if (TYPE_FIELD_TYPE (type, i) == NULL) {
                    fputs_filtered ("<unknown type>", stream);
                }
                else {
                    struct value_print_options opts = *options;
                    unsigned int field_offset;

                    opts.deref_ref = 0;
                    field_offset = offset * 8 + TYPE_PLI_STRUCT_BIT_OFFSET (type) + FIELD_BITPOS_LVAL (TYPE_FIELD (type, i));
     
                    if (field_offset % 8 != 0)
                        TYPE_PLI_STRUCT_BIT_OFFSET (FIELD_TYPE (TYPE_FIELD (type, i))) = field_offset % 8;

                    pli_val_print (TYPE_FIELD_TYPE (type, i), 
                                   valaddr, field_offset / 8, address, 
                                   stream, recurse + 1, val, &opts);
                }
            }
            annotate_field_end ();
        }

        if (options->prettyformat) {
            fprintf_filtered (stream, "\n");
            print_spaces_filtered (2 * recurse, stream);
        }
    }
    fprintf_filtered (stream, "}");
}

void
pli_val_print (struct type* type, const gdb_byte* valaddr, int embedded_offset, CORE_ADDR address, 
               struct ui_file* stream, int recurse, const struct value* original_value, const struct value_print_options* options)
{
    struct gdbarch *gdbarch = get_type_arch (type);
    enum bfd_endian byte_order = gdbarch_byte_order (gdbarch);
    unsigned int num_print_ch = 0;
    unsigned len;
    struct type* elttype;
    struct type* unresolved_elttype;
    struct type* unresolved_type = type;
    unsigned eltlen;
    LONGEST val;
    CORE_ADDR addr;

    CHECK_TYPEDEF (type);

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
                if (options->prettyformat_arrays)
                    print_spaces_filtered (2 + 2 * recurse, stream);

                fprintf_filtered (stream, "{");

                if (TYPE_CODE (elttype) == TYPE_CODE_BIT) {
                    _print_bit_array_elements (type, valaddr, embedded_offset * 8, address, stream,
                                               recurse, original_value, options, 0);
                }
                else if (TYPE_CODE (elttype) == TYPE_CODE_ARRAY) {
                    while (TYPE_CODE (elttype) == TYPE_CODE_ARRAY) {
                        unresolved_elttype = TYPE_TARGET_TYPE (elttype);
                        elttype = check_typedef (unresolved_elttype);
                    }

                    if (TYPE_CODE (elttype) == TYPE_CODE_BIT) {
                        _print_bit_array_elements (type, valaddr, embedded_offset * 8, address, stream,
                                recurse, original_value, options, 0);
                    }
                    else {
                        val_print_array_elements (type, valaddr, embedded_offset, address, stream,
                                recurse, original_value, options, 0);
                    }
                }
                else {
                    val_print_array_elements (type, valaddr, embedded_offset, address, stream,
                                              recurse, original_value, options, 0);
                }
                fprintf_filtered (stream, "}");
            }
            break;
            /* TODO: Array of unspecified length: treat like pointer to first elt.  */

        case TYPE_CODE_PTR:
            if (options->format && options->format != 's') {
                val_print_scalar_formatted (type, valaddr, embedded_offset, original_value, options, 0, stream);
                break;
            }

            unresolved_elttype = TYPE_TARGET_TYPE (type);
            elttype = check_typedef (unresolved_elttype);

            {
                addr = unpack_pointer (type, valaddr + embedded_offset);

                if (TYPE_CODE (elttype) == TYPE_CODE_FUNC) {
                    /* Try to print what function it points to.  */
                    print_function_pointer_address (options, gdbarch, addr, stream);
                    return;
                }

                if (options->addressprint)
                    fputs_filtered (paddress (gdbarch, addr), stream);
                return;
            }
            break;

        case TYPE_CODE_STRUCT:
            _print_value_fields (type, valaddr, embedded_offset, address, stream, recurse, original_value, options);
            break;

        /* TODO: need to implement */
        case TYPE_CODE_UNION:
        case TYPE_CODE_ENUM:
            error (_("Not supported yet"));
            break;

        case TYPE_CODE_SIGNED_FIXED_B:
            {
                char buf[256] = {0, };

                _print_signed_fixed_bin_val (buf, type, valaddr + embedded_offset);
                fputs_filtered (buf, stream);
            }
            break;
        case TYPE_CODE_UNSIGNED_FIXED_B:
            {
                char buf[256] = {0, };

                _print_unsigned_fixed_bin_val (buf, type, valaddr + embedded_offset);
                fputs_filtered (buf, stream);
            }
            break;

        case TYPE_CODE_PACKED:
            {
                int16_t idx, sign = 0;
                int16_t length = TYPE_PLI_DIGIT (type) / 2 + 1;
                int16_t scale  = TYPE_PLI_SCALE (type);
                const unsigned char* packed_char = valaddr + embedded_offset;
                char buf[256] = {0, };

                char* buf_ptr = buf;
                int left, right, first_nonzero_pos;

                for (idx = 0; idx < length; idx++) {
                    left = ((int) packed_char[idx] & 0xF0) >> 4;
                    right = ((int) packed_char[idx] & 0x0F);

                    *buf_ptr++ = '0' + left;

                    if (idx == length - 1) {
                        if (right == 0x0A || right == 0x0C || right == 0x0E ||
                            right == 0x0F || right == 0x00)
                        {
                            sign = 1;
                        }
                        else if (right == 0x0B || right == 0x0D) 
                        {
                            sign = -1;
                        }
                        else {
                            error (_("invalid sign char"));
                        }
                    }
                    else {
                        *buf_ptr++ = '0' + right;
                    }
                }
                *buf_ptr++ = 0x00;

                /* insert decimal point */
                if (scale > 0) {
                    int16_t digit = TYPE_PLI_DIGIT (type);

                    if (digit > scale) {
                        int16_t decimal_idx = strlen(buf) - scale;

                        memmove (buf + 1 + decimal_idx, buf + decimal_idx, scale);
                        buf[decimal_idx] = '.';
                    }
                    else if (digit == scale) {
                        int move_idx = 0;

                        if (digit % 2 == 0)
                            move_idx = 1;
                        else
                            move_idx = 2;

                        memmove (buf + move_idx, buf, strlen(buf));
                        buf[0] = '0';
                        buf[1] = '.';
                    }
                    else {
                        char scale_char[3] = {0, };
                        int16_t fscale_idx = strlen(buf);

                        buf[fscale_idx] = 'F';
                        buf[fscale_idx + 1] = '-';

                        snprintf(scale_char, sizeof(scale_char), "%d", scale);
                        buf[fscale_idx + 2] = scale_char[0];
                        buf[fscale_idx + 3] = scale_char[1];
                        buf[fscale_idx + 4] = scale_char[2];
                    }
                }
                else if (scale < 0) {
                    char scale_char[3] = {0, };
                    int16_t fscale_idx = strlen(buf);

                    buf[fscale_idx] = 'F';
                    buf[fscale_idx + 1] = '+';

                    snprintf(scale_char, sizeof(scale_char), "%d", -scale);
                    buf[fscale_idx + 2] = scale_char[0];
                    buf[fscale_idx + 3] = scale_char[1];
                    buf[fscale_idx + 4] = scale_char[2];
                }

                /* eliminate unnecessary zero */
                first_nonzero_pos = 0;
                while (buf[first_nonzero_pos] == '0')
                    first_nonzero_pos++;

                if (buf[first_nonzero_pos] == '.')
                    first_nonzero_pos--;

                /* insert sign */
                memmove (buf + 1, buf + first_nonzero_pos, strlen(buf));
                if (sign == -1)
                    buf[0] = '-';
                else if (sign == 1)
                    buf[0] = ' ';

                /* if value = 0, input '0' character */
                if (strlen(buf) == 1) {
                    buf[1] = '0';
                    buf[2] = 0x00;
                }

                fputs_filtered (buf, stream);
            }
            break;

        case TYPE_CODE_DECFLOAT: 
        case TYPE_CODE_FLT:
            {
                int16_t digit = TYPE_PLI_DIGIT (type);
                char buf[256] = {0, };

                if (TYPE_CODE (type) == TYPE_CODE_FLT)
                    digit = ceil (digit / 3.32);

                /* float */
                if (TYPE_LENGTH (type) == 4) {
                    const float* float_val_ptr = valaddr + embedded_offset;

                    if (digit == 1)
                        sprintf(buf, "%.*E", digit, *float_val_ptr);
                    else
                        sprintf(buf, "%.*E", digit-1, *float_val_ptr);
                }
                /* double */
                else if (TYPE_LENGTH (type) == 8) {
                    const double* float_val_ptr = valaddr + embedded_offset;

                    if (digit == 1)
                        sprintf(buf, "%.*E", digit, *float_val_ptr);
                    else
                        sprintf(buf, "%.*E", digit-1, *float_val_ptr);
                }
                /* ext-float */
                else if (TYPE_LENGTH (type) == 16) {
                    const __float128* float_val_ptr = valaddr + embedded_offset;

                    if (digit == 1) {
#if defined(_ARC_X86)
                    quadmath_snprintf(buf, sizeof(buf), "%.*QE", digit, *float_val_ptr);
#elif defined(_ARC_SPARC)
                    snprintf(buf, sizeof(buf), "%.*LE", digit, *float_val_ptr);
#endif
                    }
                    else {
#if defined(_ARC_X86)
                    quadmath_snprintf(buf, sizeof(buf), "%.*QE", digit-1, *float_val_ptr);
#elif defined(_ARC_SPARC)
                    snprintf(buf, sizeof(buf), "%.*LE", digit-1, *float_val_ptr);
#endif
                    }
                }
                else {
                    error (_("invalid size for FLOAT type"));
                }

                fputs_filtered (buf, stream);
            }
            break;

        case TYPE_CODE_BIT:
            {
                /* #TODO: currently, OFPLI does not support varying bit type */
                /* int8_t varying_flag = TYPE_PLI_VARYING (type); */
                const char* bit_val = valaddr + embedded_offset;
                char* buf = NULL;
                int bit_len = 0, buf_idx = 0, idx, idx_2;
                int buf_len = 0;

                /* NONVARYING BIT */
                bit_len = TYPE_PLI_BITSIZE (type);
                buf_len = TYPE_LENGTH (type) * 8;
                buf = (char*) alloca (buf_len + 1);

                for (idx = 0; idx < TYPE_LENGTH (type); idx++) {
                    for (idx_2 = 7; idx_2 >= 0; idx_2--) {
                        buf[buf_idx] = ((bit_val[idx] >> idx_2) & 1) + '0';
                        buf_idx++;
                    }
                }

                if (TYPE_PLI_BITOFFSET (type) != 0)
                    memmove(buf, buf + TYPE_PLI_BITOFFSET (type), bit_len);
                
                buf[bit_len] = 0x00;
                fputs_filtered (buf, stream);
            }
            break;

        case TYPE_CODE_CHAR:
            {
                int8_t varying_flag = TYPE_PLI_VARYING (type);
                int8_t endian_flag = TYPE_PLI_ENDIAN (type);
                char* char_val = NULL;
                char* buf = NULL;
                int char_len = 0;

                /* VARYING CHARACTER */
                if (varying_flag == 1) {
                    /* get char length */
                    char char_real_len[3] = {0, };

                    memcpy (char_real_len, valaddr + embedded_offset, 2);
                    char_len = (char_real_len[0] << 8 | char_real_len[1]);

                    /* decoding length: consider endianity */
                    /* 1: big endian & 2: little endian */
                    if (endian_flag == 1) {
#ifdef _BIG_ENDIAN
                        char_len = htons (char_len);
#endif
                    }
                    else if (endian_flag == 2) {
#ifndef _BIG_ENDIAN
                        char_len = htons (char_len);
#endif
                    }

                    char_val = valaddr + embedded_offset + 2;
                }
                /* NONVARYING CHARACTER */ 
                else {
                    char_val = valaddr + embedded_offset;
                    char_len = TYPE_PLI_LENGTH (type);
                }

                /* get & print character string */
                buf = (char*) alloca (char_len + 1);
                memcpy (buf, char_val, char_len);
                buf[char_len] = 0x00;

                fputs_filtered (buf, stream);
            }
            break;

        case TYPE_CODE_DBCS:
            error (_("Not supported yet"));
            break;

        case TYPE_CODE_PICTURE:
            {
                char* pic_str = TYPE_PLI_PIC_STR (type);
                char* pic_val = valaddr + embedded_offset;
                int pic_len = TYPE_LENGTH (type);
                char buf[512] = {0, };

                memcpy (buf, pic_val, pic_len);
                fputs_filtered (buf, stream);
            }
            break;

        case TYPE_CODE_FUNC:
            generic_val_print (type, valaddr, embedded_offset, address,
                    stream, recurse, original_value, options,
                    &pli_decorations);
            break;

        /* XXX: PL/I debugger may not need this type processing */
        case TYPE_CODE_INT:
            if (options->format || options->output_format) {
                struct value_print_options opts = *options;

                opts.format = (options->format ? options->format
                        : options->output_format);
                val_print_scalar_formatted (type, valaddr, embedded_offset,
                        original_value, &opts, 0, stream);
            }
            else {
                val_print_type_code_int (type, valaddr + embedded_offset,
                        stream);
            }
            break;

        default:
            error (_("Invalid PL/I type code %d in the symbol table"), TYPE_CODE (type));
    }

    gdb_flush (stream);
}

void
pli_value_print (struct value* val, struct ui_file* stream, const struct value_print_options* options)
{
    struct type *type, *real_type, *val_type;
    int full, top, using_enc;
    struct value_print_options opts = *options;

    opts.deref_ref = 1;

    val_type = value_type (val);
    type = check_typedef (val_type);

    if (!value_initialized (val))
        fprintf_filtered (stream, " [uninitialized] ");

    val_print (val_type, value_contents_for_printing (val),
               value_embedded_offset (val),
               value_address (val),
               stream, 0,
               val, &opts, current_language);
}
