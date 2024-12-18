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

#include "defs.h"
#include "symtab.h"
#include "gdbtypes.h"
#include "expression.h"
#include "parser-defs.h"
#include "language.h"
#include "symfile.h"
#include "objfiles.h"
#include <string.h>
#include "value.h"
#include "c-lang.h" /* temporary including */
#include "pli-lang.h"
#include "varobj.h"
#include "gdbcore.h"
#include "block.h"
#include "demangle.h"
#include "dictionary.h"
#include <ctype.h>
#include "charset.h"
#include "valprint.h"
#include "cp-support.h"

#include <math.h>
#include <string.h>

/* Local functions */
extern void _initialize_pli_language (void);

/* #FIXME: need implement */
void
pli_emit_char (int c, struct type* type, struct ui_file* stream, int quoter)
{
}

/* #FIXME: need implement */
void
pli_printchar (int c, struct type* type, struct ui_file* stream)
{
}

/* #FIXME: need implement */
void
pli_printstr (struct ui_file* stream, struct type* type, const gdb_byte* string, unsigned int length,
              const char* user_encoding, int force_ellipses, const struct value_print_options* options)
{
}


/* Return the value of EXPR[IDX] (Just for BIT type arrays) */
struct value*
value_subscripted_rvalue_pli_bit (struct value* array, LONGEST index, int lowerbound, int upperbound)
{
    struct type *array_type = check_typedef (value_type (array));
    struct type *elt_type = check_typedef (TYPE_TARGET_TYPE (array_type));
    unsigned int elt_size = TYPE_PLI_BITSIZE (elt_type);
    unsigned int elt_offs = elt_size * longest_to_int (index - lowerbound);
    unsigned int elt_byte_size = ceil((elt_offs + elt_size - 1.0) / 8) - (elt_offs / 8);

    struct value *v;

    if (index < lowerbound || (!TYPE_ARRAY_UPPER_BOUND_IS_UNDEFINED (array_type)
                && elt_offs >= elt_size * (upperbound - lowerbound + 1)))
        error (_("no such vector element"));

    if (VALUE_LVAL (array) == lval_memory && value_lazy (array))
        v = allocate_value_lazy (elt_type);
    else {
        v = allocate_value (elt_type);
        value_contents_copy (v, value_embedded_offset (v),
                array, value_embedded_offset (array) + (elt_offs / 8),
                elt_byte_size);
    }

    set_value_component_location (v, array);
    VALUE_REGNUM (v) = VALUE_REGNUM (array);
    VALUE_FRAME_ID (v) = VALUE_FRAME_ID (array);

    /* set offset */
    set_value_offset (v, value_offset (array) + (elt_offs / 8));
    TYPE_LENGTH (elt_type) = elt_byte_size;
    TYPE_PLI_BITOFFSET (elt_type) = elt_offs %  8;

    return v;
}

struct value*
value_subscript_pli (struct value* array, LONGEST index)
{
    int c_style = current_language->c_style_arrays;
    struct type *tarray;
    struct type *elt_type;

    array = coerce_ref (array);
    tarray = check_typedef (value_type (array));
    elt_type = check_typedef (TYPE_TARGET_TYPE (tarray));

    if (TYPE_CODE (tarray) == TYPE_CODE_ARRAY) {
        struct type *range_type = TYPE_INDEX_TYPE (tarray);
        LONGEST lowerbound, upperbound;

        get_discrete_bounds (range_type, &lowerbound, &upperbound);
        if (VALUE_LVAL (array) != lval_memory) {
            if (TYPE_CODE (elt_type) == TYPE_CODE_BIT)
                return value_subscripted_rvalue_pli_bit (array, index, lowerbound, upperbound);
            else
                return value_subscripted_rvalue (array, index, lowerbound);
        }

        if (c_style == 0) {
            if (index >= lowerbound && index <= upperbound) {
                if (TYPE_CODE (elt_type) == TYPE_CODE_BIT)
                    return value_subscripted_rvalue_pli_bit (array, index, lowerbound, upperbound);
                else
                    return value_subscripted_rvalue (array, index, lowerbound);
            }

            /* Emit warning unless we have an array of unknown size.
               An array of unknown size has lowerbound 0 and upperbound -1.  */
            if (upperbound > -1)
                warning (_("array index out of range"));

            /* fall doing C stuff */
            c_style = 1;
        }      

        index -= lowerbound;
        array = value_coerce_array (array);
    }      

    if (c_style)
        return value_ind (value_ptradd (array, index));
    else     
        error (_("not an array"));
}

/* Expression evaluator for the PL/I language.
   Currently, this function evaluates bit type arrays */
struct value*
evaluate_subexp_pli (struct type* expect_type, struct expression* exp, int* pos, enum noside noside)
{
    int pc = *pos;
    struct value* arg1 = NULL;
    struct value* arg2 = NULL;
    struct type* type;
    enum exp_opcode op = exp->elts[*pos].opcode;

    switch (op) {
        case BINOP_SUBSCRIPT:
            {
                (*pos)++;

                arg1 = evaluate_subexp_with_coercion (exp, pos, noside);
                arg2 = evaluate_subexp_with_coercion (exp, pos, noside);

                if (noside == EVAL_SKIP) 
                    return value_from_longest (builtin_type (exp->gdbarch)->builtin_int, 1);

                arg1 = coerce_ref (arg1);
                type = check_typedef (value_type (arg1));

                if (TYPE_CODE (type) == TYPE_CODE_STRUCT) {
                    int inputIdx = value_as_long (arg2);
                    int lower_bnd = atoi (strchr (TYPE_FIELD_NAME(type, 0), '[') + 1);
                    int upper_bnd = atoi (strchr (TYPE_FIELD_NAME(type, TYPE_NFIELDS(type) - 1), '[') + 1);

                    /* range check */
                    if (inputIdx < lower_bnd || inputIdx > upper_bnd)
                        error (_("array index out of range"));

                    return value_primitive_field (arg1, 0, inputIdx - lower_bnd, type); 
                }
                if (TYPE_CODE (type) != TYPE_CODE_ARRAY) { 
                    if (TYPE_NAME (type))
                        error (_("cannot subscript something of type `%s'"), TYPE_NAME (type));
                    else
                        error (_("cannot subscript requested type"));
                }

                if (noside == EVAL_AVOID_SIDE_EFFECTS)
                    return value_zero (TYPE_TARGET_TYPE (type), VALUE_LVAL (arg1));
                else
                    return value_subscript_pli (arg1, value_as_long (arg2));
            }
            break;

        default:
            break;
    }

    /* For other types, just call standard function */
    return evaluate_subexp_standard (expect_type, exp, pos, noside);
}

/* table mapping opcodes into strings for printing operators & precedences of the operators */
const struct op_print pli_op_print_tab[] = {
    {"=", BINOP_ASSIGN, PREC_ASSIGN, 1},
    {"|", BINOP_LOGICAL_OR, PREC_LOGICAL_OR, 0},
    {"&", BINOP_LOGICAL_AND, PREC_LOGICAL_AND, 0},
    {"|", BINOP_BITWISE_IOR, PREC_BITWISE_IOR, 0},
    {"^", BINOP_BITWISE_XOR, PREC_BITWISE_XOR, 0},
    {"&", BINOP_BITWISE_AND, PREC_BITWISE_AND, 0},
    {"=", BINOP_EQUAL, PREC_EQUAL, 0},
    {"^=", BINOP_NOTEQUAL, PREC_EQUAL, 0},
    {"<=", BINOP_LEQ, PREC_ORDER, 0},
    {">=", BINOP_GEQ, PREC_ORDER, 0},
    {">", BINOP_GTR, PREC_ORDER, 0},
    {"<", BINOP_LESS, PREC_ORDER, 0},
    {"+", BINOP_ADD, PREC_ADD, 0},
    {"-", BINOP_SUB, PREC_ADD, 0},
    {"||", BINOP_CONCAT, PREC_ADD, 0},
    {"*", BINOP_MUL, PREC_MUL, 0},
    {"/", BINOP_DIV, PREC_MUL, 0},
    {"**", BINOP_EXP, PREC_REPEAT, 0}, /*#XXX: need to implement */
    {"-", UNOP_NEG, PREC_PREFIX, 0},
    {"+", UNOP_PLUS, PREC_PREFIX, 0},
    {"^", UNOP_LOGICAL_NOT, PREC_PREFIX, 0},
    {NULL, 0, 0, 0}
};

/* PL/I primitive types */
enum pli_primitive_types {
    /* FIXED DEC type */
    pli_primitive_type_fixed_dec,

    /* FIXED BIN type */
    /** 1 byte */
    pli_primitive_type_s_8_fixed_bin,
    pli_primitive_type_u_8_fixed_bin,
    /** 2 byte */
    pli_primitive_type_s_16_fixed_bin,
    pli_primitive_type_u_16_fixed_bin,
    /** 4 byte */
    pli_primitive_type_s_32_fixed_bin,
    pli_primitive_type_u_32_fixed_bin,
    /** 8 byte */
    pli_primitive_type_s_64_fixed_bin,
    pli_primitive_type_u_64_fixed_bin,

    /* FLOAT type */
    /** float */
    pli_primitive_type_f_float_dec,
    pli_primitive_type_f_float_bin,
    /** double */
    pli_primitive_type_d_float_dec,
    pli_primitive_type_d_float_bin,
    /** 128bit fp */
    pli_primitive_type_e_float_dec,
    pli_primitive_type_e_float_bin,

    /* STRING */
    pli_primitive_type_character,
    pli_primitive_type_bit,
    pli_primitive_type_graphic,
    pli_primitive_type_widechar,

    /* PICTURE */
    pli_primitive_type_picture,

    pli_primitive_type_pointer,
    pli_primitive_type_entry,
    pli_primitive_type_offset,
    pli_primitive_type_area,

    nr_pli_primitive_types
};

/* assign built-in type info. to primitive type info. */
void 
pli_language_arch_info (struct gdbarch* gdbarch, struct language_arch_info* lai)
{
    const struct builtin_pli_type* builtin = builtin_pli_type (gdbarch);

    /* allocate memory for the primitive type vector */
    lai->string_char_type = builtin->builtin_character;
    lai->primitive_type_vector = GDBARCH_OBSTACK_CALLOC (gdbarch, nr_pli_primitive_types + 1, struct type *);

    lai->primitive_type_vector [pli_primitive_type_fixed_dec] = builtin->builtin_fixed_dec;

    lai->primitive_type_vector [pli_primitive_type_s_8_fixed_bin] = builtin->builtin_s_8_fixed_bin;
    lai->primitive_type_vector [pli_primitive_type_u_8_fixed_bin] = builtin->builtin_u_8_fixed_bin;
    lai->primitive_type_vector [pli_primitive_type_s_16_fixed_bin] = builtin->builtin_s_16_fixed_bin;
    lai->primitive_type_vector [pli_primitive_type_u_16_fixed_bin] = builtin->builtin_u_16_fixed_bin;
    lai->primitive_type_vector [pli_primitive_type_s_32_fixed_bin] = builtin->builtin_s_32_fixed_bin;
    lai->primitive_type_vector [pli_primitive_type_u_32_fixed_bin] = builtin->builtin_u_32_fixed_bin;
    lai->primitive_type_vector [pli_primitive_type_s_64_fixed_bin] = builtin->builtin_s_64_fixed_bin;
    lai->primitive_type_vector [pli_primitive_type_u_64_fixed_bin] = builtin->builtin_u_64_fixed_bin;

    lai->primitive_type_vector [pli_primitive_type_f_float_dec] = builtin->builtin_f_float_dec;
    lai->primitive_type_vector [pli_primitive_type_f_float_bin] = builtin->builtin_f_float_bin;
    lai->primitive_type_vector [pli_primitive_type_d_float_dec] = builtin->builtin_d_float_dec;
    lai->primitive_type_vector [pli_primitive_type_d_float_bin] = builtin->builtin_d_float_bin;
    lai->primitive_type_vector [pli_primitive_type_e_float_dec] = builtin->builtin_e_float_dec;
    lai->primitive_type_vector [pli_primitive_type_e_float_bin] = builtin->builtin_e_float_bin;

    lai->primitive_type_vector [pli_primitive_type_character] = builtin->builtin_character;
    lai->primitive_type_vector [pli_primitive_type_bit] = builtin->builtin_bit;
    lai->primitive_type_vector [pli_primitive_type_graphic] = builtin->builtin_graphic;
    lai->primitive_type_vector [pli_primitive_type_widechar] = builtin->builtin_widechar;

    lai->primitive_type_vector [pli_primitive_type_picture] = builtin->builtin_picture;

    lai->primitive_type_vector [pli_primitive_type_pointer] = builtin->builtin_pointer;
    lai->primitive_type_vector [pli_primitive_type_entry] = builtin->builtin_entry;
    lai->primitive_type_vector [pli_primitive_type_offset] = builtin->builtin_offset;
    lai->primitive_type_vector [pli_primitive_type_area] = builtin->builtin_area;

    lai->bool_type_default = builtin->builtin_bit;
}

const struct exp_descriptor exp_descriptor_pli = 
{
    print_subexp_standard,
    operator_length_standard,
    operator_check_standard,
    op_name_standard,
    dump_subexp_body_standard,
    evaluate_subexp_pli
};

const struct language_defn pli_language_defn = 
{
    "pl/i", /* language name */
    "PL/I",
    language_pli,
    range_check_off,
    case_sensitive_off,
    array_row_major,
    macro_expansion_c,
    &exp_descriptor_pli,
    pli_parse, /* #TODO: need to implement pli_parse */
    c_error, /* #TODO: need to implement pli_error */
    null_post_parser,
    pli_printchar,       /* Print a character constant */
    c_printstr, /* #TODO: need to implement pli_printstr / Function to print string constant */
    pli_emit_char,       /* Function to print a single character */
    pli_print_type, /* #TODO: need to implement pli_print_type / Print a type using appropriate syntax */
    default_print_typedef,    /* Print a typedef using appropriate syntax / #TODO: need to implement pli_print_typedef */
    pli_val_print,       /* Print a value using appropriate syntax */
    pli_value_print,     /* Print a top-level value */
    default_read_var_value,   /* la_read_var_value */
    NULL,             /* Language specific skip_trampoline */
    NULL,                   /* name_of_this */
    basic_lookup_symbol_nonlocal, /* lookup_symbol_nonlocal */
    basic_lookup_transparent_type,/* lookup_transparent_type */
    NULL,        /* Language specific symbol demangler */
    NULL,        /* Language specific class name */
    pli_op_print_tab,        /* expression operators for printing */
    0,                /* not c-style arrays */
    1,                /* String lower bound */
    default_word_break_characters,
    default_make_symbol_completion_list,
    pli_language_arch_info,
    default_print_array_index,
    default_pass_by_reference,
    default_get_string,
    NULL,             /* la_get_symbol_name_cmp */
    iterate_over_symbols,
    &default_varobj_ops,
    LANG_MAGIC
};

/* setting built-in type info */
static void*
build_pli_types (struct gdbarch* gdbarch)
{
    struct builtin_pli_type* builtin_pli_type = GDBARCH_OBSTACK_ZALLOC (gdbarch, struct builtin_pli_type);

    /* FIXME: need to modify the size of FIXED DEC type? */
    builtin_pli_type->builtin_fixed_dec = arch_type (gdbarch, TYPE_CODE_PACKED, 64, "FIXED DECIMAL");

    /* XXX: need to separate types signed & unsigned FIXED BIN type? */
    builtin_pli_type->builtin_s_8_fixed_bin = arch_integer_type (gdbarch, 8, 0, "FIXED BINARY");
    builtin_pli_type->builtin_u_8_fixed_bin = arch_integer_type (gdbarch, 8, 1, "FIXED BINARY");
    builtin_pli_type->builtin_s_16_fixed_bin = arch_integer_type (gdbarch, 16, 0, "FIXED BINARY");
    builtin_pli_type->builtin_u_16_fixed_bin = arch_integer_type (gdbarch, 16, 1, "FIXED BINARY");
    builtin_pli_type->builtin_s_32_fixed_bin = arch_integer_type (gdbarch, 32, 0, "FIXED BINARY");
    builtin_pli_type->builtin_u_32_fixed_bin = arch_integer_type (gdbarch, 32, 1, "FIXED BINARY");
    builtin_pli_type->builtin_s_64_fixed_bin = arch_integer_type (gdbarch, 64, 0, "FIXED BINARY");
    builtin_pli_type->builtin_u_64_fixed_bin = arch_integer_type (gdbarch, 64, 1, "FIXED BINARY");

    builtin_pli_type->builtin_f_float_dec = arch_float_type (gdbarch, 32, "FLOAT DECIMAL", NULL);
    builtin_pli_type->builtin_f_float_bin = arch_float_type (gdbarch, 32, "FLOAT BINARY", NULL);
    builtin_pli_type->builtin_d_float_dec = arch_float_type (gdbarch, 64, "FLOAT DECIMAL", NULL);
    builtin_pli_type->builtin_d_float_bin = arch_float_type (gdbarch, 64, "FLOAT BINARY", NULL);
    builtin_pli_type->builtin_e_float_dec = arch_float_type (gdbarch, 128, "FLOAT DECIMAL", NULL);
    builtin_pli_type->builtin_e_float_bin = arch_float_type (gdbarch, 128, "FLOAT BINARY", NULL);

    builtin_pli_type->builtin_character = arch_character_type (gdbarch, TARGET_CHAR_BIT, 1, "CHARACTER");
    builtin_pli_type->builtin_bit = arch_character_type (gdbarch, TARGET_CHAR_BIT, 1, "BIT");
    builtin_pli_type->builtin_graphic = arch_character_type (gdbarch, TARGET_CHAR_BIT * 2, 1, "GRAPHIC");
    builtin_pli_type->builtin_widechar = arch_character_type (gdbarch, TARGET_CHAR_BIT * 2, 1, "WIDECHAR");

    /* XXX: numeric picture type data has FIXED DEC type value? */
    builtin_pli_type->builtin_picture = arch_character_type (gdbarch, TARGET_CHAR_BIT, 1, "PICTURE");

    builtin_pli_type->builtin_pointer = arch_integer_type (gdbarch, gdbarch_ptr_bit (gdbarch), 0, "POINTER");
    builtin_pli_type->builtin_offset = arch_integer_type (gdbarch, 8, 1, "OFFSET");
    builtin_pli_type->builtin_entry = arch_integer_type (gdbarch, gdbarch_ptr_bit (gdbarch), 0, "ENTRY");

    /* FIXME: temporary assign */
    builtin_pli_type->builtin_area = arch_integer_type (gdbarch, gdbarch_ptr_bit (gdbarch), 0, "AREA");

    return builtin_pli_type;
}

static struct gdbarch_data* pli_type_data;
const struct 
builtin_pli_type* builtin_pli_type (struct gdbarch* gdbarch)
{
    return gdbarch_data (gdbarch, pli_type_data);
}

/* initializing PL/I language info */
void 
_initialize_pli_language (void) 
{
    pli_type_data = gdbarch_data_register_post_init (build_pli_types);
    add_language (&pli_language_defn);
}
