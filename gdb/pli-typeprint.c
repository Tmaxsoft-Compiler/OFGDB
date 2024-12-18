/* Support for printing PL/I types for GDB, the GNU debugger.
   Copyright (C) 1986-2014 Free Software Foundation, Inc.

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
#include "gdb_obstack.h"
#include "bfd.h"        /* Binary File Description.  */
#include "symtab.h"
#include "gdbtypes.h"
#include "expression.h"
#include "value.h"
#include "gdbcore.h"
#include "target.h"
#include "language.h"
#include "pli-lang.h"
#include "typeprint.h"
#include <string.h>
#include <errno.h>

void
pli_print_type (struct type* type, const char* varstring, struct ui_file* stream,
                int show, int level, const struct type_print_options* flags)
{
    enum type_code code;
    int demangled_args;
    int need_post_space;
    const char *local_name;

    if (show > 0)
        CHECK_TYPEDEF (type);

    local_name = find_typedef_in_hash (flags, type);
    if (local_name != NULL)
    {
        fputs_filtered (local_name, stream);
        if (varstring != NULL && *varstring != '\0')
            fputs_filtered (" ", stream);
    }
    else
    {
        /* print base type */
        pli_type_print_base (type, stream, show, level, flags);
        code = TYPE_CODE (type);

        /* print prefix such as open-parentheses */
        if ((varstring != NULL && *varstring != '\0') || 
             ( (show > 0 || TYPE_NAME (type) == 0) && (code == TYPE_CODE_PTR || code == TYPE_CODE_FUNC || code == TYPE_CODE_ARRAY) ))
        {
            fputs_filtered (" ", stream);
        }

        need_post_space = (varstring != NULL && strcmp (varstring, "") != 0);
        pli_type_print_varspec_prefix (type, stream, show, 0, need_post_space,
                flags);
    }

    if (varstring != NULL)
    {
        fputs_filtered (varstring, stream);

        if (local_name == NULL)
            pli_type_print_varspec_suffix (type, stream, show, 0, flags);
    }
}

/* print open-parentheses */
void
pli_type_print_varspec_prefix (struct type* type, struct ui_file* stream, 
                               int show, int passed_a_ptr, int need_post_space, 
                               const struct type_print_options* flags)
{
    const char* name;

    if (type == NULL) return;
    if (TYPE_NAME (type) && show <= 0) return;

    QUIT;

    switch (TYPE_CODE (type)) {
        case TYPE_CODE_FUNC:
        case TYPE_CODE_ARRAY:
            pli_type_print_varspec_prefix (TYPE_TARGET_TYPE (type), stream, show, 0, 0, flags);
            if (passed_a_ptr)
                fprintf_filtered (stream, "(");
            break;

        case TYPE_CODE_TYPEDEF:
            pli_type_print_varspec_prefix (TYPE_TARGET_TYPE (type), stream, show, passed_a_ptr, 0, flags);
            break;

        case TYPE_CODE_PTR:
      		fprintf_filtered (stream, "*");
            break;

        /* types that need no prefix */
        case TYPE_CODE_UNDEF:
        case TYPE_CODE_ERROR:
        case TYPE_CODE_STRUCT:
        case TYPE_CODE_UNION:
        case TYPE_CODE_ENUM:
        case TYPE_CODE_SIGNED_FIXED_B:
        case TYPE_CODE_UNSIGNED_FIXED_B:
        case TYPE_CODE_PACKED:
        case TYPE_CODE_DECFLOAT:
        case TYPE_CODE_FLT:
        case TYPE_CODE_CHAR:
        case TYPE_CODE_BIT:
        case TYPE_CODE_DBCS:
        case TYPE_CODE_PICTURE:
            break;

        default:
            error (_("type not handled in pli_type_print_varspec_prefix()"));
            break;
    }
}

/* print array sizes, function arguments, close parentheses */
void
pli_type_print_varspec_suffix (struct type* type, struct ui_file* stream, 
                               int show, int passed_a_ptr, const struct type_print_options* flags)
{
    if (type == NULL) return;
    if (TYPE_NAME (type) && show <= 0) return;

    QUIT;

    switch (TYPE_CODE (type)) {
        case TYPE_CODE_FUNC:
            if (passed_a_ptr)
                fprintf_filtered (stream, ")");
            pli_type_print_varspec_suffix (TYPE_TARGET_TYPE (type), stream, show, passed_a_ptr, flags);
            break;

        case TYPE_CODE_ARRAY:
            {
                LONGEST low_bound, high_bound;
                
                if (passed_a_ptr)
                    fprintf_filtered (stream, ")");
                
                /* print array size */
                fprintf_filtered (stream, "[");
                if (get_array_bounds (type, &low_bound, &high_bound))
                    fprintf_filtered (stream, "%s", plongest (high_bound - low_bound + 1));
                fprintf_filtered (stream, "]");

                pli_type_print_varspec_suffix (TYPE_TARGET_TYPE (type), stream, show, 0, flags);
                break;
            }

        case TYPE_CODE_TYPEDEF:
            pli_type_print_varspec_suffix (TYPE_TARGET_TYPE (type), stream, show, passed_a_ptr, flags);
            break;

        /* types that need no prefix */
        case TYPE_CODE_UNDEF:
        case TYPE_CODE_ERROR:
        case TYPE_CODE_STRUCT:
        case TYPE_CODE_UNION:
        case TYPE_CODE_ENUM:
        case TYPE_CODE_SIGNED_FIXED_B:
        case TYPE_CODE_UNSIGNED_FIXED_B:
        case TYPE_CODE_PACKED:
        case TYPE_CODE_DECFLOAT:
        case TYPE_CODE_FLT:
        case TYPE_CODE_CHAR:
        case TYPE_CODE_BIT:
        case TYPE_CODE_DBCS:
        case TYPE_CODE_PICTURE:
        case TYPE_CODE_PTR:
            break;

        default:
            error (_("type not handled in pli_type_print_varspec_suffix()"));
            break;
    }
}

/* print the name of the type */
void
pli_type_print_base (struct type* type, struct ui_file* stream,
                     int show, int level, const struct type_print_options* flags)
{
    int i, len;

    QUIT;

    if (type == NULL) {
        fputs_filtered (_("<type unknown>"), stream);
        return;
    }

    /* show <= 0: print the type name directly from the type */
    if (show <= 0 && TYPE_NAME (type) != NULL) {
        int buf_len = strlen (TYPE_NAME (type));
        char* type_name = (char*) alloca (buf_len);
        memcpy (type_name, TYPE_NAME (type), buf_len);

        /* eliminating additional info from type name */
        type_name = strtok (type_name, "!");
        if (type_name != NULL)
            fputs_filtered (type_name, stream);
        else
            fputs_filtered (TYPE_NAME (type), stream);
        return;
    }
    
    CHECK_TYPEDEF (type);
    switch (TYPE_CODE (type)) {
        case TYPE_CODE_TYPEDEF:
            /* If we get here, the typedef doesn't have a name, and we                                                       
               couldn't resolve TYPE_TARGET_TYPE.  Not much we can do.  */
            gdb_assert (TYPE_NAME (type) == NULL);
            gdb_assert (TYPE_TARGET_TYPE (type) == NULL);
            fprintf_filtered (stream, _("<unnamed typedef>"));
            break;

        case TYPE_CODE_ARRAY:
        case TYPE_CODE_PTR:
        case TYPE_CODE_FUNC:
            pli_type_print_base (TYPE_TARGET_TYPE (type), stream, show, level, flags);
            break;

        case TYPE_CODE_STRUCT:
        case TYPE_CODE_UNION:
            {
                struct type_print_options local_flags = *flags;
                struct type_print_options semi_local_flags = *flags;
                struct cleanup *local_cleanups = make_cleanup (null_cleanup, NULL);

                local_flags.local_typedefs = NULL;
                semi_local_flags.local_typedefs = NULL;

                if (!flags->raw) {
                    if (flags->local_typedefs)
                        local_flags.local_typedefs = copy_typedef_hash (flags->local_typedefs);
                    else
                        local_flags.local_typedefs = create_typedef_hash ();

                    make_cleanup_free_typedef_hash (local_flags.local_typedefs);
                }

                if (TYPE_CODE (type) == TYPE_CODE_UNION)
                    fprintf_filtered (stream, "union");
                else
                    fprintf_filtered (stream, "struct");

                if (show < 0) {
                    if (TYPE_TAG_NAME (type) == NULL)
                        fprintf_filtered (stream, "{...}");
                }
                else if (show > 0 || TYPE_TAG_NAME (type) == NULL) {
                    struct type *basetype;
                    int vptr_fieldno;


                    /* This holds just the global typedefs parameters.  */
                    semi_local_flags.local_typedefs
                        = copy_typedef_hash (local_flags.local_typedefs);
                    if (semi_local_flags.local_typedefs)
                        make_cleanup_free_typedef_hash (semi_local_flags.local_typedefs);

                    /* Now add in the local typedefs.  */
                    recursively_update_typedef_hash (local_flags.local_typedefs, type);

                    fprintf_filtered (stream, "{\n");
                    if (TYPE_NFIELDS (type) == 0 && TYPE_NFN_FIELDS (type) == 0 &&
                        TYPE_TYPEDEF_FIELD_COUNT (type) == 0) {
                        if (TYPE_STUB (type))
                            fprintfi_filtered (level + 4, stream, _("<incomplete type>\n"));
                        else
                            fprintfi_filtered (level + 4, stream, _("<no data fields>\n"));
                    }

                    len = TYPE_NFIELDS (type);
                    for (i = TYPE_N_BASECLASSES (type); i < len; i++)
                    {
                        QUIT;

                        print_spaces_filtered (level + 4, stream);

                        /* #XXX: how can print bit type variable? */
                        pli_print_type (TYPE_FIELD_TYPE (type, i), TYPE_FIELD_NAME (type, i),
                                        stream, show - 1, level + 4, &local_flags);
                        fprintf_filtered (stream, ";\n");
                    }

                    /* Print typedefs defined in this class.  */
                    if (TYPE_TYPEDEF_FIELD_COUNT (type) != 0 && flags->print_typedefs)
                    {
                        if (TYPE_NFIELDS (type) != 0 || TYPE_NFN_FIELDS (type) != 0)
                            fprintf_filtered (stream, "\n");

                        for (i = 0; i < TYPE_TYPEDEF_FIELD_COUNT (type); i++)
                        {
                            struct type *target = TYPE_TYPEDEF_FIELD_TYPE (type, i);

                            /* Dereference the typedef declaration itself.  */
                            gdb_assert (TYPE_CODE (target) == TYPE_CODE_TYPEDEF);
                            target = TYPE_TARGET_TYPE (target);

                            print_spaces_filtered (level + 4, stream);
                            fprintf_filtered (stream, "typedef ");

                            /* We want to print typedefs with substitutions
                               from globally-known typedefs but not local typedefs.  */
                            pli_print_type (target, TYPE_TYPEDEF_FIELD_NAME (type, i), stream, 
                                    show - 1, level + 4, &semi_local_flags);
                            fprintf_filtered (stream, ";\n");
                        }
                    }

                    fprintfi_filtered (level, stream, "}");
                }

                do_cleanups (local_cleanups);
            }
            break;

        case TYPE_CODE_ENUM:
            fprintf_filtered (stream, "ORDINAL ");

            if (TYPE_TAG_NAME (type) != NULL && strncmp (TYPE_TAG_NAME (type), "{unnamed", 8)) {
                fputs_filtered (TYPE_TAG_NAME (type), stream);
                if (show > 0)
                    fputs_filtered (" ", stream);
            }

            wrap_here ("    ");

            if (show < 0) {
                /* If we just printed a tag name, no need to print anything
                   else.  */
                if (TYPE_TAG_NAME (type) == NULL)
                    fprintf_filtered (stream, "{...}");
            }
            else if (show > 0 || TYPE_TAG_NAME (type) == NULL)
            {
                LONGEST lastval = 0;

                fprintf_filtered (stream, "{");
                len = TYPE_NFIELDS (type);
                for (i = 0; i < len; i++)
                {
                    QUIT;
                    if (i)
                        fprintf_filtered (stream, ", ");
                    wrap_here ("    ");
                    fputs_filtered (TYPE_FIELD_NAME (type, i), stream);
                    if (lastval != TYPE_FIELD_ENUMVAL (type, i))
                    {
                        fprintf_filtered (stream, " = %s",
                                plongest (TYPE_FIELD_ENUMVAL (type, i)));
                        lastval = TYPE_FIELD_ENUMVAL (type, i);
                    }
                    lastval++;
                }
                fprintf_filtered (stream, "}");
            }
            break;

        case TYPE_CODE_UNDEF:
            fprintf_filtered (stream, _("struct <unknown>"));
            break;

        case TYPE_CODE_ERROR:
            fprintf_filtered (stream, "%s", TYPE_ERROR_NAME (type));
            break;

        default:
            /* Handle types not explicitly handled by the other cases, such
               as fundamental types.  For these, just print whatever the
               type name is, as recorded in the type itself.  If there is no
               type name, then complain.  */
            if (TYPE_NAME (type) != NULL) { 
                fputs_filtered (TYPE_NAME (type), stream);
            }
            else {
                /* At least for dump_symtab, it is important that this not
                   be an error ().  */
                fprintf_filtered (stream, _("<invalid type code %d>"),
                        TYPE_CODE (type));
            }
            break;
    }
}
