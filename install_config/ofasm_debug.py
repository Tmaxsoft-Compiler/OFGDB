import gdb
import json
import os
import subprocess
import re

# Global variables
default_breakpoint_line = None
default_breakpoint_number = None

# Functions
## Default breakpoints
def set_default_breakpoint():
    global default_breakpoint_line, default_breakpoint_number
    default_breakpoint_line = int(subprocess.check_output(["ofasm", "--default-bp-line"]).decode())

    if default_breakpoint_line == None:
        print('Failed to find OFDEBUG_BREAKPOINT_LINE.')
        return

    gdb.execute('break Interpreter.h:%d if firstByte != 0x02' % default_breakpoint_line, to_string=True)
    
    breakpoints = gdb.breakpoints()
    if breakpoints:
        default_breakpoint_number = breakpoints[-1].number
        gdb.execute('disable %d' % default_breakpoint_number, to_string=True)
    else:
        print('Failed to set breakpoint.')
    return

def enable_breakpoint():
    global default_breakpoint_number
    if default_breakpoint_number is not None:
        gdb.execute('enable %d' % default_breakpoint_number, to_string=True)
    else:
        print('No breakpoint to enable.')
    return

def disable_breakpoint():
    global default_breakpoint_number
    if default_breakpoint_number is not None:
        gdb.execute('disable %d' % default_breakpoint_number, to_string=True)
    else:
        print('No breakpoint to disable.')
    return

## Executions
def ofasm_continue():
    disable_breakpoint()
    gdb.execute('continue', to_string=True)
    return

def ofasm_next():
    enable_breakpoint()
    gdb.execute('continue', to_string=True)
    return

def ofasm_finish(stackframe, vm_gdb_level):
    result = gdb.parse_and_eval('debugApi_stepOut(%d)' % stackframe)

    if result == 8192: # VM_EXIT (0x2000)
        disable_breakpoint()
        gdb.execute('frame %d' % vm_gdb_level, to_string=True)
        gdb.execute('finish', to_string=True)
    else:
        disable_breakpoint()
        gdb.execute('tbreak Interpreter.h:%d if pc == %d' % (default_breakpoint_line, result), to_string=True)
        gdb.execute('continue', to_string=True)
    return

def ofasm_vm_finish(vm_gdb_level):
    disable_breakpoint()
    gdb.execute('frame %d' % vm_gdb_level, to_string=True)
    gdb.execute('finish', to_string=True)
    return

## Breakpoints
def ofasm_set_function_breakpoint(entry_name):
    global default_breakpoint_line
    result = gdb.parse_and_eval('debugApi_setBreakPointByPgmName("%s")' % entry_name)
    if result == 0: # pending
        gdb.execute('break Interpreter.h:%d if pc == debugApi_setBreakPointByPgmName("%s")' % (default_breakpoint_line, entry_name), to_string=True)
    else:
        gdb.execute('break Interpreter.h:%d if pc == %d' % (default_breakpoint_line, result), to_string=True)
    return

def ofasm_set_line_breakpoint(file_name, line):
    global default_breakpoint_line
    result = gdb.parse_and_eval('debugApi_setBreakPointByFileNameAndLine("%s", %d)' % (file_name, line))
    if result == 0: # pending
        gdb.execute('break Interpreter.h:%d if pc == debugApi_setBreakPointByFileNameAndLine("%s", %d)' % (default_breakpoint_line, file_name, line), to_string=True)
    else:
        gdb.execute('break Interpreter.h:%d if pc == %d' % (default_breakpoint_line, result), to_string=True)
    return

def ofasm_add_register_breakpoint(reg_no):
    global default_breakpoint_line
    gdb.parse_and_eval('debugApi_addRegisterBreakPoint(%d)' % reg_no)
    gdb.execute('break Interpreter.h:%d if debugApi_checkBreakPointChangedToRegister(%d)' % (default_breakpoint_line, reg_no), to_string=True)
    return

def ofasm_delete_register_breakpoint(reg_no, break_no):
    gdb.parse_and_eval('debugApi_deleteRegisterBreakPoint(%d)' % reg_no)
    gdb.execute('delete %d' % break_no, to_string=True)
    return

def ofasm_add_symbol_breakpoint(symbol_name, entry_name):
    global default_breakpoint_line
    gdb.parse_and_eval('debugApi_addSymbolBreakPoint("%s", "%s")' % (symbol_name, entry_name))
    gdb.execute('break Interpreter.h:%d if debugApi_checkBreakPointChangedToSymbol("%s", "%s")' % (default_breakpoint_line, symbol_name, entry_name), to_string=True)
    return

def ofasm_delete_symbol_breakpoint(symbol_name, entry_name, break_no):
    gdb.parse_and_eval('debugApi_deleteSymbolBreakPoint("%s", "%s")' % (symbol_name, entry_name))
    gdb.execute('delete %d' % break_no, to_string=True)
    return

def ofasm_add_cc_breakpoint():
    global default_breakpoint_line
    gdb.parse_and_eval('debugApi_ccBreakPointOnOff(true)')
    gdb.execute('break Interpreter.h:%d if debugApi_checkBreakPointChangedToCC()' % default_breakpoint_line, to_string=True)
    return

def ofasm_delete_cc_breakpoint(break_no):
    gdb.parse_and_eval('debugApi_ccBreakPointOnOff(false)')
    gdb.execute('delete %d' % break_no, to_string=True)
    return

## Stackframe
def ofdebug_get_stackframe():
    frames = []
    frame = gdb.newest_frame()
    gdb_level = 0

    vm_groups = []
    current_vm_group = []
    inside_vm = False

    func_pattern = re.compile(r'^(ofasm::|.*OFASM_VM_ENTRY.*)')

    frame_infos = []

    while frame is not None:
        sal = frame.find_sal()
        if sal.symtab:
            func_name = frame.name()

            is_vm_func = func_name and func_pattern.match(func_name)

            frame_info = {
                "gdbLevel": gdb_level,
                "funcName": func_name,
                "fileName": os.path.basename(sal.symtab.filename),
                "fullName": sal.symtab.fullname(),
                "line": sal.line,
            }
            frame_infos.append(frame_info)

            if is_vm_func:
                if not inside_vm:
                    current_vm_group = [gdb_level]
                    inside_vm = True
                else:
                    current_vm_group.append(gdb_level)
                    if 'OFASM_VM_ENTRY' in func_name:
                        vm_groups.append(current_vm_group)
                        current_vm_group = []
                        inside_vm = False
            else:
                if inside_vm:
                    vm_groups.append(current_vm_group)
                    current_vm_group = []
                    inside_vm = False

        gdb_level += 1
        frame = frame.older()

    if current_vm_group:
        vm_groups.append(current_vm_group)

    frames = frame_infos[:]

    new_frames = []
    last_idx = 0
    asm_level = 1

    gdblevel_to_index = {frame['gdbLevel']: idx for idx, frame in enumerate(frames)}

    for idx, vm_group in enumerate(vm_groups, start=1):
        vm_start = gdblevel_to_index[vm_group[0]]
        vm_end = gdblevel_to_index[vm_group[-1]]

        new_frames.extend(frames[last_idx:vm_start])

        asm_stack_json = gdb.parse_and_eval('debugApi_getCallStack(%d)' % idx).string()
        asm_stack = json.loads(asm_stack_json)

        inserts = [{
            "vmGdbLevel": vm_group[-1],
            "asmLevel": asm_level + i,
            "funcName": asm_frame["funcName"],
            "fileName": asm_frame["fileName"],
            "fullName": asm_frame["fullName"],
            "line": asm_frame["line"]
        } for i, asm_frame in enumerate(asm_stack['stack'])]

        asm_level += len(inserts)
        new_frames.extend(inserts)

        last_idx = vm_end + 1

    new_frames.extend(frames[last_idx:])

    stack_info = {
        "stack": new_frames
    }

    gdb.write(json.dumps(stack_info), gdb.STDOUT)
    gdb.flush(gdb.STDOUT)
    return

## Data query
def ofasm_get_registers():
    asm_register_json = gdb.parse_and_eval('debugApi_getAllRegisterValue()').string()
    asm_register = json.loads(asm_register_json)

    register_info = {
        "registers": asm_register
    }

    gdb.write(json.dumps(register_info), gdb.STDOUT)
    gdb.flush(gdb.STDOUT)
    return

def ofasm_get_register(reg_no):
    asm_register_json = gdb.parse_and_eval('debugApi_getRegisterValue(%d)' % reg_no).string()
    asm_register = json.loads(asm_register_json)

    register_info = {
        "register": asm_register
    }

    gdb.write(json.dumps(register_info), gdb.STDOUT)
    gdb.flush(gdb.STDOUT)
    return

def ofasm_get_symbols(asm_pos):
    asm_symbol_json = gdb.parse_and_eval('debugApi_getLocalSymbolList(%d)' % asm_pos).string()
    asm_symbol = json.loads(asm_symbol_json)

    register_info = {
        "symbols": asm_symbol
    }

    gdb.write(json.dumps(register_info), gdb.STDOUT)
    gdb.flush(gdb.STDOUT)
    return

def ofasm_get_symbol(*args):
    if len(args) == 4: # symbol_name, asm_pos, length, offset
        fmt = 'debugApi_getSymbolValueByLengthAndOffset("%s", %d, %d, %d)'
    elif len(args) == 3: # symbol_name, asm_pos, length
        fmt = 'debugApi_getSymbolValueByLength("%s", %d, %d)'
    else: # symbol_name, asm_pos
        fmt = 'debugApi_getSymbolValue("%s", %d)'

    asm_symbol_json = gdb.parse_and_eval(fmt % args).string()
    asm_symbol = json.loads(asm_symbol_json)

    symbol_info = {
        "symbol": asm_symbol
    }

    gdb.write(json.dumps(symbol_info), gdb.STDOUT)
    gdb.flush(gdb.STDOUT)
    return

def ofasm_get_address(addr, length):
    asm_addr_json = gdb.parse_and_eval("debugApi_getAddressValue(%d, %d)" % (addr, length)).string()
    asm_addr = json.loads(asm_addr_json)

    addr_info = {
        "address": asm_addr
    }

    gdb.write(json.dumps(addr_info), gdb.STDOUT)
    gdb.flush(gdb.STDOUT)
    return

def ofasm_get_address_hex(addr, length):
    asm_addr_json = gdb.parse_and_eval("debugApi_getAddressValueForHex(%d, %d)" % (addr, length)).string()
    asm_addr = json.loads(asm_addr_json)

    addr_info = {
        "address": asm_addr
    }

    gdb.write(json.dumps(addr_info), gdb.STDOUT)
    gdb.flush(gdb.STDOUT)
    return

## Data setting
def ofasm_set_register(reg_no, value):
    asm_register_json = gdb.parse_and_eval('debugApi_setValueToRegister(%d, "%s")' % (reg_no, value)).string()
    asm_register = json.loads(asm_register_json)

    register_info = {
        "register": asm_register
    }

    gdb.write(json.dumps(register_info), gdb.STDOUT)
    gdb.flush(gdb.STDOUT)
    return

def ofasm_set_symbol(*args):
    if len(args) == 5: # symbol_name, asm_pos, value, length, offset
        fmt = 'debugApi_setValueToSymbolByLengthAndOffset("%s", %d, "%s", %d, %d)'
    elif len(args) == 4: # symbol_name, asm_pos, value, length
        fmt = 'debugApi_setValueToSymbolByLength("%s", %d, "%s", %d)'
    else: # symbol_name, asm_pos, value
        fmt = 'debugApi_setValueToSymbol("%s", %d, "%s")'

    asm_symbol_json = gdb.parse_and_eval(fmt % args).string()
    asm_symbol = json.loads(asm_symbol_json)

    symbol_info = {
        "symbol": asm_symbol
    }

    gdb.write(json.dumps(symbol_info), gdb.STDOUT)
    gdb.flush(gdb.STDOUT)
    return

def ofasm_set_address(addr, value, value_length):
    asm_addr_json = gdb.parse_and_eval('debugApi_setValueToAddress(%d, "%s", %d)' % (addr, value, value_length)).string()
    asm_addr = json.loads(asm_addr_json)

    addr_info = {
        "address": asm_addr
    }

    gdb.write(json.dumps(addr_info), gdb.STDOUT)
    gdb.flush(gdb.STDOUT)
    return

# Code
set_default_breakpoint()

gdb.execute('call (void*) dlopen("%s/lib/libofasmVM.so", 1)' % os.environ.get("OFASM_HOME"))
