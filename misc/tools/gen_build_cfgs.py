#!/usr/bin/python3

import re
import os
import os.path

class instruction:
    bc_name = ""
    define_name = ""
    do_disable = False
    new_value = ""


def error(s):
    print("error: " + s)
    print("aborting")
    exit(1)

def line_error(s, line_nb, reason):
    error("invalid line nb " + str(line_nb) + " = '" + s + "': " + reason)

def check_current_bc_name(current_bc_name, line_nb):
    #print("checking current_bc_name: " + str(current_bc_name == ""))
    if(current_bc_name == ""):
        error("missing bc context in line " + str(line_nb))


def read_build_config_spec():
    result = []
    meta_cfg_file =  open("misc/tools/gen_build_cfg_spec.dat", 'r')
    #default_cfg_file =  open("build_cfg/general/default/build_config_gen.h", 'r')
    current_bc_name = ""
    line_nb = -1
    for the_line in meta_cfg_file:
        line_nb = line_nb + 1
        line = the_line.strip()
        print("is_comment: " + str(line.startswith("#"))) 
        #print("current_bc_name = '" + current_bc_name + "'")
        if(line == "" or line.startswith("#")):
            continue
        if(line.startswith("bc")):
            line = line.replace(" ", "") 
            print("line without ws = '" + line + "'")
            tokens = line.split('=')
            if(len(tokens) != 2):
                line_error(the_line, line_nb, "error with number of tokens")
            if(tokens[0] != "bc"):
                line_error(the_line, line_nb, "error with string beginning, token[0] = '" + tokens[0] + "'")
            current_bc_name = tokens[1]
            for x in result:
                if (x.bc_name == current_bc_name or current_bc_name == "default"):
                    line_error(the_line, line_nb, "build config name already defined")
            continue
        m = re.match("([A-Za-z0-9_]+) +disable", line)
        if(None != m):
            check_current_bc_name(current_bc_name, line_nb)
            define = m.group(1) 
            print("matched 'disable': '" + define + "'") 
            x=instruction()
            x.bc_name = current_bc_name
            x.define_name = define
            x.do_disable = True
            result.append(x)
            continue
        m = re.match("([A-Za-z0-9_]+) +set_to +([A-Za-z0-9_]+)", line)
        if(None != m):
            check_current_bc_name(current_bc_name, line_nb)
            define = m.group(1) 
            new_val = m.group(2) 
            print("matched 'set_to': '" + define + "'" + " => '" + new_val + "'") 
            x=instruction()
            x.bc_name = current_bc_name
            x.define_name = define
            x.new_value = new_val
            result.append(x)
            continue
        line_error(line, line_nb, "cannot be interpreted")
    return result

def default_bc_file_as_list():
    def_cfg_path = "build_cfg/general/default/build_config_gen.h"
    current_file_contents = ""
    with open(def_cfg_path) as f:
        current_file_contents = f.readlines()
    for i in range(len(current_file_contents)):
        current_file_contents[i] = re.sub("// *FBFLAGS_.*", "", current_file_contents[i])
    return current_file_contents

def get_index_of_instruction_in_contents(instr, file_contents):
    line_nb = -1
    for line in file_contents:
        line_nb = line_nb + 1
        m = re.match(" *# *define +(" + instr.define_name + ") *(.*)", line)
        if(m != None):
            return line_nb
    error("could not match instruction for bc = '" + instr.bc_name + "' for define " + instr.define_name )

def exec_instruction(instr, file_contents):
    line_nb = get_index_of_instruction_in_contents(instr, file_contents)
    line = file_contents[line_nb]
    if(instr.do_disable):
        file_contents[line_nb] = "// " + line
    elif(instr.new_value != ""):
        #m = re.match("( *# *define +)" + instr.define_name + " *([^ ]*)(.*)", line)
        m = re.match("( *# *define +)" + instr.define_name + " *([^ ]*)", line)
        if(m == None):
            error("could not parse for set_to. line = '" + line + "'")
        file_contents[line_nb] = m.group(1) + instr.define_name + " " + instr.new_value #+ m.group(3)
        


def ensure_dir(file_path):
    directory = os.path.dirname(file_path)
    if not os.path.exists(directory):
        os.makedirs(directory)

def write_file(filename, cont_list_of_lines):
    ensure_dir(filename)
    with open(filename, 'w') as the_file:
        for line in cont_list_of_lines:
            the_file.write(line)


def create_build_configs(instructions):
    current_bc_name = ""
    current_file_contents = default_bc_file_as_list()
    current_output_file_name = ""
    for i in range (len(instructions)):
        instr = instructions[i]
        if(instr.bc_name != current_bc_name): 
            # entering a new build_cfg file
            if(current_output_file_name != ""):
                # finish file
                write_file(current_output_file_name, current_file_contents) 
            current_bc_name = instr.bc_name
            current_output_file_name = "build_cfg/general/" + current_bc_name + "/build_config_gen.h"
            current_file_contents = default_bc_file_as_list()
        exec_instruction(instr, current_file_contents)
    if(current_output_file_name != ""):
        write_file(current_output_file_name, current_file_contents)
        
        
        
instructions = read_build_config_spec()
print("instructions len = " + str(len(instructions)))
create_build_configs(instructions)

