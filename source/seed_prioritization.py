#!/usr/bin/env python

import sys
import gc
#import angr
#import driller
import time
import math
import signal
import psutil
import random
import os
import socket
import subprocess
import logging
import tempfile
import struct
import shutil
import functools

driller_timeout = 3600

g_tracer_qemu_path = '/home/whu/fuzz_job/afl_cgc_mcts/qemu-tracer-x86_64-callback'
qsym_path = "/home/whu/app/qsym/bin/run_qsym_afl.py"
virtualenv = "/home/whu/qsym/venv/bin/activate"

g_cfg = None
g_trace_list_dir = None
g_drilled_dir = None
BLOCK_CNT = 1024

afl_sync_dir = None
binary_path = None
select_type = None
qsym_index = 0
# fout = open('/home/leizhao/Desktop/501_target_paths', 'w')


'''
g_coverage_statics and g_dynamic_cfg store the branches and related branch coverage, respectively.
Two items (such as g_dynamic_cfg[0] and g_dynamic_cfg[1]] form a couple, indicating two different branches starting from the same block.

Each item g_dynamic_cfg can be represented as <call_chain_list, prev_block, cur_block>
prev_block, cur_block are the addresses of blocks.

To save memory, call_chain_list represents the call_chain list, in which the values are the indexes of g_caller_addrs, g_callee_addrs, g_return_addrs.

If call_chain_list[0] = 1, then the caller, callee, and return are g_caller_addrs[1], g_callee_addrs[1], g_return_addrs[1], respectively

'''
g_coverage_statics = []
g_dynamic_cfg = []

'''
g_traced_inputs stores the base filename of inputs
'''
g_traced_inputs = set()
g_drilled_inputs = set()

'''
g_trace_list_dir stores the path of trace files for each input.
Since the trace of an input is a list, g_trace_list is a list of list.
For each item in g_trace_list, that is, per trace,
the trace contains the list of branches.
To save memory, the values of branches are the indexes of g_dynamic_cfg.
'''

g_caller_addrs = []
g_callee_addrs = []
g_return_addrs = []
g_nopins_addrs = []
block_prev_addrs = []
block_cur_addrs = []

def system_init(afl_sync_dir, binary_path):

    #b = angr.Project(binary_path, load_options={'auto_load_libs': False})
    #global g_cfg
    #g_cfg = b.analyses.CFG()


    global g_drilled_dir
    global g_drilled_inputs
    g_drilled_dir = os.path.join(afl_sync_dir, 'driller', 'drilled')
    if os.path.isdir(g_drilled_dir):
        g_drilled_inputs.update(set(os.listdir(g_drilled_dir)))
    else:
        os.makedirs(g_drilled_dir)


    cfg_path = os.path.join(afl_sync_dir, 'driller', 'g_cfg')
    if not os.path.isfile(cfg_path):
        cfg_path = binary_path + '.cfg'
    read_cfg(cfg_path)

    block_path = os.path.join(afl_sync_dir, 'driller', 'g_block')
    if not os.path.isfile(block_path):
        block_path = binary_path + '.block'
    read_block(block_path)


    '''
    if the statics file does not exist, then initialize the g_traced_inputs
    '''
    traced_input_set = set()
    global g_trace_list_dir
    g_trace_list_dir = os.path.join(afl_sync_dir, 'driller', 'trace_list')
    if not os.path.isdir(g_trace_list_dir):
        os.makedirs(g_trace_list_dir)
    else:
        traced_input_set.update(set(os.listdir(g_trace_list_dir)))

    '''
    g_traced_inputs in the traced_input stores traced inputs that have been calculated
    '''
    global g_traced_inputs
    statics_path = os.path.join(afl_sync_dir, 'driller', 'statics')
    if os.path.isfile(statics_path):
        read_statics(statics_path)

        traced_path = os.path.join(afl_sync_dir, 'driller', 'traced_input')
        if os.path.isfile(traced_path):
            with open(traced_path, 'rb') as f:
                g_traced_inputs.update(set(f.read().split('\n')))

            '''
            It is possible that inputs in the dir of trace_list has not yet been calculated into the global statistics. Thus, we calculate the union set.
            '''
            g_traced_inputs = g_traced_inputs & traced_input_set


def read_statics(statics_path):
    with open(statics_path, 'rb') as f:
        statics_data = f.read()

    statics_list = statics_data.split('\n')
    statics_list.pop()

    for per_item in statics_list:
        item_list = per_item.split('\t')
        path = item_list[0]
        count = int(item_list[1], 10)

        path_item = path.split(',')
        str_call_chain = path_item[0]
        prev_addr = int(path_item[1], 16)
        cur_addr = int(path_item[2], 16)

        one_path = (str_call_chain, prev_addr, cur_addr)

        g_dynamic_cfg.append(one_path)
        g_coverage_statics.append(count)


def write_global_data(afl_sync_dir):

    '''
    write the global call graph
    '''
    cfg_path = os.path.join(afl_sync_dir, 'driller', 'g_cfg')

    str_list = []
    i = 0
    length = len(g_caller_addrs)
    while i < length:
        str_list.append('%x:' % g_caller_addrs[i])
        str_list.append('%x:' % g_callee_addrs[i])
        str_list.append('%x\n' % g_return_addrs[i])
        i+= 1
    for nop_addr in g_nopins_addrs:
        str_list.append('NOP_INST:')
        str_list.append('%x\n' % nop_addr)

    with open(cfg_path, 'w') as f:
        f.write(''.join(str_list))

    '''
    write the global block
    '''
    block_path = os.path.join(afl_sync_dir, 'driller', 'g_block')

    str_list = []
    i = 0
    length = len(block_prev_addrs)
    while i < length:
        str_list.append('%x:' % block_prev_addrs[i])
        str_list.append('%x\n' % block_cur_addrs[i])
        #str_list.append('%x\n' % g_return_addrs[i])
        i+= 1


    with open(block_path, 'w') as f:
        f.write(''.join(str_list))


    '''
    write the global coverage statics
    '''
    del str_list[:]
    statics_path = os.path.join(afl_sync_dir, 'driller', 'statics')
    i = 0
    length = len(g_dynamic_cfg)
    while i<length:
        covered_path = g_dynamic_cfg[i]
        count = g_coverage_statics[i]

        str_list.append('%s,' % covered_path[0])
        str_list.append('%x,' % covered_path[1])
        str_list.append('%x\t' % covered_path[2])
        str_list.append('%d\n' % count)
        i += 1

    with open(statics_path, 'w') as f:
        f.write(''.join(str_list))


    '''
    write the list of traced inputs, in case of inconsistence
    '''
    del str_list[:]
    traced_path = os.path.join(afl_sync_dir, 'driller', 'traced_input')
    for input_path in g_traced_inputs:
        str_list.append('%s\n' % input_path)

    with open(traced_path, 'w') as f:
        f.write(''.join(str_list))

def read_cfg(cfg_path):
    '''
    Read from the the static call_graph
    '''
    global g_caller_addrs
    global g_callee_addrs
    global g_return_addrs
    global g_nopins_addrs

    with open(cfg_path, 'rb') as f:
        cfg_data = f.read()

    cfg_list = cfg_data.split('\n')

    for per_line in cfg_list:
        try:
            line_list = per_line.split(':')
            if per_line.startswith('NOP_INST'):
                nop_addr = int(line_list[1], 16)
                g_nopins_addrs.append(nop_addr)
            else:
                caller_addr = int(line_list[0], 16)
                callee_addr = int(line_list[1], 16)
                return_addr = int(line_list[2], 16)

                g_caller_addrs.append(caller_addr)
                g_callee_addrs.append(callee_addr)
                g_return_addrs.append(return_addr)

        except:
            pass

def read_block(block_path):
    '''
    Read from the the static call_graph
    '''
    global block_prev_addrs
    global block_cur_addrs
    #global g_return_addrs
    global g_nopins_addrs

    with open(block_path, 'rb') as f:
        block_data = f.read()

    block_list = block_data.split('\n')

    for per_line in block_list:
        try:
            line_list = per_line.split(':')
            prev_addr = int(line_list[0], 16)
            cur_addr = int(line_list[1], 16)
            #return_addr = int(line_list[2], 16)

            block_prev_addrs.append(prev_addr)
            block_cur_addrs.append(cur_addr)
            #g_return_addrs.append(return_addr)

        except:
            pass

def aline_for_nop(trace_addr):
    if trace_addr in g_nopins_addrs:
        trace_addr = trace_addr>>4
        trace_addr += 1
        trace_addr = trace_addr << 4

    return trace_addr


def start_qsym(binary_path, afl_sync_dir, start_type, select_type, input):

    global qsym_index
    #args = ["source", virtualenv]
    #args += ["&&"]
    binary_basename = os.path.basename(binary_path)
    args = ["python", qsym_path]

    if select_type == "afl":
        src_path = afl_sync_dir
        tmp_path = os.path.join(os.path.dirname(afl_sync_dir), "out-tmp")
        if not os.path.isdir(tmp_path):
            time.sleep(10.0)
            #os.makedirs(tmp_path)
            shutil.copytree(src_path, tmp_path)
            args += ["-a", "fuzzer-1"]
            args += ["-o", tmp_path]
        else:
            args += ["-a", "fuzzer-1"]
            args += ["-o", tmp_path]
    else:
        args += ["-a", "fuzzer-1"]
        args += ["-o", afl_sync_dir]

    args += ["-n", "qsym"]
    args += ["-i", input]
    args += ["--"]
    args += [binary_path]

    if binary_basename.find("objdump") > -1:
        args += ["-fdDh", "@@"]
    elif binary_basename.find("tiff2pdf") > -1:
        args += ["@@"]
    elif binary_basename.find("tiffdump") > -1:
        args += ["@@"]
    elif binary_basename.find("nm") > -1:
        args += ["-AD", "@@"]
    elif binary_basename.find("readelf") > -1:
        args += ["-a", "@@"]
    elif binary_basename.find("size") > -1:
        args += ["-At", "@@"]
    elif binary_basename.find("xmllint") > -1:
        args += ["--debug", "@@"]
    elif binary_basename.find("sam2p") > -1:
        args += ["@@", "EPS:/dev/null"]
    elif binary_basename.find("pdfimages") > -1:
        args += ["@@", "/dev/null"]
    else:
        args += ["@@"]

    print args
    outfile = os.path.join(os.path.dirname(afl_sync_dir), 'qsym.log')
    qsym_index = qsym_index+1
    #print outfile
    with open(outfile, "w") as fp:
        p = subprocess.Popen(
            args,
            stdout=fp,
            stderr=fp,
            close_fds=True)
        #    stderr=fp)
        p.wait()
        #print args1
        #p.stdin.write(args1)
        #p = subprocess.Popen(args, stdout=fp, close_fds=True)
        #p.wait()
        #return p

def read_trace_list(input_name):

    trace_list = []

    trace_list_path = os.path.join(g_trace_list_dir, input_name)
    if not os.path.isfile(trace_list_path):
        return trace_list

    with open(trace_list_path, 'rb') as f:
        trace = f.read()

    line_list = trace.split('\n')

    for per_line in line_list:
        try:
            item_list = per_line.split('\t')
            covered_index = int(item_list[0], 10)
            missed_index = int(item_list[1], 10)

            covered_cnt = g_coverage_statics[covered_index]
            missed_cnt = g_coverage_statics[missed_index]

            block_list = []
            i = 2
            length = len(item_list)-1
            while i < length:
                block = int(item_list[i], 10)
                block_list.append(block)
                i += 1

            trace_list.append((covered_index, missed_index, block_list))
            #trace_index += 1
        except:
            pass

    return trace_list

def set_call_chain(call_chain):

    str_call_chain = ''
    length = len(call_chain)
    a = 0
    while a < length:
        str_call_chain += ('%d-' % call_chain[a])
        a += 1
    return str_call_chain

def get_call_chain(str_call_chain_index):

    call_chain_list = str_call_chain_index.split('-')

    str_call_chain = ''
    length = len(call_chain_list) - 1

    a = 0
    while a < length:
        index = int(call_chain_list[a], 10)
        str_call_chain += ('[%x:%x]' % (g_caller_addrs[index], g_callee_addrs[index]))
        a += 1

    return str_call_chain

def get_missed_branch(prev_addr, cur_addr):

    try:
        index_set = []
        index = 0
        for i in block_prev_addrs:
            if prev_addr == i:
                index_set.append(index)
            index = index+1

        for j in index_set:
            if block_cur_addrs[j] != cur_addr:
                return (prev_addr, block_cur_addrs[j])

    except:
        return None

def get_missed_branch_old(prev_addr, cur_addr):

    try:
        block = g_cfg.get_any_node(prev_addr)
        successors = block.successors

        if len(successors) == 1:
            return None

        for successor in successors:
            if successor.addr != cur_addr:
                return (prev_addr, successor.addr)

    except:
        return None

def qemu_trace_analysis(afl_sync_dir, binary, input_path, trace_path):
    '''
    For the trace generated from qemu, only callee_addr is present in the trace
    Since the caller may be called by several callers
    To generated the call graph, we must identify which one is the right caller_addr
    '''
    global g_coverage_statics
    global g_dynamic_cfg

    global g_caller_addrs
    global g_callee_addrs
    global g_return_addrs

    sample = os.path.basename(binary)

    str_call_chain = ''
    cur_addr = 0
    enter_call = False
    block_index = -1
    call_chain = []
    ret_chain = []
    self_covered_path = []
    self_trace = []
    start_time = time.time()
    # the serial index of block
    # in order to match the missed branch with that in angr
    # (block_index-1) refers to the prev_block
    # block_index refers to the cur_block, which is also the active path block in angr

    input_basename = os.path.basename(input_path)
    with open(trace_path, 'rb') as f:
        trace = f.read()
    line_list = trace.split('\n')
    #line_list = []

    if len(line_list) > 5000000:
        write_trace_list(input_basename, self_trace)
        os.remove(trace_path)
        return
    #analysis qemu_trace
    #run in test
    #print line_list
    for per_line in line_list:
        if per_line.startswith('Trace'):
            block_index += 1

            prev_addr = cur_addr
            try:
                #if sample.find("xmllint") > -1:
                # xmllint
                #    tmp = per_line.split('[')[1].split(']')[0][6:7]+per_line.split('[')[1].split(']')[0][11:]
                #    cur_addr =  int(tmp, 16)
                if sample.find("tiff2pdf") > -1:
                    #tiff2pdf tiffdump
                    tmp = per_line.split('[')[1].split(']')[0][6:8]+per_line.split('[')[1].split(']')[0][12:]
                    cur_addr = int(tmp, 16)
                elif sample.find("tiffdump") > -1:
                    #tiff2pdf tiffdump
                    tmp = per_line.split('[')[1].split(']')[0][6:8]+per_line.split('[')[1].split(']')[0][12:]
                    cur_addr = int(tmp, 16)
                else:
                    #readelf objdump
                    cur_addr = int(per_line.split('[')[1].split(']')[0][10:], 16)
            except:
                #return
                pass

            cur_addr = aline_for_nop(cur_addr)

            if prev_addr > 0:
                covered_path = (str_call_chain, prev_addr, cur_addr)
                missed_branch = get_missed_branch(prev_addr, cur_addr)

                if missed_branch is not None:
                    missed_path = (str_call_chain, prev_addr, missed_branch[1])
                    try:
                        covered_index = g_dynamic_cfg.index(covered_path)
                        g_coverage_statics[covered_index] += 1
                    except:
                        covered_index = len(g_dynamic_cfg)
                        g_dynamic_cfg.append(covered_path)
                        g_coverage_statics.append(1)

                    try:
                        missed_index = g_dynamic_cfg.index(missed_path)
                    except:
                        missed_index = len(g_dynamic_cfg)
                        g_dynamic_cfg.append(missed_path)
                        g_coverage_statics.append(0)

                    try:
                        self_covered_index = self_covered_path.index(covered_index)
                        per_branch = self_trace[self_covered_index]
                        per_branch[2].append(block_index-1)
                        # if len(per_branch[2]) < BLOCK_CNT:
                        #     per_branch[2].append(block_index-1)
                    except:
                        # self_covered_index = len(self_covered_path)
                        self_covered_path.append(covered_index)
                        block_list = []
                        block_list.append(block_index-1)
                        per_branch = (covered_index, missed_index, block_list)
                        self_trace.append(per_branch)

            if enter_call:
                caller_addr = prev_addr
                callee_addr = cur_addr
                ret_index = g_caller_addrs.index(caller_addr)
                return_addr = g_return_addrs[ret_index]

                index = index_in_cfg(caller_addr, callee_addr)
                if index < 0:
                    g_caller_addrs.append(caller_addr)
                    g_callee_addrs.append(callee_addr)
                    g_return_addrs.append(return_addr)
                    index = len(g_caller_addrs) -1

                enter_call = False
                call_chain.append(index)
                ret_chain.append(return_addr)
                str_call_chain = set_call_chain(call_chain)

            if cur_addr in g_caller_addrs:
                enter_call = True

            if len(ret_chain) > 0 and cur_addr == ret_chain[len(ret_chain)-1]:
                call_chain.pop()
                ret_chain.pop()
                str_call_chain = set_call_chain(call_chain)


        # end while
    write_trace_list(input_basename, self_trace)
    os.remove(trace_path)


def write_trace_list(input_basename, self_trace):

    trace_list_path = os.path.join(g_trace_list_dir, input_basename)

    str_trace_list = []
    for trace in self_trace:
        covered_index = trace[0]
        missed_index = trace[1]
        block_list = trace[2]
        str_trace_list.append(`covered_index`)
        str_trace_list.append('\t')
        str_trace_list.append(`missed_index`)
        str_trace_list.append('\t')
        missed_cnt = g_coverage_statics[missed_index]

        if missed_cnt == 0:
            for block in block_list:
                str_trace_list.append(`block`)
                str_trace_list.append('\t')
        else:
            block = block_list[0]
            str_trace_list.append(`block`)
            str_trace_list.append('\t')

        str_trace_list.append('\n')

    with open(trace_list_path, 'wb') as f:
        f.write(''.join(str_trace_list))
    #f = open(trace_list_path, 'wb')
    #f.write(''.join(str_trace_list))
    #f.close()


def index_in_cfg(caller_addr, callee_addr):

    cur_index = 0
    while True:
        try:
            index = g_caller_addrs[cur_index:].index(caller_addr)
            cur_index = cur_index + index
            if callee_addr == g_callee_addrs[cur_index]:
                return cur_index

            cur_index += 1

        except:
            return -1

def dynamic_trace(binary, input_path, input_type, cmd_args):
    '''
    accumulate a basic block trace using qemu
    '''

    with open(input_path, 'rb') as f:
        input_data = f.read()

    # std_writes = input_data.split('\n')
    # if std_writes[len(std_writes)-1] == '':
    #     std_writes.pop()

    sample = os.path.basename(binary)
    # log_name = input_path + "-tracer-log"
    log_name = tempfile.mkstemp(dir="/tmp/", prefix=sample+"tracer-log-")
    log_name = log_name[1]
    #print log_name

    # output_name = os.path.join(sample_dir, 'trace_log', sample+'_tracer-output')

    args = [g_tracer_qemu_path]
    args += ["-d", "exec", "-D", log_name, binary]

    if cmd_args is not None:
        args += [cmd_args]

    with open(os.devnull, 'w') as devnull:
        # stdout_f = open(output_name, 'wb')
        # in_s, out_s = socket.socketpair()
        if input_type == "file":
            if sample.find("objdump") > -1:
                args += ["-fdDh", input_path]
            elif sample.find("tiff2pdf") > -1:
                args += [input_path]
            elif sample.find("tiffdump") > -1:
                args += [input_path]
            elif sample.find("nm") > -1:
                args += ["-AD", input_path]
            elif sample.find("readelf") > -1:
                args += ["-a", input_path]
            elif sample.find("size") > -1:
                args += ["-At", input_path]
            elif sample.find("xmllint") > -1:
                args += ["--debug", input_path]
            else:
                args += [input_path]
            #args += [input_path]
            p = subprocess.Popen(
                    args,
                    stdin=subprocess.PIPE,
                    stdout=devnull,
                    stderr=devnull)
            ret = p.wait()
            ret = None
        else:
            p = subprocess.Popen(
                    args,
                    stdin=subprocess.PIPE,
                    stdout=devnull,
                    stderr=devnull)

            p.communicate(input_data)
            ret = p.wait()

    return log_name

def del_false_branches(input_name, false_list):
    """
    g_coverage_statics[missed_index] == -1 indicates that this false branch is not related to inputs, and it cannot be solved. Thus, we just ignore these unsatisfiable branches.
    """

    trace = read_trace_list(input_name)
    for branch in trace:
        block_index = branch[2]
        if block_index in false_list:
            covered_index = branch[0]
            missed_index = branch[1]
            g_coverage_statics[missed_index] = -1

def markov_prioritizing(afl_sync_dir):
    '''
    the importance refers to the coverage statistics of covered branch for which the corresponding missed branches is never covered.
    We first identify the branches of which the coverage is 0, then find its parterner branch, make the coverage of the parterner as the importance.

    This step enables us to calculate the summary of how does a trace covers important blocks.
    '''

    global g_sorted_trace
    g_sorted_trace = []

    if len(g_traced_inputs) == 0:
        return

    for input_path in g_traced_inputs:
        input_name = os.path.basename(input_path)
        trace = read_trace_list(input_name)

        transmit_propagation = 1.0
        sum_value = 0.0

        for branch in trace:
            covered_index = branch[0]
            missed_index = branch[1]

            covered_cnt = g_coverage_statics[covered_index]
            missed_cnt = g_coverage_statics[missed_index]

            assert(covered_cnt > 0)

            if missed_cnt == 0:
                fitness_gain = (1/float(covered_cnt))
                fitness_gain = transmit_propagation * fitness_gain
                sum_value += (1/fitness_gain)
            elif missed_cnt > 0:
                ratio = (covered_cnt/float(missed_cnt + covered_cnt))
                transmit_propagation = transmit_propagation * ratio


        # end for
        g_sorted_trace.append((input_path, sum_value))

    g_sorted_trace.sort(key=lambda x:x[1], reverse=True)

def mcts_prioritizing(afl_sync_dir):
    '''
    the importance refers to the coverage statistics of covered branch for which the corresponding missed branches is never covered.
    We first identify the branches of which the coverage is 0, then find its parterner branch, make the coverage of the parterner as the importance.

    one_path = (str_call_chain, prev_addr, cur_addr)
    g_dynamic_cfg.append(one_path)

    This step enables us to calculate the summary of how does a trace covers important blocks.
    '''
    global g_sorted_trace
    g_sorted_trace = []

    if len(g_traced_inputs) == 0:
        return

    g_total_execs = 0
    g_covered_execs = None
    g_new_cvg_execs = None
    g_fuzz_bitmap_size = 0

    fuzzer_stats = os.path.join(afl_sync_dir, 'fuzzer-1', "fuzzer_stats")
    fuzzer_covered_execs = os.path.join(afl_sync_dir, 'fuzzer-1', "covered_execs")
    fuzzer_new_cvg_execs = os.path.join(afl_sync_dir, 'fuzzer-1', "new_cvg_execs")
    fuzz_bitmap_path = os.path.join(afl_sync_dir, 'fuzzer-1', "fuzz_bitmap")

    try:
        with open(fuzzer_stats, 'rb') as f:
            stat_blob = f.read()
        stat_lines = stat_blob.split("\n")[:-1]
        for stat in stat_lines:
            key, val = stat.split(":")
            key = key.strip()
            val = val.strip()
            if key == 'execs_done':
                g_total_execs = int(val,10)

        with open(fuzzer_covered_execs, 'rb') as f:
            g_covered_execs = f.read()
        with open(fuzzer_new_cvg_execs, 'rb') as f:
            g_new_cvg_execs = f.read()
        with open(fuzz_bitmap_path, 'rb') as f:
            fuzz_bitmap = f.read()
        g_fuzz_bitmap_size = len(fuzz_bitmap)
    except:
        return

    if g_covered_execs is None or g_new_cvg_execs is None:
        return

    if len(g_covered_execs) != len(g_new_cvg_execs):
        # print "first bitmap_size: [%d-%d]" % (len(g_covered_execs), len(g_new_cvg_execs))
        return

    if len(g_covered_execs) != (4*g_fuzz_bitmap_size):
        # print "bitmap_size: %d-[%d-%d]" % (g_fuzz_bitmap_size, len(g_covered_execs), len(g_new_cvg_execs))
        return

    for input_path in g_traced_inputs:
        input_name = os.path.basename(input_path)
        trace = read_trace_list(input_name)
        avg_mcts_value = 0.0
        total_mcts_trace = 0.0
        mcts_value = 0.0
        sum_value = 0.0
        count = 0

        for branch in trace:
            covered_index = branch[0]
            missed_index = branch[1]

            covered_cnt = g_coverage_statics[covered_index]
            missed_cnt = g_coverage_statics[missed_index]

            if covered_cnt > 0:
                covered_path = g_dynamic_cfg[covered_index]
                missed_path = g_dynamic_cfg[missed_index]

                prev_addr = covered_path[1]
                curr_addr = covered_path[2]


                prev_loc = (prev_addr >> 4) ^ (prev_addr << 8)
                prev_loc &= (g_fuzz_bitmap_size - 1)
                prev_loc = prev_loc >> 1

                cur_loc = (curr_addr >> 4) ^ (curr_addr << 8)
                cur_loc &= (g_fuzz_bitmap_size - 1)

                bitmap_index = cur_loc ^ prev_loc

                try:
                    coverage_samples = struct.unpack("<L", g_covered_execs[4*bitmap_index : 4*bitmap_index+4])[0]
                    new_samples = struct.unpack("<L", g_new_cvg_execs[4*bitmap_index:4*bitmap_index+4])[0]
                except:
                    coverage_samples = 0

                if coverage_samples > 0:
                    mcts_value = (coverage_samples - new_samples)/float(coverage_samples)
                    mcts_value += (math.log(float(g_total_execs))/coverage_samples) ** (1./2)
                    sum_value += mcts_value
                    count += 1

        if count > 0:
            total_mcts_trace = sum_value/float(count)
            g_sorted_trace.append((input_name, total_mcts_trace))

    g_sorted_trace.sort(key=lambda x:x[1], reverse = True)
    # os._exit(1)


def mcts_prioritizing2(afl_sync_dir):
    '''
    the importance refers to the coverage statistics of covered branch for which the corresponding missed branches is never covered.
    We first identify the branches of which the coverage is 0, then find its parterner branch, make the coverage of the parterner as the importance.

    one_path = (str_call_chain, prev_addr, cur_addr)
    g_dynamic_cfg.append(one_path)

    This step enables us to calculate the summary of how does a trace covers important blocks.
    '''
    global g_sorted_trace
    g_sorted_trace = []

    if len(g_traced_inputs) == 0:
        return

    g_total_execs = 0
    g_covered_execs = None
    g_new_cvg_execs = None
    g_fuzz_bitmap_size = 0

    fuzzer_stats = os.path.join(afl_sync_dir, 'fuzzer-1', "fuzzer_stats")
    fuzzer_covered_execs = os.path.join(afl_sync_dir, 'fuzzer-1', "covered_execs")
    fuzzer_new_cvg_execs = os.path.join(afl_sync_dir, 'fuzzer-1', "new_cvg_execs")
    fuzz_bitmap_path = os.path.join(afl_sync_dir, 'fuzzer-1', "fuzz_bitmap")

    try:
        with open(fuzzer_stats, 'rb') as f:
            stat_blob = f.read()
        stat_lines = stat_blob.split("\n")[:-1]
        for stat in stat_lines:
            key, val = stat.split(":")
            key = key.strip()
            val = val.strip()
            if key == 'execs_done':
                g_total_execs = int(val,10)

        with open(fuzzer_covered_execs, 'rb') as f:
            g_covered_execs = f.read()
        with open(fuzzer_new_cvg_execs, 'rb') as f:
            g_new_cvg_execs = f.read()
        with open(fuzz_bitmap_path, 'rb') as f:
            fuzz_bitmap = f.read()
        g_fuzz_bitmap_size = len(fuzz_bitmap)
    except:
        return

    if g_covered_execs is None or g_new_cvg_execs is None:
        return

    if len(g_covered_execs) != len(g_new_cvg_execs):
        # print "first bitmap_size: [%d-%d]" % (len(g_covered_execs), len(g_new_cvg_execs))
        return

    if len(g_covered_execs) != (4*g_fuzz_bitmap_size):
        # print "bitmap_size: %d-[%d-%d]" % (g_fuzz_bitmap_size, len(g_covered_execs), len(g_new_cvg_execs))
        return

    for input_path in g_traced_inputs:
        input_name = os.path.basename(input_path)

        trace = read_trace_list(input_name)
        avg_mcts_value = 0.0
        total_mcts_trace = 0.0
        mcts_value = 0.0
        sum_value = 0.0
        count = 0

        for branch in trace:
            covered_index = branch[0]
            missed_index = branch[1]

            covered_cnt = g_coverage_statics[covered_index]
            missed_cnt = g_coverage_statics[missed_index]

            if covered_cnt > 0:

                covered_path = g_dynamic_cfg[covered_index]
                missed_path = g_dynamic_cfg[missed_index]

                prev_addr = covered_path[1]
                curr_addr = covered_path[2]

                prev_loc = (prev_addr >> 4) ^ (prev_addr << 8)
                prev_loc &= (g_fuzz_bitmap_size - 1)
                prev_loc = prev_loc >> 1

                cur_loc = (curr_addr >> 4) ^ (curr_addr << 8)
                cur_loc &= (g_fuzz_bitmap_size - 1)

                bitmap_index = cur_loc ^ prev_loc
                # bitmap_index &= (g_fuzz_bitmap_size - 1)

                # if (ord(fuzz_bitmap[bitmap_index])) < 255 :
                #     print bitmap_index
                try:
                    coverage_samples = struct.unpack("<L", g_covered_execs[4*bitmap_index : 4*bitmap_index+4])[0]
                    new_samples = struct.unpack("<L", g_new_cvg_execs[4*bitmap_index:4*bitmap_index+4])[0]
                except:
                    coverage_samples = 0

                    #print "bitmap_index: %d, bitmap_size: %d-%d-%d" % (bitmap_index, g_fuzz_bitmap_size, len(g_covered_execs), len(g_new_cvg_execs))

            # coverage_samples = struct.unpack("<L", g_covered_execs[4*bitmap_index : 4*bitmap_index+4])[0]
            # new_samples = struct.unpack("<L", g_new_cvg_execs[4*bitmap_index:4*bitmap_index+4])[0]

                if coverage_samples > 0:
                    mcts_value = (coverage_samples - new_samples)/float(coverage_samples)
                    mcts_value += (math.log(float(g_total_execs))/coverage_samples) ** (1./2)
                    sum_value += mcts_value
                    count += 1

                if missed_cnt == 0 and count > 0:
                    avg_mcts_value = sum_value/float(count)
                    total_mcts_trace += avg_mcts_value

        g_sorted_trace.append((input_name, total_mcts_trace))
    g_sorted_trace.sort(key=lambda x:x[1], reverse=True)
    # os._exit(1)

def update_trace_coverage(afl_sync_dir, binary_path, driller_input_list, input_type=None, cmd_args=None):

    global g_traced_inputs

    res = False

    for driller_input in driller_input_list:
        lack_count = 0
        if not os.path.isdir(driller_input):
            continue

        inputs = os.listdir(driller_input)
        # inputs = ['id:000002,src:000000,op:havoc,rep:32,+cov']

        for input_file in inputs:

            if input_file.startswith('.') == -1 :
            #if input_file.startswith('.') == -1 :
                continue

            if input_file.find('README') > -1 :
                continue


            input_path = os.path.join(driller_input, input_file)
            if not os.path.isfile(input_path):
                continue

            if input_path in g_traced_inputs:
                continue

            lack_count = lack_count+1
            if lack_count > 5:
                continue
            print ("qemu_trace_analysis %s" % os.path.basename(input_path))
            trace_path = dynamic_trace(binary_path, input_path, input_type, cmd_args)
            qemu_trace_analysis(afl_sync_dir, binary_path, os.path.basename(input_path), trace_path)

            g_traced_inputs.add(input_path)
            write_global_data(afl_sync_dir)
            #print "update complete"
            res = True
    #print "update complete"
    return res

def handle_feedback(solved_path_pairs):
    """
    missed_path = (str_call_chain, prev_addr, cur_addr)
    missed_path_pairs = [(missed_path, last_block)]
    """
    if len(solved_path_pairs) > 0:
        for solved_path_pair in solved_path_pairs:
            solved_path = solved_path_pair[0]
            try:
                index = g_dynamic_cfg.index(solved_path)
                if g_coverage_statics[index] == 0:
                    g_coverage_statics[index] == 1
            except:
                pass

def get_input_id(input_base):

    index = 0
    start_index = -1
    end_index = -1
    for one_char in input_base:
        if start_index == -1:
            if one_char >= '0' and one_char <= '9':
                start_index = index
        if start_index > -1:
            if one_char < '0' or one_char > '9':
                end_index = index
                break
        index += 1

    try:
        return input_base[start_index:end_index]
    except:
        return None


def smallest_id(input_id):
    try:
        index = cur_path_list.index(input_id)
        cur_execs = cur_path_execs[index]

        for input_path in g_traced_inputs:
            input_name = os.path.basename(input_path)
            try:
                loop_input_id = int(get_input_id(input_name))
                loop_index = cur_path_list.index(loop_input_id)
                loop_exec = cur_path_execs[loop_index]
                if loop_exec < cur_execs:
                    return False
            except:
                continue
    except:
        return False

    return True

def get_fast_for_driller():

    global cur_path_list
    global cur_path_execs
    del cur_path_list[:]
    del cur_path_execs[:]

    fuzzer_stats = os.path.join(afl_sync_dir, 'fuzzer-1', "plot_data")
    with open(fuzzer_stats, 'rb') as f:
            stat_blob = f.read()

    stat_lines = stat_blob.split("\n")[:-1]
    for stat in stat_lines:
        try:
            cur_path = int(stat.split(",")[2])
            if cur_path in cur_path_list:
                cur_index = cur_path_list.index(cur_path)
                cur_path_execs[cur_index] += 1
            else:
                cur_path_list.append(cur_path)
                cur_path_execs.append(1)
        except:
            continue

    global g_drilled_inputs
    missed_path_pairs = []

    for input_path in g_traced_inputs:

        input_name = os.path.basename(input_path)
        if input_name in g_drilled_inputs:
            continue
        input_id = int(get_input_id(input_name))
        if not smallest_id(input_id):
            continue

        input_trace = read_trace_list(input_name)
        for path in input_trace:
            covered_index = path[0]
            missed_index = path[1]
            block_list = path[2]
            missed_cnt = [missed_index]

            if missed_cnt == 0:
                """
                missed_path = (str_call_chain, prev_addr, cur_addr)
                missed_path_pairs = [(missed_path, block_list)]
                """
                missed_path = g_dynamic_cfg[missed_index]
                item = (missed_path, block_list)
                missed_path_pairs.append(item)

        if len(missed_path_pairs) > 0:
            return (input_path, None)

    return (None, None)

def random_one_for_driller():

    global g_drilled_inputs
    missed_path_pairs = []

    random_list = []
    for input_path in g_traced_inputs:
        input_name = os.path.basename(input_path)
        if input_name not in g_drilled_inputs:
            random_list.append(input_path)

    if len(random_list) > 0:

        random_int = int(random.uniform(0, (len(random_list)-1)))
        input_path = random_list[random_int]

        return (input_path, None)

    return (None, None)

def random_one_for_driller_with_filter():

    global g_drilled_inputs
    missed_path_pairs = []

    #print "begin random"
    random_list = []
    for input_path in g_traced_inputs:
        if os.path.basename(input_path) not in g_drilled_inputs:
            random_list.append(input_path)

    #print "len(random_list)%s",len(random_list)
    if len(random_list) > 0:
        random_int = int(random.uniform(0, (len(random_list)-1)))
        input_path = random_list[random_int]
        input_trace = read_trace_list(os.path.basename(input_path))

        for path in input_trace:
            covered_index = path[0]
            missed_index = path[1]
            block_list = path[2]
            missed_cnt = g_coverage_statics[missed_index]

            # ##########
            # covered_path = g_dynamic_cfg[covered_index]
            # str_call_chain_index = covered_path[0]
            # prev_addr = covered_path[1]
            # cur_addr  = covered_path[2]
            # str_call_chain = get_call_chain(str_call_chain_index)
            # fout.write('Covered: Branch [0x%x-0x%x] \t %s Call_chain %s\n' % (prev_addr, cur_addr, str_call_chain_index, str_call_chain))

            if missed_cnt == 0:
                """
                missed_path = (str_call_chain, prev_addr, cur_addr)
                missed_path_pairs = [(missed_path, block_list)]
                """
                missed_path = g_dynamic_cfg[missed_index]
                item = (missed_path, block_list)
                missed_path_pairs.append(item)



        if len(missed_path_pairs) > 0:
            print "input_path correct"
            return (input_path, missed_path_pairs)
    #print "input_path wrong"
    return (None, None)

######
# help function for qsym
######
def get_score(testcase):
    # New coverage is the best
    #score1 = testcase.endswith("+cov")
    # NOTE: seed files are not marked with "+cov"
    # even though it contains new coverage
    score2 = "orig:" in testcase
    # Smaller size is better
    score3 = -os.path.getsize(testcase)
    # Since name contains id, so later generated one will be chosen earlier
    score4 = testcase
    #print testcase
    #print (score1, score2, score3, score4)
    #time.sleep(10)
    return (score2, score3, score4)

def testcase_compare(a, b):
    a_score = get_score(a)
    b_score = get_score(b)
    return 1 if a_score > b_score else -1


def qsym_one_for_driller_with_filter():

    global g_drilled_inputs
    missed_path_pairs = []

    #print "begin random"
    random_list = []
    for input_path in g_traced_inputs:
        if os.path.basename(input_path) not in g_drilled_inputs:
            random_list.append(input_path)

    #sort the random_list
    sorted(random_list,key=functools.cmp_to_key(testcase_compare),reverse=True)

    #print "len(random_list)%s",len(random_list)
    if len(random_list) > 0:
        #random_int = int(random.uniform(0, (len(random_list)-1)))
        input_path = random_list[0]
        input_trace = read_trace_list(os.path.basename(input_path))

        for path in input_trace:
            covered_index = path[0]
            missed_index = path[1]
            block_list = path[2]
            missed_cnt = g_coverage_statics[missed_index]

            # ##########
            # covered_path = g_dynamic_cfg[covered_index]
            # str_call_chain_index = covered_path[0]
            # prev_addr = covered_path[1]
            # cur_addr  = covered_path[2]
            # str_call_chain = get_call_chain(str_call_chain_index)
            # fout.write('Covered: Branch [0x%x-0x%x] \t %s Call_chain %s\n' % (prev_addr, cur_addr, str_call_chain_index, str_call_chain))

            if missed_cnt == 0:
                """
                missed_path = (str_call_chain, prev_addr, cur_addr)
                missed_path_pairs = [(missed_path, block_list)]
                """
                missed_path = g_dynamic_cfg[missed_index]
                item = (missed_path, block_list)
                missed_path_pairs.append(item)



        if len(missed_path_pairs) > 0:
            print "input_path correct"
            return (input_path, missed_path_pairs)
        #else:
        #    print "cannt find missed_path_pairs"
        #    return (input_path, None)

    #print "input_path wrong"
    return (None, None)


def get_top_for_driller():

    global g_drilled_inputs
    missed_path_pairs = []

    for trace in g_sorted_trace:
        input_path = trace[0]
        input_name = os.path.basename(input_path)
        if input_name in g_drilled_inputs:
            continue

        input_trace = read_trace_list(input_name)

        for path in input_trace:
            covered_index = path[0]
            missed_index = path[1]
            block_list = path[2]
            missed_cnt = g_coverage_statics[missed_index]

            # ##########
            # covered_path = g_dynamic_cfg[covered_index]
            # str_call_chain_index = covered_path[0]
            # prev_addr = covered_path[1]
            # cur_addr  = covered_path[2]
            # str_call_chain = get_call_chain(str_call_chain_index)
            # fout.write('Covered: Branch [0x%x-0x%x] \t %s Call_chain %s\n' % (prev_addr, cur_addr, str_call_chain_index, str_call_chain))


            if missed_cnt == 0:
                """
                missed_path = (str_call_chain, prev_addr, cur_addr)
                missed_path_pairs = [(missed_path, block_list)]
                """
                missed_path = g_dynamic_cfg[missed_index]
                item = (missed_path, block_list)
                missed_path_pairs.append(item)

        #         ###########
        #         str_call_chain_index = missed_path[0]
        #         prev_addr = missed_path[1]
        #         cur_addr  = missed_path[2]
        #         str_call_chain = get_call_chain(str_call_chain_index)
        #         fout.write('Missed: Branch [0x%x-0x%x] \t %s Call_chain %s\n' % (prev_addr, cur_addr, str_call_chain_index, str_call_chain))
        # fout.close()

        if len(missed_path_pairs) > 0:
            return (input_path, missed_path_pairs)
        else:
            return (input_path, None)

    return (None, None)



#rat driller
def driller_request(binary_path, afl_sync_dir, input_path, driller_output, input_type=None, cmd_args=None, missed_path_pairs=None):


    fuzz_bitmap_path = os.path.join(afl_sync_dir, 'fuzzer-1', "fuzz_bitmap")
    with open(fuzz_bitmap_path, 'rb') as f:
        fuzz_bitmap = f.read()

    one_driller = driller.driller.Driller(binary_path, input_type, cmd_args, fuzz_bitmap=fuzz_bitmap,  output_dir=driller_output)

    one_driller.update_call_graph(g_caller_addrs=g_caller_addrs, g_callee_addrs=g_callee_addrs, g_return_addrs=g_return_addrs, g_nopins_addrs=g_nopins_addrs)

    one_driller.drill_per_input(input_path, missed_path_pairs=missed_path_pairs)
    solved_path_pairs = one_driller.get_solved_path_pairs()

    # if len(solved_path_pairs) > 0:
    #     handle_feedback(solved_path_pairs)
    #     mcts_prioritizing(afl_sync_dir)

    del fuzz_bitmap
    del solved_path_pairs
    del one_driller


def sig_handler(signum, frame):

    parent = psutil.Process(os.getpid())
    for child in parent.children(recursive=True):
        try:
            child.kill()
        except:
            pass
    parent.kill()

def afl_stuck():

    fuzzer_stats = os.path.join(afl_sync_dir, 'fuzzer-1', "fuzzer_stats")
    drill_start = False

    try:
        with open(fuzzer_stats, 'rb') as f:
            stat_blob = f.read()
        stat_lines = stat_blob.split("\n")[12]
        pending_favs = stat_lines.split(":")[1]
        pending_favs = int(pending_favs,10)
        if pending_favs == 0:
            drill_start = True
    except:
        pass

    return drill_start

def afl_stuck_precise():

    fuzzer_stats = os.path.join(afl_sync_dir, 'fuzzer-1', "plot_data")
    drill_start = False

    try:
        with open(fuzzer_stats, 'rb') as f:
            stat_blob = f.read()
        stat_lines = stat_blob.split("\n")[-2]
        pending_favs = stat_lines.split(",")[5]
        pending_favs = int(pending_favs,10)
        if pending_favs == 0:
            drill_start = True
    except:
        pass

    return drill_start


def drill_one(afl_sync_dir, binary_path, select_type, input_type, cmd_args):

    #print "drill one"
    # updated = update_trace_coverage(afl_sync_dir, binary_path, driller_input, input_type, cmd_args)
    #print "start drill_one"
    if select_type == 'mcts':
        mcts_prioritizing(afl_sync_dir)

        # for trace in g_sorted_trace:
        #     input_name = trace[0]
        #     value = trace[1]
        #     print "%s \t %f" % (input_name, value)

        (input_path, missed_path_pairs) = get_top_for_driller()

    elif select_type == 'markov':
        markov_prioritizing(afl_sync_dir)
        (input_path, missed_path_pairs) = get_top_for_driller()

    elif select_type == 'random' or select_type == 'afl' or select_type == 'afl-mcts':
        (input_path, missed_path_pairs) = random_one_for_driller_with_filter()

    elif select_type == 'fast':
        (input_path, missed_path_pairs) = get_fast_for_driller()
    elif select_type == 'qsym':
        (input_path, missed_path_pairs) = qsym_one_for_driller_with_filter()


    if input_path is None:
        return False

    #print "choose a input"
    input_base = os.path.basename(input_path)
    source_id = get_input_id(input_base)
    if input_base.find('sig') > -1:
        driller_output_base = 'driller-sig-' + source_id
    else:
        driller_output_base = 'driller-' + source_id

    driller_output = os.path.join(afl_sync_dir, driller_output_base,  'queue')

    #if select_type == 'afl' or select_type == 'afl-mcts':
    if select_type == 'afl-mcts':
        driller_output = None

    '''
    time limit for each concolic execution
    '''
    signal.signal(signal.SIGALRM, sig_handler)
    signal.alarm(driller_timeout)

    #print 'driller_request %s at %s' % (input_base, time.time())
    g_drilled_inputs.add(input_base)

    with open(os.path.join(g_drilled_dir, input_base), 'w') as f:
        pass

    #driller_request(binary_path, afl_sync_dir, input_path, driller_output, input_type, cmd_args,  missed_path_pairs)
    print "start qsym"
    start_qsym(binary_path, afl_sync_dir, start_type, select_type, input_path)


    return True
        # print 'driller_request stop'



def drill_loop(input_type, cmd_args):

    total_time = 0
    driller_running = True

    '''
    In case of crash or being killed by the os, initialize the program for each time.
    '''
    queue_input = os.path.join(afl_sync_dir, 'fuzzer-1/queue')
    if not os.path.isdir(queue_input):
        return False

    crash_input = os.path.join(afl_sync_dir, 'fuzzer-1/crashes')
    if not os.path.isdir(crash_input):
        return False

    driller_input_list = []
    driller_input_list.append(queue_input)
    driller_input_list.append(crash_input)

    system_init(afl_sync_dir, binary_path)
    while True:
        if start_type == 'stuck':
            drill_start = False
            while not drill_start:
                #time.sleep(0.2)
                time.sleep(2.0)
                drill_start = afl_stuck()
                print drill_start
            print 'stuck %s' % time.time()
            update_trace_coverage(afl_sync_dir, binary_path, driller_input_list,input_type)
            driller_running = True
            # for input_base in g_traced_inputs:
            #     print input_base
            while driller_running:
                driller_running = drill_one(afl_sync_dir, binary_path, select_type, input_type, cmd_args)
        elif start_type == 'qsym':
            update_trace_coverage(afl_sync_dir, binary_path, driller_input_list)
            driller_running = True

            driller_running = drill_one(afl_sync_dir, binary_path, select_type, input_type, cmd_args)
        else:
            update_trace_coverage(afl_sync_dir, binary_path, driller_input_list)
            driller_running = drill_one(afl_sync_dir, binary_path, select_type, input_type, cmd_args)



    # while driller_running:
    #     start_time = time.time()
    #     driller_running = drill_one(afl_sync_dir, binary_path, select_type)
        #
        # for missed_path_pair in missed_path_pairs:
        #     missed_path = missed_path_pair[0]
        #     str_call_chain_index = missed_path[0]
        #     prev_addr = missed_path[1]
        #     cur_addr  = missed_path[2]
        #     block_list = missed_path_pair[1]
        #
        #     str_call_chain = get_call_chain(str_call_chain_index)
        #     for block in block_list:
        #         fout.write('Block: %d\t Branch [0x%x-0x%x] \t %s Call_chain %s\n' % (block, prev_addr, cur_addr, str_call_chain_index, str_call_chain))

        # round_time = time.time()-start_time
        # print round_time
        # total_time += round_time
        # print total_time

def main(argv):

    for name, logger in logging.root.manager.loggerDict.iteritems():
        logger.disabled=True

    global binary_path
    global afl_sync_dir
    global select_type
    global start_type
    binary_path = sys.argv[1]
    afl_sync_dir = sys.argv[2]
    start_type = sys.argv[3]
    select_type = sys.argv[4]

    input_type = "file"
    cmd_args = None

    binary_name = os.path.basename(binary_path)
    lava_bin = ['base64_01','md5sum_01', 'uniq_01', 'who_01']
    if binary_name in lava_bin:
        input_type = "file"

    if binary_name == 'base64_01':
        cmd_args = '-d'
    if binary_name == 'md5sum_01':
        cmd_args = '-c'

    strategies = ['mcts', 'markov', 'random', 'fast', 'afl', 'afl-mcts', 'qsym']
    if start_type != 'begin' and start_type != 'stuck' and start_type != 'qsym':
        sys.exit()
    if select_type not in strategies:
        sys.exit()

    # print 'start %s' % time.time()
    drill_loop(input_type, cmd_args)



        #

if __name__ == "__main__":
    sys.exit(main(sys.argv))
