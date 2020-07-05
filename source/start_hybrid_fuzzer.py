#!/usr/bin/env python
import logging
import os
import sys
import time
import hashlib
import subprocess
import distutils
import shutil
#import angr
import signal
import psutil


FUZZER_BIN = '/home/whu/app/afl-2.52b/afl-fuzz'
driller_path = "/home/whu/fuzz_job/mcts_on_cqe/seed_prioritization.py"
TIME_LIMIT = 12*3600
SLEEP_TIME = 60
cpuid_min = 10
cpuid_max = 16

#low_binaries = ['CROMU_00018_01', 'KPRCA_00025_01', 'KPRCA_00041_01', 'KPRCA_00049_01', 'NRFIN_00033_01']

def _start_afl_instance(binary, job_dir, fuzz_id):

    in_dir = os.path.join(job_dir, "input")
    out_dir  = os.path.join(job_dir, "output")

    binary_basename = os.path.basename(binary)

    memory="2G"
    args = [FUZZER_BIN]
    args += ["-i", in_dir]
    args += ["-o", out_dir]
    args += ["-m", memory]

    dict_dir = os.path.join(os.path.dirname(binary), 'dicts')
    if os.path.isdir(dict_dir):
        args += ["-x", dict_dir]

    if not binary_basename.find("xmllint") > -1:
        args += ["-Q"]

    if fuzz_id == 0:
        args += ["-M", "fuzzer-master"]
        outfile = "fuzzer-master.log"
    else:
        args += ["-S", "fuzzer-%d" % fuzz_id]
        outfile = "fuzzer-%d.log" % fuzz_id

    args += ["--"]
    args += [binary]

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

    outfile = os.path.join(job_dir, outfile)
    print args
    with open(outfile, "w") as fp:
        p = subprocess.Popen(args, stdout=fp, close_fds=True)
        return p

def start_driller(binary_path, afl_sync_dir, start_type, select_type, cpuid):

    args = ["taskset", "-c", cpuid, "python", driller_path, binary_path, afl_sync_dir, start_type, select_type]
    outfile = os.path.join(os.path.dirname(afl_sync_dir), 'driller.log')
    print args
    with open(outfile, "w") as fp:
        p = subprocess.Popen(args, stdout=fp, close_fds=True)
        return p

def afl_stop_detect(pm, p1):

    if pm is None:
        return True
    elif pm.poll() is not None:
        return True

    if p1 is None:
        return True
    elif p1.poll() is not None:
        return True

    return False


def crash_detect(afl_sync_dir):

    afl_master = os.path.join(afl_sync_dir, 'fuzzer-master', 'crashes')
    afl_1 = os.path.join(afl_sync_dir, 'fuzzer-1', 'crashes')

    if os.path.isdir(afl_master):
        crashes = os.listdir(afl_master)
        if len(crashes) > 1:
            return True

    if os.path.isdir(afl_1):
        crashes = os.listdir(afl_1)
        if len(crashes) > 1:
            return True

    return False


'''
Large scale test script. Should just require pointing it at a directory full of binaries.
'''
def start_binary(binary_dir, job_dir, start_type, select_type):

    print binary_dir
    if not os.path.isdir(binary_dir):
        return

    identifier = os.path.basename(binary_dir)
    binary_path = os.path.join(binary_dir, identifier + '_01')
    if not os.path.isfile(binary_path):
        binary_path = os.path.join(binary_dir, identifier)

    if os.path.isdir(job_dir):
        shutil.rmtree(job_dir)
    os.makedirs(job_dir)

    in_dir = os.path.join(job_dir, "input")
    afl_sync_dir = os.path.join(job_dir, "output")
    if not os.path.isdir(in_dir):
        os.makedirs(in_dir)

    #seed_path = os.path.join(binary_dir, identifier + '_01.seed.txt')
    #if os.path.isfile(seed_path):
    #    shutil.copy(seed_path, in_dir)

    #seed_path = os.path.join(binary_dir, identifier + '_01.seed')
    #if os.path.isfile(seed_path):
    #    shutil.copy(seed_path, in_dir)

    seed_path = os.path.join(binary_dir, identifier + '.seed')
    if os.path.isfile(seed_path):
        shutil.copy(seed_path, in_dir)

    if not os.path.isdir(afl_sync_dir):
        os.makedirs(afl_sync_dir)

    if not os.listdir(in_dir):
        with open(os.path.join(in_dir, 'seed'), 'wb') as f:
            f.write('fuzz\n')

    cpuid = cpuid_min
    cpu_path = os.path.join("/home/whu", "cpuinfo")
    if not os.path.isdir(cpu_path):
        os.makedirs(cpu_path)
    while(str(cpuid) in os.listdir(cpu_path) and cpuid <= cpuid_max):
        cpuid = cpuid + 1
    cpuid = str(cpuid)
    cpu_file = os.path.join(cpu_path, cpuid)
    with open(cpu_file, "w") as fp:
        pass

    pm = _start_afl_instance(binary_path, job_dir, 0)
    p1 = _start_afl_instance(binary_path, job_dir, 1)
    pd = None
    if select_type in ['mcts', 'markov', 'random', 'afl', 'qsym']:
        pd = start_driller(binary_path, afl_sync_dir, start_type, select_type, cpuid)

    start_time = time.time()
    if pm is None or p1 is None:
        print 'AFL instance error %s' % binary_dir
        os._exit(1)

    if select_type in ['mcts', 'markov', 'random', 'afl', 'qsym']:
        if pd is None:
            print 'Driller instance error %s' % binary_dir
            os._exit(1)


    while True:
        time.sleep(SLEEP_TIME)
        running_time = time.time()

        crashed = crash_detect(afl_sync_dir)
        afl_stopped = afl_stop_detect(pm, p1)

        #if (running_time - start_time) >= TIME_LIMIT or crashed or afl_stopped:
        if (running_time - start_time) >= TIME_LIMIT or afl_stopped:
            if pm.poll() is None:
                parent = psutil.Process(pm.pid)
                for child in parent.children(recursive=True):
                    try:
                        child.kill()
                    except:
                        pass
                parent.kill()
            if p1.poll() is None:
                parent = psutil.Process(p1.pid)
                for child in parent.children(recursive=True):
                    try:
                        child.kill()
                    except:
                        pass
                parent.kill()
            if select_type in ['mcts', 'markov', 'random', 'afl', 'qsym']:
                if pd.poll() is None:
                    parent = psutil.Process(pd.pid)
                    for child in parent.children(recursive=True):
                        try:
                            child.kill()
                        except:
                            pass
                    parent.kill()
            break
        else:
            if select_type in ['mcts', 'markov', 'random', 'afl', 'qsym']:
                if pd is None:
                    print 'restart driller 0!'
                    pd = start_driller(binary_path, afl_sync_dir, start_type, select_type, cpuid)
                elif pd.poll() is not None:
                    print 'restart driller!'
                    pd = start_driller(binary_path, afl_sync_dir, start_type, select_type, cpuid)

    os.remove(cpu_file)
    print 'All done!'

def main(argv):

    for name, logger in logging.root.manager.loggerDict.iteritems():
        logger.disabled=True

    binary_path = sys.argv[1]
    job_dir = sys.argv[2]
    start_type = sys.argv[3]
    select_type = sys.argv[4]

    global cpuid_min
    global cpuid_max

    strategies = ['mcts', 'markov', 'random', 'fast', 'afl', 'afl-mcts', 'qsym']

    if start_type != 'begin' and start_type != 'stuck' and start_type != 'qsym':
        sys.exit()
    if select_type not in strategies:
        sys.exit()

    global FUZZER_BIN
    if select_type == 'mcts' or select_type == 'afl-mcts':
        FUZZER_BIN = '/home/leizhao/fuzz_job/afl_cgc_mcts/afl-fuzz-mcts'

    start_binary(binary_path, job_dir, start_type, select_type)

if __name__ == "__main__":

    sys.exit(main(sys.argv))
