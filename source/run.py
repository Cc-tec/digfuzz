#!/usr/bin/env python
import  os
import sys
import subprocess
import time
import datetime
import logging

binary_list = ["nm","size","exiv2","xmlwf","cjpeg","infotocap","jhead","pdfimages","objdump",
                "pngfix","readelf","tiffdump"]
afl_path = "/home/whu/fuzz_job/mcts_on_cqe/start_hybrid_fuzzer.py"
binary_base = "/home/whu/fuzz_job/binaries"
out_base = "/home/whu/fuzz_job/fuzzer_results_qsqs"

job_int = 0
job_container = []
SLEEP_TIME = 300

def start_job(binary):
    cmd = ["python", afl_path]
    binary_path = os.path.join(binary_base, binary)
    out_path = os.path.join(out_base, binary)
    cmd += [binary_path, out_path]
    cmd += ["qsym", "qsym"]
    print "--------------------------------------------------"
    print cmd
    outfile = os.path.join(out_base, binary+".log")
    with open(outfile, "w") as fp:
        p = subprocess.Popen(cmd, stdout=fp, stderr=fp, close_fds=True)
    #p.wait()
    return p


def main():
    for name, logger in logging.root.manager.loggerDict.iteritems():
        logger.disabled=True

    global job_int

    for binary in binary_list:
        while job_int >= 4:
            time.sleep(SLEEP_TIME)
            for i in job_container:
                if i.poll() is not None:
                    job_container.remove(i)
                    job_int = job_int - 1

        job_container.append(start_job(binary))
        time.sleep(SLEEP_TIME)
        job_int = job_int+1

if __name__ == "__main__":
    main()
