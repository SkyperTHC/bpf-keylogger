import os, sys
import atexit
import signal
import time

from bcc import BPF

from defs import project_path, ticksleep
from keys import translate_keycode

class BPFProgram():
    def __init__(self, args):
        self.bpf = None

        self.debug = args.debug

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
            print(translate_keycode(event.code))
        self.bpf["keypresses"].open_perf_buffer(keypress)


    def load_bpf(self):
        assert self.bpf == None

        # Set flags
        flags = []
        if self.debug:
            flags.append(f'-DBKL_DEBUG')

        with open(os.path.join(project_path, "src/bpf/bpf_program.c"), "r") as f:
            text = f.read()
            self.bpf = BPF(text=text, cflags=flags)
        self.register_exit_hooks()
        self.register_perf_buffers()

    def main(self):
        self.load_bpf()

        print("Logging key presses... ctrl-c to quit")

        while True:
            time.sleep(ticksleep)
            if self.debug:
                self.bpf.trace_print()
            self.bpf.perf_buffer_poll()
