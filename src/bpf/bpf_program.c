#include <linux/interrupt.h>
#include <linux/input.h>
#include <linux/timer.h>
#include <uapi/linux/input-event-codes.h>

#include "src/bpf/bpf_program.h"
#include "src/bpf/helpers.h"

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
int kprobe__input_repeat_key(struct pt_regs *ctx)
{
#ifdef BKL_DEBUG
    bpf_trace_printk("repeat key!\n");
#endif

    return 0;
}
