#include <linux/interrupt.h>
#include <linux/input.h>
#include <uapi/linux/input-event-codes.h>

#include "src/bpf/bpf_program.h"
#include "src/bpf/helpers.h"

/* BPF programs below this line ---------------------------------- */

/* https://github.com/torvalds/linux/blob/master/drivers/input/input.c */
int kprobe__input_handle_event(struct pt_regs *ctx, struct input_dev *dev,
			       unsigned int type, unsigned int code, int value)
{
    /* Keypress event */
    if (type == EV_KEY)
    {
        bpf_trace_printk("code %u\n", code);
    }

    return 0;
}

int kprobe__input_repeat_key(struct pt_regs *ctx)
{
    bpf_trace_printk("repeat key!\n");

    return 0;
}
