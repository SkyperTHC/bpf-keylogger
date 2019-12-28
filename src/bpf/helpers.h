/*
    bpf_helpers: These are my customer BPF helpers. They are included in all my projects.
                 I might submit a PR for these upstream someday.
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

#ifndef HELPERS_H
#define HELPERS_H

#include <linux/sched.h>

static inline struct pt_regs *bpf_get_current_pt_regs()
{
    struct task_struct* __current = (struct task_struct*)bpf_get_current_task();
    void* __current_stack_page = __current->stack;
    void* __ptr = __current_stack_page + THREAD_SIZE - TOP_OF_KERNEL_STACK_PADDING;
    return ((struct pt_regs *)__ptr) - 1;
}

static inline u32 bpf_strlen(char *s)
{
    u32 i;
    for (i = 0; s[i] != '\0' && i < (1 << (32 - 1)); i++);
    return i;
}

static inline int bpf_strncmp(char *s1, char *s2, u32 n)
{
    int mismatch = 0;
    for (int i = 0; i < n && i < sizeof(s1) && i < sizeof(s2); i++)
    {
        if (s1[i] != s2[i])
            return s1[i] - s2[i];

        if (s1[i] == s2[i] == '\0')
            return 0;
    }

    return 0;
}

static inline int bpf_strcmp(char *s1, char *s2)
{
    u32 s1_size = sizeof(s1);
    u32 s2_size = sizeof(s2);

    return bpf_strncmp(s1, s2, s1_size < s2_size ? s1_size : s2_size);
}

#endif /* HELPERS_H */
