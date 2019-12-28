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

#ifndef BPF_PROGRAM_H
#define BPF_PROGRAM_H

struct bkl_key_event
{
    unsigned int code;
};

#endif /* BPF_PROGRAM_H */
