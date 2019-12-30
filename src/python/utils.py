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

# Execute a function with dropped privileges (if we have privileges to drop)
def drop_privileges(func):
    def inner(*args, **kwargs):
        try:
            sudo_uid = os.environ['SUDO_UID']
            sudo_gid = os.environ['SUDO_GID']

            # Remember current euid and egid
            euid = os.geteuid()
            egid = os.getegid()

            # Drop privileges
            os.setegid(int(sudo_gid))
            os.seteuid(int(sudo_uid))

            # Call wrapped function
            ret = func(*args, **kwargs)

            # Restore privileges
            os.setegid(egid)
            os.seteuid(euid)

            return ret

        except KeyError:
            print('WARNING: Unable to drop privileges. Are you running as root?', file=sys.stderr)
            return func(*args, **kwargs)
    return inner
