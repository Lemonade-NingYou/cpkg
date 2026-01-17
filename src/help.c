/*
 * Copyright (C) 2025 lemonade_NingYou
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

#include "../include/help.h"

const char *help_message =
"Usage: cpkg [<option>...] <command>\n"
"\n"
"Commands:\n"
"  -i|--install       <.deb filename> ... | -R|--recursive <directory> ...\n"
"  --unpack           <.deb filename> ... | -R|--recursive <directory> ...\n"
"  -A|--record-avail  <.deb filename> ... | -R|--recursive <directory> ...\n"
"  --configure        <package>       ... | -a|--pending\n"
"  --triggers-only    <package>       ... | -a|--pending\n"
"  -r|--remove        <package>       ... | -a|--pending\n"
"  -P|--purge         <package>       ... | -a|--pending\n"
"  -V|--verify <package> ...          Verify package integrity.\n"
"  --get-selections [<pattern> ...]   Print list of selected packages to stdout.\n"
"  --set-selections                   Read selections from stdin.\n"
"  --clear-selections                 Deselect all non-essential packages.\n"
"  --update-avail <Packages-file>     Replace available packages info.\n"
"  --merge-avail  <Packages-file>     Merge with info from file.\n"
"  --clear-avail                      Clear existing package info.\n"
"  --forget-old-unavail               Forget uninstalled unavailable packages.\n"
"  -s|--status      <package> ...     Display package status details.\n"
"  -p|--print-avail <package> ...     Display available version of package.\n"
"  -L|--listfiles   <package> ...     List files 'owned' by package(s).\n"
"  -l|--list  [<pattern> ...]         List packages concisely.\n"
"  -S|--search <pattern> ...          Find package(s) owning file(s).\n"
"  -C|--audit [<pattern> ...]         Check for broken package(s).\n"
"  --yet-to-unpack                    List packages selected for unpacking.\n"
"  --predep-package                   List unpacked but unconfigured pre-dependencies.\n"
"  --add-architecture    <arch>       Add <arch> to the list of architectures.\n"
"  --remove-architecture <arch>       Remove <arch> from the list of architectures.\n"
"  --print-architecture               Display dpkg architecture.\n"
"  --print-foreign-architectures      Display enabled foreign architectures.\n"
"  --assert-<feature>                 Assert support for the specified feature.\n"
"  --validate-<property> <string>     Validate a <property> <string>.\n"
"  --compare-versions <a> <op> <b>    Compare version numbers - see below.\n"
"  --force-help                       Show help on forcing.\n"
"  -Dh|--debug=help                   Show help on debugging.\n"
"\n"
"  -?, --help                        Show this help message.\n"
"      --version                     Display version information.\n"
"\n"
"Validatable properties: pkgname, archname, trigname, version.\n"
"\n"
"Invoking cpkg with -b, --build, -c, --contents, -e, --control, -I, --info,\n"
"  -f, --field, -x, --extract, -X, --vextract, --ctrl-tarfile, --fsys-tarfile\n"
"pertains to archives. (Type cpkg-deb --help for help)\n"
"\n"
"Options:\n"
"  --admindir=<directory>          Use <directory> instead of /var/lib/dpkg.\n"
"  --root=<directory>              Install on a different root directory.\n"
"  --instdir=<directory>           Change installation dir without changing admin dir.\n"
"  --pre-invoke=<command>          Set a pre-invoke hook.\n"
"  --post-invoke=<command>         Set a post-invoke hook.\n"
"  --path-exclude=<pattern>        Do not install paths matching shell pattern.\n"
"  --path-include=<pattern>        Re-include a pattern after a previous exclusion.\n"
"  -O|--selected-only              Skip packages not selected for install/upgrade.\n"
"  -E|--skip-same-version          Skip packages whose installed version matches.\n"
"  -G|--refuse-downgrade           Skip packages with earlier version than installed.\n"
"  -B|--auto-deconfigure           Install even if it would break other packages.\n"
"  --[no-]triggers                 Skip or force trigger processing.\n"
"  --verify-format=<format>        Verify output format (supported: 'rpm')\n"
"  --no-pager                      Disables all pagers.\n"
"  --no-debsig                     Do not verify package signatures.\n"
"  --no-act|--dry-run|--simulate   Just say what we would do - don't do it.\n"
"  -D|--debug=<octal>              Enable debugging (see -Dhelp or --debug=help).\n"
"  --status-fd <n>                 Send status update messages to file descriptor <n>.\n"
"  --status-logger=<command>       Send status updates to <command>'s stdin.\n"
"  --log=<filename>                Write status updates and actions to <filename>.\n"
"  --ignore-depends=<package>[,...] Ignore dependency problems involving <package>.\n"
"  --force-<thing>[,...]           Override problems (see --force-help).\n"
"  --no-force-<thing>[,...]        Stop when <thing> encountered.\n"
"  --refuse-<thing>[,...]          Ditto.\n"
"  --abort-after <n>               Abort after encountering <n> errors.\n"
"  --robot                         Use machine-readable output on some commands.\n"
"\n"
"Comparison operators for --compare-versions:\n"
" lt le eq ne ge gt        (treat empty version as earlier than any version);\n"
" lt-nl le-nl ge-nl gt-nl  (treat empty version as later than any version);\n"
" < << <= = >= >> >        (only for compatibility with control file syntax).\n"
"\n"
"'capt' and 'captitude' provide more user-friendly package management.\n";