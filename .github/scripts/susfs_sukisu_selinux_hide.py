#!/usr/bin/env python3
"""Finish the SUSFS enable patch on SukiSU's selinux_hide.c when its last hunk rejects.

usage: susfs_sukisu_selinux_hide.py <selinux_hide.c> [common-kernel-root]

SUSFS v2.3.0 moves selinuxfs hiding into the kernel-side patch, so the enable
patch deletes the runtime write_op / status_open / setprocattr hooking from
ksu_selinux_hide_enable() and drops ksu_selinux_hide_unhook() and _disable().
On SukiSU v4.2.1 that hunk rejects (my_sel_open_handle_status() grew a mutex),
which leaves the hooking code behind while the declarations it needs are gone.
This re-does what the hunk does, keeping the two kallsyms lookups the AV helpers
below still depend on.
When given a kernel root, reconnect SukiSU's exported context/access handlers
at the existing selinuxfs query sites, retaining NoMount's preceding guards.
"""
import io
import re
import sys

ENABLE = '''static int ksu_selinux_hide_enable()
{
    pr_info("selinux_hide: init selinux hide\\n");
    if (!backup_sepolicy) {
        pr_err("no backup sepolicy available, please save feature and reboot to retry!\\n");
        return -EAGAIN;
    }
    security_dump_masked_av_fn = find_kernel_symbol_exact("security_dump_masked_av");
    if (!security_dump_masked_av_fn)
        pr_warn("security_dump_masked_av not found!\\n");
    context_struct_compute_av_fn = find_kernel_symbol_exact("context_struct_compute_av");
    if (!context_struct_compute_av_fn)
        pr_warn("context_struct_compute_av not found!\\n");

    return 0;
}

'''


def wire_query_handlers(path, kernel_root):
    source = io.open(path, encoding='utf-8').read()
    kernel_path = kernel_root.rstrip('/') + '/security/selinux/selinuxfs.c'
    kernel = io.open(kernel_path, encoding='utf-8').read()
    declarations = '''#ifdef CONFIG_KSU_SUSFS
extern bool ksu_selinux_hide_running;
extern ssize_t my_write_context(struct file *file, char *buf, size_t size);
extern ssize_t my_write_access(struct file *file, char *buf, size_t size);
#endif

'''
    for name, anchor in (
        ('context', r'length = security_context_to_sid\('
         r'(?:&selinux_state,\s*)?buf,'),
        ('access', r'length = security_context_str_to_sid\('
         r'(?:&selinux_state,\s*)?scon,'),
    ):
        handler = 'my_write_' + name
        if not re.search(r'^ssize_t ' + handler + r'\(', source, re.M):
            raise ValueError('SUSFS did not export ' + handler)
        region = re.search(
            r'^static ssize_t sel_write_' + name + r'\([^;]*?\n\{.*?^\}',
            kernel, re.M | re.S)
        if not region:
            raise ValueError('selinuxfs query handler not found: ' + name)
        body = region.group()
        if handler + '(file, buf, size)' not in body:
            addition = '''#ifdef CONFIG_KSU_SUSFS
    if (current_uid().val >= 10000 && ksu_selinux_hide_running) {
        length = %s(file, buf, size);
        goto out;
    }
#endif
''' % handler
            body, count = re.subn(
                r'(?m)^[ \t]*' + anchor,
                lambda match: addition + match.group(), body)
            if count != 1:
                raise ValueError('ambiguous selinuxfs query anchor: ' + name)
            kernel = kernel[:region.start()] + body + kernel[region.end():]
    if 'extern ssize_t my_write_access(' not in kernel:
        if 'enum sel_inos {' not in kernel:
            raise ValueError('selinuxfs declaration anchor missing')
        kernel = kernel.replace('enum sel_inos {',
                                declarations + 'enum sel_inos {', 1)
    io.open(kernel_path, 'w', encoding='utf-8').write(kernel)
    print('selinuxfs: SukiSU context/access handlers reconnected')


def main():
    path = sys.argv[1]
    s = io.open(path, encoding='utf-8').read()
    if 'find_kernel_symbol_exact("write_op")' not in s:
        print('selinux_hide.c: enable hunk already applied, nothing to do')
        if len(sys.argv) > 2:
            wire_query_handlers(path, sys.argv[2])
        return 0

    start = re.search(r'^typedef int \(\*sel_open_handle_status_fn\)[^\n]*\n', s, re.M)
    end = re.search(r'^static int selinux_hide_feature_get\(', s, re.M)
    if not start or not end or end.start() < start.start():
        print('::error::selinux_hide.c: could not locate the region between the status-open typedef and selinux_hide_feature_get()')
        return 1
    s = s[:start.start()] + ENABLE + s[end.start():]

    s, n = re.subn(r'^static void hook_selinux_status_open\(\)\n\{.*?\n\}\n', '', s, count=1, flags=re.M | re.S)
    if n:
        print('selinux_hide.c: dropped the dead hook_selinux_status_open() the fixer restored')

    if '#include "infra/symbol_resolver.h"' not in s:
        s = s.replace('#include "selinux_hide.h"\n', '#include "selinux_hide.h"\n#include "infra/symbol_resolver.h"\n', 1)

    for fn in ('security_dump_masked_av_fn', 'context_struct_compute_av_fn'):
        if re.search(r'\(\*%s\)' % fn, s):
            s = s.replace('if (&%s)' % fn, 'if (%s)' % fn)

    left = [w for w in ('selinux_write_op', 'ksu_lsm_hook', 'ksu_lsm_unhook', 'sel_open_handle_status', 'context_write', 'access_write =', 'ksu_selinux_hide_unhook')
            if w in s]
    if left or s.count('static int ksu_selinux_hide_enable()') != 1:
        print('::error::selinux_hide.c: hooking remnants survived: %s' % ', '.join(left))
        return 1

    io.open(path, 'w', encoding='utf-8').write(s)
    print('selinux_hide.c: enable() reduced to the SUSFS v2.3.0 shape, hooking code removed')
    if len(sys.argv) > 2:
        wire_query_handlers(path, sys.argv[2])
    return 0


if __name__ == '__main__':
    sys.exit(main())
