import ida_kernwin


def get_ida_version():
    return float(ida_kernwin.get_kernel_version())
