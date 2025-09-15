import struct
import ida_kernwin


def get_ida_version():
    return float(ida_kernwin.get_kernel_version())


def dword_to_ip(dword: int) -> str:
    ip = []
    for x in range(4):
        ip.append(str((dword >> (8 * x)) & 0xff))
    return '.'.join(ip)


def is_valid_ip(ip: str) -> bool:
    """
    This function is not perfect as an IP address can end in 255 but the likelihood that a
    threat actor is using it is low as it's reserved.  Same with IP addresses that start
    with 0.
    """
    parts = ip.split('.')
    if len(parts) != 4:
        return False
    if int(parts[0], 10) == 0x0:
        return False
    if int(parts[3], 10) == 0xff:
        return False
    return True


def word_to_port(word: int) -> str:
    return str(struct.unpack('>H', struct.pack('<H', word))[0])
