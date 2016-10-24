TAB_1 = '\t   '
TAB_2 = '\t\t   '
TAB_3 = '\t\t\t   '
TAB_4 = '\t\t\t\t   '


# Returns MAC as string from bytes (ie AA:BB:CC:DD:EE:FF)
def get_mac_addr(mac_raw):
    byte_str = map('{:02x}'.format, mac_raw)
    mac_addr = ':'.join(byte_str).upper()
    return mac_addr
