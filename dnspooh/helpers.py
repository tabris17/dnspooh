

def split_domain(name, reverse=True):
    dot_pos = name.find('.')
    if reverse:
        yield name
        while dot_pos > 0:
            yield name[dot_pos + 1:]
            dot_pos = name.find('.', dot_pos + 1)
    else:
        while dot_pos > 0:
            yield name[:dot_pos]
            dot_pos = name.find('.', dot_pos + 1)
        yield name


def s_addr(addr):
    if isinstance(addr, tuple):
        len_addr = len(addr)
        if len_addr == 2:
            return '%s:%d' % addr
        elif len_addr == 4:
            return '[%s]:%d' % addr[:2]
    return str(addr)
