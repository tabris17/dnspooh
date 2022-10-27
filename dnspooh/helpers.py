

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
