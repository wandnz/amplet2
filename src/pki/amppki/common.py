from re import search


def verify_common_name(name):
    if search("[^a-zA-Z0-9.-]+", name) is None:
        return True
    return False
