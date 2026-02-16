def derive_initials(first_names) -> str:
    """
    Return initials based on first names. Only look for space as a separator.

    For example the following names will return:
    - Kees John -> K.J.
    - Anne-Fleur -> A.
    - Jan-Willem Gerard -> J.G.
    - Ijsbrand -> I.
    """
    initials = [n[:1] for n in first_names.split(" ")]
    return ".".join(initials + [""])
