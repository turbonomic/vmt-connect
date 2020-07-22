from decimal import Decimal
import re



def unit_cast(value, ufrom, uto, factor, unit_list, precision=False):
    offset = unit_list.index(uto) - unit_list.index(ufrom)
    chg = Decimal(pow(factor, abs(offset)))

    res = value * chg if offset <= 0 else value * (1/chg)

    return round(res, precision) if precision else res.normalize()


def mem_cast(value, unit=None, src=None):
    """
    Converts memory from one unit of measure to another. Values are interpreted
    as base 2 values (JEDEC memory standard), not SI values.

    Args:
        value (string): Base value, represented as a string.
        unit (string): Destination value to convert to. (default: ``G``)
        src (string): Source value unit of measure to convert from. (default: ``b``)
    """
    value = value.replace(' ', '')
    unit = 'G' if not unit else unit[0]
    src = 'B' if not src else src[0]

    if re.match(r'^[\d]+[BKMGTPEZY]{1}[B]?$', value, re.IGNORECASE):
        src = value[-2] if value[-2].isalpha() else value[-1]
        value = value[:-2] if value[-2].isalpha() else value[:-1]
    elif not value.isnumeric():
        raise ValueError(f"'{value}' is not a recognized value")

    return unit_cast(Decimal(value),
                     src.upper(),
                     unit.upper(),
                     1024,
                     ['B', 'K', 'M', 'G', 'T', 'P', 'E', 'Z', 'Y']
                     )
