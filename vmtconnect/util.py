# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from collections import defaultdict
from copy import deepcopy
from decimal import Decimal
from io import StringIO
import re



def enumerate_stats(data, entity=None, period=None, stat=None):
    """Enumerates stats endpoint results

    Provides an iterator for more intuitive and cleaner parsing of nested
    statistics results. Each iteration returns a tuple containing the statistics
    period `date` timestamp, as well as the next individual statistic entry as
    a dictionary.

    Args:
        data (list): Stats endpoint data results to parse.
        entity (function, optional): Optional entity level filter function.
        period (function, optional): Optional period level filter function.
        stat (function, optional): Optional statistic level filter function.

    Notes:
        Filter functions must return ``True``, to continue processing, or ``False``
        to skip processing the current level element.

    Examples:
        .. code-block:: python

            # filter stats for a specific ID
            desired_id = '284552108476721'
            enumerate_stats(data, entity=lambda x: x['uuid'] == desired_uuid)

            # filter specific stats for all IDs
            blacklist = ['Ballooning']
            enumerate_stats(data, stat=lambda x: x['name'] not in blacklist)
    """
    for k1, v1 in enumerate(data):
        if entity is not None and not entity(v1) \
        or 'stats' not in v1:
            continue

        for k2, v2 in enumerate(v1['stats']):
            if period is not None and not period(v2):
                continue

            for k3, v3 in enumerate(v2['statistics']):
                if stat is not None and not stat(v3):
                    continue
                yield v2['date'], v3


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


def _filter(src, filter, dest=None):
    def rdest():
        try:
            return dest[idx]
        except (TypeError, KeyError):
            return None

    def ret(idx, value):
        if not value:
            return

        if dest:
            dest[idx] = deepcopy(value)
            return dest

        return {idx: deepcopy(value)}

    if not filter:
        return deepcopy(src)

    keys = filter.split('.', 1)
    idx = keys[0]

    if '[' in idx:
        sub = idx.split('[')[1].rstrip(']')
        sub = '0:' if sub in ('', '*') else sub
        idx = idx.split('[')[0]
    else:
        sub = None

    tree = keys[1] if len(keys) > 1 else None

    if ',' in idx:
        return {i: _filter(src[i], tree, rdest()) for i in idx.split(',') if i in src}
    elif sub and idx in src:
        if ':' in sub:
            sub = slice(*map(lambda x: int(x) if x.isdigit() else None,
                             sub.split(':')
                             ))
        else:
            sub = slice(int(sub),int(sub)+1)

        return ret(idx, [_filter(x, tree) for x in src[idx][sub]])
    elif idx in src:
        return ret(idx, _filter(src[idx], tree, rdest()))


def filter_copy(source, filter, size=500, use_float=False):
    """Permits response nested key filtering.

    Args:
        source (obj): Raw server response to filter.
        filter (obj): Whitelist filter(s) to apply to the source data. Must be a
            :py:class:`list` to use the native DSL, or a string to use a JQ script.
            This represents data you want to explicitly keep.
        size (int, optional): Array buffer size. (default: ``500``)

    Notes:
        The source data must not be pre-processed by a JSON converter.

        The native filtering DSL is simpler than JQ script, and more human readable.

        JQ scripts are executed per item returned, not against the entire JSON as
        a whole. JQ scripts provide significantly more features than the native DSL
        at the cost of performance.
    """
    import ijson

    if isinstance(filter, str):
        import jq
        jq = True
        use_float = True
    elif isinstance(filter, list):
        jq = False

    def apply(_s, _f):
        _out = {}

        for i in _f:
            x = _filter(_s, i, _out)
            _out = x if x else _out

        return _out

    out = [None] * size
    idx = 0

    for x in ijson.items(StringIO(source), 'item', use_float=use_float):
        if idx >= len(out):
            out.extend([None] * size)

        if jq:
            out[idx] = deepcopy(jq.all(filter, x))
        else:
            out[idx] = deepcopy(apply(x, filter))

        idx += 1

    if idx == 0:
        if jq:
            out[idx] = deepcopy(jq.all(filter, json.loads(source)))
        else:
            out[0] = deepcopy(apply(json.loads(source), filter))

        idx = 1

    del out[idx:]

    return out


def to_defaultdict(factory, data):
    """
    Convert a list or dictionary to a defaultdict object

    Args:
        factory (obj): Used as the default value.
        data (obj): List or dict to convert.

    See Also:
        https://docs.python.org/3.8/library/collections.html#defaultdict-objects
    """
    if isinstance(data, dict):
        return defaultdict(factory, {k: to_defaultdict(factory, v) for k, v in data.items()})

    if isinstance(data, list):
        return [to_defaultdict(factory, v) for v in data]

    return data


def str_to_bool(str):
    return str.lower() in ('yes', 'true', 'y', 't', '1')
