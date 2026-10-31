"""Unambiguous JSON decoding for source and delivery evidence."""

import json
import math


def loads(data):
    """Decode JSON while rejecting duplicate keys and every nonfinite number."""
    def unique_object(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("duplicate JSON key: " + key)
            result[key] = value
        return result

    def invalid_constant(value):
        raise ValueError("nonfinite JSON constant: " + value)

    def finite_float(value):
        number = float(value)
        if not math.isfinite(number):
            raise ValueError("nonfinite JSON number: " + value)
        return number

    return json.loads(data, object_pairs_hook=unique_object,
                      parse_constant=invalid_constant, parse_float=finite_float)
