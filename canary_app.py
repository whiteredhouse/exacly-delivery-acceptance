"""A side-effect-free invoice total for the merge acceptance canary."""

from collections.abc import Iterable


def total_cents(line_items: Iterable[tuple[int, int]]) -> int:
    """Return the total for (unit price in cents, quantity) line items.

    Prices must be nonnegative integers and quantities positive integers.
    Integer cents avoid rounding. Boolean values are not monetary inputs.
    """
    result = 0
    for price, quantity in line_items:
        if type(price) is not int or price < 0:
            raise ValueError("unit price must be a nonnegative integer number of cents")
        if type(quantity) is not int or quantity <= 0:
            raise ValueError("quantity must be a positive integer")
        result += price * quantity
    return result
