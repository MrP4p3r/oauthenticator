"""Shared rendering helper for the terminal UI.

Every value printed through here may have come from the provider (an
endpoint URL, a claim, a token), so markup and highlighting stay off: a
value is never reinterpreted as rich markup or recoloured by the
highlighter, only labelled.
"""

from rich.text import Text


def print_field(console, label, value):
    console.print(Text(f'{label}:', style='bold'), value, markup=False, highlight=False)
