#!/usr/bin/env python3
"""
Permute most possible settings to crack the RNG from only a set of numbers generated with Math.random().

- All samples + multiple -1000
- Reversed
- Split in max 32
- Automatically find round MULTIPLE from max of samples
"""


from math import ceil, log10
import os
from pathlib import Path
import sys
from xs128p import create_solver
from z3 import *
import itertools


def get_offset(multiple):
    return 10**(ceil(log10(multiple))-1)


def perm_reverse(samples, multiple):
    """Due to the cache being a Last In First Out (LIFO) structure, we get the samples in reverse."""
    return samples[::-1], multiple


def perm_offset(samples, multiple):
    """Guess common offset like `Math.floor(9000 * Math.random()) + 1000` to make n-digit numbers"""
    offset = get_offset(multiple)
    samples = list(map(lambda x: x - offset, samples))
    if any(map(lambda x: x < 0, samples)):
        return None, None  # Impossible if any sample is negative

    return samples, multiple - offset


def perm_minus_one(samples, multiple):
    """Multiple could be 9999 instead of 10000"""
    return samples, multiple - 1


def perm_half_first(samples, multiple):
    """Inputs may lie on a 64-wide cache boundary so we try both the first and second half so that at least one works."""
    mid = len(samples)//2
    return samples[:mid], multiple


def perm_half_last(samples, multiple):
    mid = len(samples)//2
    return samples[mid:], multiple


permutations = [
    perm_reverse,
    perm_offset,
    perm_minus_one,
    perm_half_first,
    perm_half_last,
]


def try_permutations(samples, multiple):
    for l in range(len(permutations)+1):
        for perm in itertools.combinations(permutations, l):
            if perm_half_first in perm and perm_half_last in perm:
                continue  # mutually exclusive

            perm_samples = samples
            perm_multiple = multiple
            for p in perm:
                perm_samples_, perm_multiple_ = p(perm_samples, perm_multiple)
                if perm_samples_ is None or perm_multiple_ is None:
                    print("Impossible permutation:",
                          p.__name__.split("perm_")[1])
                    break

                perm_samples, perm_multiple = perm_samples_, perm_multiple_

            print("-"*80)
            print("Permutation:", [p.__name__.split("perm_")[1] for p in perm])
            print("Samples:", perm_samples)
            print("Multiple:", perm_multiple)

            s, (state0_, state1_) = create_solver(perm_samples, perm_multiple)
            if s.check() == sat:
                m = s.model()
                state0 = m[state0_].as_long()
                state1 = m[state1_].as_long()
                s.add(Or(state0 != state0_, state1 != state1_))
                if s.check() == sat:
                    m = s.model()
                    print("WARNING: multiple solutions found! use more samples!")
                    print(f"1. {state0},{state1}")
                    print(f"2. {m[state0_].as_long()},{m[state1_].as_long()}")
                    print("...")
                    continue

                return (state0, state1), perm
            else:
                print("Failed to solve")

    return None, None


def find_multiple(samples):
    max_sample = max(samples)
    multiple = 1
    while multiple < max_sample:
        multiple *= 10
    return multiple


def explain_permutations(perm, states, multiple):
    print()
    if perm_half_first in perm:
        print("- The last half of your samples appear to be on a 64-wide cache boundary, therefore only the first half was used.")
    if perm_half_last in perm:
        print("- The first half of your samples appear to be on a 64-wide cache boundary, therefore only the last half was used.")
    if perm_reverse in perm:
        print("- The samples were reversed. This is because the cache is a Last In First Out (LIFO) structure.")
    if perm_offset in perm:
        offset = get_offset(multiple)
        multiple -= offset
        print(
            f"- The samples were offset by {offset} to make them n-digit numbers.")
    if perm_minus_one in perm:
        print(
            f"- The multiple was decremented by one. Instead of {multiple}, it is {multiple-1}.")
        multiple -= 1
    print("""\
The following is likely how the generator is implemented:
```js
""" +
          f"Math.floor({multiple} * Math.random())" +
          (f" + {offset}" if perm_offset in perm else "") +
          """
```
""")

    print("Use the following command to predict new numbers:")
    print(
        f"./xs128p.py -s {states[0]},{states[1]} -m {multiple}{f' -a {offset}' if perm_offset in perm else ''} -g 5")


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument('samples', type=Path, nargs='?',
                        help="The file containing the leaked, unbucketed points")
    parser.add_argument('-m', '--multiple', type=float,
                        help="Specifies the multiplier used in 'Math.floor(MULTIPLE * Math.random())' if it cannot be guessed")

    args = parser.parse_args()
    if args.samples is not None:
        with args.samples.open() as f:
            args.samples = list(map(lambda line: int(line), f.readlines()))
    else:
        if os.isatty(sys.stdin.fileno()):
            print("Reading samples from stdin. Press Ctrl-D when done.")
        else:
            print("Reading samples from pipe.")
        args.samples = list(map(lambda line: int(line), sys.stdin.readlines()))

    print("Samples:", args.samples)
    assert len(args.samples) > 0, "Failed reading samples"

    if args.multiple is None:
        print("Guessing multiple from samples...")
        args.multiple = find_multiple(args.samples)

    print("Multiple:", args.multiple)

    print("Starting permutations...")
    (state0, state1), perm = try_permutations(args.samples, args.multiple)
    print()
    if state0 is None and state1 is None:
        print("Failed to solve for all permutations")
    else:
        print(f"Found states: {state0},{state1}")

        explain_permutations(perm, (state0, state1), args.multiple)
