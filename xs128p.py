#!/usr/bin/env python3
import argparse
from pathlib import Path
import struct
from decimal import *
import os
from z3 import *
import sys
import math

MAX_UNUSED_THREADS = 2


def log(*args, **kwargs):
    print(*args, **kwargs, file=sys.stderr)

# Calculates xs128p (XorShift128Plus)


def xs128p(state0, state1):
    s1 = state0 & 0xFFFFFFFFFFFFFFFF
    s0 = state1 & 0xFFFFFFFFFFFFFFFF
    s1 ^= (s1 << 23) & 0xFFFFFFFFFFFFFFFF
    s1 ^= (s1 >> 17) & 0xFFFFFFFFFFFFFFFF
    s1 ^= s0 & 0xFFFFFFFFFFFFFFFF
    s1 ^= (s0 >> 26) & 0xFFFFFFFFFFFFFFFF
    state0 = state1 & 0xFFFFFFFFFFFFFFFF
    state1 = s1 & 0xFFFFFFFFFFFFFFFF
    generated = state0 & 0xFFFFFFFFFFFFFFFF

    return state0, state1, generated


def inv_xs128p(state0, state1):
    mask = 0xFFFFFFFFFFFFFFFF
    y = state0 & mask
    t = state1 & mask
    u = (t ^ y ^ (y >> 26)) & mask

    def unxor_rshift(val, shift):
        res = val
        i = shift
        while i < 64:
            res ^= res >> i
            i <<= 1
        return res & mask

    def unxor_lshift(val, shift):
        res = val
        i = shift
        while i < 64:
            res ^= (res << i) & mask
            i <<= 1
        return res & mask

    x = unxor_lshift(unxor_rshift(u, 17), 23)
    prev_state0 = x & mask
    prev_state1 = y & mask
    return prev_state0, prev_state1, prev_state1


def sym_xs128p(sym_state0, sym_state1):
    # Symbolically represent xs128p
    s1 = sym_state0
    s0 = sym_state1
    s1 ^= (s1 << 23)
    s1 ^= LShR(s1, 17)
    s1 ^= s0
    s1 ^= LShR(s0, 26)
    sym_state0 = sym_state1
    sym_state1 = s1
    # end symbolic execution

    return sym_state0, sym_state1


# Symbolic execution of xs128p
def sym_floor_random(slvr, sym_state0, sym_state1, generated, multiple):
    sym_state0, sym_state1 = sym_xs128p(sym_state0, sym_state1)

    # "::ToDouble"
    calc = LShR(sym_state0, 12)

    """
    Symbolically compatible Math.floor expression.

    Here's how it works:

    64-bit floating point numbers are represented using IEEE 754 (https://en.wikipedia.org/wiki/Double-precision_floating-point_format) which describes how
    bit vectors represent decimal values. In our specific case, we're dealing with a function (Math.random) that only generates numbers in the range [0, 1).

    This allows us to make some assumptions in how we deal with floating point numbers (like ignoring parts of the bitvector entirely).

    The 64bit floating point is laid out as follows
    [1 bit sign][11 bit expr][52 bit "mantissa"]

    The formula to calculate the value is as follows: (-1)^sign * (1 + Sigma_{i=1 -> 52}(M_{52 - i} * 2^-i)) * 2^(expr - 1023)

    Therefore 0_01111111111_1100000000000000000000000000000000000000000000000000 is equal to "1.75"

    sign => 0 => ((-1) ^ 0) => 1
    expr => 1023 => 2^(expr - 1023) => 1
    mantissa => <bitstring> => (1 + sum(M_{52 - i} * 2^-i) => 1.75

    1 * 1 * 1.75 = 1.75 :)

    Clearly we can ignore the sign as our numbers are entirely non-negative.

    Additionally, we know that our values are between 0 and 1 (exclusive) and therefore the expr MUST be, at most, 1023, always.

    What about the expr?

    """
    lower = from_double(Decimal(generated) / Decimal(multiple))
    upper = from_double((Decimal(generated) + 1) / Decimal(multiple))

    lower_mantissa = (lower & 0x000FFFFFFFFFFFFF)
    upper_mantissa = (upper & 0x000FFFFFFFFFFFFF)
    upper_expr = (upper >> 52) & 0x7FF

    slvr.add(And(lower_mantissa <= calc, Or(
        upper_mantissa >= calc, upper_expr == 1024)))
    return sym_state0, sym_state1


def create_solver(points, multiple):
    # setup symbolic state for xorshift128+
    state0, state1 = BitVecs('state0 state1', 64)
    sym_state0, sym_state1 = state0, state1
    set_option("parallel.enable", True)
    set_option("parallel.threads.max", (
        max(os.cpu_count() - MAX_UNUSED_THREADS, 1)))  # will use max or max cpu thread support, whatever is smaller
    s = SolverFor(
        "QF_BV")  # This type of problem is much faster computed using QF_BV (also, if branching happens, we can use parallelization)

    for point in points:
        sym_state0, sym_state1 = sym_floor_random(
            s, sym_state0, sym_state1, point, multiple)

    return s, (state0, state1)


def to_double(value):
    """
    https://github.com/v8/v8/blob/master/src/base/utils/random-number-generator.h#L111
    """
    double_bits = (value >> 12) | 0x3FF0000000000000
    return struct.unpack('d', struct.pack('<Q', double_bits))[0] - 1


def from_double(dbl):
    """
    https://github.com/v8/v8/blob/master/src/base/utils/random-number-generator.h#L111

    This function acts as the inverse to @to_double. The main difference is that we
    use 0x7fffffffffffffff as our mask as this ensures the result _must_ be not-negative
    but makes no other assumptions about the underlying value.

    That being said, it should be safe to change the flag to 0x3ff...
    """
    return struct.unpack('<Q', struct.pack('d', dbl + 1))[0] & 0x7FFFFFFFFFFFFFFF


def get_args():
    parser = argparse.ArgumentParser(
        description="Uses Z3 to predict future states for 'Math.floor(MULTIPLE * Math.random())' given some consecutive historical values. Pipe unbucketed points in via STDIN.")
    parser.add_argument('samples', type=Path, nargs='?',
                        help="The file containing the leaked, unbucketed points")
    parser.add_argument('-m', '--multiple', required=True, type=float,
                        help="Specifies the multiplier used in 'Math.floor(MULTIPLE * Math.random())'")
    parser.add_argument('-o', '--output', type=Path,
                        help="Output file to write constraints to instead of solving (useful for github.com/SRI-CSL/yices2)")
    parser.add_argument('-s', '--state',
                        help="Instead of predicting state, take a state pair and generate output. (state0,state1)")
    parser.add_argument('-g', '--gen', default=5, type=int,
                        help="Number of predictions to generate")
    parser.add_argument('-a', '--add', type=int, default=0,
                        help="Offset to add to all input samples and output predictions")
    parser.add_argument('-i', '--include-samples', action='store_true',
                        help="Include the samples in the prediction output")

    args = parser.parse_args()

    if args.state is not None:
        args.state = list(map(lambda x: int(x), args.state.split(",")))

    if args.samples is not None:
        args.samples = list(map(lambda line: int(line),
                                args.samples.read_text().splitlines()))
    elif args.state is None:
        args.samples = list(map(lambda line: int(line), sys.stdin.readlines()))

    assert args.samples is None or len(args.samples) > 0, \
        "Failed reading samples"

    return args


if __name__ == "__main__":
    args = get_args()

    state = args.state

    if state is None:
        if not all(map(lambda x: 0 <= x < args.multiple, args.samples)):
            log("[-] Error: All points must be in the range [0, MULTIPLE)")
            exit(1)

        log(f"Inputs ({len(args.samples)}):", args.samples)
        args.samples = [n + args.add for n in args.samples]
        s, (state0, state1) = create_solver(args.samples, args.multiple)

        if args.output is not None:
            with open(args.output, "w") as f:
                # Export z3 constraints to file, for other runners
                f.write("(set-logic QF_BV)\n")
                f.write(s.to_smt2())
                f.write("(get-model)")
            log("Wrote constraints to z3.smt2.")
            exit(0)
        else:
            log("Solving states...\n")
            if s.check() == sat:
                # get a solved state
                m = s.model()
                state0 = m[state0].as_long()
                state1 = m[state1].as_long()
            else:
                log("""[-] Failed to find a valid solution. Some potential reasons:
- The generator does not use Math.random()
- The MULTIPLE value is incorrect
- You forgot a newline at the end of the input file, causing `tac` to merge the last value with the first value
- The input is not reversed
- The input was bucketed (not inside a 64-sample boundary)""")
                exit(1)
    else:
        state0, state1 = state

    if state0 is not None and state1 is not None:
        log(f"[+] Found states: {state0},{state1}\n")

    if args.gen > 0:
        log(f"Predictions ({args.gen}):")

    if args.samples is not None and not args.include_samples:
        for _ in range(len(args.samples)):
            state0, state1, _ = xs128p(state0, state1)

    if args.gen >= 0:
        for _ in range(args.gen):
            state0, state1, output = xs128p(state0, state1)
            print(math.floor(args.multiple * to_double(output)) + args.add)
    else:
        for _ in range(abs(args.gen)):
            output = state0 & 0xFFFFFFFFFFFFFFFF
            print(math.floor(args.multiple * to_double(output)) + args.add)
            state0, state1, _ = inv_xs128p(state0, state1)
    # TODO: make support for 64-value cache boundaries, somehow recover the offset or arg it
