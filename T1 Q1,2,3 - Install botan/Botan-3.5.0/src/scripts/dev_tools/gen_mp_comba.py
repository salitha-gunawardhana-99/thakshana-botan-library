#!/usr/bin/env python3

import sys
import datetime

# (C) 2011,2014,2015,2016 Jack Lloyd
# Botan is released under the Simplified BSD License (see license.txt)

# Used to generate src/lib/math/mp/mp_comba.cpp

def comba_indexes(N):

    indexes = []

    for i in range(0, 2*N):
        x = []

        for j in range(max(0, i-N+1), min(N, i+1)):
            x += [(j,i-j)]
        indexes += [sorted(x)]

    return indexes

def comba_sqr_indexes(N):

    indexes = []

    for i in range(0, 2*N):
        x = []

        for j in range(max(0, i-N+1), min(N, i+1)):
            if j < i-j:
                x += [(j,i-j)]
            else:
                x += [(i-j,j)]
        indexes += [sorted(x)]

    return indexes

def comba_multiply_code(N):
    indexes = comba_indexes(N)

    for (i,idx) in zip(range(0, len(indexes)), indexes):
        for pair in idx:
            print("   accum.mul(x[%d], y[%d]);" % (pair[0], pair[1]))

        print("   z[%d] = accum.extract();" % (i))

def comba_square_code(N):
    indexes = comba_sqr_indexes(N)

    for (rnd,idx) in zip(range(0, len(indexes)), indexes):
        for (i,pair) in zip(range(0, len(idx)), idx):
            if pair[0] == pair[1]:
                print("   accum.mul(x[%d], x[%d]);" % (pair[0], pair[1]))
            elif i % 2 == 0:
                print("   accum.mul_x2(x[%d], x[%d]);" % (pair[0], pair[1]))

        print("   z[%d] = accum.extract();" % (rnd))

def main(args = None):
    if args is None:
        args = sys.argv

    if len(args) <= 1:
        sizes = [4, 6, 7, 8, 9, 16, 24]
    else:
        sizes = map(int, args[1:])

    print("""/*
* Comba Multiplication and Squaring
*
* This file was automatically generated by %s on %s
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/mp_core.h>

namespace Botan {
""" % (sys.argv[0], datetime.date.today().strftime("%Y-%m-%d")))

    for n in sizes:
        print("/*\n* Comba %dx%d Squaring\n*/" % (n, n))
        print("void bigint_comba_sqr%d(word z[%d], const word x[%d]) {" % (n, 2*n, n))
        print("   word3<word> accum;\n")

        comba_square_code(n)

        print("}\n")

        print("/*\n* Comba %dx%d Multiplication\n*/" % (n, n))
        print("void bigint_comba_mul%d(word z[%d], const word x[%d], const word y[%d]) {" % (n, 2*n, n, n))
        print("   word3<word> accum;\n")

        comba_multiply_code(n)

        print("}\n")

    print("}  // namespace Botan")

    return 0

if __name__ == '__main__':
    sys.exit(main())
