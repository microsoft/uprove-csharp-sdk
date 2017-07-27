//*********************************************************
//
// This file was imported from the C# Bouncy Castle project. Original license header is retained:
//
//
// License
// Copyright (c) 2000-2014 The Legion of the Bouncy Castle Inc. (http://www.bouncycastle.org)
//
// Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE. 
//
//*********************************************************

using System;

namespace BouncyCastle
{
    /**
    * Class implementing the WNAF (Window Non-Adjacent Form) multiplication
    * algorithm.
    */
    public class WNafL2RMultiplier
        : AbstractECMultiplier
    {
        /**
         * Multiplies <code>this</code> by an integer <code>k</code> using the
         * Window NAF method.
         * @param k The integer by which <code>this</code> is multiplied.
         * @return A new <code>ECPoint</code> which equals <code>this</code>
         * multiplied by <code>k</code>.
         */
        protected override ECPoint MultiplyPositive(ECPoint p, BigInteger k)
        {
            // Clamp the window width in the range [2, 16]
            int width = System.Math.Max(2, System.Math.Min(16, GetWindowSize(k.BitLength)));

            WNafPreCompInfo wnafPreCompInfo = WNafUtilities.Precompute(p, width, true);
            ECPoint[] preComp = wnafPreCompInfo.PreComp;
            ECPoint[] preCompNeg = wnafPreCompInfo.PreCompNeg;

            int[] wnaf = WNafUtilities.GenerateCompactWindowNaf(width, k);

            ECPoint R = p.Curve.Infinity;

            int i = wnaf.Length;

            /*
             * NOTE: We try to optimize the first window using the precomputed points to substitute an
             * addition for 2 or more doublings.
             */
            if (i > 1)
            {
                int wi = wnaf[--i];
                int digit = wi >> 16, zeroes = wi & 0xFFFF;

                int n = System.Math.Abs(digit);
                ECPoint[] table = digit < 0 ? preCompNeg : preComp;

                // Optimization can only be used for values in the lower half of the table
                if ((n << 2) < (1 << width))
                {
                    int highest = BigInteger.BitLengthTable[n];

                    // TODO Get addition/doubling cost ratio from curve and compare to 'scale' to see if worth substituting?
                    int scale = width - highest;
                    int lowBits = n ^ (1 << (highest - 1));

                    int i1 = ((1 << (width - 1)) - 1);
                    int i2 = (lowBits << scale) + 1;
                    R = table[i1 >> 1].Add(table[i2 >> 1]);

                    zeroes -= scale;

                    //Console.WriteLine("Optimized: 2^" + scale + " * " + n + " = " + i1 + " + " + i2);
                }
                else
                {
                    R = table[n >> 1];
                }

                R = R.TimesPow2(zeroes);
            }

            while (i > 0)
            {
                int wi = wnaf[--i];
                int digit = wi >> 16, zeroes = wi & 0xFFFF;

                int n = System.Math.Abs(digit);
                ECPoint[] table = digit < 0 ? preCompNeg : preComp;
                ECPoint r = table[n >> 1];

                R = R.TwicePlus(r);
                R = R.TimesPow2(zeroes);
            }

            return R;
        }

        /**
         * Determine window width to use for a scalar multiplication of the given size.
         * 
         * @param bits the bit-length of the scalar to multiply by
         * @return the window size to use
         */
        protected virtual int GetWindowSize(int bits)
        {
            return WNafUtilities.GetWindowSize(bits);
        }
    }
}
