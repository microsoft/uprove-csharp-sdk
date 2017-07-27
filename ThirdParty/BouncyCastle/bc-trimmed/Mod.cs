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
using System.Diagnostics;

namespace BouncyCastle
{
    internal abstract class Mod
    {
        public static void Invert(uint[] p, uint[] x, uint[] z)
        {
            int len = p.Length;
            if (Nat.IsZero(len, x))
                throw new ArgumentException("cannot be 0", "x");
            if (Nat.IsOne(len, x))
            {
                Array.Copy(x, 0, z, 0, len);
                return;
            }

            uint[] u = Nat.Copy(len, x);
            uint[] a = Nat.Create(len);
            a[0] = 1;
            int ac = 0;

            if ((u[0] & 1) == 0)
            {
                InversionStep(p, u, len, a, ref ac);
            }
            if (Nat.IsOne(len, u))
            {
                InversionResult(p, ac, a, z);
                return;
            }

            uint[] v = Nat.Copy(len, p);
            uint[] b = Nat.Create(len);
            int bc = 0;

            int uvLen = len;

            for (; ; )
            {
                while (u[uvLen - 1] == 0 && v[uvLen - 1] == 0)
                {
                    --uvLen;
                }

                if (Nat.Gte(len, u, v))
                {
                    Nat.Sub(len, u, v, u);
                    Debug.Assert((u[0] & 1) == 0);
                    ac += Nat.Sub(len, a, b, a) - bc;
                    InversionStep(p, u, uvLen, a, ref ac);
                    if (Nat.IsOne(len, u))
                    {
                        InversionResult(p, ac, a, z);
                        return;
                    }
                }
                else
                {
                    Nat.Sub(len, v, u, v);
                    Debug.Assert((v[0] & 1) == 0);
                    bc += Nat.Sub(len, b, a, b) - ac;
                    InversionStep(p, v, uvLen, b, ref bc);
                    if (Nat.IsOne(len, v))
                    {
                        InversionResult(p, bc, b, z);
                        return;
                    }
                }
            }
        }

        public static void Subtract(uint[] p, uint[] x, uint[] y, uint[] z)
        {
            int len = p.Length;
            int c = Nat.Sub(len, x, y, z);
            if (c != 0)
            {
                Nat.Add(len, z, p, z);
            }
        }

        private static void InversionResult(uint[] p, int ac, uint[] a, uint[] z)
        {
            if (ac < 0)
            {
                Nat.Add(p.Length, a, p, z);
            }
            else
            {
                Array.Copy(a, 0, z, 0, p.Length);
            }
        }

        private static void InversionStep(uint[] p, uint[] u, int uLen, uint[] x, ref int xc)
        {
            int len = p.Length;
            int count = 0;
            while (u[0] == 0)
            {
                Nat.ShiftDownWord(u, uLen, 0);
                count += 32;
            }

            {
                int zeroes = GetTrailingZeroes(u[0]);
                if (zeroes > 0)
                {
                    Nat.ShiftDownBits(u, uLen, zeroes, 0);
                    count += zeroes;
                }
            }

            for (int i = 0; i < count; ++i)
            {
                if ((x[0] & 1) != 0)
                {
                    if (xc < 0)
                    {
                        xc += (int)Nat.Add(len, x, p, x);
                    }
                    else
                    {
                        xc += Nat.Sub(len, x, p, x);
                    }
                }

                Debug.Assert(xc == 0 || xc == -1);
                Nat.ShiftDownBit(x, len, (uint)xc);
            }
        }

        private static int GetTrailingZeroes(uint x)
        {
            //        assert x != 0;

            int count = 0;
            while ((x & 1) == 0)
            {
                x >>= 1;
                ++count;
            }
            return count;
        }
    }
}
