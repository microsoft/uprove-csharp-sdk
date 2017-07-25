//***********************************************************************************************
//
// This file was imported from the C# Bouncy Castle project. Original license header is retained:
//
//
// The Bouncy Castle Cryptographic C#® API
//
// License:
// 
// The Bouncy Castle License
// Copyright (c) 2000-2014 The Legion of the Bouncy Castle Inc. (http://www.bouncycastle.org)
// Permission is hereby granted, free of charge, to any person obtaining a copy of this software
// and associated documentation files (the "Software"), to deal in the Software without restriction,
// including without limitation the rights to use, copy, modify, merge, publish, distribute,
// sub license, and/or sell copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
// The above copyright notice and this permission notice shall be included in all copies or
// substantial portions of the Software.
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED,
// INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR
// PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
// LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR
// OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
// DEALINGS IN THE SOFTWARE.
//
//***********************************************************************************************

using System;
using Org.BouncyCastle.Math.EC.Multiplier;
using Org.BouncyCastle.Math.Field;

namespace Org.BouncyCastle.Math.EC
{
    public class ECAlgorithms
    {
        // note: IsF2mCurve method removed

        public static bool IsFpCurve(ECCurve c)
        {
            return c.Field.Dimension == 1;
        }

        public static ECPoint SumOfMultiplies(ECPoint[] ps, BigInteger[] ks)
        {
            if (ps == null || ks == null || ps.Length != ks.Length || ps.Length < 1)
                throw new ArgumentException("point and scalar arrays should be non-null, and of equal, non-zero, length");

            int count = ps.Length;
            switch (count)
            {
                case 1:
                    return ps[0].Multiply(ks[0]);
                case 2:
                    return SumOfTwoMultiplies(ps[0], ks[0], ps[1], ks[1]);
                default:
                    break;
            }

            ECPoint p = ps[0];
            ECCurve c = p.Curve;

            ECPoint[] imported = new ECPoint[count];
            imported[0] = p;
            for (int i = 1; i < count; ++i)
            {
                imported[i] = ImportPoint(c, ps[i]);
            }

            // note: GLV code removed

            return ImplSumOfMultiplies(imported, ks);
        }

        public static ECPoint SumOfTwoMultiplies(ECPoint P, BigInteger a, ECPoint Q, BigInteger b)
        {
            ECCurve cp = P.Curve;
            Q = ImportPoint(cp, Q);

            // note: f2m curve code removed
            // note: GLV code removed
            
            return ImplShamirsTrickWNaf(P, a, Q, b);
        }

        /*
        * "Shamir's Trick", originally due to E. G. Straus
        * (Addition chains of vectors. American Mathematical Monthly,
        * 71(7):806-808, Aug./Sept. 1964)
        *  
        * Input: The points P, Q, scalar k = (km?, ... , k1, k0)
        * and scalar l = (lm?, ... , l1, l0).
        * Output: R = k * P + l * Q.
        * 1: Z <- P + Q
        * 2: R <- O
        * 3: for i from m-1 down to 0 do
        * 4:        R <- R + R        {point doubling}
        * 5:        if (ki = 1) and (li = 0) then R <- R + P end if
        * 6:        if (ki = 0) and (li = 1) then R <- R + Q end if
        * 7:        if (ki = 1) and (li = 1) then R <- R + Z end if
        * 8: end for
        * 9: return R
        */
        public static ECPoint ShamirsTrick(ECPoint P, BigInteger k, ECPoint Q, BigInteger l)
        {
            ECCurve cp = P.Curve;
            Q = ImportPoint(cp, Q);

            return ImplShamirsTrickJsf(P, k, Q, l);
        }

        public static ECPoint ImportPoint(ECCurve c, ECPoint p)
        {
            ECCurve cp = p.Curve;
            if (!c.Equals(cp))
                throw new ArgumentException("Point must be on the same curve");

            return c.ImportPoint(p);
        }

        public static void MontgomeryTrick(ECFieldElement[] zs, int off, int len)
        {
            /*
             * Uses the "Montgomery Trick" to invert many field elements, with only a single actual
             * field inversion. See e.g. the paper:
             * "Fast Multi-scalar Multiplication Methods on Elliptic Curves with Precomputation Strategy Using Montgomery Trick"
             * by Katsuyuki Okeya, Kouichi Sakurai.
             */

            ECFieldElement[] c = new ECFieldElement[len];
            c[0] = zs[off];

            int i = 0;
            while (++i < len)
            {
                c[i] = c[i - 1].Multiply(zs[off + i]);
            }

            ECFieldElement u = c[--i].Invert();

            while (i > 0)
            {
                int j = off + i--;
                ECFieldElement tmp = zs[j];
                zs[j] = c[i].Multiply(u);
                u = u.Multiply(tmp);
            }

            zs[off] = u;
        }

        internal static ECPoint ImplShamirsTrickJsf(ECPoint P, BigInteger k, ECPoint Q, BigInteger l)
        {
            ECCurve curve = P.Curve;
            ECPoint infinity = curve.Infinity;

            // TODO conjugate co-Z addition (ZADDC) can return both of these
            ECPoint PaddQ = P.Add(Q);
            ECPoint PsubQ = P.Subtract(Q);

            ECPoint[] points = new ECPoint[] { Q, PsubQ, P, PaddQ };
            curve.NormalizeAll(points);

            ECPoint[] table = new ECPoint[] {
            points[3].Negate(), points[2].Negate(), points[1].Negate(),
            points[0].Negate(), infinity, points[0],
            points[1], points[2], points[3] };

            byte[] jsf = WNafUtilities.GenerateJsf(k, l);

            ECPoint R = infinity;

            int i = jsf.Length;
            while (--i >= 0)
            {
                int jsfi = jsf[i];

                // NOTE: The shifting ensures the sign is extended correctly
                int kDigit = ((jsfi << 24) >> 28), lDigit = ((jsfi << 28) >> 28);

                int index = 4 + (kDigit * 3) + lDigit;
                R = R.TwicePlus(table[index]);
            }

            return R;
        }

        internal static ECPoint ImplShamirsTrickWNaf(ECPoint P, BigInteger k,
            ECPoint Q, BigInteger l)
        {
            bool negK = k.SignValue < 0, negL = l.SignValue < 0;

            k = k.Abs();
            l = l.Abs();

            int widthP = System.Math.Max(2, System.Math.Min(16, WNafUtilities.GetWindowSize(k.BitLength)));
            int widthQ = System.Math.Max(2, System.Math.Min(16, WNafUtilities.GetWindowSize(l.BitLength)));

            WNafPreCompInfo infoP = WNafUtilities.Precompute(P, widthP, true);
            WNafPreCompInfo infoQ = WNafUtilities.Precompute(Q, widthQ, true);

            ECPoint[] preCompP = negK ? infoP.PreCompNeg : infoP.PreComp;
            ECPoint[] preCompQ = negL ? infoQ.PreCompNeg : infoQ.PreComp;
            ECPoint[] preCompNegP = negK ? infoP.PreComp : infoP.PreCompNeg;
            ECPoint[] preCompNegQ = negL ? infoQ.PreComp : infoQ.PreCompNeg;

            byte[] wnafP = WNafUtilities.GenerateWindowNaf(widthP, k);
            byte[] wnafQ = WNafUtilities.GenerateWindowNaf(widthQ, l);

            return ImplShamirsTrickWNaf(preCompP, preCompNegP, wnafP, preCompQ, preCompNegQ, wnafQ);
        }

        internal static ECPoint ImplShamirsTrickWNaf(ECPoint P, BigInteger k, ECPointMap pointMapQ, BigInteger l)
        {
            bool negK = k.SignValue < 0, negL = l.SignValue < 0;

            k = k.Abs();
            l = l.Abs();

            int width = System.Math.Max(2, System.Math.Min(16, WNafUtilities.GetWindowSize(System.Math.Max(k.BitLength, l.BitLength))));

            ECPoint Q = WNafUtilities.MapPointWithPrecomp(P, width, true, pointMapQ);
            WNafPreCompInfo infoP = WNafUtilities.GetWNafPreCompInfo(P);
            WNafPreCompInfo infoQ = WNafUtilities.GetWNafPreCompInfo(Q);

            ECPoint[] preCompP = negK ? infoP.PreCompNeg : infoP.PreComp;
            ECPoint[] preCompQ = negL ? infoQ.PreCompNeg : infoQ.PreComp;
            ECPoint[] preCompNegP = negK ? infoP.PreComp : infoP.PreCompNeg;
            ECPoint[] preCompNegQ = negL ? infoQ.PreComp : infoQ.PreCompNeg;

            byte[] wnafP = WNafUtilities.GenerateWindowNaf(width, k);
            byte[] wnafQ = WNafUtilities.GenerateWindowNaf(width, l);

            return ImplShamirsTrickWNaf(preCompP, preCompNegP, wnafP, preCompQ, preCompNegQ, wnafQ);
        }

        private static ECPoint ImplShamirsTrickWNaf(ECPoint[] preCompP, ECPoint[] preCompNegP, byte[] wnafP,
            ECPoint[] preCompQ, ECPoint[] preCompNegQ, byte[] wnafQ)
        {
            int len = System.Math.Max(wnafP.Length, wnafQ.Length);

            ECCurve curve = preCompP[0].Curve;
            ECPoint infinity = curve.Infinity;

            ECPoint R = infinity;
            int zeroes = 0;

            for (int i = len - 1; i >= 0; --i)
            {
                int wiP = i < wnafP.Length ? (int)(sbyte)wnafP[i] : 0;
                int wiQ = i < wnafQ.Length ? (int)(sbyte)wnafQ[i] : 0;

                if ((wiP | wiQ) == 0)
                {
                    ++zeroes;
                    continue;
                }

                ECPoint r = infinity;
                if (wiP != 0)
                {
                    int nP = System.Math.Abs(wiP);
                    ECPoint[] tableP = wiP < 0 ? preCompNegP : preCompP;
                    r = r.Add(tableP[nP >> 1]);
                }
                if (wiQ != 0)
                {
                    int nQ = System.Math.Abs(wiQ);
                    ECPoint[] tableQ = wiQ < 0 ? preCompNegQ : preCompQ;
                    r = r.Add(tableQ[nQ >> 1]);
                }

                if (zeroes > 0)
                {
                    R = R.TimesPow2(zeroes);
                    zeroes = 0;
                }

                R = R.TwicePlus(r);
            }

            if (zeroes > 0)
            {
                R = R.TimesPow2(zeroes);
            }

            return R;
        }

        internal static ECPoint ImplSumOfMultiplies(ECPoint[] ps, BigInteger[] ks)
        {
            int count = ps.Length;
            bool[] negs = new bool[count];
            WNafPreCompInfo[] infos = new WNafPreCompInfo[count];
            byte[][] wnafs = new byte[count][];

            for (int i = 0; i < count; ++i)
            {
                BigInteger ki = ks[i]; negs[i] = ki.SignValue < 0; ki = ki.Abs();

                int width = System.Math.Max(2, System.Math.Min(16, WNafUtilities.GetWindowSize(ki.BitLength)));
                infos[i] = WNafUtilities.Precompute(ps[i], width, true);
                wnafs[i] = WNafUtilities.GenerateWindowNaf(width, ki);
            }

            return ImplSumOfMultiplies(negs, infos, wnafs);
        }

        // note: ImplSumOfMultipliesGlv method removed

        internal static ECPoint ImplSumOfMultiplies(ECPoint[] ps, ECPointMap pointMap, BigInteger[] ks)
        {
            int halfCount = ps.Length, fullCount = halfCount << 1;

            bool[] negs = new bool[fullCount];
            WNafPreCompInfo[] infos = new WNafPreCompInfo[fullCount];
            byte[][] wnafs = new byte[fullCount][];

            for (int i = 0; i < halfCount; ++i)
            {
                int j0 = i << 1, j1 = j0 + 1;

                BigInteger kj0 = ks[j0]; negs[j0] = kj0.SignValue < 0; kj0 = kj0.Abs();
                BigInteger kj1 = ks[j1]; negs[j1] = kj1.SignValue < 0; kj1 = kj1.Abs();

                int width = System.Math.Max(2, System.Math.Min(16, WNafUtilities.GetWindowSize(System.Math.Max(kj0.BitLength, kj1.BitLength))));

                ECPoint P = ps[i], Q = WNafUtilities.MapPointWithPrecomp(P, width, true, pointMap);
                infos[j0] = WNafUtilities.GetWNafPreCompInfo(P);
                infos[j1] = WNafUtilities.GetWNafPreCompInfo(Q);
                wnafs[j0] = WNafUtilities.GenerateWindowNaf(width, kj0);
                wnafs[j1] = WNafUtilities.GenerateWindowNaf(width, kj1);
            }

            return ImplSumOfMultiplies(negs, infos, wnafs);
        }

        private static ECPoint ImplSumOfMultiplies(bool[] negs, WNafPreCompInfo[] infos, byte[][] wnafs)
        {
            int len = 0, count = wnafs.Length;
            for (int i = 0; i < count; ++i)
            {
                len = System.Math.Max(len, wnafs[i].Length);
            }

            ECCurve curve = infos[0].PreComp[0].Curve;
            ECPoint infinity = curve.Infinity;

            ECPoint R = infinity;
            int zeroes = 0;

            for (int i = len - 1; i >= 0; --i)
            {
                ECPoint r = infinity;

                for (int j = 0; j < count; ++j)
                {
                    byte[] wnaf = wnafs[j];
                    int wi = i < wnaf.Length ? (int)(sbyte)wnaf[i] : 0;
                    if (wi != 0)
                    {
                        int n = System.Math.Abs(wi);
                        WNafPreCompInfo info = infos[j];
                        ECPoint[] table = (wi < 0 == negs[j]) ? info.PreCompNeg : info.PreComp;
                        r = r.Add(table[n >> 1]);
                    }
                }

                if (r == infinity)
                {
                    ++zeroes;
                    continue;
                }

                if (zeroes > 0)
                {
                    R = R.TimesPow2(zeroes);
                    zeroes = 0;
                }

                R = R.TwicePlus(r);
            }

            if (zeroes > 0)
            {
                R = R.TimesPow2(zeroes);
            }

            return R;
        }
    }
}
