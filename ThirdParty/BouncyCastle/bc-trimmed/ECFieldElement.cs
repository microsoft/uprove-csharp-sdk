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
using System.Diagnostics;

using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Math.EC
{
    public abstract class ECFieldElement
    {
        public abstract BigInteger ToBigInteger();
        public abstract string FieldName { get; }
        public abstract int FieldSize { get; }
        public abstract ECFieldElement Add(ECFieldElement b);
        public abstract ECFieldElement AddOne();
        public abstract ECFieldElement Subtract(ECFieldElement b);
        public abstract ECFieldElement Multiply(ECFieldElement b);
        public abstract ECFieldElement Divide(ECFieldElement b);
        public abstract ECFieldElement Negate();
        public abstract ECFieldElement Square();
        public abstract ECFieldElement Invert();
        public abstract ECFieldElement Sqrt();

        public virtual int BitLength
        {
            get { return ToBigInteger().BitLength; }
        }

        public virtual bool IsOne
        {
            get { return BitLength == 1; }
        }

        public virtual bool IsZero
        {
            get { return 0 == ToBigInteger().SignValue; }
        }

        public virtual ECFieldElement MultiplyMinusProduct(ECFieldElement b, ECFieldElement x, ECFieldElement y)
        {
            return Multiply(b).Subtract(x.Multiply(y));
        }

        public virtual ECFieldElement MultiplyPlusProduct(ECFieldElement b, ECFieldElement x, ECFieldElement y)
        {
            return Multiply(b).Add(x.Multiply(y));
        }

        public virtual ECFieldElement SquareMinusProduct(ECFieldElement x, ECFieldElement y)
        {
            return Square().Subtract(x.Multiply(y));
        }

        public virtual ECFieldElement SquarePlusProduct(ECFieldElement x, ECFieldElement y)
        {
            return Square().Add(x.Multiply(y));
        }

        public virtual bool TestBitZero()
        {
            return ToBigInteger().TestBit(0);
        }

        public override bool Equals(object obj)
        {
            return Equals(obj as ECFieldElement);
        }

        public virtual bool Equals(ECFieldElement other)
        {
            if (this == other)
                return true;
            if (null == other)
                return false;
            return ToBigInteger().Equals(other.ToBigInteger());
        }

        public override int GetHashCode()
        {
            return ToBigInteger().GetHashCode();
        }

        public override string ToString()
        {
            return this.ToBigInteger().ToString(16);
        }

        public virtual byte[] GetEncoded()
        {
            return BigIntegers.AsUnsignedByteArray((FieldSize + 7) / 8, ToBigInteger());
        }
    }

    public class FpFieldElement
        : ECFieldElement
    {
        private readonly BigInteger q, r, x;

        internal static BigInteger CalculateResidue(BigInteger p)
        {
            int bitLength = p.BitLength;
            if (bitLength >= 96)
            {
                BigInteger firstWord = p.ShiftRight(bitLength - 64);
                if (firstWord.LongValue == -1L)
                {
                    return BigInteger.One.ShiftLeft(bitLength).Subtract(p);
                }
                if ((bitLength & 7) == 0)
                {
                    return BigInteger.One.ShiftLeft(bitLength << 1).Divide(p).Negate();
                }
            }
            return null;
        }

        [Obsolete("Use ECCurve.FromBigInteger to construct field elements")]
        public FpFieldElement(BigInteger q, BigInteger x)
            : this(q, CalculateResidue(q), x)
        {
        }

        internal FpFieldElement(BigInteger q, BigInteger r, BigInteger x)
        {
            if (x == null || x.SignValue < 0 || x.CompareTo(q) >= 0)
                throw new ArgumentException("value invalid in Fp field element", "x");

            this.q = q;
            this.r = r;
            this.x = x;
        }

        public override BigInteger ToBigInteger()
        {
            return x;
        }

        /**
         * return the field name for this field.
         *
         * @return the string "Fp".
         */
        public override string FieldName
        {
            get { return "Fp"; }
        }

        public override int FieldSize
        {
            get { return q.BitLength; }
        }

        public BigInteger Q
        {
            get { return q; }
        }

        public override ECFieldElement Add(
            ECFieldElement b)
        {
            return new FpFieldElement(q, r, ModAdd(x, b.ToBigInteger()));
        }

        public override ECFieldElement AddOne()
        {
            BigInteger x2 = x.Add(BigInteger.One);
            if (x2.CompareTo(q) == 0)
            {
                x2 = BigInteger.Zero;
            }
            return new FpFieldElement(q, r, x2);
        }

        public override ECFieldElement Subtract(
            ECFieldElement b)
        {
            return new FpFieldElement(q, r, ModSubtract(x, b.ToBigInteger()));
        }

        public override ECFieldElement Multiply(
            ECFieldElement b)
        {
            return new FpFieldElement(q, r, ModMult(x, b.ToBigInteger()));
        }

        public override ECFieldElement MultiplyMinusProduct(ECFieldElement b, ECFieldElement x, ECFieldElement y)
        {
            BigInteger ax = this.x, bx = b.ToBigInteger(), xx = x.ToBigInteger(), yx = y.ToBigInteger();
            BigInteger ab = ax.Multiply(bx);
            BigInteger xy = xx.Multiply(yx);
            return new FpFieldElement(q, r, ModReduce(ab.Subtract(xy)));
        }

        public override ECFieldElement MultiplyPlusProduct(ECFieldElement b, ECFieldElement x, ECFieldElement y)
        {
            BigInteger ax = this.x, bx = b.ToBigInteger(), xx = x.ToBigInteger(), yx = y.ToBigInteger();
            BigInteger ab = ax.Multiply(bx);
            BigInteger xy = xx.Multiply(yx);
            BigInteger sum = ab.Add(xy);
            if (r != null && r.SignValue < 0 && sum.BitLength > (q.BitLength << 1))
            {
                sum = sum.Subtract(q.ShiftLeft(q.BitLength));
            }
            return new FpFieldElement(q, r, ModReduce(sum));
        }

        public override ECFieldElement Divide(
            ECFieldElement b)
        {
            return new FpFieldElement(q, r, ModMult(x, ModInverse(b.ToBigInteger())));
        }

        public override ECFieldElement Negate()
        {
            return x.SignValue == 0 ? this : new FpFieldElement(q, r, q.Subtract(x));
        }

        public override ECFieldElement Square()
        {
            return new FpFieldElement(q, r, ModMult(x, x));
        }

        public override ECFieldElement SquareMinusProduct(ECFieldElement x, ECFieldElement y)
        {
            BigInteger ax = this.x, xx = x.ToBigInteger(), yx = y.ToBigInteger();
            BigInteger aa = ax.Multiply(ax);
            BigInteger xy = xx.Multiply(yx);
            return new FpFieldElement(q, r, ModReduce(aa.Subtract(xy)));
        }

        public override ECFieldElement SquarePlusProduct(ECFieldElement x, ECFieldElement y)
        {
            BigInteger ax = this.x, xx = x.ToBigInteger(), yx = y.ToBigInteger();
            BigInteger aa = ax.Multiply(ax);
            BigInteger xy = xx.Multiply(yx);
            BigInteger sum = aa.Add(xy);
            if (r != null && r.SignValue < 0 && sum.BitLength > (q.BitLength << 1))
            {
                sum = sum.Subtract(q.ShiftLeft(q.BitLength));
            }
            return new FpFieldElement(q, r, ModReduce(sum));
        }

        public override ECFieldElement Invert()
        {
            // TODO Modular inversion can be faster for a (Generalized) Mersenne Prime.
            return new FpFieldElement(q, r, ModInverse(x));
        }

        /**
         * return a sqrt root - the routine verifies that the calculation
         * returns the right value - if none exists it returns null.
         */
        public override ECFieldElement Sqrt()
        {
            if (IsZero || IsOne)
                return this;

            if (!q.TestBit(0))
                throw Platform.CreateNotImplementedException("even value of q");

            if (q.TestBit(1)) // q == 4m + 3
            {
                BigInteger e = q.ShiftRight(2).Add(BigInteger.One);
                return CheckSqrt(new FpFieldElement(q, r, x.ModPow(e, q)));
            }

            if (q.TestBit(2)) // q == 8m + 5
            {
                BigInteger t1 = x.ModPow(q.ShiftRight(3), q);
                BigInteger t2 = ModMult(t1, x);
                BigInteger t3 = ModMult(t2, t1);

                if (t3.Equals(BigInteger.One))
                {
                    return CheckSqrt(new FpFieldElement(q, r, t2));
                }

                // TODO This is constant and could be precomputed
                BigInteger t4 = BigInteger.Two.ModPow(q.ShiftRight(2), q);

                BigInteger y = ModMult(t2, t4);

                return CheckSqrt(new FpFieldElement(q, r, y));
            }

            // q == 8m + 1

            BigInteger legendreExponent = q.ShiftRight(1);
            if (!(x.ModPow(legendreExponent, q).Equals(BigInteger.One)))
                return null;

            BigInteger X = this.x;
            BigInteger fourX = ModDouble(ModDouble(X)); ;

            BigInteger k = legendreExponent.Add(BigInteger.One), qMinusOne = q.Subtract(BigInteger.One);

            BigInteger U, V;
            Random rand = new Random();
            do
            {
                BigInteger P;
                do
                {
                    P = new BigInteger(q.BitLength, rand);
                }
                while (P.CompareTo(q) >= 0
                    || !ModReduce(P.Multiply(P).Subtract(fourX)).ModPow(legendreExponent, q).Equals(qMinusOne));

                BigInteger[] result = LucasSequence(P, X, k);
                U = result[0];
                V = result[1];

                if (ModMult(V, V).Equals(fourX))
                {
                    return new FpFieldElement(q, r, ModHalfAbs(V));
                }
            }
            while (U.Equals(BigInteger.One) || U.Equals(qMinusOne));

            return null;
        }

        private ECFieldElement CheckSqrt(ECFieldElement z)
        {
            return z.Square().Equals(this) ? z : null;
        }

        private BigInteger[] LucasSequence(
            BigInteger	P,
            BigInteger	Q,
            BigInteger	k)
        {
            // TODO Research and apply "common-multiplicand multiplication here"

            int n = k.BitLength;
            int s = k.GetLowestSetBit();

            Debug.Assert(k.TestBit(s));

            BigInteger Uh = BigInteger.One;
            BigInteger Vl = BigInteger.Two;
            BigInteger Vh = P;
            BigInteger Ql = BigInteger.One;
            BigInteger Qh = BigInteger.One;

            for (int j = n - 1; j >= s + 1; --j)
            {
                Ql = ModMult(Ql, Qh);

                if (k.TestBit(j))
                {
                    Qh = ModMult(Ql, Q);
                    Uh = ModMult(Uh, Vh);
                    Vl = ModReduce(Vh.Multiply(Vl).Subtract(P.Multiply(Ql)));
                    Vh = ModReduce(Vh.Multiply(Vh).Subtract(Qh.ShiftLeft(1)));
                }
                else
                {
                    Qh = Ql;
                    Uh = ModReduce(Uh.Multiply(Vl).Subtract(Ql));
                    Vh = ModReduce(Vh.Multiply(Vl).Subtract(P.Multiply(Ql)));
                    Vl = ModReduce(Vl.Multiply(Vl).Subtract(Ql.ShiftLeft(1)));
                }
            }

            Ql = ModMult(Ql, Qh);
            Qh = ModMult(Ql, Q);
            Uh = ModReduce(Uh.Multiply(Vl).Subtract(Ql));
            Vl = ModReduce(Vh.Multiply(Vl).Subtract(P.Multiply(Ql)));
            Ql = ModMult(Ql, Qh);

            for (int j = 1; j <= s; ++j)
            {
                Uh = ModMult(Uh, Vl);
                Vl = ModReduce(Vl.Multiply(Vl).Subtract(Ql.ShiftLeft(1)));
                Ql = ModMult(Ql, Ql);
            }

            return new BigInteger[] { Uh, Vl };
        }

        protected virtual BigInteger ModAdd(BigInteger x1, BigInteger x2)
        {
            BigInteger x3 = x1.Add(x2);
            if (x3.CompareTo(q) >= 0)
            {
                x3 = x3.Subtract(q);
            }
            return x3;
        }

        protected virtual BigInteger ModDouble(BigInteger x)
        {
            BigInteger _2x = x.ShiftLeft(1);
            if (_2x.CompareTo(q) >= 0)
            {
                _2x = _2x.Subtract(q);
            }
            return _2x;
        }

        protected virtual BigInteger ModHalf(BigInteger x)
        {
            if (x.TestBit(0))
            {
                x = q.Add(x);
            }
            return x.ShiftRight(1);
        }

        protected virtual BigInteger ModHalfAbs(BigInteger x)
        {
            if (x.TestBit(0))
            {
                x = q.Subtract(x);
            }
            return x.ShiftRight(1);
        }

        protected virtual BigInteger ModInverse(BigInteger x)
        {
            int bits = FieldSize;
            int len = (bits + 31) >> 5;
            uint[] p = Nat.FromBigInteger(bits, q);
            uint[] n = Nat.FromBigInteger(bits, x);
            uint[] z = Nat.Create(len);
            Mod.Invert(p, n, z);
            return Nat.ToBigInteger(len, z);
        }

        protected virtual BigInteger ModMult(BigInteger x1, BigInteger x2)
        {
            return ModReduce(x1.Multiply(x2));
        }

        protected virtual BigInteger ModReduce(BigInteger x)
        {
            if (r == null)
            {
                x = x.Mod(q);
            }
            else
            {
                bool negative = x.SignValue < 0;
                if (negative)
                {
                    x = x.Abs();
                }
                int qLen = q.BitLength;
                if (r.SignValue > 0)
                {
                    BigInteger qMod = BigInteger.One.ShiftLeft(qLen);
                    bool rIsOne = r.Equals(BigInteger.One);
                    while (x.BitLength > (qLen + 1))
                    {
                        BigInteger u = x.ShiftRight(qLen);
                        BigInteger v = x.Remainder(qMod);
                        if (!rIsOne)
                        {
                            u = u.Multiply(r);
                        }
                        x = u.Add(v);
                    }
                }
                else
                {
                    int d = ((qLen - 1) & 31) + 1;
                    BigInteger mu = r.Negate();
                    BigInteger u = mu.Multiply(x.ShiftRight(qLen - d));
                    BigInteger quot = u.ShiftRight(qLen + d);
                    BigInteger v = quot.Multiply(q);
                    BigInteger bk1 = BigInteger.One.ShiftLeft(qLen + d);
                    v = v.Remainder(bk1);
                    x = x.Remainder(bk1);
                    x = x.Subtract(v);
                    if (x.SignValue < 0)
                    {
                        x = x.Add(bk1);
                    }
                }
                while (x.CompareTo(q) >= 0)
                {
                    x = x.Subtract(q);
                }
                if (negative && x.SignValue != 0)
                {
                    x = q.Subtract(x);
                }
            }
            return x;
        }

        protected virtual BigInteger ModSubtract(BigInteger x1, BigInteger x2)
        {
            BigInteger x3 = x1.Subtract(x2);
            if (x3.SignValue < 0)
            {
                x3 = x3.Add(q);
            }
            return x3;
        }

        public override bool Equals(
            object obj)
        {
            if (obj == this)
                return true;

            FpFieldElement other = obj as FpFieldElement;

            if (other == null)
                return false;

            return Equals(other);
        }

        public virtual bool Equals(
            FpFieldElement other)
        {
            return q.Equals(other.q) && base.Equals(other);
        }

        public override int GetHashCode()
        {
            return q.GetHashCode() ^ base.GetHashCode();
        }
    }

    // note: F2mFieldElement class deleted

}
