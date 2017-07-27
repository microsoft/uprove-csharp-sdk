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

namespace BouncyCastle
{
    public abstract class AbstractECMultiplier
        : ECMultiplier
    {
        public virtual ECPoint Multiply(ECPoint p, BigInteger k)
        {
            int sign = k.SignValue;
            if (sign == 0 || p.IsInfinity)
                return p.Curve.Infinity;

            ECPoint positive = MultiplyPositive(p, k.Abs());
            return sign > 0 ? positive : positive.Negate();
        }

        protected abstract ECPoint MultiplyPositive(ECPoint p, BigInteger k);
    }
}
