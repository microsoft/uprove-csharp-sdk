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
    public abstract class FiniteFields
    {
        internal static readonly IFiniteField GF_2 = new PrimeField(BigInteger.ValueOf(2));
        internal static readonly IFiniteField GF_3 = new PrimeField(BigInteger.ValueOf(3));

        //public static IPolynomialExtensionField GetBinaryExtensionField(int[] exponents)
        //{
        //    if (exponents[0] != 0)
        //    {
        //        throw new ArgumentException("Irreducible polynomials in GF(2) must have constant term", "exponents");
        //    }
        //    for (int i = 1; i < exponents.Length; ++i)
        //    {
        //        if (exponents[i] <= exponents[i - 1])
        //        {
        //            throw new ArgumentException("Polynomial exponents must be montonically increasing", "exponents");
        //        }
        //    }

        //    return new GenericPolynomialExtensionField(GF_2, new GF2Polynomial(exponents));
        //}

        //    public static IPolynomialExtensionField GetTernaryExtensionField(Term[] terms)
        //    {
        //        return new GenericPolynomialExtensionField(GF_3, new GF3Polynomial(terms));
        //    }

        public static IFiniteField GetPrimeField(BigInteger characteristic)
        {
            int bitLength = characteristic.BitLength;
            if (characteristic.SignValue <= 0 || bitLength < 2)
            {
                throw new ArgumentException("Must be >= 2", "characteristic");
            }

            if (bitLength < 3)
            {
                switch (characteristic.IntValue)
                {
                    case 2:
                        return GF_2;
                    case 3:
                        return GF_3;
                }
            }

            return new PrimeField(characteristic);
        }
    }
}
