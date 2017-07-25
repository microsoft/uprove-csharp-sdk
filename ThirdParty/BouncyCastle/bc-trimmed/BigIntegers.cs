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

using Org.BouncyCastle.Math;

namespace Org.BouncyCastle.Utilities
{
    /**
     * BigInteger utilities.
     */
    public abstract class BigIntegers
    {
        private const int MaxIterations = 1000;

        /**
        * Return the passed in value as an unsigned byte array.
        *
        * @param value value to be converted.
        * @return a byte array without a leading zero byte if present in the signed encoding.
        */
        public static byte[] AsUnsignedByteArray(
            BigInteger n)
        {
            return n.ToByteArrayUnsigned();
        }

        /**
         * Return the passed in value as an unsigned byte array of specified length, zero-extended as necessary.
         *
         * @param length desired length of result array.
         * @param n value to be converted.
         * @return a byte array of specified length, with leading zeroes as necessary given the size of n.
         */
        public static byte[] AsUnsignedByteArray(int length, BigInteger n)
        {
            byte[] bytes = n.ToByteArrayUnsigned();

            if (bytes.Length > length)
                throw new ArgumentException("standard length exceeded", "n");

            if (bytes.Length == length)
                return bytes;

            byte[] tmp = new byte[length];
            Array.Copy(bytes, 0, tmp, tmp.Length - bytes.Length, bytes.Length);
            return tmp;
        }

        // note: CreateRandomInRange method deleted

    }
}
