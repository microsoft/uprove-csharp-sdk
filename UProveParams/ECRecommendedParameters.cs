//*********************************************************
//
//    Copyright (c) Microsoft. All rights reserved.
//    This code is licensed under the Apache License
//    Version 2.0.
//
//    THIS CODE IS PROVIDED *AS IS* WITHOUT WARRANTY OF
//    ANY KIND, EITHER EXPRESS OR IMPLIED, INCLUDING ANY
//    IMPLIED WARRANTIES OF FITNESS FOR A PARTICULAR
//    PURPOSE, MERCHANTABILITY, OR NON-INFRINGEMENT.
//
//*********************************************************

using Org.BouncyCastle.Asn1.Nist;
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Math.EC;
using System;
using System.Security.Cryptography;

namespace UProveParams
{
    /// <summary>
    /// Generates the ECC values for the U-Prove Recommended Parameters Profile, using a modified version
    /// of the algorithm specified in ANSI X9.62 - 1998, section D.3.1 (Finding a Point on an Elliptic Curve)
    /// 
    /// Input:	A prime p, the parameters a and b of an elliptic curve E over Fp, a string curveName, and an integer index.
    /// Output: An arbitrary point (other than O) on E, and an integer counter.
    /// 1.a	counter = 0
    /// 1.b	numIteration = ⌈ bit length of  p /  256 ⌉
    /// 1.c	for 0 &le;= iteration &lt; numIteration
    /// Set x_iteration = SHA-256("U-Prove Recommended Profile Parameters" || curveName || index || counter || iteration), 
    /// where index, counter, iteration are encoded as strings, and the hash input is the UTF8 encoding of the concatenation of all strings.
    /// 1.d	x = x_0 || ... || x_(numIteration-1) mod p 
    /// 2.	Set α = x^3 + ax + b mod p.
    /// 3.	If α = 0 then output (x,0) and stop.
    /// 4.	Apply the appropriate algorithm from Annex D.1.4 to look for a square root (mod p) of α.
    /// 5.	If the output of Step 4 is “no square roots exist,” then increase counter and go to Step 1.b. Otherwise the output of Step 4 is an integer y with 0&lt;y&lt;p such that y^2≡α (mod p).
    /// 6.	Output (x,y).
    /// </summary>
    public class ECRecommendedParameters : RecommendedParameters
    {
        public class ECParams
        {
            public string Oid;
            public BigInteger q;
            public FpPoint g;
            public FpPoint g_d;
            public FpPoint g_t;
            public FpPoint[] g_i = new FpPoint[NumberOfPregeneratedGenerators];
            public X9ECParameters parameters;
            internal int[] counter = new int[NumberOfPregeneratedGenerators];
            internal int counter_d;
            internal int counter_t;
        }

        public enum CurveNames { P256 = 0, P384, P521 };
        static public readonly string[] OID = new string[] { "1.3.6.1.4.1.311.75.1.2.1", "1.3.6.1.4.1.311.75.1.2.2", "1.3.6.1.4.1.311.75.1.2.3" };
        static public ECParams[] ecParams = new ECParams[3];
        static public CurveNames GetCurveName(string curveName)
        {
            if (curveName == "P-256")
            {
                return CurveNames.P256;
            }
            else if (curveName == "P-384")
            {
                return CurveNames.P384;
            }
            else if (curveName == "P-521")
            {
                return CurveNames.P521;
            }
            else
            {
                throw new ArgumentException("unsupported curve: " + curveName);
            }
        }

        static ECRecommendedParameters()
        {
            ecParams[(int)CurveNames.P256] = GenerateParameters("P-256");
            ecParams[(int)CurveNames.P384] = GenerateParameters("P-384");
            ecParams[(int)CurveNames.P521] = GenerateParameters("P-521");
        }

        static private string UProveHashInput = "U-Prove Recommended Parameters Profile";
        static private HashAlgorithm hash = HashAlgorithm.Create("SHA-256");
        static private int hashByteSize = hash.HashSize / 8;
        static System.Text.UTF8Encoding encoding = new System.Text.UTF8Encoding();

        private static void CheckIsOnCurve(FpCurve curve, FpPoint point)
        {
            ECFieldElement lhs = point.Y.Square();
            ECFieldElement rhs = point.X.Multiply(point.X.Square().Add(curve.A)).Add(curve.B);
            if (!lhs.Equals(rhs))
            {
                throw new CryptographicException("point not on curve");
            }
        }

        public static FpFieldElement GetX(string input, FpCurve curve, int index, int counter)
        {
            int numIteration = (int)Math.Ceiling((double)(curve.Q.BitLength / 8) / (double)hashByteSize);
            byte[] digest = new byte[numIteration * hashByteSize];
            for (int iteration = 0; iteration < numIteration; iteration++)
            {
                byte[] hashInput = encoding.GetBytes(input + index.ToString() + counter.ToString() + iteration.ToString());
                Array.Copy(hash.ComputeHash(hashInput), 0, digest, hashByteSize * iteration, hashByteSize);
            }
            BigInteger x = new BigInteger(1, digest).Mod(curve.Q);
            return curve.FromBigInteger(x) as FpFieldElement;
        }

        public static FpPoint GetRandomPoint(string input, FpCurve curve, int index, Formatter formater, out int finalCounter)
        {
            int counter = 0;
            ECFieldElement x = null, y = null, z = null;
            while (y == null)
            {
                x = GetX(input, curve, index, counter);
                z = x.Multiply(x.Square().Add(curve.A)).Add(curve.B);
                if (z.ToBigInteger() == BigInteger.Zero)
                {
                    y = z;
                }
                else
                {
                    y = z.Sqrt(); // returns null if sqrt does not exist
                }
                counter++;
            }
            finalCounter = counter - 1;
            if (formater != null)
            {
                formater.PrintBigInteger("vr_z", "UCAHR", null, z.ToBigInteger());
            }
            ECFieldElement yPrime = y.Negate();
            return new FpPoint(curve, x, y.ToBigInteger().CompareTo(yPrime.ToBigInteger()) < 0 ? y : yPrime);
        }

        static public ECParams GenerateParameters(string curveName)
        {
            ECParams ecParams = new ECParams();

            CurveNames curveEnum = GetCurveName(curveName);
            ecParams.Oid = ECRecommendedParameters.OID[(int)curveEnum];
            ecParams.parameters = NistNamedCurves.GetByName(curveName);
            FpCurve curve = ecParams.parameters.Curve as FpCurve;
            ecParams.q = ecParams.parameters.N;
            ecParams.g = ecParams.parameters.G as FpPoint;
            string pointGenerationHashInput = UProveHashInput + curveName;

            // g_1 ... g_n
            ecParams.g_i = new FpPoint[NumberOfPregeneratedGenerators];
            ecParams.counter = new int[NumberOfPregeneratedGenerators];
            for (int i = 1; i <= NumberOfPregeneratedGenerators; i++)
            {
                ecParams.g_i[i - 1] = GetRandomPoint(pointGenerationHashInput, curve, i, null, out ecParams.counter[i - 1]);
                CheckIsOnCurve(curve, ecParams.g_i[i - 1]);
            }

            // g_t
            ecParams.g_t = GetRandomPoint(pointGenerationHashInput, curve, 255, null, out ecParams.counter_t);
            CheckIsOnCurve(curve, ecParams.g_t);

            // g_d
            ecParams.g_d = GetRandomPoint(pointGenerationHashInput, curve, 254, null, out ecParams.counter_d);
            CheckIsOnCurve(curve, ecParams.g_d);

            return ecParams;
        }

        static public void Print(Formatter formatter, string curveName)
        {
            CurveNames curveEnum = GetCurveName(curveName);
            ECParams ecp = ECRecommendedParameters.ecParams[(int)curveEnum];
            ecp.Oid = ECRecommendedParameters.OID[(int)curveEnum];
            formatter.PrintText("OID", ecp.Oid);
            formatter.PrintBigInteger("p", "UCHAR", null, (ecp.parameters.Curve as FpCurve).Q);
            formatter.PrintBigInteger("a", "UCHAR", null, ecp.parameters.Curve.A.ToBigInteger());
            formatter.PrintBigInteger("b", "UCHAR", null, ecp.parameters.Curve.B.ToBigInteger());
            formatter.PrintBigInteger("n", "UCHAR", null, ecp.parameters.N);
            formatter.PrintBigInteger("h", "UCHAR", null, ecp.parameters.H);
            formatter.PrintPoint("g", "UCHAR", null, ecp.parameters.G as FpPoint);

            // g_1 ... g_n
            for (int i = 1; i <= NumberOfPregeneratedGenerators; i++)
            {
                formatter.PrintPoint("g" + i, "UCHAR", null, ecp.g_i[i - 1], ecp.counter[i - 1]);
            }

            // g_t
            formatter.PrintPoint("gt", "UCHAR", null, ecp.g_t, ecp.counter_t);

            // g_d
            formatter.PrintPoint("gd", "UCHAR", null, ecp.g_d, ecp.counter_d);
        }
    }
}
