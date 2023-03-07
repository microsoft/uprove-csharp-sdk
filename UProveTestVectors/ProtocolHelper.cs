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

using Org.BouncyCastle.Math;
using Org.BouncyCastle.Math.EC;
using System;
using System.Security.Cryptography;
using System.Text;
using UProveParams;

namespace UProveTestVectors
{
    class ProtocolHelper
    {
        public static BigInteger HashToZq(HashAlgorithm hasher, object[] array, BigInteger q)
        {
            return new BigInteger(1, HashToBytes(hasher, array)).Mod(q);
        }

        public static byte[] HashToBytes(HashAlgorithm hasher, object[] array) 
        {
            hasher.Initialize();
            Hash(hasher, array);
            
            hasher.TransformFinalBlock(new byte[0], 0, 0);
            return hasher.Hash;
        }

        private static void HashBytes(HashAlgorithm hasher, byte[] value)
        {
            hasher.TransformBlock(value, 0, value.Length, value, 0);
        }

        private static void HashSize(HashAlgorithm hasher, int size)
        {
            byte[] buffer = new byte[4];
            buffer[0] = (byte)(size >> 24);
            buffer[1] = (byte)(size >> 16);
            buffer[2] = (byte)(size >> 8);
            buffer[3] = (byte)size;
            HashBytes(hasher, buffer);
        }

        private static void HashLenghtAndBytes(HashAlgorithm hasher, byte[] bytes)
        {
            HashSize(hasher, bytes.Length);
            HashBytes(hasher, bytes);
        }

        public static void Hash(HashAlgorithm hasher, object[] array)
        {
            byte[] buffer = new byte[] { (byte) 0, (byte) 0, (byte) 0, (byte) 0 };
    	    // handle each array element
            for (int i = 0; i < array.Length; i++)
            {
        	    if (array[i] == null)
                {
                    HashBytes(hasher, buffer);
                }
                else if (array[i] is byte)
                {
                    HashBytes(hasher, new byte[] { (byte) array[i] });
                }
                else if (array[i] is int)
                { 
                    int integer = (int) array[i];
                    HashSize(hasher, integer);
                }
                else if (array[i] is BigInteger)
                {
                    HashLenghtAndBytes(hasher, (array[i] as BigInteger).ToByteArrayUnsigned());
                }
                else if (array[i] is GroupElement)
                {
                    HashLenghtAndBytes(hasher, (array[i] as GroupElement).ToByteArray());
                }
                else if (array[i] is FpPoint)
                {
                    HashLenghtAndBytes(hasher, (array[i] as FpPoint).GetEncoded());
                }
                else if (array[i] is byte[])
                {
                    HashLenghtAndBytes(hasher, (array[i] as byte[]));
                }
                else if (array[i] is BigInteger[])
                {
                    BigInteger[] bi = (BigInteger[])array[i];
                    HashSize(hasher, bi.Length);
                    Hash(hasher, bi);
                }
                else if (array[i] is int[])
                {
                    int[] integers = (int[])array[i];
                    HashSize(hasher, integers.Length);
                    foreach (int integer in integers) { HashSize(hasher, integer); }
                }
                else if (array[i] is GroupElement[])
                {
                    GroupElement[] groupElements = (GroupElement[])array[i];
                    HashSize(hasher, groupElements.Length);
                    Hash(hasher, groupElements);
                }
                else if (array[i] is byte[][])
                {
                    byte[][] bytes = (byte[][])array[i];
                    HashSize(hasher, bytes.Length);
                    Hash(hasher, bytes);
                }
                else
                {
                    throw new ArgumentException("i=" + i);
                }
            }    	
        }

        // note: this random number generator is _not_ suited for cryptographic use. It is used here for simplicity.
        private static Random random = new Random("U-Prove".GetHashCode());
        /// <summary>
        /// Returns a random integer smaller than q. Note that this method is _not_ suited for cryptographic use.
        /// </summary>
        /// <param name="q">The interval maximum.</param>
        /// <param name="nonZero">If <c>true</c>, then the return value can't be 0.</param>
        /// <returns>A random BigInteger.</returns>
        public static BigInteger GetRandom(BigInteger q, bool nonZero = false)
        {
            BigInteger i;
            do
            {
                i = new BigInteger(q.BitLength, random).Mod(q);
            } while (nonZero == true && BigInteger.Zero.Equals(i));
            return i;
        }

        public static BigInteger ComputeXi(HashAlgorithm hash, BigInteger q, byte encodingByte, byte[] attribute)
        {
            if (encodingByte == (byte)1)
            {
                if (attribute == null || attribute.Length == 0)
                {
                    return BigInteger.Zero;
                }
                else
                {
                    return HashToZq(hash, new object[] { attribute }, q);
                }
            }
            else if (encodingByte == (byte)0)
            {
                BigInteger xi = new BigInteger(1, attribute);
                if (xi.CompareTo(q) >= 0)
                { 
                    throw new ArgumentException("xi >= q"); 
                }
                return xi;
            }
            else
            {
                throw new ArgumentException("invalid encoding byte");
            }
        }

        public static BigInteger ComputeXt(HashAlgorithm hash, byte[] UIDp, Group Gq, GroupElement[] g, GroupElement g_d, byte[] e, byte[] S, byte[] TI, out byte[] P)
        {
            bool deviceSupported = (g_d != null);
            GroupElement[] gToHash = new GroupElement[g.Length + (deviceSupported ? 1 : 0)];
            for (int i = 0; i < g.Length; i++) 
            {
                gToHash[i] = g[i];
            }
            if (deviceSupported)
            {
                gToHash[g.Length] = g_d;
            }

            object[] preGqArray = new object[] { UIDp };
            object[] postGqArray = new object[] { gToHash, e, S };
            object[] GqArray = null;
            if (Gq is P256ECGroup) // TODO: what about the other groups?
            {
                FpCurve curve = (FpCurve) RecommendedParameters.P256.parameters.Curve;
                GqArray = new object[] { curve.Q, curve.A.ToBigInteger(), curve.B.ToBigInteger(), RecommendedParameters.P256.g, RecommendedParameters.P256.parameters.N, BigInteger.One };
            }
            P = HashToBytes(hash, ConcatArrays(new object[][] { preGqArray, GqArray, postGqArray }));
            
            BigInteger xt = HashToZq(hash, new object[] { (byte) 1, P, TI}, Gq.Order);
            return xt;
        }

        public static GroupElement MultiModPow(Group group, GroupElement[] bases, BigInteger[] exponents)
        {
            if (bases == null || exponents == null || bases.Length != exponents.Length)
            {
                throw new ArgumentException();
            }

            GroupElement ge = group.Identity;
            for (int i = 0; i < bases.Length; i++)
            {
                ge = ge.Multiply(bases[i].Exponentiate(exponents[i]));
            }
            return ge;
        }

        public static byte[] ComputeTokenID(HashAlgorithm hash, GroupElement h, GroupElement sigmaZPrime, BigInteger sigmaCPrime, BigInteger sigmaRPrime)
        {
            return HashToBytes(hash, new object[] { h, sigmaZPrime, sigmaCPrime, sigmaRPrime });
        }

        public static void GenerateChallenge(int d, HashAlgorithm hash, BigInteger q, byte[] UIDt, byte[] a, int p, byte[] ap, GroupElement Ps, byte[] m, byte[] md, int[] D, BigInteger[] x, int[] C, GroupElement[] tildeC, byte[][] tildeA, out BigInteger c, out byte[] cp)
        {
            int pPrime = (p == d) ? 0 : p;
            object[] hashArray = new object[] { UIDt, a, D, x, C, tildeC, tildeA, pPrime, ap, Ps, m };
            cp = HashToBytes(hash, hashArray);
            c = HashToZq(hash, new object[] { new byte[][] { cp, md } }, q);
        }

        private static readonly int pseudonymIndex = 0;

        public static GroupElement GenerateScopeElement(Group group, byte[] scope, Formatter formater)
        {
            if (group is P256ECGroup) // TODO: what about the other groups?
            {
                int finalCounter;
                var curve = (((((group as P256ECGroup).Identity) as ECElement).point as Org.BouncyCastle.Math.EC.ECPoint).Curve as FpCurve);
                return new ECElement(ECRecommendedParameters.GetRandomPoint(Encoding.UTF8.GetString(scope), curve, pseudonymIndex, formater, out finalCounter));
            }
            else
            {
                throw new Exception("Unknown group");
            }
        }

        // H(UID_p, UID_t, H, Cxb, E1, E2, Cxb’, E1’, E2’, additionalInfo)
        public static BigInteger GenerateIdEscrowChallenge(HashAlgorithm hash, BigInteger q, byte[] UIDp, byte[] UIDt, GroupElement H, GroupElement Cxb, GroupElement E1, GroupElement E2, GroupElement CxbPrime, GroupElement E1Prime, GroupElement E2Prime, byte[] additionalInfo)
        {
            object[] hashArray = new object[] { UIDp, UIDt, H, Cxb, E1, E2, CxbPrime, E1Prime, E2Prime, additionalInfo };
            BigInteger c = HashToZq(hash, hashArray, q);
            return c;
        }

        public static BigInteger GenerateRevocationChallenge(HashAlgorithm hash, BigInteger q, GroupElement g, GroupElement g1, GroupElement gt, GroupElement K, GroupElement tildeCid, GroupElement X, GroupElement Y, GroupElement Cd, GroupElement T1, GroupElement T2, GroupElement T3)
        {
            object[] hashArray = new object[] { g, g1, gt, K, tildeCid, X, Y, Cd, T1, T2, T3 };
            BigInteger c = HashToZq(hash, hashArray, q);
            return c;
        }

        internal static BigInteger GenerateSetMembershipChallenge(HashAlgorithm hash, BigInteger q, Group Gq, GroupElement g, GroupElement g1, BigInteger[] S, GroupElement tildeCid, GroupElement[] a)
        {
            object[] protocolArray = { g, g1, S, tildeCid, a };
            BigInteger c = HashToZq(hash, ConcatArrays(new object[][] { GetGroupDescription(Gq), protocolArray }), q);
            return c;
        }

        internal static object[] GetGroupDescription(Group Gq)
        {
            if (Gq is P256ECGroup) // TODO: what about the other groups?
            {
                FpCurve curve = (FpCurve)RecommendedParameters.P256.parameters.Curve;
                return new object[] { curve.Q, curve.A.ToBigInteger(), curve.B.ToBigInteger(), RecommendedParameters.P256.g, RecommendedParameters.P256.parameters.N, BigInteger.One };
            }
            else
            {
                return null;
            }
        }

        internal static object[] ConcatArrays(object[][] a)
        {
            int size = 0;
            for (int i = 0; i < a.Length; i++)
            {
                size += a[i].Length;
            }
            object[] concat = new object[size];
            int index = 0;
            for (int i = 0; i < a.Length; i++)
            {
                a[i].CopyTo(concat, index);
                index += a[i].Length;
            }
            return concat;
        }
    }
}
