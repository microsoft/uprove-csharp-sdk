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
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using UProveParams;

namespace UProveTestVectors
{
    class TestVectors
    {
        internal static void GenerateHashTestVectors(Formatter formater)
        {
            string UIDh = "SHA-256";
            formater.PrintText("UIDh", null, null, UIDh);
            HashAlgorithm hash = System.Security.Cryptography.SHA256.Create();            

            byte[] hash_byte = ProtocolHelper.HashToBytes(hash, new object[] { (byte)1 });
            formater.PrintHex("hash_byte (0x01)", null, null, hash_byte);

            byte[] hash_octectstring = ProtocolHelper.HashToBytes(hash, new object[] { new byte[] { (byte)1, (byte)2, (byte)3, (byte)4, (byte)5 } });
            formater.PrintHex("hash_octectstring (0x0102030405)", null, null, hash_octectstring);

            byte[] hash_null = ProtocolHelper.HashToBytes(hash, new object[] { null });
            formater.PrintHex("hash_null (null)", null, null, hash_null);

            byte[] hash_list = ProtocolHelper.HashToBytes(hash, new object[] { 
                3,
                (byte) 1,
                new byte[] {(byte) 1, (byte) 2, (byte) 3, (byte) 4, (byte) 5},
                null
            });
            formater.PrintHex("hash_list [0x01, 0x0102030405, null]", null, null, hash_list);

            // hash default group construction
            FpCurve curve = (FpCurve)RecommendedParameters.P256.parameters.Curve;
            byte[] hash_ecgroup = ProtocolHelper.HashToBytes(hash, new object[] { curve.Q, curve.A.ToBigInteger(), curve.B.ToBigInteger(), RecommendedParameters.P256.g, RecommendedParameters.P256.parameters.N, BigInteger.One });
            formater.PrintHex("hash_group (1.3.6.1.4.1.311.75.1.2.1)", null, null, hash_ecgroup);
        }

        internal static int UIDpIndex = 1;
        internal static void GenerateTestVectors(string uidp, Formatter formater, bool supportDevice, bool lite, int maxAttribIndex, int[] D)
        {
            if (formater.type != Formatter.Type.doc)
            {
                throw new ArgumentException("Test vectors can only be printed with a doc formatter");
            }

            int n = maxAttribIndex;
            int t = n + 1; // the token information field index
            int d = n + 2; // the device field index

            //
            // hash input formatting
            //
            string UIDh = "SHA-256";
            formater.PrintText("UIDh", UIDh);
            HashAlgorithm hash = System.Security.Cryptography.SHA256.Create();

            //
            // Setup
            //

            Group Gq = new P256ECGroup();
            BigInteger q = Gq.Order;

            // issuer setup
            byte[] UIDp = Encoding.UTF8.GetBytes(uidp);
            formater.PrintHex("UIDp", UIDp);

            formater.PrintText("GroupName", Gq.OID);

            BigInteger y0 = ProtocolHelper.GetRandom(q, true);
            formater.PrintBigInteger("y0", y0);

            GroupElement[] generators = new GroupElement[n + 2];
            generators[0] = Gq.Generator.Exponentiate(y0);
            generators[0].Print("g0", formater);
            GroupElement deviceGenerator;
            for (int i = 1; i <= n; i++)
            {
                // we use the recommended parameters for the g_i
                generators[i] = new ECElement(RecommendedParameters.P256.g_i[i - 1]); // g_i is zero-based
            }
            generators[t] = new ECElement(RecommendedParameters.P256.g_t);
            deviceGenerator = new ECElement(RecommendedParameters.P256.g_d);

            byte[] e = { 0x00, 0x01, 0x01, 0x00, 0x00 };
            for (int i = 0; i < e.Length; i++)
            {
                formater.PrintHex("e" + (i + 1), new byte[] { e[i] });
            }

            string SValue = "Issuer parameters specification";
            byte[] S = Encoding.UTF8.GetBytes(SValue);
            formater.PrintHex("S", S);

            //
            // ID Escrow - Auditor setup
            //

            BigInteger ie_x = null;
            GroupElement ie_H = null;
            byte[] ie_additionalInfo = null;
            if (!lite) // TODO: only print if hasCommitment is true
            {
                ie_x = ProtocolHelper.GetRandom(q);
                formater.PrintBigInteger("ie_x", ie_x);
                ie_H = Gq.Generator.Exponentiate(ie_x);
                ie_H.Print("ie_H", formater);
                String ie_additionalInfoValue = "ID Escrow policy";
                ie_additionalInfo = Encoding.UTF8.GetBytes(ie_additionalInfoValue);
                formater.PrintHex("ie_additionalInfo", ie_additionalInfo);
            }

            //
            // Revocation Authority setup
            //

            BigInteger r_delta = null;
            GroupElement r_K = null;
            BigInteger[] r_R = null;
            GroupElement r_V = null;
            if (!lite)  // TODO: only print if hasCommitment is true
            {
                r_delta = ProtocolHelper.GetRandom(q);
                formater.PrintBigInteger("r_delta", r_delta);
                // K = g^delta
                r_K = Gq.Generator.Exponentiate(r_delta);
                r_K.Print("r_K", formater);
                // revoked values
                r_R = new BigInteger[4];
                BigInteger vExponentAccumulator = BigInteger.One;
                for (int i = 0; i < r_R.Length; i++)
                {
                    r_R[i] = ProtocolHelper.GetRandom(q);
                    formater.PrintBigInteger("r_R" + (i + 1), r_R[i]);
                    // V = gt ^ Prod_{x \in R} (delta + x)
                    vExponentAccumulator = vExponentAccumulator.Multiply(r_delta.Add(r_R[i]).Mod(q)).Mod(q);
                }
                r_V = generators[t].Exponentiate(vExponentAccumulator);
                r_V.Print("r_V", formater);
            }

            //
            // Issuance
            //

            // issuance protocol input
            byte[][] A = 
            {
                new BigInteger("1234567890", 10).ToByteArray(), // user unique ID, direct-encoding
                Encoding.UTF8.GetBytes("Alice Smith"), // name, hashed
                Encoding.UTF8.GetBytes("USA"), // country of residence, hashed
                new byte[] { 0x02 }, // level, direct-encoding
                new BigInteger("25", 10).ToByteArray() // age, direct-encoding
            };
            for (int i = 0; i < A.Length; i++)
            {
                formater.PrintHex("A" + (i + 1), A[i]);
            }

            byte[] TI = Encoding.UTF8.GetBytes("Token information field value");
            formater.PrintHex("TI", TI);
            byte[] PI = Encoding.UTF8.GetBytes("Prover information field value");
            formater.PrintHex("PI", PI);

            BigInteger[] x = new BigInteger[n + 2];
            BigInteger xd = null;
            x[0] = BigInteger.One;
            for (int i = 0; i < n; i++)
            {
                x[i + 1] = ProtocolHelper.ComputeXi(hash, q, e[i], A[i]);
                formater.PrintBigInteger("x" + (i + 1), x[i + 1]);
            }

            byte[] P;
            x[t] = ProtocolHelper.ComputeXt(hash, UIDp, Gq, generators, supportDevice ? deviceGenerator : null, e, S, TI, out P);
            formater.PrintHex("P", P);
            formater.PrintBigInteger("xt", x[t]);

            // device info
            GroupElement hd = Gq.Identity;
            if (supportDevice)
            {
                xd = ProtocolHelper.ComputeXi(hash, q, (byte)1, Encoding.UTF8.GetBytes("Device secret"));
                formater.PrintBigInteger("xd", xd);
                hd = deviceGenerator.Exponentiate(xd);
                hd.Print("hd", formater);
            }

            GroupElement gamma = ProtocolHelper.MultiModPow(Gq, generators, x);
            if (supportDevice)
            {
                gamma = gamma.Multiply(hd);
            }
            gamma.Print("gamma", formater);

            // issuer precomputations
            GroupElement sigmaZ = gamma.Exponentiate(y0);
            sigmaZ.Print("sigmaZ", formater);

            BigInteger issuerW = ProtocolHelper.GetRandom(q);
            formater.PrintBigInteger("w", issuerW);

            GroupElement sigmaA = Gq.Generator.Exponentiate(issuerW);
            sigmaA.Print("sigmaA", formater);

            GroupElement sigmaB = gamma.Exponentiate(issuerW);
            sigmaB.Print("sigmaB", formater);

            // user precomputations
            BigInteger alpha = ProtocolHelper.GetRandom(q, true);
            formater.PrintBigInteger("alpha", alpha);
            BigInteger beta1 = ProtocolHelper.GetRandom(q);
            formater.PrintBigInteger("beta1", beta1);
            BigInteger beta2 = ProtocolHelper.GetRandom(q);
            formater.PrintBigInteger("beta2", beta2);

            GroupElement h = gamma.Exponentiate(alpha);
            h.Print("h", formater);

            BigInteger alphaInverse = alpha.ModInverse(q);
            formater.PrintBigInteger("alphaInverse", alphaInverse);

            // user second message computations
            GroupElement sigmaZPrime = sigmaZ.Exponentiate(alpha);
            sigmaZPrime.Print("sigmaZPrime", formater);
            GroupElement sigmaAPrime = generators[0].Exponentiate(beta1).Multiply(Gq.Generator.Exponentiate(beta2)).Multiply(sigmaA);
            sigmaAPrime.Print("sigmaAPrime", formater);
            GroupElement sigmaBPrime = sigmaZPrime.Exponentiate(beta1).Multiply(h.Exponentiate(beta2)).Multiply(sigmaB.Exponentiate(alpha));
            sigmaBPrime.Print("sigmaBPrime", formater);
            BigInteger sigmaCPrime = ProtocolHelper.HashToZq(hash, new object[] { h, PI, sigmaZPrime, sigmaAPrime, sigmaBPrime }, q);
            formater.PrintBigInteger("sigmaCPrime", sigmaCPrime);
            BigInteger sigmaC = sigmaCPrime.Add(beta1).Mod(q);
            formater.PrintBigInteger("sigmaC", sigmaC);

            // issuer third message computations
            BigInteger sigmaR = sigmaC.Multiply(y0).Add(issuerW).Mod(q);
            formater.PrintBigInteger("sigmaR", sigmaR);

            // user token generation computations
            BigInteger sigmaRPrime = sigmaR.Add(beta2).Mod(q);
            formater.PrintBigInteger("sigmaRPrime", sigmaRPrime);

            // token signature verification
            if (!(sigmaAPrime.Multiply(sigmaBPrime)).Equals(
                ((Gq.Generator.Multiply(h)).Exponentiate(sigmaRPrime)).Multiply(
                (generators[0].Multiply(sigmaZPrime)).Exponentiate(sigmaCPrime.Negate().Mod(q))))
                )
            {
                throw new Exception("signature is invalid");
            }

            //
            // Presentation
            //

            // parameters
            formater.PrintSet("D", D);

            int[] U = new int[n - D.Length];
            int dIndex = 0, uIndex = 0;
            for (int i = 1; i <= n; i++)
            {
                if (D.Length > 0 && D[dIndex] == i)
                {
                    // i is disclosed, skip
                    dIndex++;
                }
                else
                {
                    // i is undisclosed, add to U
                    U[uIndex++] = i;
                }
            }
            formater.PrintSet("U", U);
            // we commit to the first undisclosed index, if any
            bool hasCommitment = !lite && U.Length > 0;
            if (hasCommitment && (U.Length < 2 || !U.Contains<int>(1) || !U.Contains<int>(4)))
            {
                // we can't commit to attributes 1 and 4
                throw new ArgumentException("U must have at least two elements");
            }
            int[] C = hasCommitment ? new int[] { 1, 4 } : new int[] { };
            if (hasCommitment)
            {
                formater.PrintSet("C", C);
            }
            // p is the first committed attribute (if any), or the device attribute if device-protected
            int p = hasCommitment ? (supportDevice ? d : C[0]) : 0;
            if (hasCommitment)
            {
                formater.PrintText("p", supportDevice ? "d" : p.ToString());
            }
            byte[] s = Encoding.UTF8.GetBytes("VerifierUID");
            if (hasCommitment)
            {
                formater.PrintHex("s", s);
            }
            byte[] m = Encoding.UTF8.GetBytes("VerifierUID+random data");
            formater.PrintHex("m", m);
            byte[] md = Encoding.UTF8.GetBytes("Direct message");
            formater.PrintHex("md", md);

            // Prover's precomputation
            BigInteger[] w = new BigInteger[n + 2 + (supportDevice ? 1 : 0)];
            BigInteger[] tildeO = new BigInteger[C.Length];
            BigInteger[] tildeW = new BigInteger[C.Length];
            GroupElement[] tildeC = new GroupElement[C.Length];
            byte[][] tildeA = new byte[C.Length][];
            GroupElement[] bases = new GroupElement[U.Length + 1 + (supportDevice ? 1 : 0)];
            BigInteger[] exponents = new BigInteger[U.Length + 1 + (supportDevice ? 1 : 0)];
            w[0] = ProtocolHelper.GetRandom(q);
            formater.PrintBigInteger("w0", w[0]);
            GroupElement ad = null;
            BigInteger wdPrime = null;
            GroupElement Ps = null;
            GroupElement gs = null;
            GroupElement apPrime = null;
            if (p > 0 && s != null && hasCommitment)
            {
                gs = ProtocolHelper.GenerateScopeElement(Gq, s, formater);
                gs.Print("gs", formater);
            }
            if (supportDevice)
            {
                w[d] = ProtocolHelper.GetRandom(q);
                formater.PrintBigInteger("wd", w[d]);

                // Device's commitment
                wdPrime = ProtocolHelper.GetRandom(q);
                formater.PrintBigInteger("wdPrime", wdPrime);
                ad = deviceGenerator.Exponentiate(wdPrime);
                ad.Print("ad", formater);

                if (hasCommitment)
                {
                    // Device's pseudonym
                    apPrime = gs.Exponentiate(wdPrime);
                    apPrime.Print("apPrime", formater);
                    Ps = gs.Exponentiate(xd);
                    Ps.Print("Ps", formater);
                }
            }

            // Presentation proof generation
            bases[0] = h;
            exponents[0] = w[0];
            if (supportDevice)
            {
                bases[1] = deviceGenerator;
                exponents[1] = w[d];
            }
            for (int i = 0; i < U.Length; i++)
            {
                int index = U[i];
                w[index] = ProtocolHelper.GetRandom(q);
                formater.PrintBigInteger("w" + index, w[index]);
                bases[i + 1 + (supportDevice ? 1 : 0)] = generators[index];
                exponents[i + 1 + (supportDevice ? 1 : 0)] = w[index];
            }
            GroupElement aInput = ProtocolHelper.MultiModPow(Gq, bases, exponents);
            if (supportDevice)
            {
                aInput = aInput.Multiply(ad);
            }
            byte[] a = ProtocolHelper.HashToBytes(hash, new Object[] { aInput });
            formater.PrintHex("a", a);
            byte[] ap = null;

            // Generate commitments
            for (int i = 0; i < C.Length; i++)
            {
                int index = C[i];
                tildeO[i] = ProtocolHelper.GetRandom(q);
                formater.PrintBigInteger("tildeO" + index, tildeO[i]);
                tildeW[i] = ProtocolHelper.GetRandom(q);
                formater.PrintBigInteger("tildeW" + index, tildeW[i]);
                bases = new GroupElement[2] { Gq.Generator, generators[1] };
                exponents = new BigInteger[2] { x[index], tildeO[i] };
                tildeC[i] = ProtocolHelper.MultiModPow(Gq, bases, exponents);
                tildeC[i].Print("tildeC" + index, formater);
                exponents = new BigInteger[2] { w[index], tildeW[i] };
                tildeA[i] = ProtocolHelper.HashToBytes(hash, new object[] { ProtocolHelper.MultiModPow(Gq, bases, exponents) });
                formater.PrintHex("tildeA" + index, tildeA[i]);
            }

            // compute pseudonym
            if (p > 0 && s != null)
            {
                GroupElement apInput = gs.Exponentiate(w[p]);
                if (p == d)
                {
                    apInput = apInput.Multiply(apPrime);
                }
                ap = ProtocolHelper.HashToBytes(hash, new Object[] { apInput });
                formater.PrintHex("ap", ap);
                if (p != d)
                {
                    Ps = gs.Exponentiate(x[p]);
                    Ps.Print("Ps", formater);
                }
            }
            BigInteger[] disclosedX = new BigInteger[D.Length];
            for (int i = 0; i < D.Length; i++)
            {
                disclosedX[i] = x[D[i]];
            }
            byte[] UIDt = ProtocolHelper.ComputeTokenID(hash, h, sigmaZPrime, sigmaCPrime, sigmaRPrime);
            formater.PrintHex("UIDt", UIDt);
            BigInteger c;
            byte[] cp;
            ProtocolHelper.GenerateChallenge(d, hash, q, UIDt, a, p, ap, Ps, m, md, D, disclosedX, C, tildeC, tildeA, out c, out cp);
            formater.PrintHex("cp", cp);
            formater.PrintBigInteger("c", c);
            BigInteger[] r = new BigInteger[n + 3];
            r[0] = c.Multiply(alphaInverse).Add(w[0]).Mod(q);
            formater.PrintBigInteger("r0", r[0]);
            for (int i = 0; i < U.Length; i++)
            {
                int index = U[i];
                r[index] = c.Negate().Mod(q).Multiply(x[index]).Add(w[index]).Mod(q);
                formater.PrintBigInteger("r" + index, r[index]);
            }

            if (supportDevice)
            {
                // Device response computation
                BigInteger rdPrime = c.Negate().Mod(q).Multiply(xd).Add(wdPrime).Mod(q);
                formater.PrintBigInteger("rdPrime", rdPrime);
                // a_d = g_d^r'_d h_d^c
                GroupElement validation = deviceGenerator.Exponentiate(rdPrime).Multiply(hd.Exponentiate(c));
                if (!ad.Equals(validation))
                {
                    throw new Exception("invalid device response");
                }

                r[d] = rdPrime.Add(w[d]).Mod(q);
                formater.PrintBigInteger("rd", r[d]);
            }

            BigInteger[] tildeR = new BigInteger[C.Length];
            for (int i = 0; i < C.Length; i++)
            {
                int index = C[i];
                tildeR[i] = c.Negate().Mod(q).Multiply(tildeO[i]).Add(tildeW[i]).Mod(q);
                formater.PrintBigInteger("tildeR" + index, tildeR[i]);
            }

            //
            // ID Escrow - Veriable encryption
            //
            int ie_bIndex = 0, commitmentIndex = 0;
            BigInteger ie_r = null, ie_xbPrime = null, ie_rPrime = null, ie_obPrime = null, ie_c = null, ie_rxb = null, ie_rr = null, ie_rob = null;
            GroupElement ie_E1 = null, ie_E2 = null, ie_CxbPrime = null, ie_E1Prime = null, ie_E2Prime = null;
            if (hasCommitment)
            {
                ie_bIndex = 1; // x1 is used as ID escrow attribute
                formater.PrintText("ie_b", ie_bIndex.ToString());
                commitmentIndex = 0;

                ie_r = ProtocolHelper.GetRandom(q);
                formater.PrintBigInteger("ie_r", ie_r);

                ie_E1 = Gq.Generator.Exponentiate(ie_r);
                ie_E1.Print("ie_E1", formater);
                ie_E2 = Gq.Generator.Exponentiate(x[1]).Multiply(ie_H.Exponentiate(ie_r));
                ie_E2.Print("ie_E2", formater);

                ie_xbPrime = ProtocolHelper.GetRandom(q);
                formater.PrintBigInteger("ie_xbPrime", ie_xbPrime);
                ie_rPrime = ProtocolHelper.GetRandom(q);
                formater.PrintBigInteger("ie_rPrime", ie_rPrime);
                ie_obPrime = ProtocolHelper.GetRandom(q);
                formater.PrintBigInteger("ie_obPrime", ie_obPrime);
                ie_CxbPrime = Gq.Generator.Exponentiate(ie_xbPrime).Multiply(generators[1].Exponentiate(ie_obPrime));
                ie_CxbPrime.Print("ie_CxbPrime", formater);
                ie_E1Prime = Gq.Generator.Exponentiate(ie_rPrime);
                ie_E1Prime.Print("ie_E1Prime", formater);
                ie_E2Prime = Gq.Generator.Exponentiate(ie_xbPrime).Multiply(ie_H.Exponentiate(ie_rPrime));
                ie_E2Prime.Print("ie_E2Prime", formater);
                ie_c = ProtocolHelper.GenerateIdEscrowChallenge(hash, q, UIDp, UIDt, ie_H, tildeC[commitmentIndex], ie_E1, ie_E2, ie_CxbPrime, ie_E1Prime, ie_E2Prime, ie_additionalInfo);
                formater.PrintBigInteger("ie_c", ie_c);
                ie_rxb = ie_c.Negate().Mod(q).Multiply(x[ie_bIndex]).Add(ie_xbPrime).Mod(q);
                formater.PrintBigInteger("ie_rxb", ie_rxb);
                ie_rr = ie_c.Negate().Mod(q).Multiply(ie_r).Add(ie_rPrime).Mod(q);
                formater.PrintBigInteger("ie_rr", ie_rr);
                ie_rob = ie_c.Negate().Mod(q).Multiply(tildeO[commitmentIndex]).Add(ie_obPrime).Mod(q);
                formater.PrintBigInteger("ie_rob", ie_rob);
            }

            //
            // Revocation 
            //
            int r_id = 0;
            BigInteger r_d = null, r_cPrime = null;
            BigInteger[] r_t = new BigInteger[2 + 1], r_k = new BigInteger[6 + 1], r_s = new BigInteger[6 + 1]; // we waste index 0 for readability
            GroupElement r_W = null, r_Q = null, r_X = null, r_Y = null, r_Cd = null, r_T1 = null, r_T2 = null, r_T3 = null;
            if (hasCommitment)
            {
                r_id = 1; // x1 is used as revocation attribute
                formater.PrintText("r_id", r_id.ToString());

                // compute revocation witness

                r_d = BigInteger.One;
                BigInteger deltaPlusXid = r_delta.Add(x[r_id]); // delta + x_id
                BigInteger wExponentAccumulator = BigInteger.One;
                for (int i = 0; i < r_R.Length; i++)
                {
                    // rd = Prod_{x \in R}(x - xid)
                    // r_d = r_d.Multiply(r_delta.Add(r_R[i])).Mod(deltaPlusXid); // TODO (FIXME): delete, old calculation
                    r_d = r_d.Multiply(r_R[i].Subtract(x[r_id]).Mod(q)).Mod(q);
                    wExponentAccumulator = wExponentAccumulator.Multiply(r_delta.Add(r_R[i])).Mod(q);
                }
                formater.PrintBigInteger("r_d", r_d);
                BigInteger wExponent = wExponentAccumulator.Subtract(r_d).Mod(q).Multiply(
                                       r_delta.Add(x[r_id]).ModInverse(q)
                                       ).Mod(q);
                // W = gt ^ [( Prod_{x \in R}(delta + x)-d ) / (delta + x_id)]
                r_W = generators[t].Exponentiate(wExponent);
                r_W.Print("r_W", formater);
                // Q = V W^(-x_id) gt^(-d)
                r_Q = r_V.Multiply(r_W.Exponentiate(x[r_id].Negate())).Multiply(generators[t].Exponentiate(r_d.Negate()));
                r_Q.Print("r_Q", formater);

                // compute non-revocation proof
                for (int i = 1; i <= 2; i++)
                {
                    r_t[i] = ProtocolHelper.GetRandom(q);
                    formater.PrintBigInteger("r_t" + i, r_t[i]);
                }
                for (int i = 1; i <= 6; i++)
                {
                    r_k[i] = ProtocolHelper.GetRandom(q);
                    formater.PrintBigInteger("r_k" + i, r_k[i]);
                }
                // X = W g^t1
                r_X = r_W.Multiply(Gq.Generator.Exponentiate(r_t[1]));
                r_X.Print("r_X", formater);
                // Y = Q K^t1
                r_Y = r_Q.Multiply(r_K.Exponentiate(r_t[1]));
                r_Y.Print("r_Y", formater);
                // Cd = gt^d g1^t2
                r_Cd = generators[t].Exponentiate(r_d).Multiply(generators[1].Exponentiate(r_t[2]));
                r_Cd.Print("r_Cd", formater);
                // w = d^(-1) mod q
                BigInteger r_w = r_d.ModInverse(q);
                formater.PrintBigInteger("r_w", r_w);
                // z = t1 tildaO_id - t2 mod q
                BigInteger r_z = r_t[1].Multiply(tildeO[commitmentIndex]).Mod(q).Subtract(r_t[2]).Mod(q);
                formater.PrintBigInteger("r_z", r_z);
                // z' = -t2 w mod q
                BigInteger r_zPrime = r_t[2].Negate().Multiply(r_w).Mod(q);
                formater.PrintBigInteger("r_zPrime", r_zPrime);
                // T1 = X^k1 (tildeC_id K)^-k2 g1^k3
                r_T1 =
                    r_X.Exponentiate(r_k[1]).Multiply(
                    tildeC[commitmentIndex].Multiply(r_K).Exponentiate(r_k[2].Negate()).Multiply(
                    generators[1].Exponentiate(r_k[3])));
                r_T1.Print("r_T1", formater);
                // T2 = g^k1 g1^k4
                r_T2 = Gq.Generator.Exponentiate(r_k[1]).Multiply(generators[1].Exponentiate(r_k[4]));
                r_T2.Print("r_T2", formater);
                // T3 = Cd^k5 g1^k6
                r_T3 = r_Cd.Exponentiate(r_k[5]).Multiply(generators[1].Exponentiate(r_k[6]));
                r_T3.Print("r_T3", formater);
                // c' = H(g, g1, gt, K, tildeC_id, X, Y, Cd, T1, T2, T3)
                r_cPrime = ProtocolHelper.GenerateRevocationChallenge(hash, q, Gq.Generator, generators[1], generators[t], r_K, tildeC[commitmentIndex], r_X, r_Y, r_Cd, r_T1, r_T2, r_T3);
                formater.PrintBigInteger("r_cPrime", r_cPrime);
                BigInteger r_cPrimeNegate = r_cPrime.Negate().Mod(q);
                // s1 = -c x_id + k1 mod q
                // s2 = -c t1 + k2 mod q
                // s3 = -c z + k3 mod q
                // s4 = -c tildeO_id + k4 mod q
                // s5 = -c w + k5 mod q
                // s6 = -c z' + k6 mod q
                BigInteger[] r_sVariable = { null, x[r_id], r_t[1], r_z, tildeO[commitmentIndex], r_w, r_zPrime };
                for (int i = 1; i <= 6; i++)
                {
                    r_s[i] = r_cPrimeNegate.Multiply(r_sVariable[i]).Add(r_k[i]).Mod(q);
                    formater.PrintBigInteger("r_s" + i, r_s[i]);
                }
            }

            //
            // Set membership
            //

            int sm_x_index = 0, sm_i = 0;
            int smCommitmentIndex = 1; // x4 (2nd committed value) is used for set membership proof
            BigInteger sm_challenge = null;
            BigInteger[] sm_S = null, sm_c = null, sm_r = null;
            GroupElement[] sm_a = null;
            if (hasCommitment)
            {
                // x4 is used as the committed attribute
                sm_x_index = 4;
                formater.PrintText("sm_x_index", sm_x_index.ToString());
                
                sm_i = 2; // x4 is the 2nd value in the set
                formater.PrintText("sm_i", sm_i.ToString());

                int sm_n = 3; // size of the attribute set
                formater.PrintText("sm_n", sm_n.ToString());

                // attribute set
                sm_S = new BigInteger[sm_n];
                for (int i = 1; i <= sm_S.Length; i++)
                {
                    sm_S[i - 1] = new BigInteger(i.ToString(), 10);
                    formater.PrintBigInteger("sm_s" + i, sm_S[i - 1]);
                }

                // SetMembershipProve
                sm_a = new GroupElement[sm_S.Length];
                sm_c = new BigInteger[sm_S.Length];
                sm_r = new BigInteger[sm_S.Length];
                BigInteger sm_sumC = BigInteger.Zero;
                for (int i = 1; i <= sm_S.Length; i++)
                {
                    if (i == sm_i)
                    {
                        continue;
                    }
                    sm_c[i - 1] = ProtocolHelper.GetRandom(q, true);
                    formater.PrintBigInteger("sm_c" + i, sm_c[i - 1]);
                    sm_sumC = sm_sumC.Add(sm_c[i - 1]).Mod(q);
                    sm_r[i - 1] = ProtocolHelper.GetRandom(q, true);
                    formater.PrintBigInteger("sm_r" + i, sm_r[i - 1]);
                    sm_a[i - 1] = 
                        generators[1].Exponentiate(sm_r[i - 1]).Multiply(
                        Gq.Generator.Exponentiate(sm_S[i - 1].Multiply(sm_c[i - 1]).Mod(q)).Multiply(
                        tildeC[smCommitmentIndex].Exponentiate(sm_c[i - 1].Negate().Mod(q))));
                    sm_a[i - 1].Print("sm_a" + i, formater);
                }
                BigInteger sm_w = ProtocolHelper.GetRandom(q, true);
                formater.PrintBigInteger("sm_w", sm_w);
                sm_a[sm_i - 1] = generators[1].Exponentiate(sm_w);
                sm_a[sm_i - 1].Print("sm_a" + sm_i, formater);
                sm_challenge =
                    ProtocolHelper.GenerateSetMembershipChallenge(hash, q, Gq, Gq.Generator, generators[1], sm_S, tildeC[smCommitmentIndex], sm_a);
                formater.PrintBigInteger("sm_c", sm_challenge);
                sm_c[sm_i - 1] = sm_challenge.Subtract(sm_sumC).Mod(q);
                formater.PrintBigInteger("sm_c" + sm_i, sm_c[sm_i - 1]);
                sm_r[sm_i - 1] = sm_c[sm_i - 1].Multiply(tildeO[smCommitmentIndex]).Add(sm_w).Mod(q);
                formater.PrintBigInteger("sm_r" + sm_i, sm_r[sm_i - 1]);
            }

            //
            // Proof verification
            //

            // Verifier's U-Prove token signature verification
            BigInteger digest = ProtocolHelper.HashToZq(hash, new object[] {
					h,
					PI,
					sigmaZPrime,
					Gq.Generator.Exponentiate(sigmaRPrime).Multiply(generators[0].Exponentiate(sigmaCPrime.Negate().Mod(q))),
					h.Exponentiate(sigmaRPrime).Multiply(sigmaZPrime.Exponentiate(sigmaCPrime.Negate().Mod(q)))
			}, q);
            if (!sigmaCPrime.Equals(digest))
            {
                throw new Exception("invalid signature");
            }

            // Verifier's proof verification
            bases = new GroupElement[D.Length + 2];
            exponents = new BigInteger[D.Length + 2];
            bases[0] = generators[0];
            exponents[0] = BigInteger.One;
            bases[1] = generators[t];
            exponents[1] = x[t];
            for (int i = 0; i < D.Length; i++)
            {
                int index = D[i];
                bases[i + 2] = generators[index];
                exponents[i + 2] = x[index];
            }
            GroupElement temp = ProtocolHelper.MultiModPow(Gq, bases, exponents);
            bases = new GroupElement[U.Length + 2 + (supportDevice ? 1 : 0)];
            exponents = new BigInteger[U.Length + 2 + (supportDevice ? 1 : 0)];
            bases[0] = temp;
            exponents[0] = c.Negate().Mod(q);
            bases[1] = h;
            exponents[1] = r[0];
            if (supportDevice)
            {
                bases[2] = deviceGenerator;
                exponents[2] = r[d];
            }
            for (int i = 0; i < U.Length; i++)
            {
                int index = U[i];
                bases[i + 2 + (supportDevice ? 1 : 0)] = generators[index];
                exponents[i + 2 + (supportDevice ? 1 : 0)] = r[index];
            }
            GroupElement digest2Input = ProtocolHelper.MultiModPow(Gq, bases, exponents);
            byte[] digest2 = ProtocolHelper.HashToBytes(hash, new object[] { digest2Input });
            if (!a.SequenceEqual(digest2))
            {
                throw new Exception("invalid proof");
            }
            if (hasCommitment)
            {
                // verify pseudonym
                bases = new GroupElement[2] { Ps, gs };
                exponents = new BigInteger[2] { c, r[p] };
                digest2Input = ProtocolHelper.MultiModPow(Gq, bases, exponents);
                digest2 = ProtocolHelper.HashToBytes(hash, new object[] { digest2Input });
                if (!ap.SequenceEqual(digest2))
                {
                    throw new Exception("invalid pseudonym");
                }

                // verify commitment
                for (int i = 0; i < C.Length; i++)
                {
                    int index = C[i];
                    bases = new GroupElement[3] { tildeC[i], Gq.Generator, generators[1] };
                    exponents = new BigInteger[3] { c, r[index], tildeR[i] };
                    digest2Input = ProtocolHelper.MultiModPow(Gq, bases, exponents);
                    digest2 = ProtocolHelper.HashToBytes(hash, new object[] { digest2Input });
                    if (!tildeA[i].SequenceEqual(digest2))
                    {
                        throw new Exception("invalid commitment: " + index);
                    }
                }

                //
                // ID Escrow - Verifier validation
                //

                GroupElement ie_CxBDoublePrime = Gq.Generator.Exponentiate(ie_rxb).Multiply(generators[1].Exponentiate(ie_rob)).Multiply(tildeC[commitmentIndex].Exponentiate(ie_c));
                GroupElement ie_E1DoublePrime = Gq.Generator.Exponentiate(ie_rr).Multiply(ie_E1.Exponentiate(ie_c));
                GroupElement ie_E2DoublePrime = Gq.Generator.Exponentiate(ie_rxb).Multiply(ie_H.Exponentiate(ie_rr)).Multiply(ie_E2.Exponentiate(ie_c));
                BigInteger ie_cPrime = ProtocolHelper.GenerateIdEscrowChallenge(hash, q, UIDp, UIDt, ie_H, tildeC[commitmentIndex], ie_E1, ie_E2, ie_CxBDoublePrime, ie_E1DoublePrime, ie_E2DoublePrime, ie_additionalInfo);
                if (!ie_c.Equals(ie_cPrime))
                {
                    throw new Exception("invalid ID escrow encryption");
                }

                //
                // ID Escrow - Auditor decryption
                //

                GroupElement ie_PE = ie_E2.Multiply(ie_E1.Exponentiate(ie_x.Negate()));
                if (!Gq.Generator.Exponentiate(x[ie_bIndex]).Equals(ie_PE))
                {
                    throw new Exception("invalid ID escrow decryption");
                }

                //
                // Revocation : verify non-revocation proof
                //

                // T1 = (V Y^-1 Cd^-1)^c' X^s1 (tildeC_id K)^-s2 g1^s3
                GroupElement r_T1_2 =
                    (r_V.Multiply(r_Y.Exponentiate(BigInteger.One.Negate())).Multiply(r_Cd.Exponentiate(BigInteger.One.Negate()))).Exponentiate(r_cPrime).Multiply(
                    r_X.Exponentiate(r_s[1])).Multiply(
                    tildeC[commitmentIndex].Multiply(r_K).Exponentiate(r_s[2].Negate())).Multiply(
                    generators[1].Exponentiate(r_s[3]));
                // T2 = tildeC_id^c' g^s1 g1^s4
                GroupElement r_T2_2 =
                    tildeC[commitmentIndex].Exponentiate(r_cPrime).Multiply(Gq.Generator.Exponentiate(r_s[1])).Multiply(generators[1].Exponentiate(r_s[4]));
                // T3 = gt^c' Cd^s5 g1^s6
                GroupElement r_T3_2 =
                    generators[t].Exponentiate(r_cPrime).Multiply(r_Cd.Exponentiate(r_s[5])).Multiply(generators[1].Exponentiate(r_s[6]));
                BigInteger r_cPrime_2 = ProtocolHelper.GenerateRevocationChallenge(hash, q, Gq.Generator, generators[1], generators[t], r_K, tildeC[commitmentIndex], r_X, r_Y, r_Cd, r_T1_2, r_T2_2, r_T3_2);
                if (!r_cPrime.Equals(r_cPrime_2) || !r_Y.Equals(r_X.Exponentiate(r_delta)))
                {
                    throw new Exception("invalid non-revocation proof");
                }

                //
                // Set membership proof verification
                //
                BigInteger sm_challenge_2 = ProtocolHelper.GenerateSetMembershipChallenge(hash, q, Gq, Gq.Generator, generators[1], sm_S, tildeC[smCommitmentIndex], sm_a);
                if (!sm_challenge_2.Equals(sm_challenge))
                {
                    throw new Exception("invalid membership challenge");
                }
                BigInteger sm_sumC_2 = BigInteger.Zero;
                // c_n is not serialized, so we recalculate it from the challenge and the other c values
                for (int i = 0; i < sm_c.Length - 1; i++)
                {
                    sm_sumC_2 = sm_sumC_2.Add(sm_c[i]);
                }
                // c_n = c - \sum_{1 <= j < n} (c_j) mod q
                sm_c[sm_c.Length - 1] = sm_challenge_2.Subtract(sm_sumC_2).Mod(q); // replace c_n
                for (int i = 0; i < sm_r.Length; i++)
                {
                    if (!generators[1].Exponentiate(sm_r[i]).Equals(
                        tildeC[smCommitmentIndex].Exponentiate(sm_c[i]).Multiply(
                        Gq.Generator.Exponentiate(sm_c[i].Multiply(sm_S[i]).Negate().Mod(q)).Multiply(
                        sm_a[i]))
                        ))
                    {
                        throw new Exception("invalid membership proof");
                    }
                }
            }
        }
    }
}
