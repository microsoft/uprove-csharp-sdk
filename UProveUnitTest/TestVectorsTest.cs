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

// comment the following to skip testing the ID Escrow extension feature
// #define TEST_ID_ESCROW
// comment the following to skip testing the DVA revocation extension feature
// #define TEST_DVA_REVOCATION
// comment the following to skip testing the set membership extension feature
// #define TEST_SET_MEMBERSHIP

using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.Collections.Generic;
using System.Linq;
using UProveCrypto;
using System.Globalization;
using UProveCrypto.Math;
using System.Diagnostics;
#if TEST_ID_ESCROW
using IDEscrow;
#endif
#if TEST_DVA_REVOCATION
using UProveCrypto.DVARevocation;
#endif
#if TEST_SET_MEMBERSHIP
using UProveCrypto.PolyProof;
#endif

namespace UProveCryptoTest
{
    [TestClass]
    [DeploymentItem(@"..\..\..\TestVectorData\", "TestVectorData")]

    public class TestVectorsTest
    {
        public static GroupElement CreateGroupElement(Group Gq, string value)
        {
            if (Gq is SubgroupGroup)
            {
                return Gq.CreateGroupElement(HexToBytes(value));
            }
            else
            {
                ECGroup ecGq = Gq as ECGroup;
                string[] point = value.Split(',');
                return ecGq.CreateGroupElement(HexToBytes(point[0]), HexToBytes(point[1]));
            }
        }

        [TestMethod]
        public void HashFormattingTest()
        {
            HashFunction hash;

            // byte
            hash = new HashFunction(TestVectorData.HashVectors.UIDh);
            byte b = 0x01;
            hash.Hash(b);
            Assert.IsTrue(HexToBytes(TestVectorData.HashVectors.hash_byte).SequenceEqual(hash.Digest), "hash_byte");

            // octet string
            hash = new HashFunction(TestVectorData.HashVectors.UIDh);
            byte[] octetString = new byte[] { 0x01, 0x02, 0x03, 0x04, 0x05 };
            hash.Hash(octetString);
            Assert.IsTrue(HexToBytes(TestVectorData.HashVectors.hash_octetstring).SequenceEqual(hash.Digest), "hash_octetstring");

            // null
            hash = new HashFunction(TestVectorData.HashVectors.UIDh);
            hash.HashNull();
            Assert.IsTrue(HexToBytes(TestVectorData.HashVectors.hash_null).SequenceEqual(hash.Digest), "hash_null");

            // list
            hash = new HashFunction(TestVectorData.HashVectors.UIDh);
            hash.Hash(3); // list length
            hash.Hash(b);
            hash.Hash(octetString);
            hash.HashNull();
            Assert.IsTrue(HexToBytes(TestVectorData.HashVectors.hash_list).SequenceEqual(hash.Digest), "hash_list");

            // subgroup 1.3.6.1.4.1.311.75.1.1.1
            hash = new HashFunction(TestVectorData.HashVectors.UIDh);
            hash.Hash(SubgroupParameterSets.ParamSetL2048N256V1.Group);
            Assert.IsTrue(HexToBytes(TestVectorData.HashVectors.hash_subgroup).SequenceEqual(hash.Digest), "hash_subgroup");

            // ec group 1.3.6.1.4.1.311.75.1.2.1
            hash = new HashFunction(TestVectorData.HashVectors.UIDh);
            hash.Hash(ECParameterSets.ParamSet_EC_P256_V1.Group);
            Assert.IsTrue(HexToBytes(TestVectorData.HashVectors.hash_ecgroup).SequenceEqual(hash.Digest), "hash_ecgroup");
        }

        public static byte[] HexToBytes(string hexString)
        {
            int length = hexString.Length;
            if ((length % 2) != 0)
            {
                // prepend 0
                hexString = "0" + hexString;
            }

            byte[] bytes = new byte[hexString.Length / 2];
            for (int i = 0; i < length; i += 2)
            {
                try
                {
                    bytes[i / 2] = Byte.Parse(hexString.Substring(i, 2), NumberStyles.HexNumber);
                }
                catch (Exception)
                {
                    throw new ArgumentException("hexString is invalid");
                }
            }
            return bytes;
        }

        IssuerKeyAndParameters LoadIssuerKeyAndParameters(bool useSubgroupConstruction, string oid, bool supportDevice, Dictionary<string, string> vectors)
        {
            IssuerSetupParameters isp = new IssuerSetupParameters();

            isp.UseRecommendedParameterSet = true;
            isp.GroupConstruction = useSubgroupConstruction ? GroupType.Subgroup : GroupType.ECC;
            isp.UidP = HexToBytes(vectors["UIDp"]);
            isp.UidH = vectors["UIDh"];
            isp.E = new byte[] 
            { 
                byte.Parse(vectors["e1"]),
                byte.Parse(vectors["e2"]),
                byte.Parse(vectors["e3"]),
                byte.Parse(vectors["e4"]),
                byte.Parse(vectors["e5"]) 
            };
            isp.S = HexToBytes(vectors["S"]);
            IssuerKeyAndParameters ikap = isp.Generate(supportDevice);
            Assert.AreEqual<string>(ikap.IssuerParameters.Gq.GroupName, oid);
            return ikap;
        }

        static readonly string[] separator = new string[] { " = " };
        /// <summary>
        /// Read a test vector file. EC points are treated specially: two lines in the
        /// file are merged as one comma-separated value in the returned dictionary
        /// </summary>
        /// <param name="filePath"></param>
        /// <returns></returns>
        Dictionary<string, string> GetTestVectors(string filePath)
        {
            string ecPoint = null;
            Dictionary<string, string> dic = new Dictionary<string, string>();
            foreach (var row in System.IO.File.ReadAllLines(filePath))
            {
                string[] columns = row.Split(separator, StringSplitOptions.None);
                if (columns.Length > 1) // skip headers and comments
                {
                    if (ecPoint != null)
                    {
                        // we started to read an EC point
                        if (!columns[0].EndsWith(".y"))
                        {
                            throw new System.IO.IOException("y point coordinate expected. " + columns[0]);
                        }
                        ecPoint += columns[1];
                        dic.Add(columns[0].Substring(0, columns[0].Length - 2), ecPoint);
                        ecPoint = null;
                    }
                    else if (columns[0].EndsWith(".x"))
                    {
                        // first part of an EC point
                        ecPoint = columns[1];
                        ecPoint += ",";
                    }
                    else
                    {
                        dic.Add(columns[0], columns[1]);
                    }
                }
            }

            return dic;
        }

        public static int stringToInt(string s)
        {
            return int.Parse(s);
        }


        [TestMethod]
        public void ProtocolTest()
        {
            Stopwatch sw = new Stopwatch();
            sw.Start();
            bool[] bools = new bool[] { true, false };
            foreach (bool isSubgroupConstruction in bools)
            {
                foreach (bool supportDevice in bools)
                {
                    foreach (int DSize in new int[] { 0, 2, 5 })
                    {
                        foreach (bool isLite in bools)
                        {
                            string filename = "TestVectorData\\testvectors_";
                            if (isSubgroupConstruction)
                            {
                                filename += "SG";
                            }
                            else
                            {
                                filename += "EC";
                            }
                            if (supportDevice)
                            {
                                filename += "_Device";
                            }
                            filename += ("_D" + DSize);
                            if (isLite)
                            {
                                filename += "_lite";
                            }
                            filename += "_doc.txt";
                            var vectors = GetTestVectors(filename);

                            IssuerKeyAndParameters ikap = LoadIssuerKeyAndParameters(isSubgroupConstruction, vectors["GroupName"], supportDevice, vectors);
                            FieldZq Zq = ikap.IssuerParameters.Zq;
                            // replace random y0/g0 with test vector values
                            ikap.PrivateKey = Zq.GetElement(HexToBytes(vectors["y0"]));
                            ikap.IssuerParameters.G[0] = CreateGroupElement(ikap.IssuerParameters.Gq, vectors["g0"]);
                            Assert.AreEqual(ikap.IssuerParameters.G[0], ikap.IssuerParameters.Gq.G.Exponentiate(ikap.PrivateKey), "g0 computation");
                            IssuerParameters ip = ikap.IssuerParameters;
                            ip.Verify();

                            /*
                             * issuance
                             */

                            byte[][] A = new byte[][] {
                                HexToBytes(vectors["A1"]), 
                                HexToBytes(vectors["A2"]),
                                HexToBytes(vectors["A3"]),
                                HexToBytes(vectors["A4"]),
                                HexToBytes(vectors["A5"])
                            };

                            Assert.AreEqual(Zq.GetElement(HexToBytes(vectors["x1"])), ProtocolHelper.ComputeXi(ip, 0, A[0]), "x1");
                            Assert.AreEqual(Zq.GetElement(HexToBytes(vectors["x2"])), ProtocolHelper.ComputeXi(ip, 1, A[1]), "x2");
                            Assert.AreEqual(Zq.GetElement(HexToBytes(vectors["x3"])), ProtocolHelper.ComputeXi(ip, 2, A[2]), "x3");
                            Assert.AreEqual(Zq.GetElement(HexToBytes(vectors["x4"])), ProtocolHelper.ComputeXi(ip, 3, A[3]), "x4");
                            Assert.AreEqual(Zq.GetElement(HexToBytes(vectors["x5"])), ProtocolHelper.ComputeXi(ip, 4, A[4]), "x5");

                            byte[] TI = HexToBytes(vectors["TI"]);
                            Assert.IsTrue(HexToBytes(vectors["P"]).SequenceEqual(ip.Digest(supportDevice)), "P");
                            Assert.AreEqual(Zq.GetElement(HexToBytes(vectors["xt"])), ProtocolHelper.ComputeXt(ip, TI, supportDevice), "xt");

                            IDevice device = null;
                            GroupElement hd = null;
                            if (supportDevice)
                            {
                                device = new VirtualDevice(ip, Zq.GetElement(HexToBytes(vectors["xd"])), Zq.GetElement(HexToBytes(vectors["wdPrime"])));
                                IDevicePresentationContext context = device.GetPresentationContext();
                                // Test device responses
                                Assert.AreEqual(CreateGroupElement(ip.Gq, vectors["hd"]), device.GetDevicePublicKey(), "hd");
                                Assert.AreEqual(CreateGroupElement(ip.Gq, vectors["ad"]), context.GetInitialWitness(), "ad");
                                Assert.AreEqual(Zq.GetElement(HexToBytes(vectors["rdPrime"])), context.GetDeviceResponse(HexToBytes(vectors["md"]), HexToBytes(vectors["cp"]), ip.HashFunctionOID), "rdPrime");
                                hd = CreateGroupElement(ip.Gq, vectors["hd"]);
                            }

                            IssuerProtocolParameters ipp = new IssuerProtocolParameters(ikap);
                            ipp.Attributes = A;
                            ipp.NumberOfTokens = 1;
                            ipp.TokenInformation = TI;
                            ipp.DevicePublicKey = hd;
                            ipp.PreGeneratedW = new FieldZqElement[] { Zq.GetElement(HexToBytes(vectors["w"])) };
                            Issuer issuer = ipp.CreateIssuer();
                            byte[] PI = HexToBytes(vectors["PI"]);

                            ProverProtocolParameters ppp = new ProverProtocolParameters(ip);
                            ppp.Attributes = A;
                            ppp.NumberOfTokens = 1;
                            ppp.TokenInformation = TI;
                            ppp.ProverInformation = PI;
                            ppp.DevicePublicKey = hd;
                            ppp.ProverRandomData = new ProverRandomData(
                                new FieldZqElement[] { Zq.GetElement(HexToBytes(vectors["alpha"])) },
                                new FieldZqElement[] { Zq.GetElement(HexToBytes(vectors["beta1"])) },
                                new FieldZqElement[] { Zq.GetElement(HexToBytes(vectors["beta2"])) });
                            Prover prover = ppp.CreateProver();

                            FirstIssuanceMessage msg1 = issuer.GenerateFirstMessage();
                            Assert.AreEqual(msg1.sigmaZ, CreateGroupElement(ip.Gq, vectors["sigmaZ"]), "sigmaZ");
                            Assert.AreEqual(msg1.sigmaA[0], CreateGroupElement(ip.Gq, vectors["sigmaA"]), "sigmaA");
                            Assert.AreEqual(msg1.sigmaB[0], CreateGroupElement(ip.Gq, vectors["sigmaB"]), "sigmaB");

                            SecondIssuanceMessage msg2 = prover.GenerateSecondMessage(msg1);
                            Assert.AreEqual(msg2.sigmaC[0], Zq.GetElement(HexToBytes(vectors["sigmaC"])), "sigmaC");

                            ThirdIssuanceMessage msg3 = issuer.GenerateThirdMessage(msg2);
                            Assert.AreEqual(msg3.sigmaR[0], Zq.GetElement(HexToBytes(vectors["sigmaR"])), "sigmaR");

                            UProveKeyAndToken[] upkt = prover.GenerateTokens(msg3);
                            Assert.AreEqual(upkt[0].PrivateKey, Zq.GetElement(HexToBytes(vectors["alphaInverse"])), "alphaInverse");
                            UProveToken token = upkt[0].Token;
                            Assert.AreEqual(token.H, CreateGroupElement(ip.Gq, vectors["h"]), "h");
                            Assert.AreEqual(token.SigmaZPrime, CreateGroupElement(ip.Gq, vectors["sigmaZPrime"]), "sigmaZPrime");
                            Assert.AreEqual(token.SigmaCPrime, Zq.GetElement(HexToBytes(vectors["sigmaCPrime"])), "sigmaCPrime");
                            Assert.AreEqual(token.SigmaRPrime, Zq.GetElement(HexToBytes(vectors["sigmaRPrime"])), "sigmaRPrime");
                            Assert.IsTrue(HexToBytes(vectors["UIDt"]).SequenceEqual(ProtocolHelper.ComputeTokenID(ip, token)), "UIDt");
                            Assert.IsTrue(supportDevice == token.IsDeviceProtected);

                            /*
                             * presentation
                             */


                            int[] disclosed = new int[] { };
                            if (vectors.ContainsKey("D") && vectors["D"].Length > 0)
                            {
                                disclosed = Array.ConvertAll<string, int>(vectors["D"].Split(','), new Converter<string, int>(stringToInt));
                            }
                            int[] undisclosed = new int[5 - disclosed.Length];
                            int dIndex = 0, uIndex = 0;
                            for (int i = 1; i <= 5; i++)
                            {
                                if (disclosed.Length > 0 && disclosed[dIndex] == i)
                                {
                                    dIndex++;
                                }
                                else
                                {
                                    undisclosed[uIndex++] = i;
                                }
                            }
                            int[] committed = new int[] { };
                            if (vectors.ContainsKey("C") && vectors["C"].Length > 0)
                            {
                                committed = Array.ConvertAll<string, int>(vectors["C"].Split(','), new Converter<string, int>(stringToInt));
                            }
                            byte[] m = HexToBytes(vectors["m"]);
                            byte[] md = HexToBytes(vectors["md"]);
                            IDevicePresentationContext deviceContext = null;
                            if (supportDevice)
                            {
                                deviceContext = device.GetPresentationContext();
                            }
                            int p = 0;
                            if (vectors.ContainsKey("p") && !int.TryParse(vectors["p"], out p))
                            {
                                p = PresentationProof.DeviceAttributeIndex;
                            }
                            byte[] s = vectors.ContainsKey("s") ? HexToBytes(vectors["s"]) : null;
                            int commitmentIndex = committed.Length > 0 ? committed[0] : 0;
                            ProverPresentationProtocolParameters pppp = new ProverPresentationProtocolParameters(ip, disclosed, m, upkt[0], A);
                            pppp.Committed = committed;
                            pppp.PseudonymAttributeIndex = p;
                            pppp.PseudonymScope = s;
                            pppp.DeviceMessage = md;
                            pppp.DeviceContext = deviceContext;
                            FieldZqElement[] w = new FieldZqElement[undisclosed.Length];
                            for (int i = 0; i < undisclosed.Length; i++)
                            {
                                w[i] = Zq.GetElement(HexToBytes(vectors["w" + undisclosed[i]]));
                            }
                            FieldZqElement[] tildeO = new FieldZqElement[committed.Length];
                            FieldZqElement[] tildeW = new FieldZqElement[committed.Length];
                            for (int i = 0; i < committed.Length; i++)
                            {
                                tildeO[i] = Zq.GetElement(HexToBytes(vectors["tildeO" + committed[i]]));
                                tildeW[i] = Zq.GetElement(HexToBytes(vectors["tildeW" + committed[i]]));
                            }
                            pppp.RandomData = new ProofGenerationRandomData(
                                    Zq.GetElement(HexToBytes(vectors["w0"])),
                                    w,
                                    supportDevice ? Zq.GetElement(HexToBytes(vectors["wd"])) : null,
                                    tildeO,
                                    tildeW);
                            CommitmentPrivateValues cpv;
                            PresentationProof proof = PresentationProof.Generate(pppp, out cpv);
                            Assert.IsTrue(HexToBytes(vectors["a"]).SequenceEqual(proof.A), "a");
                            if (vectors.ContainsKey("gs"))
                            {
                                Assert.AreEqual(ProtocolHelper.GenerateScopeElement(ip.Gq, s), CreateGroupElement(ip.Gq, vectors["gs"]));
                                Assert.IsTrue(HexToBytes(vectors["ap"]).SequenceEqual(proof.Ap), "ap");
                                Assert.AreEqual(proof.Ps, CreateGroupElement(ip.Gq, vectors["Ps"]), "Ps");
                            }
                            for (int i = 0; i < disclosed.Length; i++)
                            {
                                Assert.IsTrue(HexToBytes(vectors["A" + disclosed[i]]).SequenceEqual(proof.DisclosedAttributes[i]), "A" + disclosed[i]);
                            }
                            Assert.AreEqual(proof.R[0], Zq.GetElement(HexToBytes(vectors["r0"])), "r0");
                            for (int i = 0; i < undisclosed.Length; i++)
                            {
                                Assert.AreEqual(proof.R[i + 1], Zq.GetElement(HexToBytes(vectors["r" + undisclosed[i]])), "r" + undisclosed[i]);
                            }
                            if (supportDevice)
                            {
                                Assert.AreEqual(proof.R[proof.R.Length - 1], Zq.GetElement(HexToBytes(vectors["rd"])), "rd");
                            }
                            for (int i = 0; i < committed.Length; i++)
                            {
                                Assert.AreEqual(proof.Commitments[i].TildeR, Zq.GetElement(HexToBytes(vectors["tildeR" + committed[i]])), "tildeR" + committed[i]);
                                Assert.IsTrue(cpv.TildeO.Length == committed.Length);
                                Assert.AreEqual(cpv.TildeO[i], Zq.GetElement(HexToBytes(vectors["tildeO" + committed[i]])), "tildeO" + committed[i]);
                            }
                            VerifierPresentationProtocolParameters vppp = new VerifierPresentationProtocolParameters(ip, disclosed, m, upkt[0].Token);
                            vppp.Committed = committed;
                            vppp.PseudonymAttributeIndex = p;
                            vppp.PseudonymScope = s;
                            vppp.DeviceMessage = md;
                            proof.Verify(vppp);
#if TEST_ID_ESCROW
                            if (committed.Length > 0)
                            {
                                IDEscrowParams escrowParams = new IDEscrowParams(ip);
                                IDEscrowPrivateKey escrowPrivateKey = new IDEscrowPrivateKey(Zq.GetElement(HexToBytes(vectors["ie_x"])));
                                IDEscrowPublicKey escrowPublicKey = new IDEscrowPublicKey(escrowParams, escrowPrivateKey);
                                Assert.AreEqual(escrowPublicKey.H, CreateGroupElement(ip.Gq, vectors["ie_H"]), "ie_H");
                                byte[] additionalInfo = HexToBytes(vectors["ie_additionalInfo"]);
                                int ie_bIndex = int.Parse(vectors["ie_b"]);

                                IDEscrowCiphertext ctext = IDEscrowFunctions.VerifiableEncrypt(
                                    escrowParams,
                                    escrowPublicKey,
                                    HexToBytes(vectors["UIDt"]),
                                    proof.Commitments[0].TildeC,
                                    ProtocolHelper.ComputeXi(ip, ie_bIndex - 1, A[ie_bIndex - 1]),
                                    cpv.TildeO[0],
                                    additionalInfo,
                                    new IDEscrowFunctions.IDEscrowProofGenerationRandomData(
                                        Zq.GetElement(HexToBytes(vectors["ie_r"])),
                                        Zq.GetElement(HexToBytes(vectors["ie_xbPrime"])),
                                        Zq.GetElement(HexToBytes(vectors["ie_rPrime"])),
                                        Zq.GetElement(HexToBytes(vectors["ie_obPrime"]))));
                                Assert.IsTrue(IDEscrowFunctions.UProveVerify(escrowParams, ctext, proof, upkt[0].Token, escrowPublicKey));
                                Assert.AreEqual(ctext.E1, CreateGroupElement(ip.Gq, vectors["ie_E1"]), "ie_E1");
                                Assert.AreEqual(ctext.E2, CreateGroupElement(ip.Gq, vectors["ie_E2"]), "ie_E2");
                                Assert.AreEqual(ctext.proof.c, Zq.GetElement(HexToBytes(vectors["ie_c"])), "ie_c");
                                Assert.AreEqual(ctext.proof.rR, Zq.GetElement(HexToBytes(vectors["ie_rr"])), "ie_rr");
                                Assert.AreEqual(ctext.proof.rXb, Zq.GetElement(HexToBytes(vectors["ie_rxb"])), "ie_rxb");
                                Assert.AreEqual(ctext.proof.rOb, Zq.GetElement(HexToBytes(vectors["ie_rob"])), "ie_rob");
                                GroupElement PE = IDEscrowFunctions.Decrypt(escrowParams, ctext, escrowPrivateKey);
                            }
#endif

#if TEST_DVA_REVOCATION
                            if (committed.Length > 0)
                            {
                                RAParameters raParams = new RAParameters(ip.Gq.GroupName, CreateGroupElement(ip.Gq, vectors["r_K"]), ip.UidH);
                                FieldZqElement delta = Zq.GetElement(HexToBytes(vectors["r_delta"]));
                                RevocationAuthority RA = new RevocationAuthority(raParams, delta);
                                HashSet<FieldZqElement> revoked = new HashSet<FieldZqElement>();
                                for (int i = 1; i <= 4; i++)
                                {
                                    revoked.Add(Zq.GetElement(HexToBytes(vectors["r_R" + i])));
                                }
                                RA.UpdateAccumulator(revoked, null);
                                Assert.AreEqual(RA.Accumulator, CreateGroupElement(ip.Gq, vectors["r_V"]), "r_V");
                                int r_id = 0;
                                int.TryParse(vectors["r_id"], out r_id);
                                RevocationWitness witness = RA.ComputeRevocationWitness(revoked, Zq.GetElement(HexToBytes(vectors["x" + r_id])));
                                Assert.AreEqual(witness.d, Zq.GetElement(HexToBytes(vectors["r_d"])), "r_d");
                                Assert.AreEqual(witness.W, CreateGroupElement(ip.Gq, vectors["r_W"]), "r_W");
                                Assert.AreEqual(witness.Q, CreateGroupElement(ip.Gq, vectors["r_Q"]), "r_Q");

                                NonRevocationProof nrProof = RevocationUser.GenerateNonRevocationProof(
                                    raParams, 
                                    witness, 
                                    proof.Commitments[0].TildeC, ProtocolHelper.ComputeXi(ip, r_id - 1, A[r_id - 1]),
                                    cpv.TildeO[0],
                                    new NonRevocationProofGenerationRandomData(new FieldZqElement[] {
                                        Zq.GetElement(HexToBytes(vectors["r_t1"])),
                                        Zq.GetElement(HexToBytes(vectors["r_t2"])),
                                        Zq.GetElement(HexToBytes(vectors["r_k1"])),
                                        Zq.GetElement(HexToBytes(vectors["r_k2"])),
                                        Zq.GetElement(HexToBytes(vectors["r_k3"])),
                                        Zq.GetElement(HexToBytes(vectors["r_k4"])),
                                        Zq.GetElement(HexToBytes(vectors["r_k5"])),
                                        Zq.GetElement(HexToBytes(vectors["r_k6"]))
                                    }));
                                Assert.AreEqual(nrProof.X, CreateGroupElement(ip.Gq, vectors["r_X"]), "r_X");
                                Assert.AreEqual(nrProof.Y, CreateGroupElement(ip.Gq, vectors["r_Y"]), "r_Y");
                                Assert.AreEqual(nrProof.Cd, CreateGroupElement(ip.Gq, vectors["r_Cd"]), "r_Cd");
                                Assert.AreEqual(nrProof.cPrime, Zq.GetElement(HexToBytes(vectors["r_cPrime"])), "r_cPrime");
                                Assert.AreEqual(nrProof.s[0], Zq.GetElement(HexToBytes(vectors["r_s1"])), "r_s1");
                                Assert.AreEqual(nrProof.s[1], Zq.GetElement(HexToBytes(vectors["r_s2"])), "r_s2");
                                Assert.AreEqual(nrProof.s[2], Zq.GetElement(HexToBytes(vectors["r_s3"])), "r_s3");
                                Assert.AreEqual(nrProof.s[3], Zq.GetElement(HexToBytes(vectors["r_s4"])), "r_s4");
                                Assert.AreEqual(nrProof.s[4], Zq.GetElement(HexToBytes(vectors["r_s5"])), "r_s5");
                                Assert.AreEqual(nrProof.s[5], Zq.GetElement(HexToBytes(vectors["r_s6"])), "r_s6");

                                // validate proof
                                RA.VerifyNonRevocationProof(ip, 0, proof, nrProof);
                            }
#endif

#if TEST_SET_MEMBERSHIP
                            if (committed.Length > 0)
                            {
                                int sm_x_index = 0;
                                int.TryParse(vectors["sm_x_index"], out sm_x_index);
                                int sm_n = 0;
                                int.TryParse(vectors["sm_n"], out sm_n);
                                int sm_i = 0;
                                int.TryParse(vectors["sm_i"], out sm_i);
                                byte[][] setValues = new byte[sm_n][];
                                FieldZqElement[] sm_c = new FieldZqElement[sm_n - 1];
                                FieldZqElement[] sm_r = new FieldZqElement[sm_n - 1];
                                int randomIndex = 0;
                                for (int i = 1; i <= sm_n; i++)
                                {
                                    if (i == sm_i) {
                                        setValues[i - 1] = HexToBytes(vectors["A" + sm_x_index]);
                                    } else {
                                        setValues[i - 1] = HexToBytes(vectors["sm_s" + i]);
                                        sm_c[randomIndex] = Zq.GetElement(HexToBytes(vectors["sm_c" + i]));
                                        sm_r[randomIndex] = Zq.GetElement(HexToBytes(vectors["sm_r" + i]));
                                        randomIndex++;
                                    }
                                }
                                SetMembershipProofGenerationRandomData smRandom = new SetMembershipProofGenerationRandomData(sm_c, sm_r, Zq.GetElement(HexToBytes(vectors["sm_w"])));
                                SetMembershipProof setMembershipProof = SetMembershipProof.Generate(pppp, proof, cpv, sm_x_index, setValues, smRandom);
                                for (int i = 1; i <= sm_n; i++)
                                {
                                    Assert.AreEqual(setMembershipProof.a[i - 1], CreateGroupElement(ip.Gq, vectors["sm_a" + i]), "sm_a" + i);
                                    if (i < sm_n) // no c_n in the proof
                                    {
                                        Assert.AreEqual(setMembershipProof.c[i - 1], Zq.GetElement(HexToBytes(vectors["sm_c" + i])), "sm_c" + i);
                                    }
                                    Assert.AreEqual(setMembershipProof.r[i - 1], Zq.GetElement(HexToBytes(vectors["sm_r" + i])), "sm_r" + i);
                                }

                                if (!SetMembershipProof.Verify(vppp, proof, setMembershipProof, sm_x_index, setValues))
                                {
                                    throw new InvalidUProveArtifactException("Invalid set membership proof");
                                }

                            }
#endif
                        }
                    }
                }
            }
            sw.Stop();
            Debug.WriteLine("Protocol Test Elapsed Time: " + sw.ElapsedMilliseconds + "ms");
        }
    }
}
