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

using Microsoft.VisualStudio.TestTools.UnitTesting;
using System.Collections.Generic;
using System.Diagnostics;
using UProveCrypto;

namespace UProveUnitTest
{
    /// <summary>
    /// Tests the recommended parameters.
    /// </summary>
    [TestClass]
    public class RecommendedParametersTest
    {
        private void RunProtocol(IssuerKeyAndParameters ikap, IssuerParameters ip)
        {
            ip.Verify(); // sanity check

            // Issuance
            int numberOfAttribs = ip.G.Length - 2; // minus g_0 and g_t
            byte[][] attributes = new byte[numberOfAttribs][];
            for (int i = 0; i < numberOfAttribs; i++)
            {
                attributes[i] = new byte[] { (byte)i };
            }
            byte[] tokenInformation = new byte[] { 0x01 };
            byte[] proverInformation = new byte[] { 0x01 };
            int numberOfTokens = 1;

            IssuerProtocolParameters ipp = new IssuerProtocolParameters(ikap);
            ipp.Attributes = attributes;
            ipp.NumberOfTokens = numberOfTokens;
            ipp.TokenInformation = tokenInformation;
            Issuer issuer = ipp.CreateIssuer();
            FirstIssuanceMessage msg1 = issuer.GenerateFirstMessage();
            ProverProtocolParameters ppp = new ProverProtocolParameters(ip);
            ppp.NumberOfTokens = numberOfTokens;
            ppp.Attributes = attributes;
            ppp.TokenInformation = tokenInformation;
            ppp.ProverInformation = proverInformation;
            Prover prover = ppp.CreateProver();
            SecondIssuanceMessage msg2 = prover.GenerateSecondMessage(msg1);
            ThirdIssuanceMessage msg3 = issuer.GenerateThirdMessage(msg2);
            // issue token
            UProveKeyAndToken[] upkt = prover.GenerateTokens(msg3);

            // Presentation
            int[] disclosed = new int[] { 1 };
            byte[] message = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8, 9 };

            // generate the presentation proof
            PresentationProof proof = PresentationProof.Generate(new ProverPresentationProtocolParameters(ip, disclosed, message, upkt[0], attributes));

            // verify the presentation proof
            proof.Verify(new VerifierPresentationProtocolParameters(ip, disclosed, message, upkt[0].Token));
        }


        /// <summary>
        /// Test the recommended parameters.
        /// </summary>
        [TestMethod]
        public void TestRecommendedParameters()
        {
            ParameterSet set;
            const string ECCNamePrefix = "U-Prove Recommended Parameters Profile";
            var encoder = System.Text.UnicodeEncoding.UTF8;
            Dictionary<string, byte[]> oidContextDictionary = new Dictionary<string, byte[]>();
            // Elliptic Curve (OID, ECC Prefix + curve name)
            oidContextDictionary.Add("1.3.6.1.4.1.311.75.1.2.1", encoder.GetBytes(ECCNamePrefix + "P-256"));  // NIST P-256
            oidContextDictionary.Add("1.3.6.1.4.1.311.75.1.2.2", encoder.GetBytes(ECCNamePrefix + "P-384"));  // NIST P-384
            oidContextDictionary.Add("1.3.6.1.4.1.311.75.1.2.3", encoder.GetBytes(ECCNamePrefix + "P-521"));  // NIST P-521
            oidContextDictionary.Add("1.3.6.1.4.1.311.75.1.3.1", encoder.GetBytes(ECCNamePrefix + "BN254"));  // BN

            foreach (string oid in oidContextDictionary.Keys)
            {
                ParameterSet.TryGetNamedParameterSet(oid, out set);
                Assert.AreEqual<string>(oid, set.Name);
                Assert.AreEqual<int>(ParameterSet.NumberOfIssuerGenerators + 1, set.G.Length); // g_t is also in the list
                Group Gq = set.Group;
                Gq.Verify();
                int counter;
                byte[] context = oidContextDictionary[oid];

                // tests gi
                for (int i = 1; i < set.G.Length; i++ )
                {
                    GroupElement gi = set.G[i - 1];
                    Gq.ValidateGroupElement(gi);
                    GroupElement derived = Gq.DeriveElement(context, (byte)i, out counter);
                    Gq.ValidateGroupElement(derived);
                    if (!gi.Equals(derived))
                    {
                        Debugger.Break();
                    }

                    Assert.AreEqual<GroupElement>(gi, derived);
                }
                // gt uses index = 255
                Assert.AreEqual<GroupElement>(set.G[set.G.Length - 1], Gq.DeriveElement(context, (byte)255, out counter));
                Gq.ValidateGroupElement(set.Gd);

                // gd uses index = 254
                Assert.AreEqual<GroupElement>(set.Gd, Gq.DeriveElement(context, (byte)254, out counter));
                Gq.ValidateGroupElement(set.Gd);

                // Issuer setup
                IssuerSetupParameters isp = new IssuerSetupParameters();
                isp.UidP = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8, 9 };
                if (oid == "1.3.6.1.4.1.311.75.1.2.3") // P-521
                {
                    isp.UidH = "SHA-512";
                }
                isp.E = new byte[ParameterSet.NumberOfIssuerGenerators];
                isp.ParameterSet = set;
                for (int i = 0; i < ParameterSet.NumberOfIssuerGenerators; i++)
                {
                    isp.E[i] = (byte)0;
                }
                isp.S = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8, 9 };
                IssuerKeyAndParameters ikap = isp.Generate();
                IssuerParameters ip = ikap.IssuerParameters;

                RunProtocol(ikap, ip);
            }
        }

        /// <summary>
        /// Test the non-recommeded generators.
        /// </summary>
        [TestMethod]
        public void FreshParametersTest()
        {
            //
            // test with 1 attribute
            //

            // Issuer setup
            IssuerSetupParameters isp = new IssuerSetupParameters();
            isp.UidP = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8, 9 };
            isp.NumberOfAttributes = 1;
            isp.UseRecommendedParameterSet = false; // use freshly generated generators
            isp.GroupConstruction = GroupType.ECC;
            IssuerKeyAndParameters ikap = isp.Generate();
            IssuerParameters ip = ikap.IssuerParameters;

            // get the default ECC group to make sure that is _not_ what we are generating
            ParameterSet set;
            ParameterSet.TryGetNamedParameterSet("1.3.6.1.4.1.311.75.1.2.1", out set);
            Assert.AreNotEqual(ip.G[1], set.G[0]); // set's index 0 is g_1

            RunProtocol(ikap, ip);

            //
            // test with max+1 attributes
            //

            isp.NumberOfAttributes = IssuerSetupParameters.RecommendedParametersMaxNumberOfAttributes + 1;
            ikap = isp.Generate();
            ip = ikap.IssuerParameters;
            Assert.IsTrue(ip.E.Length == IssuerSetupParameters.RecommendedParametersMaxNumberOfAttributes + 1);
            RunProtocol(ikap, ip);

            //
            // test invalid number of attributes
            //

            isp.UseRecommendedParameterSet = true;
            try
            {
                ikap = isp.Generate();
                Assert.Fail();
            }
            catch (System.ArgumentException) 
            {
                // expected
            };
        }

        /// <summary>
        /// Test custom group.
        /// </summary>
        [TestMethod]
        public void CustomGroupTest()
        {
            // we reuse an exisiting group, but without setting it by name.
            // we expect new generators to be generated.
            ParameterSet set;
            ParameterSet.TryGetNamedParameterSet(ECParameterSets.ParamSet_EC_P256_V1Name, out set);

            IssuerSetupParameters isp = new IssuerSetupParameters();
            isp.UidP = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8, 9 };
            isp.NumberOfAttributes = 1;
            isp.Gq = set.Group; // reusing an existing group.
            IssuerKeyAndParameters ikap = isp.Generate();
            IssuerParameters ip = ikap.IssuerParameters;

            // new generators should have been generated, to the issuer parameters' g1 and parameter set's g1
            // should be different.
            Assert.AreNotEqual(ip.G[1], set.G[0]); // set's index 0 is g_1
        }
    }
}
