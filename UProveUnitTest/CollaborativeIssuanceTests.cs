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
using System.Linq;
using UProveCrypto;
using UProveCrypto.Math;

// ignore warnings for obsolete methods
#pragma warning disable 0618

namespace UProveUnitTest
{
    public class PreIssuanceData
    {
        public GroupElement Gamma { get; set; }
        public FieldZqElement Beta0 { get; set; }
    }
    
    /// <summary>
    /// Unit tests for the collaborative issuance feature
    ///</summary>
    [TestClass()]
    public class CollaborativeIssuanceTests
    {

        private TestContext testContextInstance;

        /// <summary>
        ///Gets or sets the test context which provides
        ///information about and functionality for the current test run.
        ///</summary>
        public TestContext TestContext
        {
            get
            {
                return testContextInstance;
            }
            set
            {
                testContextInstance = value;
            }
        }

        static IssuerKeyAndParameters sourceIkap, ikap;
        static IssuerParameters sourceIp, ip;

        #region Additional test attributes
        // Use ClassInitialize to run code before running the first test in the class
        [ClassInitialize()]
        public static void MyClassInitialize(TestContext testContext)
        {
            // initialize source params
            IssuerSetupParameters sourceIsp = new IssuerSetupParameters();
            sourceIsp.UidP = encoding.GetBytes("source issuer UID");
            sourceIsp.UseRecommendedParameterSet = true;
            sourceIsp.NumberOfAttributes = 2;
            sourceIsp.S = encoding.GetBytes("source spec");
            sourceIkap = sourceIsp.Generate();
            sourceIp = sourceIkap.IssuerParameters;
            
            // initialize collab issuer params
            IssuerSetupParameters isp = new IssuerSetupParameters();
            isp.UidP = encoding.GetBytes("collab issuer UID");
            isp.UseRecommendedParameterSet = true;
            isp.NumberOfAttributes = 3;
            isp.S = encoding.GetBytes("collab spec");
            ikap = isp.Generate();
            ip = ikap.IssuerParameters;
        }

        // Use ClassCleanup to run code after all tests in a class have run
        // [ClassCleanup()]
        // public static void MyClassCleanup() { }
        //
        // Use TestInitialize to run code before running each test 
        //[TestInitialize()]
        //public void MyTestInitialize() { }
        //
        // Use TestCleanup to run code after each test has run
        // [TestCleanup()]
        // public void MyTestCleanup() { }
        //
        #endregion

        private static System.Text.UTF8Encoding encoding = new System.Text.UTF8Encoding();

        // If true, we serialize/deserialize the collaborative issuance PreIssuanceProofs
        private static bool TEST_SERIALIZATION = true;

        PreIssuanceData PreIssuance(ProverPreIssuanceParameters ppip, IssuerPreIssuanceParameters ipip)
        {
            byte[] message = encoding.GetBytes("Optional Message");
            UProveCrypto.Math.FieldZqElement beta0;

            ppip.Validate();
            PreIssuanceProof proof = PreIssuanceProof.CreateProof(ppip, out beta0, message);

            if (TEST_SERIALIZATION)
            {
                string _proof = ip.Serialize<PreIssuanceProof>(proof);
                proof = ip.Deserialize<PreIssuanceProof>(_proof);
            }
            GroupElement gamma = null;
            try
            {
                gamma = PreIssuanceProof.VerifyProof(ipip, proof, message);
            }
            catch (InvalidUProveArtifactException e)
            {
                Assert.Fail("Invalid proof: " + e.Message);
            }

            PreIssuanceData pid = new PreIssuanceData();
            pid.Gamma = gamma;
            pid.Beta0 = beta0;
            return pid;
        }

        UProveKeyAndToken[] IssueSourceToken(byte[][] attributes)
        {
            byte[] tokenInformation = new byte[] { };
            IssuerProtocolParameters ipp = new IssuerProtocolParameters(sourceIkap);
            ipp.Attributes = attributes;
            ipp.TokenInformation = tokenInformation;
            Issuer issuer = ipp.CreateIssuer();
            FirstIssuanceMessage msg1 = issuer.GenerateFirstMessage();
            ProverProtocolParameters ppp = new ProverProtocolParameters(sourceIp);
            ppp.Attributes = attributes;
            ppp.TokenInformation = tokenInformation;
            Prover prover = ppp.CreateProver();
            SecondIssuanceMessage msg2 = prover.GenerateSecondMessage(msg1);
            ThirdIssuanceMessage msg3 = issuer.GenerateThirdMessage(msg2);
            return prover.GenerateTokens(msg3);
        }

        /// <summary>
        /// Unit test with one unknown attribute, all other attributes known 
        /// </summary>
        [TestMethod]
        public void CollaborativeIssuanceNoCarryOver()
        {
            byte[] tokenInformation = new byte[] { };
            ProverPreIssuanceParameters ppip = new ProverPreIssuanceParameters(ip);
            ppip.Attributes = new byte[][] { encoding.GetBytes("New attribute 1"), encoding.GetBytes("Secret attribute 2"), encoding.GetBytes("New attribute 3")};
            ppip.U = new int[] { 2 };
            ppip.K = new int[] { 1, 3 };
            ppip.TI = tokenInformation;

            IssuerPreIssuanceParameters ipip = new IssuerPreIssuanceParameters(ip);
            ipip.Attributes = new byte[][] { encoding.GetBytes("New attribute 1"), null, encoding.GetBytes("New attribute 3") };
            ipip.U = ppip.U;
            ipip.K = ppip.K;
            ipip.TI = tokenInformation;

            PreIssuance(ppip, ipip);
        }

        /// <summary>
        /// Test where there is a carry-over and known attributes, but no unkonwn ones
        /// </summary>
        [TestMethod]
        public void CollaborativeIssuanceNoUnknown()
        {
            // Regular Issuance:  we need a token to use in the collaborative issuance protocol
            byte[][] attributes = new byte[][] { encoding.GetBytes("Attribute 1"), encoding.GetBytes("Attribute 2") };
            UProveKeyAndToken[] upkt = IssueSourceToken(attributes);

            // Collaborative Issuance 
            ProverPreIssuanceParameters ppip = new ProverPreIssuanceParameters(ip);
            ppip.Attributes = new byte[][] { encoding.GetBytes("Attribute 1"), encoding.GetBytes("New attribute 2"), encoding.GetBytes("New attribute 3") };
            ppip.CarryOverAttribute(new int[] { 1 }, new int[] { 1 }, sourceIp, upkt[0], attributes);
            ppip.K = new int[] { 2, 3 };
            IssuerPreIssuanceParameters ipip = new IssuerPreIssuanceParameters(ip);
            ipip.Attributes = new byte[][] { null, encoding.GetBytes("New attribute 2"), encoding.GetBytes("New attribute 3") };
            ipip.CarryOverAttribute(new int[] { 1 }, new int[] { 1 }, sourceIp, upkt[0].Token);
            ipip.K = ppip.K;

            PreIssuance(ppip, ipip);
        }

        /// <summary>
        /// Test where all the attributes are Unknown (no carry-over or known)
        /// </summary>
        [TestMethod]
        public void CollaborativeIssuanceAllUnknown()
        {
            ProverPreIssuanceParameters ppip = new ProverPreIssuanceParameters(ip);
            ppip.Attributes = new byte[][] { encoding.GetBytes("Secret attribute 1"), encoding.GetBytes("Secret attribute 2"), encoding.GetBytes("Secret attribute 3")};
            ppip.U = new int[] { 1, 2, 3 };

            IssuerPreIssuanceParameters ipip = new IssuerPreIssuanceParameters(ip);
            ipip.Attributes = new byte[][] { null, null, null };
            ipip.U = ppip.U;

            PreIssuance(ppip, ipip);
        }

        /// <summary>
        /// Test with a carry-over, and all other attributes unknown
        /// </summary>
        [TestMethod]
        public void CollaborativeIssuanceTestNoKnown()
        {
            // Regular Issuance:  we need a token to use in the collaborative issuance protocol
            byte[][] attributes = new byte[][] { encoding.GetBytes("carried-over attribute"), encoding.GetBytes("Attribute 2") };
            UProveKeyAndToken[] upkt = IssueSourceToken(attributes);

            // Collaborative Issuance 
            ProverPreIssuanceParameters ppip = new ProverPreIssuanceParameters(ip);
            ppip.Attributes = new byte[][] { encoding.GetBytes("New attribute 1"), encoding.GetBytes("carried-over attribute"), encoding.GetBytes("New attribute 3") };
            ppip.CarryOverAttribute(new int[] { 1 }, new int[] { 2 }, sourceIp, upkt[0], attributes);
            ppip.U = new int[] { 1, 3 };
            IssuerPreIssuanceParameters ipip = new IssuerPreIssuanceParameters(ip);
            ipip.Attributes = new byte[][] { null, null, null };
            ipip.CarryOverAttribute(new int[] { 1 }, new int[] { 2 }, sourceIp, upkt[0].Token);
            ipip.U = ppip.U;

            PreIssuance(ppip, ipip);
        }

               /// <summary>
        /// Test carrying-over all attributes
        /// </summary>
        [TestMethod]
        public void CollaborativeIssuanceTestCarryAllOver()
        {
            // Regular Issuance:  we need a token to use in the collaborative issuance protocol
            byte[][] attributes = new byte[][] { encoding.GetBytes("carried-over attribute 1"), encoding.GetBytes("carried-over attribute 2") };
            UProveKeyAndToken[] upkt = IssueSourceToken(attributes);

            // Collaborative Issuance, carrying-over two attributes
            ProverPreIssuanceParameters ppip = new ProverPreIssuanceParameters(ip);
            ppip.Attributes = new byte[][] { encoding.GetBytes("New attribute 1"), encoding.GetBytes("carried-over attribute 2"), encoding.GetBytes("carried-over attribute 1") };
            ppip.CarryOverAttribute(new int[] { 1, 2 }, new int[] { 3, 2 }, sourceIp, upkt[0], attributes);
            ppip.U = new int[] { 1 };
            IssuerPreIssuanceParameters ipip = new IssuerPreIssuanceParameters(ip);
            ipip.Attributes = new byte[][] { null, null, null };
            ipip.CarryOverAttribute(new int[] { 1, 2 }, new int[] { 3, 2 }, sourceIp, upkt[0].Token);
            ipip.U = ppip.U;

            PreIssuance(ppip, ipip);
        }


        /// <summary>
        /// Test with a carry-over, an unknown and the rest known attributes
        /// </summary>
        [TestMethod]
        public void CollaborativeIssuanceTestFull()
        {
            byte[][] attributes = new byte[][] { encoding.GetBytes("A1"), encoding.GetBytes("A2") };
            UProveKeyAndToken[] upkt = IssueSourceToken(attributes);

            // carry over one attribute to various positions
            for (int sourceIndex = 0; sourceIndex < attributes.Length; sourceIndex++)
            {
                for (int destinationIndex = 0; destinationIndex < 3; destinationIndex++)
                {
                    // Collaborative Issuance 
                    // First the Prover creates a PreIssuanceProof
                    int[] sourceIndices = new int[] { sourceIndex + 1 };
                    int[] destinationIndices = new int[] { destinationIndex + 1 };
                    ProverPreIssuanceParameters ppip = new ProverPreIssuanceParameters(ip);
                    ppip.Attributes = new byte[3][];
                    ppip.CarryOverAttribute(sourceIndices, destinationIndices, sourceIp, upkt[0], attributes); 
                    ppip.U = new int[] { ((destinationIndex + 1) % 3) + 1 };
                    ppip.K = new int[] { ((destinationIndex + 2) % 3) + 1 };
                    ppip.Attributes[destinationIndex] = attributes[sourceIndex];
                    ppip.Attributes[ppip.U[0] - 1] = encoding.GetBytes("unknown");
                    ppip.Attributes[ppip.K[0] - 1] = encoding.GetBytes("known");
                    byte[] message = encoding.GetBytes("Optional Message");

                    // The verifier will only have the token, not the keyAndToken 
                    IssuerPreIssuanceParameters ipip = new IssuerPreIssuanceParameters(ip);
                    ipip.Attributes = new byte[3][];
                    ipip.CarryOverAttribute(sourceIndices, destinationIndices, sourceIp, upkt[0].Token);
                    ipip.U = ppip.U;
                    ipip.K = ppip.K;
                    ipip.Attributes[destinationIndex] = null; // carried-over
                    ipip.Attributes[ppip.U[0] - 1] = null;
                    ipip.Attributes[ppip.K[0] - 1] = encoding.GetBytes("known");

                    PreIssuanceData pid = PreIssuance(ppip, ipip); 

                    // Issuance (collaborative, using blindedGamma)
                    IssuerProtocolParameters ipp2 = new IssuerProtocolParameters(ikap);
                    ipp2.Gamma = pid.Gamma;
                    Issuer issuer2 = ipp2.CreateIssuer();
                    FirstIssuanceMessage msg1_2 = issuer2.GenerateFirstMessage();

                    ProverProtocolParameters ppp2 = new ProverProtocolParameters(ip);
                    ppp2.SetBlindedGamma(pid.Gamma, pid.Beta0);
                    Prover prover2 = ppp2.CreateProver();
                    SecondIssuanceMessage msg2_2 = prover2.GenerateSecondMessage(msg1_2);
                    ThirdIssuanceMessage msg3_2 = issuer2.GenerateThirdMessage(msg2_2);
                    UProveKeyAndToken[] upkt_2 = prover2.GenerateTokens(msg3_2);

                    // Create a presentation proof for each token, disclosing everything, to make sure the new token works
                    for (int i = 0; i < upkt_2.Length; i++)
                    {
                        int[] disclosed = { 1, 2, 3 };
                        int[] committed = { };
                        PresentationProof P = PresentationProof.Generate(ip, disclosed, message, null, null, upkt_2[i], ppip.Attributes);
                        P.Verify(ip, disclosed, message, null, upkt_2[i].Token);
                        // verify that carried-over attribute was properly set
                        Assert.IsTrue(P.DisclosedAttributes[destinationIndex].SequenceEqual<byte>(attributes[sourceIndex]));
                        Assert.IsTrue(P.DisclosedAttributes[ppip.U[0] - 1].SequenceEqual<byte>(encoding.GetBytes("unknown")));
                        Assert.IsTrue(P.DisclosedAttributes[ppip.K[0] - 1].SequenceEqual<byte>(encoding.GetBytes("known")));
                    }
                }
            }
        }

        // Test for the CA-RA split case. (a party trusted by the issuer provides the gamma value to the 
        // Issuer, and the attributes to the Prover)
        // TODO: we should probably have a serializable object to store gamma so that it can be sent from the RA to the CA.
        [TestMethod]
        public void CollaborativeIssuanceTrustedGamma()
        {
            // Issuance
            byte[][] attributes = new byte[][] { encoding.GetBytes("Attribute 1"), encoding.GetBytes("Attribute 2"), encoding.GetBytes("Attribute 3") };
            ProverProtocolParameters ppp = new ProverProtocolParameters(ip);
            ppp.Attributes = attributes;
            Prover prover = ppp.CreateProver();

            IssuerProtocolParameters ipp = new IssuerProtocolParameters(ikap);
            ipp.Gamma = ProtocolHelper.ComputeIssuanceInput(ip, attributes, null, null); // computed by some other party. 
            Issuer issuer = ipp.CreateIssuer();

            FirstIssuanceMessage msg1 = issuer.GenerateFirstMessage();
            SecondIssuanceMessage msg2 = prover.GenerateSecondMessage(msg1);
            ThirdIssuanceMessage msg3 = issuer.GenerateThirdMessage(msg2);
            UProveKeyAndToken[] upkt = prover.GenerateTokens(msg3);

            // use the token to make sure everything is ok
            int[] disclosed = new int[0];
            byte[] message = encoding.GetBytes("this is the presentation message, this can be a very long message");
            UProveCrypto.Math.FieldZqElement[] unused;
            byte[] scope = null;
            PresentationProof proof = PresentationProof.Generate(ip, disclosed, null, 1, scope, message, null, null, upkt[0], attributes, out unused);
            proof.Verify(ip, disclosed, null, 1, scope, message, null, upkt[0].Token);
        }


    }// end class
}   // end namespace