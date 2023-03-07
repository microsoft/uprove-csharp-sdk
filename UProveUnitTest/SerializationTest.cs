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
using System;
using System.Diagnostics;
using System.IO;
using System.Runtime.Serialization;
using System.Runtime.Serialization.Formatters.Binary;
using UProveCrypto;
using UProveCrypto.Math;

// ignore warnings for obsolete methods
#pragma warning disable 0618

namespace UProveUnitTest
{
    [TestClass]
    [DeploymentItem(@"../../../SerializationReference", "SerializationReference")]
    public class SerializationTest
    {
        static bool CREATE_SERIALIZATION_TEST_FILES = false;

        static byte[] HexToBytes(string hexString)
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
                    bytes[i / 2] = Byte.Parse(hexString.Substring(i, 2), System.Globalization.NumberStyles.HexNumber);
                }
                catch (Exception)
                {
                    throw new ArgumentException("hexString is invalid");
                }
            }
            return bytes;
        }



        [TestMethod]
        public void TestSerialization()
        {
            Console.WriteLine("TestSerialization");

            // Create IssuerSetupParameters
            System.Text.UTF8Encoding encoding = new System.Text.UTF8Encoding();

            for (int i = 0; i <= 1; i++)
            {
                bool useCustomGroup = (i == 0);

                IssuerSetupParameters isp = new IssuerSetupParameters();
                isp.GroupConstruction = GroupType.ECC;
                if (useCustomGroup)
                {
                    continue;
                }

                isp.UidP = encoding.GetBytes("http://issuer/uprove/issuerparams/software");
                isp.E = IssuerSetupParameters.GetDefaultEValues(3);
                isp.S = encoding.GetBytes("application-specific specification");

                // Generate IssuerKeyAndParameters
                IssuerKeyAndParameters ikap = isp.Generate();

                // Create an IssuerParameters
                IssuerParameters ip = ikap.IssuerParameters;

                VerifySerialization(useCustomGroup, ip, ikap);
                VerifySerialization(useCustomGroup, ip, ikap.IssuerParameters);

                // specify the attribute values
                byte[][] attributes = new byte[][] {
                encoding.GetBytes("first attribute value"),
                encoding.GetBytes("second attribute value"),
                encoding.GetBytes("third attribute value")   };

                // specify the special field values
                byte[] tokenInformation = encoding.GetBytes("token information value");
                byte[] proverInformation = encoding.GetBytes("prover information value");

                // specify the number of tokens to issue
                int numberOfTokens = 5;

                // setup the issuer and generate the first issuance message
                IssuerProtocolParameters ipp = new IssuerProtocolParameters(ikap);
                ipp.Attributes = attributes;
                ipp.NumberOfTokens = numberOfTokens;
                ipp.TokenInformation = tokenInformation;
                Issuer issuer = ipp.CreateIssuer();
                FirstIssuanceMessage firstMessage = issuer.GenerateFirstMessage();
                VerifySerialization(useCustomGroup, ip, firstMessage);

                // setup the prover and generate the second issuance message
                Prover prover = new Prover(ip, numberOfTokens, attributes, tokenInformation, proverInformation, null);
                SecondIssuanceMessage secondMessage = prover.GenerateSecondMessage(firstMessage);
                VerifySerialization(useCustomGroup, ip, secondMessage);

                // generate the third issuance message
                ThirdIssuanceMessage thirdMessage = issuer.GenerateThirdMessage(secondMessage);
                VerifySerialization(useCustomGroup, ip, thirdMessage);

                // generate the tokens
                UProveKeyAndToken[] upkt = prover.GenerateTokens(thirdMessage);

                for (int k = 0; k < upkt.Length; k++)
                {
                    string json = ip.Serialize(upkt[k]);
                    UProveKeyAndToken upkt_fromJson = ip.Deserialize<UProveKeyAndToken>(json);
                    Assert.IsTrue(Verify(upkt[k], upkt_fromJson));
                }

                VerifySerialization(useCustomGroup, ip, upkt[0].Token);

                /*
                    *  token presentation
                    */
                // the indices of disclosed attributes
                int[] disclosed = new int[] { 2 };
                // the indices of committed attributes
                int[] committed = new int[] { 3 };
                // the returned commitment randomizers, to be used by an external proof module
                FieldZqElement[] tildeO;
                // the application-specific message that the prover will sign. Typically this is a nonce combined
                // with any application-specific transaction data to be signed.
                byte[] message = encoding.GetBytes("message");
                // the application-specific verifier scope from which a scope-exclusive pseudonym will be created
                // (if null, then a pseudonym will not be presented)
                byte[] scope = encoding.GetBytes("verifier scope");
                // generate the presentation proof
                PresentationProof proof = PresentationProof.Generate(ip, disclosed, committed, 1, scope, message, null, null, upkt[0], attributes, out tildeO);
                VerifySerialization(useCustomGroup, ip, proof);

                // verify the presentation proof
                proof.Verify(ip, disclosed, committed, 1, scope, message, null, upkt[0].Token);
            }

        }
        [TestMethod]
        public void TestSerializationReference()
        {
            Console.WriteLine("TestSerializationReference");
            // Create IssuerSetupParameters
            System.Text.UTF8Encoding encoding = new System.Text.UTF8Encoding();
            foreach (string fileName in Directory.GetFiles("SerializationReference"))
            {
                FileStream f = File.OpenRead(fileName);
                BinaryReader br = new BinaryReader(f);

                bool useCustomGroup = (bool)br.ReadBoolean();//  parameters[0];
                // TODO: delete from here ----
                // TODO: current test files contain a group boolean; we don't need that anymore since deprecating
                // the subgroup construction. We need to delete the ones corresponding to the deprecated constructions.
                bool useSubgroupConstruction = (bool)br.ReadBoolean();
                if (useSubgroupConstruction)
                {
                    Console.WriteLine("Delete subgroup test file: " + fileName);
                    continue;
                }
                // TODO: ---- until here
                string typeName = (string)br.ReadString();
                string json = (string)br.ReadString();

                f.Close();

                IssuerSetupParameters isp = new IssuerSetupParameters();
                isp.GroupConstruction = GroupType.ECC;
                if (useCustomGroup)
                {
                    continue;
                }

                isp.UidP = encoding.GetBytes("http://issuer/uprove/issuerparams/software");
                isp.E = IssuerSetupParameters.GetDefaultEValues(3);
                isp.S = encoding.GetBytes("application-specific specification");

                // Generate IssuerKeyAndParameters
                IssuerKeyAndParameters ikap = isp.Generate();

                // Create an IssuerParameters
                IssuerParameters ip = ikap.IssuerParameters;

                // check that we didn't send any null fields
                Assert.IsFalse(json.Contains(":null"));

                string roundTrip = "";
                if (typeName == "UProveCrypto.IssuerParameters")
                {
                    IssuerParameters obj = ip.Deserialize<IssuerParameters>(json);
                    roundTrip = ip.Serialize<IssuerParameters>(obj);
                }
                else if (typeName == "UProveCrypto.IssuerKeyAndParameters")
                {
                    IssuerKeyAndParameters obj = ip.Deserialize<IssuerKeyAndParameters>(json);
                    roundTrip = ip.Serialize<IssuerKeyAndParameters>(obj);
                }
                else if (typeName == "UProveCrypto.FirstIssuanceMessage")
                {
                    FirstIssuanceMessage obj = ip.Deserialize<FirstIssuanceMessage>(json);
                    roundTrip = ip.Serialize<FirstIssuanceMessage>(obj);
                }
                else if (typeName == "UProveCrypto.SecondIssuanceMessage")
                {
                    SecondIssuanceMessage obj = ip.Deserialize<SecondIssuanceMessage>(json);
                    roundTrip = ip.Serialize<SecondIssuanceMessage>(obj);
                }
                else if (typeName == "UProveCrypto.ThirdIssuanceMessage")
                {
                    ThirdIssuanceMessage obj = ip.Deserialize<ThirdIssuanceMessage>(json);
                    roundTrip = ip.Serialize<ThirdIssuanceMessage>(obj);
                }
                else if (typeName == "UProveCrypto.UProveKeyAndToken")
                {
                    UProveKeyAndToken obj = ip.Deserialize<UProveKeyAndToken>(json);
                    roundTrip = ip.Serialize<UProveKeyAndToken>(obj);
                }
                else if (typeName == "UProveCrypto.UProveToken")
                {
                    UProveToken obj = ip.Deserialize<UProveToken>(json);
                    roundTrip = ip.Serialize<UProveToken>(obj);
                }
                else if (typeName == "UProveCrypto.PresentationProof")
                {
                    PresentationProof obj = ip.Deserialize<PresentationProof>(json);
                    roundTrip = ip.Serialize<PresentationProof>(obj);
                }
                else
                {
                    Assert.Fail("Unrecognized type " + typeName + " in SerializationReference files");
                }

                Assert.AreEqual(json, roundTrip);
            }
        }

        public void VerifySerialization<T>(bool useCustomGroup, IssuerParameters ip, T obj) where T : IParametrizedDeserialization
        {
            // serialize the object to json string
            string json = ip.Serialize(obj);

            if (CREATE_SERIALIZATION_TEST_FILES)
                WriteSerializationTestFile(useCustomGroup, json, obj);

            // output the serialization string
            Debug.WriteLine(typeof(T).Name);
            //Debug.WriteLine(FormatJSON(json, ""));

            // check that we didn't send any null fields
            Assert.IsFalse(json.Contains(":null"));

            // deserialize the object into a new object of the same type
            T deserialized_object = ip.Deserialize<T>(json);

            // verify the new object is equal to the original

            if (typeof(T) == typeof(IssuerParameters))
            {
                Assert.IsTrue(Verify(obj as IssuerParameters, deserialized_object));
            }

            if (typeof(T) == typeof(IssuerKeyAndParameters))
            {
                Assert.IsTrue(Verify(obj as IssuerKeyAndParameters, deserialized_object));
            }

            if (typeof(T) == typeof(FirstIssuanceMessage))
            {
                Assert.IsTrue(Verify(obj as FirstIssuanceMessage, deserialized_object));
            }

            if (typeof(T) == typeof(SecondIssuanceMessage))
            {
                Assert.IsTrue(Verify(obj as SecondIssuanceMessage, deserialized_object));
            }

            if (typeof(T) == typeof(ThirdIssuanceMessage))
            {
                Assert.IsTrue(Verify(obj as ThirdIssuanceMessage, deserialized_object));
            }

            if (typeof(T) == typeof(UProveKeyAndToken))
            {
                Assert.IsTrue(Verify(obj as UProveKeyAndToken, deserialized_object));
            }

            if (typeof(T) == typeof(UProveToken))
            {
                Assert.IsTrue(Verify(obj as UProveToken, deserialized_object));
            }

            if (typeof(T) == typeof(PresentationProof))
            {
                Assert.IsTrue(Verify(obj as PresentationProof, deserialized_object));
            }

            // replace the original with the new object
            obj = deserialized_object;

        }

        private void WriteSerializationTestFile<T>(bool useCustomGroup, string json, T obj)
        {
            FileStream fs = File.Open("../../../SerializationReference/" + Path.GetRandomFileName() + ".dat", FileMode.Create);

            BinaryWriter bw = new BinaryWriter(fs);
            bw.Write(useCustomGroup);
            bw.Write(obj.GetType().FullName);
            bw.Write(json);

            fs.Close();
        }

        // check that two objects are of the same type
        public static T GetSameType<T, K>(T object1, K object2) where T : class
        {
            // if one or the other is null return false
            if ((object1 == null) && (object2 != null))
                return null;
            if ((object1 != null) && (object2 == null))
                return null;

            T obj = object2 as T;
            if (obj == null)
                return null;

            return object2 as T;
        }

        public static bool CompareFields<T>(T[] array1, T[] array2)
        {
            if (array1 == null & array2 == null)
                return true;

            if (array1 == null & array2 != null)
                return false;

            if (array1 != null & array2 == null)
                return false;

            // if we're comparing the same object, then we probably messed up somewhere
            if (Object.ReferenceEquals(array1, array2))
                return true;

            if (array1.Length != array2.Length)
                return false;

            for (int i = 0; i < array1.Length; i++)
            {

                if (array1[i].Equals(array2[i]) == false)
                    return false;

            }

            return true;
        }

        public static bool CompareFields<T>(T field1, T field2)
        {
            if (field1 == null & field2 == null)
                return true;

            if (field1 == null & field2 != null)
                return false;

            if (field1 != null & field2 == null)
                return false;

            // if we're comparing the same object, then we probably messed up somewhere
            if (Object.ReferenceEquals(field1, field2))
                return true;

            return field1.Equals(field2);
        }

        public static bool Verify(IssuerParameters ip1, object obj)
        {
            IssuerParameters ip2 = GetSameType(ip1, obj);

            if (ip2 == null)
                return false;

            if (Object.ReferenceEquals(ip1, obj))
                return true;

            if (CompareFields(ip2.UidH, ip1.UidH) == false)
                return false;

            if (CompareFields(ip2.UidP, ip1.UidP) == false)
                return false;

            if (CompareFields(ip2.Gq, ip1.Gq) == false)
                return false;

            if (CompareFields(ip1.S, ip2.S) == false)
                return false;

            if (CompareFields<GroupElement>(ip1.Gd, ip2.Gd) == false)
                return false;

            if (CompareFields(ip1.G, ip2.G) == false)
                return false;

            return true;
        }

        public static bool Verify(IssuerKeyAndParameters ipk1, object obj)
        {
            IssuerKeyAndParameters ipk2 = GetSameType(ipk1, obj);

            if (ipk2 == null)
                return false;

            if (Object.ReferenceEquals(ipk1, ipk2))
                return true;

            if (Verify(ipk1.IssuerParameters, ipk2.IssuerParameters) == false)
                return false;

            if (CompareFields(ipk1.PrivateKey, ipk2.PrivateKey) == false)
                return false;

            return true;
        }

        public static bool Verify(FirstIssuanceMessage fim1, object obj)
        {
            FirstIssuanceMessage fim2 = GetSameType(fim1, obj);

            if (fim2 == null)
                return false;

            if (Object.ReferenceEquals(fim1, fim2))
                return true;

            if (CompareFields(fim1.sigmaA, fim2.sigmaA) == false)
                return false;

            if (CompareFields(fim1.sigmaB, fim2.sigmaB) == false)
                return false;

            if (CompareFields(fim1.sigmaZ, fim2.sigmaZ) == false)
                return false;

            return true;
        }

        public static bool Verify(SecondIssuanceMessage sim1, object obj)
        {
            SecondIssuanceMessage sim2 = GetSameType(sim1, obj);

            if (sim2 == null)
                return false;

            if (Object.ReferenceEquals(sim1, sim2))
                return true;

            if (CompareFields(sim1.sigmaC, sim2.sigmaC) == false)
                return false;

            return true;
        }

        public static bool Verify(ThirdIssuanceMessage tim1, object obj)
        {
            ThirdIssuanceMessage tim2 = GetSameType(tim1, obj);

            if (tim2 == null)
                return false;

            if (Object.ReferenceEquals(tim1, tim2))
                return true;

            if (CompareFields(tim1.sigmaR, tim2.sigmaR) == false)
                return false;

            return true;
        }

        public static bool Verify(UProveKeyAndToken ukat, object obj)
        {
            if (obj == null)
                return false;

            if (Object.ReferenceEquals(obj, ukat))
                return true;

            UProveKeyAndToken upkt_obj = obj as UProveKeyAndToken;
            if (upkt_obj == null)
                return false;

            if (upkt_obj.PrivateKey.Equals(ukat.PrivateKey) == false)
                return false;

            if (Verify(ukat.Token, upkt_obj.Token) == false)
                return false;

            return true;
        }

        public static bool Verify(UProveToken upt1, object obj)
        {
            UProveToken upt2 = GetSameType(upt1, obj);

            if (upt2 == null)
                return false;

            if (Object.ReferenceEquals(upt1, upt2))
                return true;

            if (CompareFields(upt2.Uidp, upt1.Uidp) == false)
                return false;

            if (CompareFields(upt2.H, upt1.H) == false)
                return false;

            if (CompareFields(upt2.TI, upt1.TI) == false)
                return false;

            if (CompareFields(upt2.PI, upt1.PI) == false)
                return false;

            if (CompareFields(upt2.SigmaZPrime, upt1.SigmaZPrime) == false)
                return false;

            if (CompareFields(upt2.SigmaCPrime, upt1.SigmaCPrime) == false)
                return false;

            if (CompareFields(upt2.SigmaRPrime, upt1.SigmaRPrime) == false)
                return false;

            if (upt2.IsDeviceProtected != upt1.IsDeviceProtected)
                return false;

            return true;

        }

        public static bool Verify(PresentationProof pp1, object obj)
        {
            PresentationProof pp2 = GetSameType(pp1, obj);

            if (pp2 == null)
                return false;

            if (Object.ReferenceEquals(pp1, pp2))
                return true;

            if (pp1.DisclosedAttributes.Length != pp2.DisclosedAttributes.Length)
                return false;

            for (int i = 0; i < pp1.DisclosedAttributes.Length; i++)
            {
                if (CompareFields(pp1.DisclosedAttributes[i], pp2.DisclosedAttributes[i]) == false)
                    return false;
            }

            //if (CompareFields(pp1.DisclosedAttributes, pp2.DisclosedAttributes) == false)
            //    return false;

            if (CompareFields(pp2.A, pp1.A) == false)
                return false;

            if (CompareFields(pp2.Ap, pp1.Ap) == false)
                return false;

            if (CompareFields(pp2.Ps, pp1.Ps) == false)
                return false;

            if (CompareFields(pp2.R, pp1.R) == false)
                return false;

            if (CompareFields(pp2.Commitments, pp1.Commitments) == false)
                return false;

            return true;
        }

        public string FormatJSON(string json, string pad)
        {
            int start = json.IndexOf('{');
            if (start < 0)
                return pad + json;

            int end = json.LastIndexOf('}');
            int count = (end - 1) - (start + 1);

            string pre = json.Substring(0, start) + "{" + Environment.NewLine;

            string mid = pad + FormatJSON(json.Substring(start + 1, count), pad + "    ") + Environment.NewLine + pad + "}" + Environment.NewLine; ;

            string post = json.Substring(end + 1, json.Length - (end + 1));

            return pre + mid + post;
        }
    }
}
