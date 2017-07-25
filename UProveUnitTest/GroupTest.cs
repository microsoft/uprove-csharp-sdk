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
using UProveCrypto;
using UProveCrypto.Math;

namespace UProveUnitTest
{
    /// <summary>
    ///This is a test class for GroupTest and is intended
    ///to contain all GroupTest Unit Tests
    ///</summary>
    [TestClass()]
    public class GroupTest
    {


        // Valid subgroup description
        private Group _smallGroup = SubgroupGroup.CreateSubgroupGroup(
                StaticTestHelpers.IntToBigEndianBytes(11), // p
                StaticTestHelpers.IntToBigEndianBytes(5), // q
                StaticTestHelpers.IntToBigEndianBytes(3), // g
                null,
                null);

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

        #region Additional test attributes
        // 
        //You can use the following additional attributes as you write your tests:
        //
        //Use ClassInitialize to run code before running the first test in the class
        //[ClassInitialize()]
        //public static void MyClassInitialize(TestContext testContext)
        //{
        //}
        //
        //Use ClassCleanup to run code after all tests in a class have run
        //[ClassCleanup()]
        //public static void MyClassCleanup()
        //{
        //}
        //
        //Use TestInitialize to run code before running each test
        //[TestInitialize()]
        //public void MyTestInitialize()
        //{
        //}
        //
        //Use TestCleanup to run code after each test has run
        //[TestCleanup()]
        //public void MyTestCleanup()
        //{
        //}
        //
        #endregion

        /// <summary>
        ///A test for VerifyGroup
        ///</summary>
        [TestMethod()]
        public void VerifySubgroupGroupTest()
        {
            SubgroupGroup Gq = SubgroupGroup.CreateSubgroupGroup(
                StaticTestHelpers.IntToBigEndianBytes(2), // p
                StaticTestHelpers.IntToBigEndianBytes(2), // q
                StaticTestHelpers.IntToBigEndianBytes(0), // g
                null,
                null);
            try { Gq.Verify(); Assert.Fail(); }
            catch (InvalidUProveArtifactException) { }

            Gq = SubgroupGroup.CreateSubgroupGroup(
                            StaticTestHelpers.IntToBigEndianBytes(6), // p not prime
                            StaticTestHelpers.IntToBigEndianBytes(2), // q
                            StaticTestHelpers.IntToBigEndianBytes(0), // g
                            null,
                            null);
            try { Gq.Verify(); Assert.Fail(); }
            catch (InvalidUProveArtifactException) { }

            Gq = SubgroupGroup.CreateSubgroupGroup(
                            StaticTestHelpers.IntToBigEndianBytes(7), // p
                            StaticTestHelpers.IntToBigEndianBytes(2), // q
                            StaticTestHelpers.IntToBigEndianBytes(0), // g
                            null,
                            null);
            try { Gq.Verify(); Assert.Fail(); }
            catch (InvalidUProveArtifactException) { }

            Gq = SubgroupGroup.CreateSubgroupGroup(
                            StaticTestHelpers.IntToBigEndianBytes(7), // p
                            StaticTestHelpers.IntToBigEndianBytes(4), // q not prime
                            StaticTestHelpers.IntToBigEndianBytes(0), // g
                            null,
                            null);
            try { Gq.Verify(); Assert.Fail(); }
            catch (InvalidUProveArtifactException) { }

            Gq = SubgroupGroup.CreateSubgroupGroup(
                            StaticTestHelpers.IntToBigEndianBytes(7), // p
                            StaticTestHelpers.IntToBigEndianBytes(5), // q doesnt divide p - 1
                            StaticTestHelpers.IntToBigEndianBytes(0), // g
                            null,
                            null);
            try { Gq.Verify(); Assert.Fail(); }
            catch (InvalidUProveArtifactException) { }

            Gq = SubgroupGroup.CreateSubgroupGroup(
                            StaticTestHelpers.IntToBigEndianBytes(7), // p
                            StaticTestHelpers.IntToBigEndianBytes(3), // q
                            StaticTestHelpers.IntToBigEndianBytes(0), // g
                            null,
                            null);
            try { Gq.Verify(); Assert.Fail(); }
            catch (InvalidUProveArtifactException) { }

            Gq = SubgroupGroup.CreateSubgroupGroup(
                            StaticTestHelpers.IntToBigEndianBytes(7), // p
                            StaticTestHelpers.IntToBigEndianBytes(3), // q
                            StaticTestHelpers.IntToBigEndianBytes(1), // g invalid value
                            null,
                            null);
            try { Gq.Verify(); Assert.Fail(); }
            catch (InvalidUProveArtifactException) { }

            Gq = SubgroupGroup.CreateSubgroupGroup(
                StaticTestHelpers.IntToBigEndianBytes(7), // p
                StaticTestHelpers.IntToBigEndianBytes(3), // q
                StaticTestHelpers.IntToBigEndianBytes(5), // g^q mod p != 1
                null,
                null);
            try { Gq.Verify(); Assert.Fail(); }
            catch (InvalidUProveArtifactException) { }

            // Valid subgroup description
            Gq = SubgroupGroup.CreateSubgroupGroup(
                StaticTestHelpers.IntToBigEndianBytes(7), // p
                StaticTestHelpers.IntToBigEndianBytes(3), // q
                StaticTestHelpers.IntToBigEndianBytes(2), // g
                null,
                null);
            Gq.Verify();
        }

        /// <summary>
        ///A test for multi-exponentiation.
        ///</summary>
        [TestMethod()]
        public void MultiExponentiateTest()
        {
            // make sure test works with both subgroup and ECC
            string[] groupOIDs = {SubgroupParameterSets.ParamSet_SG_2048256_V1Name, ECParameterSets.ParamSet_EC_P256_V1Name};
            foreach (string groupOID in groupOIDs) {
                ParameterSet set;
                ParameterSet.TryGetNamedParameterSet(groupOID, out set);

                Group Gq = set.Group;
                FieldZq Zq = FieldZq.CreateFieldZq(Gq.Q);
                int length = 10;
                GroupElement[] bases = new GroupElement[length];
                System.Array.Copy(set.G, bases, length);
                FieldZqElement[] exponents = Zq.GetRandomElements(length, false);

                GroupElement value = Gq.Identity;
                for (int i = 0; i < length; i++)
                {
                    value = value * bases[i].Exponentiate(exponents[i]);
                }

                Assert.AreEqual(value, Gq.MultiExponentiate(bases, exponents));
            }
        }

        /// <summary>
        /// A test method for property fieldZq.
        /// </summary>
        [TestMethod]
        public void FieldZqTest()
        {
            Group group = SubgroupParameterSets.ParamSetL2048N256V1.Group;
            FieldZq field1 = group.FieldZq;
            FieldZq field2 = group.FieldZq;
            Assert.ReferenceEquals(field1, field2);
        }

        /// <summary>
        /// Tests Group.GetRandomElements()
        /// </summary>
        [TestMethod]
        public void GetRandomGroupElementsTest()
        {
            // make sure that setting nonIndentity=true results in no no zero elements.
            GroupElement [] nonIdentityElements = _smallGroup.GetRandomElements(30, true);
            for (int i = 0; i < nonIdentityElements.Length; ++i)
            {
                Assert.AreNotEqual(_smallGroup.Identity, nonIdentityElements[i], "identity");
           }

            // check that setting nonIndentity=false results in at least one identity element
            bool foundIdentity = false;
            GroupElement [] identityElements = _smallGroup.GetRandomElements(50, false);
            for (int i = 0; i < 50; ++i)
            {
                if (identityElements[i] == _smallGroup.Identity)
                {
                    foundIdentity = true;
                    break;
                }
            }
            if (!foundIdentity)
            {
                Assert.Inconclusive("GetRandomElements did not create a single identity value.  Try running this test again. Chances of failure on correct behavior is 0.0000000002.");
            }

            // check that setting maxBitLength=-1 results in at least one element 2, 3, or 4
            bool foundLargeElement = false;
                GroupElement [] fullScopeElements = _smallGroup.GetRandomElements(100, false, -1);
            for (int i = 0; i < fullScopeElements.Length; ++i)
            {
                if ((fullScopeElements[i] != _smallGroup.Identity) || (fullScopeElements[i] != _smallGroup.G))
                {
                    foundLargeElement = true;
                    break;
                }
            }
            if (!foundLargeElement)
            {
                Assert.Inconclusive("GetRandomElements did not create a single value in the set {g^2,g^3,g^4}.  Try running this test again. Chances of failure on correct behavior is 2.6 x 10^-40.");
            }
        }


        /// <summary>
        /// Tests Group.GetRandomElements()
        /// </summary>
        [TestMethod]
        public void GetRandomGroupElementTest()
        {
            // make sure that setting nonIndentity=true results in no no zero elements.
            for (int i = 0; i < 30; ++i)
            {
                GroupElement  nonIdentityElement = _smallGroup.GetRandomElement(true);
                Assert.AreNotEqual(_smallGroup.Identity, nonIdentityElement, "identity");
           }

            // check that setting nonIndentity=false results in at least one identity element
            bool foundIdentity = false;
            for (int i = 0; i < 50; ++i)
            {
                GroupElement identityElement = _smallGroup.GetRandomElement(false);
                if (identityElement == _smallGroup.Identity)
                {
                    foundIdentity = true;
                    break;
                }
            }
            if (!foundIdentity)
            {
                Assert.Inconclusive("GetRandomElement did not create a single identity value.  Try running this test again. Chances of failure on correct behavior is 0.0000000002.");
            }

            // check that setting maxBitLength=-1 results in at least one element 2, 3, or 4
            bool foundLargeElement = false;
            for (int i = 0; i < 100; ++i)
            {
                GroupElement fullScopeElement = _smallGroup.GetRandomElement(false, -1);
                if ((fullScopeElement != _smallGroup.Identity) || (fullScopeElement != _smallGroup.G))
                {
                    foundLargeElement = true;
                    break;
                }
            }
            if (!foundLargeElement)
            {
                Assert.Inconclusive("GetRandomElements did not create a single value in the set {g^2,g^3,g^4}.  Try running this test again. Chances of failure on correct behavior is 2.6 x 10^-40.");
            }
        }

/* TODO: enable test when maxBitLenght works
        /// <summary>
        /// Tests everything related to maxbitlength
        /// </summary>
        [TestMethod]
        public void GetRandomGroupElementsMaxBitLengthTest()
        {
            Group group = ECParameterSets.ParamSet_EC_P256_V1.Group;

            // make sure that random elements are at most one bit long (e.g. g^0 or g^1);
            GroupElement [] smallBit = group.GetRandomElements(50, false, 1);
            for (int i = 0; i < smallBit.Length; ++i)
            {
                if ((smallBit[i] != group.Identity) && (smallBit[i] != group.G))
                {
                    Assert.Fail("smallBit contains an element that is not a 0 or 1.");
                }
            }

            for (int i = 0; i < 100; ++i)
            {
                GroupElement small = group.GetRandomElement(false, 1);
                Assert.IsTrue(small == group.Identity || small == group.G);
            }
        }
*/
        /// <summary>
        /// Tests Group.Invert
        /// </summary>
        [TestMethod]
        public void GroupInvertTest()
        {
            FieldZqElement one = _smallGroup.FieldZq.One;
            FieldZqElement two = _smallGroup.FieldZq.GetElement(2);
            FieldZqElement three = _smallGroup.FieldZq.GetElement(3);
            FieldZqElement four = _smallGroup.FieldZq.GetElement(4);

            Assert.AreEqual(_smallGroup.Identity, _smallGroup.Invert(_smallGroup.Identity), "G^0.Invert = 1");
            Assert.AreEqual<GroupElement>(_smallGroup.G.Exponentiate(four), _smallGroup.Invert(_smallGroup.G), "G^1");
            Assert.AreEqual<GroupElement>(_smallGroup.G.Exponentiate(three), _smallGroup.Invert(_smallGroup.G.Exponentiate(two)), "G^2");
            Assert.AreEqual<GroupElement>(_smallGroup.G.Exponentiate(two), _smallGroup.Invert(_smallGroup.G.Exponentiate(three)), "G^3");
            Assert.AreEqual<GroupElement>(_smallGroup.G.Exponentiate(one), _smallGroup.Invert(_smallGroup.G.Exponentiate(four)), "G^1");
        }

        /// <summary>
        /// Tests Group.Divide
        /// </summary>
        [TestMethod]
        public void GroupDivideTest()
        {
            Group group = ECParameterSets.ParamSet_EC_P384_V1.Group;
            for (int i = 0; i < 10; ++i)
            {
                GroupElement a = group.GetRandomElement(false);
                GroupElement b = group.GetRandomElement(true);
                GroupElement c = group.Divide(a, b);
                Assert.AreEqual<GroupElement>(a * group.Invert(b), c, "a.divide(b).");
            }

            for (int i = 0; i < 20; ++i)
            {
                FieldZqElement a = group.FieldZq.GetRandomElement(true);
                FieldZqElement b = group.FieldZq.GetRandomElement(true);
                Assert.AreEqual(group.G.Exponentiate(a - b), group.Divide(group.G.Exponentiate(a), group.G.Exponentiate(b)));
            }

            FieldZqElement one = _smallGroup.FieldZq.One;
            FieldZqElement two = _smallGroup.FieldZq.GetElement(2);
            FieldZqElement three = _smallGroup.FieldZq.GetElement(3);
            FieldZqElement four = _smallGroup.FieldZq.GetElement(4);
            GroupElement G = _smallGroup.G;

            Assert.AreEqual<GroupElement>(_smallGroup.Invert(G), _smallGroup.Divide(G.Exponentiate(two),G.Exponentiate(three)), "G^2/G^3");
            Assert.AreEqual<GroupElement>(G.Exponentiate(two), _smallGroup.Divide(G.Exponentiate(one), G.Exponentiate(four)), "G^1/G^4");
            Assert.AreEqual<GroupElement>(G.Exponentiate(three), _smallGroup.Divide(G.Exponentiate(one), G.Exponentiate(three)), "G^1/G^3");
        }

        [TestMethod]
        public void GroupDivideArraysTest()
        {
            Group group = ECParameterSets.ParamSet_EC_P521_V1.Group;
            for (int i = 0; i < 10; ++i)
            {
                GroupElement[] numerators = group.GetRandomElements(10, false);
                GroupElement[] denominators = group.GetRandomElements(20, false);
                GroupElement expectedQuotient = group.Identity;
                for (int j = 0; j < numerators.Length; ++j)
                {
                    expectedQuotient *= numerators[j];
                }
                for (int j = 0; j < denominators.Length; ++j)
                {
                    expectedQuotient *= group.Invert(denominators[j]);
                }

                Assert.AreEqual(expectedQuotient, group.Divide(numerators, denominators));
            }
        }

    }
}
