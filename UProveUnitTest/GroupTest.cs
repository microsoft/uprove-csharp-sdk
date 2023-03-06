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
        ///A test for multi-exponentiation.
        ///</summary>
        [TestMethod()]
        public void MultiExponentiateTest()
        {
            string[] groupOIDs = {ECParameterSets.ParamSet_EC_P256_V1Name};
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
            Group group = ECParameterSets.ParamSet_EC_P256_V1.Group;
            FieldZq field1 = group.FieldZq;
            FieldZq field2 = group.FieldZq;
            Assert.ReferenceEquals(field1, field2);
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
