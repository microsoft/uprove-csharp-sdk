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
using UProveCrypto;
using UProveCrypto.Math;

namespace UProveUnitTest
{
    /// <summary>
    ///This is a test class for FieldZqTest and is intended
    ///to contain all FieldZqTest Unit Tests
    ///</summary>
    [TestClass()]
    public class FieldZqTest
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
        ///A test for Inverse
        ///</summary>
        [TestMethod()]
        public void InverseTest()
        {
            FieldZq Zq = FieldZq.CreateFieldZq(new byte[] { 0x05 });
            try 
            { 
                FieldZqElement inverse = Zq.Zero.Invert(); 
                Assert.Fail(); 
            } 
            catch (ArgumentOutOfRangeException) 
            { 
            };

            Assert.AreEqual<FieldZqElement>(Zq.One.Invert(), Zq.One);
            Assert.AreEqual<FieldZqElement>(Zq.GetElement(2).Invert(), Zq.GetElement(3));
            Assert.AreEqual<FieldZqElement>(Zq.GetElement(3).Invert(), Zq.GetElement(2));
            Assert.AreEqual<FieldZqElement>(Zq.GetElement(4).Invert(), Zq.GetElement(4));
        }

        /// <summary>
        ///A test for Negate
        ///</summary>
        [TestMethod()]
        public void NegateTest()
        {
            FieldZq Zq = FieldZq.CreateFieldZq(new byte[] { 0x05 });
            Assert.AreEqual<FieldZqElement>(Zq.Zero.Negate(), Zq.Zero);
            Assert.AreEqual<FieldZqElement>(Zq.GetElement(1).Negate(), Zq.GetElement(4));
            Assert.AreEqual<FieldZqElement>(Zq.GetElement(2).Negate(), Zq.GetElement(3));
            Assert.AreEqual<FieldZqElement>(Zq.GetElement(3).Negate(), Zq.GetElement(2));
            Assert.AreEqual<FieldZqElement>(Zq.GetElement(4).Negate(), Zq.GetElement(1));
        }

        /// <summary>
        /// A test for Subtract and operator-
        /// </summary>
        [TestMethod]
        public void SubtractTest()
        {
            FieldZq Zq = FieldZq.CreateFieldZq(new byte[] { 0x05 });
            FieldZqElement two = Zq.GetElement(2);
            FieldZqElement three = Zq.GetElement(3);
            FieldZqElement four = Zq.GetElement(4);

            Assert.AreEqual<FieldZqElement>(four, four - Zq.Zero, "4-0=4");
            Assert.AreEqual<FieldZqElement>(three, four - Zq.One, "4-1=3");
            Assert.AreEqual<FieldZqElement>(two, four - two, "4-2=2");
            Assert.AreEqual<FieldZqElement>(Zq.One, four - three, "4-3=1");
            Assert.AreEqual<FieldZqElement>(Zq.Zero, four - four, "4-4=0");
            Assert.AreEqual<FieldZqElement>(three, two - four, "2-4=3");
            Assert.AreEqual<FieldZqElement>(four, two - three, "2-3=4");

            Assert.AreEqual<FieldZqElement>(two, two.Subtract(Zq.Zero), "2-0=2");
            Assert.AreEqual<FieldZqElement>(Zq.One, two.Subtract(Zq.One), "2-1=1");
            Assert.AreEqual<FieldZqElement>(Zq.Zero, two.Subtract(two), "2-2=0");
            Assert.AreEqual<FieldZqElement>(four, two.Subtract(three), "2-3=4");
            Assert.AreEqual<FieldZqElement>(three, two.Subtract(four), "2-4=3");
        }

        /// <summary>
        /// A test for Divide and operator/
        /// </summary>
        [TestMethod]
        public void DivideTest()
        {
            ParameterSet parameters = ECParameterSets.ParamSet_EC_P256_V1;
            for (int i = 0; i < 10; ++i)
            {
                FieldZqElement a = parameters.Group.FieldZq.GetRandomElement(false);
                FieldZqElement b = parameters.Group.FieldZq.GetRandomElement(true);
                FieldZqElement c = a.Divide(b);
                Assert.AreEqual<FieldZqElement>(a * b.Invert(), c, "a.divide(b).");
                FieldZqElement d = a / b;
                Assert.AreEqual<FieldZqElement>(c, d, "a / b");
            }

            FieldZq Zq = FieldZq.CreateFieldZq(new byte[] { 0x05 });
            Assert.AreEqual<FieldZqElement>(Zq.GetElement(4), Zq.GetElement(2) / Zq.GetElement(3), "2/3 = 4");
            Assert.AreEqual<FieldZqElement>(Zq.GetElement(4), Zq.GetElement(1) / Zq.GetElement(4), "1/4 = 4");
            Assert.AreEqual<FieldZqElement>(Zq.GetElement(1), Zq.GetElement(2) / Zq.GetElement(2), "2/3 = 1");
        }

        /// <summary>
        /// Tests property NegativeOne
        /// </summary>
        [TestMethod]
        public void NegativeOneTest()
        {
            FieldZq Zq = FieldZq.CreateFieldZq(new byte[] { 0x05 });
            FieldZqElement negone = Zq.NegativeOne;
            Assert.AreEqual<FieldZqElement>(Zq.One.Negate(), negone, "test first time.");

            FieldZqElement negoneAgain = Zq.NegativeOne;
            Assert.ReferenceEquals(negone, negoneAgain);
            Assert.AreEqual(Zq.One.Negate(), negoneAgain, "negone again");
        }

        /// <summary>
        /// Test for GetElement(int) 
        /// </summary>
        [TestMethod]
        public void GetElementIntTest()
        {
            FieldZq Zq = FieldZq.CreateFieldZq(new byte[] { 0x05 });
            Assert.AreEqual<FieldZqElement>(Zq.GetElement(0), Zq.GetElement(-0), "-0");
            Assert.AreEqual<FieldZqElement>(Zq.GetElement(1).Negate(), Zq.GetElement(-1), "-1");
            Assert.AreEqual<FieldZqElement>(Zq.GetElement(2).Negate(), Zq.GetElement(-2), "-2");
            Assert.AreEqual<FieldZqElement>(Zq.GetElement(3).Negate(), Zq.GetElement(-3), "-3");
            Assert.AreEqual<FieldZqElement>(Zq.GetElement(4).Negate(), Zq.GetElement(-4), "-4");

            ParameterSet parameters = ECParameterSets.ParamSet_EC_P256_V1;
            Assert.AreEqual<FieldZqElement>(parameters.Group.FieldZq.GetElement(456).Negate(), parameters.Group.FieldZq.GetElement(-456), "-456");
            Assert.AreEqual<FieldZqElement>(parameters.Group.FieldZq.GetElement(1).Negate(), parameters.Group.FieldZq.GetElement(-1), "-1");
            Assert.AreEqual<FieldZqElement>(parameters.Group.FieldZq.GetElement(10000034).Negate(), parameters.Group.FieldZq.GetElement(-10000034), "-10000034");
        }

        /// <summary>
        /// Test for getRandomElements
        /// </summary>
        [TestMethod]
        public void GetRandomElementsTest()
        {
            FieldZq Zq = FieldZq.CreateFieldZq(new byte[] { 0x05 });

            // make sure that setting nonZero=true results in no no zero elements.
            FieldZqElement[] nonZeroElements = Zq.GetRandomElements(30, true);
            for (int i = 0; i < nonZeroElements.Length; ++i)
            {
                Assert.AreNotEqual(Zq.Zero, nonZeroElements[i], "element " + i + " is 0.");
            }

            // check that setting nonZero=false results in at least one zero element
            bool foundNonZero = false;
            FieldZqElement[] zeroElements = Zq.GetRandomElements(100, false);
            for (int i = 0; i < zeroElements.Length; ++i)
            {
                if (zeroElements[i] == Zq.Zero)
                {
                    foundNonZero = true;
                    break;
                }
            }
            if (!foundNonZero)
            {
                Assert.Inconclusive("GetRandomElements did not create a single zero value.  Try running this test again. Chances of failure on correct behavior is 0.0000000002.");
            }

            // check that setting maxBitLength=-1 results in at least one element 2, 3, or 4
            bool foundLargeElement = false;
            FieldZqElement[] fullScopeElements = Zq.GetRandomElements(100, false, -1);
            for (int i = 0; i < fullScopeElements.Length; ++i)
            {
                if ((fullScopeElements[i] != Zq.Zero) && fullScopeElements[i] != Zq.One)
                {
                    foundLargeElement = true;
                    break;
                }
            }
            if (!foundLargeElement)
            {
                Assert.Inconclusive("GetRandomElements did not create a single value in the set {2,3,4}.  Try running this test again. Chances of failure on correct behavior is 2.6 x 10^-40.");
            }
        }

/* TODO: enable test when maxBitLenght works
        /// <summary>
        /// Tests everything related to maxbitlength
        /// </summary>
        [TestMethod]
        public void GetRandomElementsMaxBitLengthTest()
        {
            ParameterSet parameters = ECParameterSets.ParamSet_EC_P256_V1;
            FieldZq Zq = parameters.Group.FieldZq;
            
            // make sure that random elements are at most one bit long (e.g. 0 or 1);
            FieldZqElement[] smallBit = Zq.GetRandomElements(50, false, 1);
            for (int i = 0; i < smallBit.Length; ++i)
            {
                if ((smallBit[i] != Zq.Zero) && (smallBit[i] != Zq.One))
                {
                    Assert.Fail("smallBit contains an element that is not a 0 or 1.");
                }
            }

            for (int i = 0; i < 100; ++i)
            {
                FieldZqElement small = Zq.GetRandomElement(false, 1);
                Assert.IsTrue(small == Zq.One || small == Zq.Zero);
            }
        }
*/
    }
}
