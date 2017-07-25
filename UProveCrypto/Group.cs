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

using System;
using System.Runtime.Serialization;
using UProveCrypto.Math;

namespace UProveCrypto
{
    /// <summary>
    /// Describes a group of order q, denoted Gq.  MUST NOT be modified after construction.
    /// </summary>
    [DataContract]
    public abstract class Group
    {
        /// <summary>
        /// The type of group.
        /// </summary>
        public GroupType Type { get; private set; }

        /// <summary>
        /// The parameter Q as a big-endian byte array.
        /// It describes the order of the group.  MUST NOT be modified after construction.
        /// </summary>
        public abstract byte[] Q { get; internal set; }

        /// <summary>
        /// Last computed value of FieldZq
        /// </summary>
        private FieldZq _fieldZq = null;

        /// <summary>
        /// Returns the field associated with this group.  The field
        /// is computed once using the modulus Q.
        /// </summary>
        public FieldZq FieldZq
        {
            get
            {
                // impossible to compute field
                if (this.Q == null)
                {
                    return null;
                }

                if (this._fieldZq == null)
                {
                    _fieldZq = FieldZq.CreateFieldZq(this.Q);
                }
                return _fieldZq;
            }
        }

        /// <summary>
        /// The generator element.
        /// </summary>
        public abstract GroupElement G { get; internal set; }

        /// <summary>
        /// The name of the group.
        /// </summary>
        public string GroupName { get; set; }

        /// <summary>
        /// Constructs a Group.
        /// <param name="type">The group construction.</param>
        /// <param name="q">The value q.</param>
        /// <param name="groupName">The group name.</param>
        /// </summary>
        protected Group(GroupType type, byte[] q, string groupName)
        {
            if (q== null) throw new ArgumentNullException("q");

            Type = type;
            Q = q;
            GroupName = groupName;
        }

        /// <summary>
        /// Verifies that e is a group element.
        /// </summary>
        /// <param name="e">The element to test.</param>
        /// <exception cref="InvalidUProveArtifactException">
        /// Thrown if e is not in the group.</exception>
        public abstract void ValidateGroupElement(GroupElement e);

        /// <summary>
        /// Returns the group element encoded in byte array.
        /// </summary>
        /// <param name="value">A byte array encoding a group element.</param>
        /// <returns>A group element.</returns>
        public abstract GroupElement CreateGroupElement(byte[] value);

        /// <summary>
        /// Generates a random group element. Generates a random exponent r and computes G^r.
        /// </summary>
        /// <param name="nonIdentity">True to return a non-identity element.</param>
        /// <param name="maxBitLength">Maximum length of the exponent used to get random element. For example, to choose a random  
        /// group elements from the set {G^0, G^1, G^2, G^3}, set maxBitLength to 2. Set maxBitLength to -1 to choose random group elements 
        /// from the entire group.</param>
        /// <returns>A random group element.</returns>
        public GroupElement GetRandomElement(bool nonIdentity, int maxBitLength = -1)
        {
            if (maxBitLength != -1)
            {
                throw new NotImplementedException("GetRandomElement cannot handle argument maxBitLength != -1.");
            }

            FieldZqElement random = this.FieldZq.GetRandomElement(nonIdentity, maxBitLength);
            return this.G.Exponentiate(random);
        }

        /// <summary>
        /// Generates an array of random group elements.  Calls GetRandomElement n times.
        /// </summary>
        /// <param name="n">The number of elements to return.</param>
        /// <param name="nonIdentity">True to return non-identity elements.</param>
        /// <param name="maxBitLength">Maximum length of the exponent used to get random element. For example, to choose a random  
        /// group elements from the set {G^0, G^1, G^2, G^3}, set maxBitLength to 2. Set maxBitLength to -1 to choose random group elements 
        /// from the entire group.</param>
        /// <returns>Random group elements.</returns>
        public GroupElement[] GetRandomElements(int n, bool nonIdentity, int maxBitLength = -1)
        {
            if (maxBitLength != -1)
            {
                throw new NotImplementedException("GetRandomElement cannot handle argument maxBitLength != -1.");
            }

            GroupElement[] r = new GroupElement[n];
            for (int i = 0; i < n; i++)
            {
                r[i] = GetRandomElement(nonIdentity, maxBitLength);
            }
            return r;
        }


        /// <summary>
        /// Updates the specified hash function with the group description elements.
        /// </summary>
        /// <param name="h">An hash function object.</param>
        public abstract void UpdateHash(HashFunction h);

        /// <summary>
        /// Verifies that the group is correctly constructed.
        /// </summary>
        /// <exception cref="InvalidUProveArtifactException">
        /// Thrown if the group parameters are invalid.</exception>
        public abstract void Verify();

        /// <summary>
        /// Returns the identity element in the group.
        /// </summary>
        public abstract GroupElement Identity { get; }

        /// <summary>
        /// Derives an unpredictable element of the group, using the input. Each 
        /// construction defines its own derivation mechanism, but each takes an 
        /// optional context string and an index, and returns a counter. Calling 
        /// this method with the same parameter values returns the same element 
        /// and counter, calling it with a different context or index value must 
        /// return a different element.
        /// </summary>
        /// <param name="context">An optional context used by the derivation 
        /// mechanism, can be null.</param>
        /// <param name="index">An 8-bit integer index value.</param>
        /// <param name="counter">A counter value indicating the state at which the 
        /// derivation mechanism stopped.</param>
        /// <returns>A random group element.</returns>
        public abstract GroupElement DeriveElement(
            byte[] context, 
            byte index, 
            out int counter);

        /// <summary>
        /// Compute a product of powers.
        /// Return the product of the <code>bases[i].Exponentiate(exponents[i])</code> for <c>i</c> from <c>0</c> to <c>bases.Length -1</c>.
        /// The inputs <c>bases</c> and <c>exponents</c> must have the same length
        /// </summary>
        /// <param name="bases">Group elements array.</param>
        /// <param name="exponents">Field elements array.</param>
        /// <returns>Multi-exponentiation of the group elements to the field elements.</returns>
        public abstract GroupElement MultiExponentiate(GroupElement[] bases, FieldZqElement[] exponents);

        /// <summary>
        /// Convenience method to compute P = (base1^exponent1)*(base2^exponent2). Calls the MultiExponentiate routine
        /// </summary>
        /// <param name="base1">The first base in the product</param>
        /// <param name="base2">The second base in the product</param>
        /// <param name="exponent1">The first exponent in the product</param>
        /// <param name="exponent2">The second exponent in the prodcut</param>
        /// <returns>The product of powers base1^exponent1 and base2^exponent2.</returns>
        public GroupElement MultiExponentiate(GroupElement base1, GroupElement base2, FieldZqElement exponent1, FieldZqElement exponent2)
        {
            return MultiExponentiate(new GroupElement[] { base1, base2 }, new FieldZqElement[] { exponent1, exponent2 });
        }

        /// <summary>
        /// Returns g^{-1}.
        /// </summary>
        /// <param name="g">Group element to invert.</param>
        /// <returns></returns>
        public GroupElement Invert(GroupElement g)
        {
            return g.Exponentiate(this.FieldZq.NegativeOne);
        }

        /// <summary>
        /// Returns numerator/denominator.
        /// </summary>
        /// <param name="numerator">Numerator</param>
        /// <param name="denominator">Denominator</param>
        /// <returns></returns>
        public GroupElement Divide(GroupElement numerator, GroupElement denominator)
        {
            return numerator.Multiply(this.Invert(denominator));
        }


        /// <summary>
        /// Returns the product of all the numerators divided by the product of all the denominators.
        /// </summary>
        /// <param name="numerators">Array of group elements to multiply together to form the numerator.</param>
        /// <param name="denominators">Array of group elements to multiply together to form the denominator.</param>
        /// <returns>Quotient.</returns>
        public GroupElement Divide(GroupElement[] numerators, GroupElement[] denominators)
        {
            if ((numerators == null) || (denominators == null))
            {
                throw new ArgumentNullException("Divide expects all arguments to be not null.");
            }

            GroupElement numerator = this.Identity;
            for (int i = 0; i < numerators.Length; ++i)
            {
                numerator *= numerators[i];
            }

            GroupElement denominator = this.Identity;
            for (int i = 0; i < denominators.Length; ++i)
            {
                denominator *= denominators[i];
            }

            return this.Divide(numerator, denominator);
        }

        /// <summary>
        /// Returns a string describing the underlying math implementation being used. 
        /// This returns the name of the math implementation used to compile UProveCrypto.
        /// </summary>
        public static string MathImplName()
        {
#if BOUNCY_CASTLE
            return "Bouncy Castle";
#endif
        }

    }
}
