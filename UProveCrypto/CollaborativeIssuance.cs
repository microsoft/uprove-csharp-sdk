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
using System.Collections.Generic;
#if DEBUG
using System.Diagnostics;
#endif
using System.Linq;
using System.Runtime.Serialization;
using UProveCrypto.Math;

// v1 limitations of collaborative issuance
//  - carry over attributes only from one token
//  - can't carry over from device-protected tokens

namespace UProveCrypto
{
    /// <summary>
    /// Class that will be extended to create parameters for provers and issuers to use
    /// in the collaborative issuance protocol. 
    /// </summary>
    abstract public class PreIssuanceParameters
    {

        /// The Issuer parameters for the new token
        public IssuerParameters IP { get; protected set; }
        /// Issuer parameters used to carry-over attributes
        public IssuerParameters SourceIP { get; set; }
        /// attribute values for the new token. (this will always have length n, but may have some null attributes for the Issuer)
        public byte[][] Attributes { get; set; }           
        /// the token information field for the new token
        public byte[] TI { get; set; }
        /// indicies of committed attributes (in new token)
        public int[] C { get; set; }
        /// indicies of committed attributes (in old token(s))
        public int[] Corig { get; set; }
        /// flag indicating that there are carry-over attributes in the proof
        public bool HasCarryOverAttributes { get; set; }
        /// private attributes known only to the prover (must have ip.e[U[i]] == 0 (not hahsed) for all i)
        public int[] U { get; set; }
        /// attributes known to both the prover and issuer
        public int[] K { get; set; }

        /// <summary>
        /// Validates the parameters object, throws an ArgumentException if they are invalid.
        /// </summary>
        public virtual void Validate()
        {
            if (Attributes == null)
            {
                throw new ArgumentException("Attributes array is null");
            }

            if (C != null || Corig != null)
            {
                if (C == null || Corig == null)
                {
                    throw new ArgumentException("Both C and Corig must be null, or both must be non-null");
                }
            }

            if (C != null && (C.Length != Corig.Length))
            {
                throw new ArgumentException("C and Corig must have the same length");
            }

            if (C == null && U == null && K != null)
            {
                throw new ArgumentException("If all attributes are known, then the standard issuance protocol should be used, not collaborative issuance");
            }
            
            // Make any of the integer arrays that are null have length zero
            if (C == null)
            {
                C = new int[] { };
            }
            if (Corig == null)
            {
                Corig = new int[] { };
            }
            if (K == null)
            {
                K = new int[] { };
            }
            if (U == null)
            {
                U = new int[] { };
            }

            // Check that C, U, K are pairwise disjoint 
            if (C.Intersect(U).Count() != 0)
            {
                throw new ArgumentException("C and U not disjoint: " + C.Intersect(U));
            }
            if (U.Intersect(K).Count() != 0)
            {
                throw new ArgumentException("U and K are not disjoint: " + U.Intersect(K));
            }
            if (C.Intersect(K).Count() != 0)
            {
                throw new ArgumentException("C and K are not disjoint: " + C.Intersect(K));
            }

            // Check that C, U, K contain all attributes
            if ((U.Union(C)).Union(K).Count() != (IP.G.Length - 2))
            {
                throw new ArgumentException("C, U and K do not jointly contain all attributes");
            }
        }
    }


    /// <summary>
    /// Parameters for collaborative issuance used by the Prover. 
    /// </summary>
    public class ProverPreIssuanceParameters : PreIssuanceParameters
    {
        /// One or more <c>UProveKeyAndToken</c> objects (null for Issuer, set Tokens)
        public UProveKeyAndToken KeyAndToken { get; set;}

        /// Set of attributes corresponding to the token in <c>KeyAndToken</c>, the source for being carried over
        public byte[][] SourceAttributes { get; set; }

        /// The device's public key. Can be <code>null</code>.
        public GroupElement DevicePublicKey { get; set; }

        /// <summary>
        /// Create a new set of parameters.  Once created you can set properties
        /// of this object to control aspects of the PreIssuanceProof. 
        /// </summary>
        /// <param name="ip">The issuer parameters to be used when creating the proof</param>
        public ProverPreIssuanceParameters(IssuerParameters ip)
        {
            IP = ip;
        }

        /// <summary>
        /// After setting properties on this PreIssuanceProofParameters object, the Prover
        /// should call Validate() to ensure they are correct.
        /// </summary>
        /// <exception cref="ArgumentException">Thrown if parameters are invalid.</exception>
        public override void Validate()
        {
            base.Validate();

            if (C.Length != 0 && KeyAndToken == null)
            {
                throw new ArgumentException("KeyAndToken cannot be null if C is non-null");
            }
        }

        /// <summary>
        /// Indicates that attributes are carried over from the source token into the new one. 
        /// </summary>
        /// <param name="sourceIndex">The indices of the attributes in the existing token.</param>
        /// <param name="destinationIndex">The indices of the attributes in the new token.</param>
        /// /// <param name="sourceIP">The Issuer Parameters used to issue the source token. This can be the same as <c>Ip</c> if the
        /// same Issuer issues the source and new tokens.</param>
        /// <param name="sourceKeyAndToken">The source key and token.</param>
        /// <param name="sourceAttributes">The attributes in the source token.</param>
        public void CarryOverAttribute(int[] sourceIndex, int[] destinationIndex, IssuerParameters sourceIP, UProveKeyAndToken sourceKeyAndToken, byte[][] sourceAttributes)
        {
            if (sourceIndex == null || destinationIndex == null || sourceIP == null || sourceKeyAndToken == null || sourceAttributes == null)
            {
                throw new ArgumentNullException("arguments can't be null");
            }
            if (sourceIndex.Length != destinationIndex.Length)
            {
                throw new ArgumentException("sourceIndex and destinationIndex must have the same lenght");
            }
            if (!sourceKeyAndToken.Token.Uidp.SequenceEqual<byte>(sourceIP.UidP))
            {
                throw new ArgumentException("sourceToken and sourceIP do not match");
            }
            C = destinationIndex;
            Corig = sourceIndex;
            SourceIP = sourceIP;
            KeyAndToken = sourceKeyAndToken;
            SourceAttributes = sourceAttributes;
            HasCarryOverAttributes = true;
        }
    }

    /// <summary>
    /// Parameters used by the Issuer for collaborative issuance. 
    /// </summary>
    public class IssuerPreIssuanceParameters : PreIssuanceParameters
    {
        /// The source <c>UProveToken</c> object
        public UProveToken Tokens { get; set; }
        /// True if the new token will be device protected
        public bool DeviceProtected { get; set; } 

        /// <summary>
        /// Create parameters.
        /// </summary>
        /// <param name="ip">The issuer parameters to be used for collaborative issuance.</param>
        public IssuerPreIssuanceParameters(IssuerParameters ip)
        {
            IP = ip;
            DeviceProtected = false;        // default is false, can be changed
        }

        /// <summary>
        /// After setting properties on this PreIssuanceProofParameters object, the Prover
        /// should call Validate() to ensure they are correct.
        /// </summary>
        /// <returns></returns>
        public override void Validate()
        {
            base.Validate();

            for (int i = 0; i < Attributes.Length; i++)
            {
                if (K.Contains(i + 1) && Attributes[i] == null)
                {
                    // known attributes must be non null
                    throw new ArgumentException("Attribute " + i + " is null");
                }
            }
        }

        /// <summary>
        /// Indicates that attributes are carried over from the source token into the new one. 
        /// </summary>
        /// <param name="sourceIndex">The indices of the attributes in the existing token.</param>
        /// <param name="destinationIndex">The indices of the attributes in the new token.</param>
        /// /// <param name="sourceIP">The Issuer Parameters used to issue the source token. This can be the same as <c>Ip</c> if the
        /// same Issuer issues the source and new tokens.</param>
        /// <param name="sourceToken">The source token.</param>
        public void CarryOverAttribute(int[] sourceIndex, int[] destinationIndex, IssuerParameters sourceIP, UProveToken sourceToken)
        {
            if (sourceIndex == null || destinationIndex == null || sourceIP == null || sourceToken == null)
            {
                throw new ArgumentNullException("arguments can't be null");
            }
            if (sourceIndex.Length != destinationIndex.Length)
            {
                throw new ArgumentException("sourceIndex and destinationIndex must have the same lenght");
            }
            if (!sourceToken.Uidp.SequenceEqual<byte>(sourceIP.UidP))
            {
                throw new ArgumentException("sourceToken and sourceIP do not match");
            }
            C = destinationIndex;
            Corig = sourceIndex;
            SourceIP = sourceIP;
            Tokens = sourceToken;
            HasCarryOverAttributes = true;
        }
    }


    /// <summary>
    /// A class to create and verify proofs used with collaborative issuance. 
    /// These proofs are created by the Prover, and verified by the Issuer, to
    /// provide assurance to the Issuer that the tokens being created have valid
    /// attributes, even if the Issuer does not see these attributes. 
    /// </summary>
    [DataContract]
    public class PreIssuanceProof : IParametrizedDeserialization
    {
        // values to be sent to verifier
        public GroupElement h0;
        public GroupElement CGamma;
        public GroupElement Ch0;
        public byte[] c;

        public Dictionary<String, FieldZqElement> responses;

        [DataMember(Name = "presentation", EmitDefaultValue = false, Order = 7)]
        public PresentationProof presentation;  // presentation for carry-over attribute commitments

        // This is private because everyone should use CreateProof
        private PreIssuanceProof(GroupElement h0, GroupElement CGamma, GroupElement Ch0, byte[] c, 
            Dictionary<String, FieldZqElement> responses, PresentationProof presentation)
        {
            this.h0 = h0;
            this.CGamma = CGamma;
            this.Ch0 = Ch0;
            this.c = c;
            this.responses = responses;
            this.presentation = presentation;
        }

        // helper method to get the response by name; wraps up the error-checking for convenience
        internal FieldZqElement GetResponse(String name)
        {
            FieldZqElement f;
            bool OK = responses.TryGetValue(name, out f);
            if (!OK)
            {
                throw new InvalidUProveArtifactException("Failed to validate proof, missing response " + name);
            }
            return f;
        }

        /// <summary>
        /// Create a new pre-issuance proof.
        /// </summary>
        /// <param name="pipp">The prover parameters.</param>
        /// <param name="beta0">The random blinding value used to create the proof, output so that the prover can use it during the issuance protocol</param>
        /// <param name="message">An optional message to sign while creating the proof.</param>
        /// <returns></returns>
        public static PreIssuanceProof CreateProof(ProverPreIssuanceParameters pipp, out FieldZqElement beta0, byte[] message)
        {
            // validate paramters first
            pipp.Validate();

            bool supportDevice = (pipp.DevicePublicKey == null) ? false : true;

            IssuerParameters ip = pipp.IP;
            FieldZq Zq = ip.Zq;
            Group Gq = ip.Gq;
            Dictionary<string, FieldZqElement> responses = new Dictionary<string, FieldZqElement>();

            // these will be used if there is a carry-over attribute
            CommitmentPrivateValues cpv = null;
            PresentationProof presProof = null;
            GroupElement[] C = null;
            GroupElement[] tildeC = null;
            FieldZqElement[] tildeR = null;

            // Generate random values
            beta0 = Zq.GetRandomElement(true);
            FieldZqElement tildeBeta0 = Zq.GetRandomElement(true);
            FieldZqElement rho = Zq.GetRandomElement(true);
            FieldZqElement tildeRho = Zq.GetRandomElement(true);
            FieldZqElement tilde_d = Zq.GetRandomElement(true);
            FieldZqElement[] tildeX = new FieldZqElement[ip.G.Length - 1];
            for (int i = 1; i < ip.G.Length - 1; i++)
            {
                if (!pipp.K.Contains(i))
                {
                    tildeX[i] = Zq.GetRandomElement(true);
                }
            }

            // Compute the U-Prove presentation proof, if there are carry-over attributes
            if(pipp.HasCarryOverAttributes)
            {
                // generate the presentation proof
                int[] disclosed = new int[] { };
                ProverPresentationProtocolParameters pppp = new ProverPresentationProtocolParameters(pipp.SourceIP, disclosed, message, pipp.KeyAndToken, pipp.SourceAttributes);
                pppp.Committed = pipp.Corig;

                // TODO: What if the source token is device protected?  need to handle this as well. (a pointer to the device should be included in pipp
                //if (device != null)
                //{
                //    pppp.SetDeviceData(deviceMessage, device.GetPresentationContext());
                //}-
                // For now just fail: 
                if (pipp.KeyAndToken.Token.IsDeviceProtected)
                {
                    throw new NotImplementedException("Device protected tokens may not be used for carry-over attributes");
                }

                presProof = PresentationProof.Generate(pppp, out cpv);
 
                //set C
                C = new GroupElement[pipp.C.Length];
                // Generate random values for the commitment randomizers
                tildeR = Zq.GetRandomElements(pipp.C.Length, true);
                tildeC = new GroupElement[C.Length];
                for (int i = 0; i < C.Length; i++)
                {
                    C[i] = presProof.Commitments[i].TildeC;
                    tildeC[i] = Gq.MultiExponentiate(Gq.G, ip.G[1], tildeX[pipp.C[i]], tildeR[i]);
                }
            }   // end if cary-over attributes

            // Compute gamma
            GroupElement gamma = ProtocolHelper.ComputeIssuanceInput(ip, pipp.Attributes, pipp.TI, pipp.DevicePublicKey);

            // Compute h0, Cgamma, Ch0, tildeD, tildeT:
            GroupElement h0 = gamma.Exponentiate(beta0);
            GroupElement Cgamma = gamma.Multiply(Gq.G.Exponentiate(rho));        // Cgamma = gamma*(g^rho)
            GroupElement Ch0 = Cgamma.Exponentiate(beta0);
            GroupElement tildeD = Gq.G.Exponentiate(tilde_d);
            
            GroupElement tildeT = Cgamma.Exponentiate(tildeBeta0);

            // Compute tildeCgamma:
            List<GroupElement> bases = new List<GroupElement>();
            List<FieldZqElement> exponents = new List<FieldZqElement>();
            
            bases.Add(Gq.G);
            exponents.Add(tildeRho);
            for (int i = 1; i < ip.G.Length-1; i++)
            {
                if (!pipp.K.Contains(i))     // i \not\in K
                {
                    bases.Add(ip.G[i]);
                    exponents.Add(tildeX[i]);
                }
            }
            GroupElement tildeCgamma = Gq.MultiExponentiate(bases.ToArray(), exponents.ToArray());
            // TODO: if device protected, then multiply tildeCgamma by the public key
            // Note: We leave TI out, (i.e., (g_t)^(x_t) because t \in K implicitly.

            // Compute the challenge
            byte[] c = ComputeChallenge(ip, h0, Cgamma, Ch0, C, tildeD, tildeCgamma, tildeT, tildeC, message);
            FieldZqElement negc = Zq.GetElementFromDigest(c).Negate();

            // Compute the responses
            responses.Add("sBeta0", tildeBeta0.Add(beta0.Multiply(negc)));          // sBeta0 = tildeBeta0 - beta0*c
            responses.Add("sD", tilde_d.Add(beta0.Multiply(rho).Multiply(negc)));   // sD = tilde_d - beta0*rho*c
            responses.Add("sRho", tildeRho.Add(rho.Multiply(negc)));                // sRho = tildeRho - rho*c

            for (int i = 1; i < ip.G.Length-1; i++)
            {
                if (!pipp.K.Contains(i))      // in \not\in K
                {
                    FieldZqElement xi = ProtocolHelper.ComputeXi(ip, i-1, pipp.Attributes[i-1]);
                    responses.Add("sx" + i, tildeX[i].Add(xi.Multiply(negc)));          // sxi = tildeX[i] - xi*c
                }
            }

            if (pipp.HasCarryOverAttributes)
            {
                for (int i = 0; i < C.Length; i++)
                {
                    responses.Add("sR"+i, tildeR[i].Add(cpv.TildeO[i].Multiply(negc)));      // sRi = tildeR[i] - tildeO[i]*c
                }
            }

            return new PreIssuanceProof(h0, Cgamma, Ch0, c, responses, 
                pipp.HasCarryOverAttributes ? presProof : null);
        }

        // Verifies the pre-issuance proof, and returns the element gamma needed for the token issuance.
        /// <summary>
        /// Verifies a pre-issuance proof and returns the element gamma needed for collaborative issuance. 
        /// </summary>
        /// <param name="ipip">The pre-issuance proof parameters for the Issuer</param>
        /// <param name="proof">The proof to be verified</param>
        /// <param name="message">An optional message to be verified (must match the one signed by the prover)</param>
        /// <returns>The group element <c>gamma^beta0</c>, a blinded version of the element gamma used during token issuance.</returns>
        /// <exception cref="InvalidUProveArtifactException">Thrown if the proof is invalid.</exception>
        public static GroupElement VerifyProof(IssuerPreIssuanceParameters ipip, PreIssuanceProof proof, byte[] message)
        {
            // Validate paramters first
            ipip.Validate();

            IssuerParameters ip = ipip.IP;
            FieldZq Zq = ip.Zq;
            Group Gq = ip.Gq;

            List<GroupElement> bases = new List<GroupElement>();
            List<FieldZqElement> exponents = new List<FieldZqElement>();

            GroupElement[] C = null;
            GroupElement[] CPrime = null;

            FieldZqElement c = Zq.GetElementFromDigest(proof.c);

            if (ipip.HasCarryOverAttributes)
            {
                // validate presentation proof
                int[] disclosed = new int[] {}; 
                VerifierPresentationProtocolParameters vppp = new VerifierPresentationProtocolParameters(ipip.SourceIP, disclosed, message, ipip.Tokens);
                vppp.Committed = ipip.Corig;

                try
                {
                    proof.presentation.Verify(vppp);
                }
                catch (InvalidUProveArtifactException e)
                {
                    throw new InvalidUProveArtifactException("Failed to verify pre-Issuance proof, presentation proof " + 0 + " failed to verify ("+e.ToString()+")");
                }

                // extract the commitments
                C = new GroupElement[ipip.C.Length];
                CPrime = new GroupElement[ipip.C.Length];
                for (int i = 0; i < C.Length; i++)
                {
                    C[i] = proof.presentation.Commitments[i].TildeC;
                
                    // Compute the CPrime[i] values. 
                    bases = new List<GroupElement>();
                    exponents = new List<FieldZqElement>();
                    bases.Add(C[i]);
                    exponents.Add(c);
                    bases.Add(Gq.G);
                    exponents.Add(proof.GetResponse("sx" + ipip.C[i]));
                    bases.Add(ip.G[1]);
                    exponents.Add(proof.GetResponse("sR" + i));
                    CPrime[i] = Gq.MultiExponentiate(bases.ToArray(), exponents.ToArray());
                    //Debug.WriteLine("CPrime[i] = " + BitConverter.ToString(CPrime[i].GetEncoded()));                
                }
            }

            // Compute D'
            FieldZqElement sd = proof.GetResponse("sD");
            GroupElement DPrime = Gq.MultiExponentiate(proof.Ch0, proof.h0, c, c.Negate()); // TODO: add Inverse() to group element to simplify this
            DPrime = DPrime.Multiply(Gq.G.Exponentiate(sd));
            //Debug.WriteLine("DPrime = " + BitConverter.ToString(DPrime.GetEncoded()));

            // Compute T'
            FieldZqElement sBeta0 = proof.GetResponse("sBeta0");
            GroupElement TPrime = Gq.MultiExponentiate(proof.Ch0, proof.CGamma, c, sBeta0);
            //Debug.WriteLine("TPrime = " + BitConverter.ToString(TPrime.GetEncoded()));

            // Compute gammaK (product of known attributes)
            bases = new List<GroupElement>();
            exponents = new List<FieldZqElement>();
            int t = ip.G.Length-1;
            FieldZqElement xt = ProtocolHelper.ComputeXt(ip, ipip.TI, ipip.DeviceProtected);
            bases.Add(ip.G[0]);
            exponents.Add(ip.Zq.One);
            bases.Add(ip.G[t]);
            exponents.Add(xt);  // gammaK = g0*(gt^xt)
            for (int i = 1; i < ip.G.Length - 1; i++)
            {
                if (ipip.K.Contains(i))
                {
                    FieldZqElement xi = ProtocolHelper.ComputeXi(ip, i-1, ipip.Attributes[i-1]);
                    bases.Add(ip.G[i]);
                    exponents.Add(xi);
                }
            }
            GroupElement gammaK = Gq.MultiExponentiate(bases.ToArray(), exponents.ToArray());

            // Compute Cgamma'
            bases = new List<GroupElement>();
            exponents = new List<FieldZqElement>();
            bases.Add(proof.CGamma);
            exponents.Add(c);
            bases.Add(gammaK);
            exponents.Add(c.Negate());  // TODO: do with one exp; i.e., (CGamma/gammaK)^c
            for (int i = 1; i < ip.G.Length - 1; i++)
            {
                if (!ipip.K.Contains(i))
                {
                    FieldZqElement sxi = proof.GetResponse("sx" + i);
                    bases.Add(ip.G[i]);
                    exponents.Add(sxi);
                }
            }
            bases.Add(Gq.G);
            exponents.Add(proof.GetResponse("sRho"));
            GroupElement CgammaPrime = Gq.MultiExponentiate(bases.ToArray(), exponents.ToArray());
            // TODO: if deviceprotected multiply device base/response.
            //Debug.WriteLine("CgammaPrime = " + BitConverter.ToString(CgammaPrime.GetEncoded()));

            // Recompute challenge
            byte[] cPrime = ComputeChallenge(ip, proof.h0, proof.CGamma, proof.Ch0, C, DPrime, CgammaPrime, TPrime, CPrime, message);
            //Debug.WriteLine("c' = " + BitConverter.ToString(cPrime));

            if (!cPrime.SequenceEqual<byte>(proof.c))
            {
                throw new InvalidUProveArtifactException("invalid proof");
            }

            return proof.h0;
        }

        /// <summary>
        /// Returns the blinded gamma value created during this pre-issuance proof. 
        /// The Prover will typically call this method to retrive the blinded gamma
        /// value from this PreIssuanceProof. 
        /// The Issuer should not use this method to access the blinded gamma value,
        /// since the proof must be verified, and VerifyProof returns this value 
        /// if verification is successful. 
        /// </summary>
        /// <returns>A blinded version of gamma; i.e., gamma^beta0.</returns>
        public GroupElement GetBlindedGamma()
        {
            return h0;
        }

        // Private helper function
        private static byte[] ComputeChallenge(IssuerParameters ip, GroupElement h0, GroupElement CGamma, 
            GroupElement Ch0, GroupElement[] C, GroupElement tildeD, GroupElement tildeCgamma, GroupElement tildeT, 
            GroupElement[] tildeC, byte[] message)
        {
            HashFunction H = ip.HashFunction;
            H.Hash(ip.Digest(false));
            H.Hash(h0);
            H.Hash(CGamma);
            H.Hash(Ch0);
            H.Hash(C);
            H.Hash(tildeD);
            H.Hash(tildeCgamma);
            H.Hash(tildeT);
            H.Hash(tildeC);
            H.Hash(message);

            byte[] digest = H.Digest;

#if DEBUG
            Debug.WriteLine("h0 = " + BitConverter.ToString(h0.GetEncoded()));
            Debug.WriteLine("CGamma = " + BitConverter.ToString(CGamma.GetEncoded()));
            Debug.WriteLine("Ch0 = " + BitConverter.ToString(Ch0.GetEncoded()));
            if(tildeC != null) Debug.WriteLine("tildeC[0] = " + BitConverter.ToString(tildeC[0].GetEncoded()));
            Debug.WriteLine("tildeD = " + BitConverter.ToString(tildeD.GetEncoded()));
            Debug.WriteLine("tildeT = " + BitConverter.ToString(tildeT.GetEncoded()));
            Debug.WriteLine("tildeCgamma = " + BitConverter.ToString(tildeCgamma.GetEncoded()));
            Debug.WriteLine("digest = " + BitConverter.ToString(digest));
#endif 

            return digest;
        }


        #region Serialization

        [DataMember(Name = "h0", EmitDefaultValue = false, Order = 1)]
        internal string _h0;

        [DataMember(Name = "CGamma", EmitDefaultValue = false, Order = 2)]
        internal string _CGamma;

        [DataMember(Name = "Ch0", EmitDefaultValue = false, Order = 3)]
        internal string _Ch0;

        [DataMember(Name = "c", EmitDefaultValue = false, Order = 4)]
        internal string _c;

        [DataMember(Name = "responses_values", EmitDefaultValue = false, Order = 5)]
        internal string[] _responses_values;

        [DataMember(Name = "responses_keys", EmitDefaultValue = false, Order = 6)]
        internal string[] _responses_keys;

        [OnSerializing]
        internal void OnSerializing(StreamingContext context)
        {
            _h0 = h0.ToBase64String();
            _CGamma = CGamma.ToBase64String();
            _Ch0 = Ch0.ToBase64String();
            _c = c.ToBase64String();
            // Serialize the responses dictionary.  TODO: if FieldZqElement was serializable, then this wouldn't be necessary, since Dictionary knows how to serializae itself proivded the keys and values are serializable. 
            _responses_keys = new string[responses.Count];
            _responses_values = new string[responses.Count];

            int i = 0;
            foreach (KeyValuePair<string, FieldZqElement> resp in responses)
            {
                _responses_keys[i] = resp.Key;
                _responses_values[i] = resp.Value.ToBase64String();
                i++;
            } 
        }

        bool deserializationStarted = false;
        [OnDeserialized]
        internal void OnDeserialized(StreamingContext context)
        {
            try
            {
                if (_h0 == null)
                {
                    throw new UProveSerializationException("h0");
                }
                if (_CGamma == null)
                {
                    throw new UProveSerializationException("CGamma");
                }
                if (_Ch0 == null)
                {
                    throw new UProveSerializationException("Ch0");
                }
                if (_c == null)
                {
                    throw new UProveSerializationException("c");
                }
                if (_responses_keys == null || _responses_values == null)
                {
                    throw new UProveSerializationException("responses");
                }
                c = _c.ToByteArray();
            }
            catch
            {
                throw;
            }
            finally
            {
                this.deserializationStarted = true;
            }
        }

        void IParametrizedDeserialization.FinishDeserialization(IssuerParameters ip)
        {
            try
            {
                if (!this.deserializationStarted)
                {
                    throw new SerializationException("deserialization not started");
                }
                h0 = _h0.ToGroupElement(ip);
                CGamma = _CGamma.ToGroupElement(ip);
                Ch0 = _Ch0.ToGroupElement(ip);
                if (_responses_values.Length != _responses_keys.Length)
                {
                    throw new UProveSerializationException("number of response keys does not match number of response values");
                }
                responses = new Dictionary<string, FieldZqElement>();
                for (int i = 0; i < _responses_keys.Length; i++)
                {
                    responses.Add(_responses_keys[i], _responses_values[i].ToFieldElement(ip));
                }
                if (presentation != null)
                {
                    (presentation as IParametrizedDeserialization).FinishDeserialization(ip);
                }
            }
            catch
            {
                throw;
            }
            finally
            {
                this.deserializationStarted = false;
            }
        }
        #endregion

    }   // end class
    
}