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

using System.ComponentModel;
using System.Runtime.Serialization;
using UProveCrypto.Math;

/*
 * Simple classes to hold values in issuance protocol messages. 
*/

namespace UProveCrypto
{
    /// <summary>
    /// Class to hold values in the first message of the issuance protocol.
    /// Sent from Issuer to Prover.
    /// </summary>
    [DataContract]
    public class FirstIssuanceMessage : IParametrizedDeserialization
    {

        /// <summary> The protocol value sigma_z </summary>
        public GroupElement sigmaZ { get; internal set; }

        /// <summary> The protocol value sigma_a </summary>
        public GroupElement[] sigmaA { get; internal set; }

        /// <summary> The protocol value sigma_b </summary>
        public GroupElement[] sigmaB { get; internal set; }

        /// <summary>
        /// Create a first issuance message. Notation defined in the U-Prove spec.
        /// </summary>
        public FirstIssuanceMessage(GroupElement sigmaZ, GroupElement[] sigmaA, GroupElement[] sigmaB)
        {
            this.sigmaA = sigmaA;
            this.sigmaB = sigmaB;
            this.sigmaZ = sigmaZ;
        }


        #region Serialization

        [DataMember(Name = "sz")]
        [EditorBrowsable(EditorBrowsableState.Never)]
        internal string _sigmaZ;

        [DataMember(Name = "sa")]
        [EditorBrowsable(EditorBrowsableState.Never)]
        internal string[] _sigmaA;

        [DataMember(Name = "sb")]
        [EditorBrowsable(EditorBrowsableState.Never)]
        internal string[] _sigmaB;

        [OnSerializing]
        [EditorBrowsable(EditorBrowsableState.Never)]
        internal void OnSerializing(StreamingContext context)
        {
            _sigmaZ = this.sigmaZ.ToBase64String();
            _sigmaA = this.sigmaA.ToBase64StringArray();
            _sigmaB = this.sigmaB.ToBase64StringArray();
        }

        bool deserializationStarted = false;
        [OnDeserialized]
        [EditorBrowsable(EditorBrowsableState.Never)]
        internal void OnDeserialized(StreamingContext context)
        {
            if (_sigmaZ == null)
                throw new UProveSerializationException("sz");
            if (_sigmaA == null)
                throw new UProveSerializationException("sa");
            if (_sigmaB == null)
                throw new UProveSerializationException("sb");

            deserializationStarted = true;
        }

        void IParametrizedDeserialization.FinishDeserialization(IssuerParameters ip)
        {
            try
            {
                if (!this.deserializationStarted)
                {
                    throw new SerializationException("deserialization not started");
                }

                this.sigmaZ = _sigmaZ.ToGroupElement(ip.Gq);
                this.sigmaA = _sigmaA.ToGroupElementArray(ip.Gq);
                this.sigmaB = _sigmaB.ToGroupElementArray(ip.Gq);

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

        #endregion Serialization

    }

    /// <summary>
    /// Class to hold values in the second message of the issuance protocol.
    /// Sent from Prover to Issuer.
    /// </summary>
    [DataContract]
    public class SecondIssuanceMessage : IParametrizedDeserialization
    {
        /// <summary>
        /// The sigma_c protocol value. 
        /// </summary>
        public FieldZqElement[] sigmaC { get; internal set; }

        /// <summary>
        /// Create a second issuance message. Notation defined in the U-Prove spec.
        /// </summary>
        public SecondIssuanceMessage(FieldZqElement[] sigmaC)
        {
            this.sigmaC = sigmaC;
        }

        #region Serialization

        [DataMember(Name = "sc")]
        [EditorBrowsable(EditorBrowsableState.Never)]
        internal string[] _sigmaC;

        [OnSerializing]
        [EditorBrowsable(EditorBrowsableState.Never)]
        internal void OnSerializing(StreamingContext context)
        {
            _sigmaC = this.sigmaC.ToBase64StringArray();
        }

        bool deserializationStarted = false;
        [OnDeserialized]
        [EditorBrowsable(EditorBrowsableState.Never)]
        internal void OnDeserialized(StreamingContext context)
        {
            if (_sigmaC == null)
                throw new UProveSerializationException("sc");

            deserializationStarted = true;
        }

        void IParametrizedDeserialization.FinishDeserialization(IssuerParameters ip)
        {
            try
            {
                if (!this.deserializationStarted)
                {
                    throw new SerializationException("deserialization not started");
                }

                this.sigmaC = _sigmaC.ToFieldElementArray(ip.Zq);
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

        #endregion Serialization

    }

    /// <summary>
    /// Class to hold values in the third message of the issuance protocol.
    /// Final message of issuance, sent from Issuer to Prover. 
    /// </summary>
    [DataContract]
    public class ThirdIssuanceMessage : IParametrizedDeserialization
    {
        /// <summary>
        /// The sigma_r protocol value. 
        /// </summary>
        public FieldZqElement[] sigmaR { get; internal set; }

        /// <summary>
        /// Create a third issuance message. Notation defined in the U-Prove spec.
        /// </summary>
        public ThirdIssuanceMessage(FieldZqElement[] sigmaR)
        {
            this.sigmaR = sigmaR;
        }

        #region Serialization

        [DataMember(Name = "sr")]
        [EditorBrowsable(EditorBrowsableState.Never)]
        internal string[] _sigmaR;

        [OnSerializing]
        [EditorBrowsable(EditorBrowsableState.Never)]
        internal void OnSerializing(StreamingContext context)
        {
            _sigmaR = this.sigmaR.ToBase64StringArray();
        }

        bool deserializationStarted = false;
        [OnDeserialized]
        [EditorBrowsable(EditorBrowsableState.Never)]
        internal void OnDeserialized(StreamingContext context)
        {
            if (_sigmaR == null)
                throw new UProveSerializationException("sr");

            deserializationStarted = true;
        }

        void IParametrizedDeserialization.FinishDeserialization(IssuerParameters ip)
        {
            try
            {
                if (!this.deserializationStarted)
                {
                    throw new SerializationException("deserialization not started");
                }
                this.sigmaR = _sigmaR.ToFieldElementArray(ip.Zq);
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


        #endregion Serialization
    }

}
