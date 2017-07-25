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
using System.IO;
using System.Runtime.Serialization;
using System.Runtime.Serialization.Json;
using System.Text;

namespace UProveCrypto
{
    /// <summary>
    /// Defines an object that requires an <code>IssuerParameters</code> instance to
    /// complete the deserialization of an object.
    /// </summary>
    public interface IParametrizedDeserialization
    {
        /// <summary>
        /// Completes the deserialization of the object.
        /// </summary>
        /// <param name="ip">The Issuer parameters used to parse the algebraic elements.</param>
        void FinishDeserialization(IssuerParameters ip);
    }

    /// <summary>
    /// An object used for serializing various U-Prove types.
    /// </summary>
    public class Serializer
    {

        private static Type[] knownTypes = new Type[] { };

        internal string GetJson<T>(T obj)
        {
            string result;

            try
            {
                using (MemoryStream ms = new MemoryStream())
                {
                    DataContractJsonSerializer jsonSerializer =
                        new DataContractJsonSerializer(typeof(T), Serializer.knownTypes);

                    jsonSerializer.WriteObject(ms, obj);
                    ms.Position = 0;

                    StreamReader reader = new StreamReader(ms);
                    result = reader.ReadToEnd();
                }
            }
            catch (UProveSerializationException exp)
            {
                throw new SerializationException(typeof(T).Name + ":" + exp.Field);
            }
            catch (Exception exp)
            {
                throw new SerializationException(typeof(T).Name, exp);
            }

            return result;
        }

        internal T FromJson<T>(string jsonString)
        {
            T result = default(T);

            UTF8Encoding encoding = new UTF8Encoding();
            byte[] bytes = encoding.GetBytes(jsonString);

            try
            {
                using (MemoryStream ms = new MemoryStream(bytes))
                {
                    DataContractJsonSerializer jsonSerializer =
                        new DataContractJsonSerializer(typeof(T), Serializer.knownTypes);

                    result = (T)jsonSerializer.ReadObject(ms);
                }
            }
            catch (UProveSerializationException exp)
            {
                throw new SerializationException(typeof(T).Name + ":" + exp.Field);
            }
            catch (Exception exp)
            {
                throw new SerializationException(typeof(T).Name, exp);
            }

            return result;
        }
    }

    /// <summary>
    /// An exception caused in the process of serializing U-Prove types.
    /// </summary>
    public class UProveSerializationException : Exception
    {
        internal UProveSerializationException()
        {

        }

        /// <summary>
        /// Construct a serialization exception.
        /// </summary>
        /// <param name="fieldName">The name of the field being serialized/deserialized.</param>
        public UProveSerializationException(string fieldName)
        {
            this.Field = fieldName;
        }

        internal string Field
        {
            get;
            set;
        }
    }
}