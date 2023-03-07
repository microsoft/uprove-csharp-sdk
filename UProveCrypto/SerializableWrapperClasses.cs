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

using System.Runtime.Serialization;
using UProveCrypto.Math;

namespace UProveCrypto
{

    #region Serializable Wrapper Classes

    /// <summary>
    /// This class is a serializable version of Group used only during serialization.
    /// Serializing Group will result in the creation and serialization of this class instead.
    /// This class is also created upon deserialization. The ToGroup() method will be called
    /// by the surrogate class to create a new Group from this class.
    /// </summary>
    [DataContract]
    public class GroupSerializable
    {
        /// <summary>
        /// The type of the group.
        /// </summary>
        [DataMember(Order=0)]
        public string type;

        /// <summary>
        /// The name of the group.
        /// </summary>
        [DataMember(Name = "name", Order = 1, EmitDefaultValue = false)]
        public string name;

        /// <summary>
        /// Construct a GroupSerializable object from a Group object.
        /// </summary>
        /// <param name="group">The Group object being serialized.</param>
        public GroupSerializable(Group group)
        {
            if (this.InRecommendedGroup(group.GroupName))
            {
                this.type = "named";
                this.name = group.GroupName;
            }
            else if (group.Type == GroupType.ECC)
            {
                this.type = "ec";
                this.name = null;
            }
            else
            {
                throw new UProveSerializationException("Invalid GroupConstruction");
            }

            return;
        }

        /// <summary>
        /// Deserialize this object into a Group object.
        /// </summary>
        /// <returns>The Group object represented by this GroupSerializable object.</returns>
        public Group ToGroup()
        {
            ParameterSet parameterSet;

            switch (type)
            {
                case "named":
                    if (ParameterSet.TryGetNamedParameterSet(name, out parameterSet) == false)
                        throw new UProveSerializationException("Unsupported named group :" + this.name);
                    break;

                default:
                    throw new UProveSerializationException("Invalid GroupConstruction: " + this.type);
            }

            return parameterSet.Group;
        }

        private bool InRecommendedGroup(string groupName)
        {
            switch (groupName)
            {
                case ECParameterSets.ParamSet_EC_P256_V1Name:
                case ECParameterSets.ParamSet_EC_P384_V1Name:
                case ECParameterSets.ParamSet_EC_P521_V1Name:
                case ECParameterSets.ParamSet_EC_BN254_V1Name:
                    return true;

                default:
                    return false;
            }
        }

    }

    #endregion

}
