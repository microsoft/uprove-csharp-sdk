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

using Org.BouncyCastle.Math;
using Org.BouncyCastle.Math.EC;
using UProveParams;

namespace UProveTestVectors
{
    public abstract class Group
    {
        public string OID { get; internal set; }
        public abstract GroupElement Identity { get; }
        public abstract BigInteger Order { get; }
        public abstract GroupElement Generator { get; }
    }

    public class P256ECGroup : Group
    {
        public P256ECGroup()
        {
            OID = RecommendedParameters.P256.Oid;
        }

        public override GroupElement Identity
        {
            get { return new ECElement(RecommendedParameters.P256.parameters.Curve.Infinity as FpPoint); }
        }

        public override BigInteger Order
        {
            get { return RecommendedParameters.P256.parameters.N; }
        }

        public override GroupElement Generator
        {
            get { return new ECElement(RecommendedParameters.P256.g); }
        }

    }

    public abstract class GroupElement
    {
        public abstract GroupElement Multiply(GroupElement other);
        public abstract GroupElement Exponentiate(BigInteger exponent);
        public abstract void Print(string varLabel, string varType, string varNamespace, Formatter formatter);
        public void Print(string varLabel, Formatter formatter)     
        {
            Print(varLabel, null, null, formatter);
        }
        public abstract byte[] ToByteArray();
        public abstract string ToString(int radix = 16);
    }

    public class ECElement : GroupElement
    {
        public FpPoint point;
        public ECElement(FpPoint point)
        {
            this.point = point;
        }

        public override GroupElement Multiply(GroupElement other)
        {
            return new ECElement(point.Add((other as ECElement).point) as FpPoint);
        }

        public override GroupElement Exponentiate(BigInteger exponent)
        {
            return new ECElement(point.Multiply(exponent) as FpPoint);
        }

        public override void Print(string varLabel, string varType, string varNamespace, Formatter formatter)
        {
            formatter.PrintPoint(varLabel, varType, varNamespace, point);
        }

        public override byte[] ToByteArray()
        {
            return point.GetEncoded();
        }

        public override bool Equals(object o)
        {
            if (o == null) { return false; }
            ECElement e = o as ECElement;
            if ((System.Object)e == null)
            {
                return false;
            }
            return point.Equals(e.point);
        }

        public override string ToString(int radix = 16)
        {
            return "x=" + point.XCoord.ToBigInteger().ToString(radix) + "," + "y=" + point.YCoord.ToBigInteger().ToString(radix);
        }

    }
}
