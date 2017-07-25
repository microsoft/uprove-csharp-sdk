//***********************************************************************************************
//
// This file was imported from the C# Bouncy Castle project. Original license header is retained:
//
//
// The Bouncy Castle Cryptographic C#® API
//
// License:
// 
// The Bouncy Castle License
// Copyright (c) 2000-2014 The Legion of the Bouncy Castle Inc. (http://www.bouncycastle.org)
// Permission is hereby granted, free of charge, to any person obtaining a copy of this software
// and associated documentation files (the "Software"), to deal in the Software without restriction,
// including without limitation the rights to use, copy, modify, merge, publish, distribute,
// sub license, and/or sell copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
// The above copyright notice and this permission notice shall be included in all copies or
// substantial portions of the Software.
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED,
// INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR
// PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
// LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR
// OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
// DEALINGS IN THE SOFTWARE.
//
//***********************************************************************************************

using System;
using System.Collections;

using Org.BouncyCastle.Math.EC.Multiplier;
using Org.BouncyCastle.Math.Field;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Math.EC
{
    /// <remarks>Base class for an elliptic curve.</remarks>
    public abstract class ECCurve
    {
        public const int COORD_AFFINE = 0;
        public const int COORD_HOMOGENEOUS = 1;
        public const int COORD_JACOBIAN = 2;
        public const int COORD_JACOBIAN_CHUDNOVSKY = 3;
        public const int COORD_JACOBIAN_MODIFIED = 4;
        public const int COORD_LAMBDA_AFFINE = 5;
        public const int COORD_LAMBDA_PROJECTIVE = 6;
        public const int COORD_SKEWED = 7;

        public static int[] GetAllCoordinateSystems()
        {
            return new int[]{ COORD_AFFINE, COORD_HOMOGENEOUS, COORD_JACOBIAN, COORD_JACOBIAN_CHUDNOVSKY,
                COORD_JACOBIAN_MODIFIED, COORD_LAMBDA_AFFINE, COORD_LAMBDA_PROJECTIVE, COORD_SKEWED };
        }
     
        // note: Config class removed

        protected readonly IFiniteField m_field;
        protected ECFieldElement m_a, m_b;
        protected BigInteger m_order, m_cofactor;

        protected int m_coord = COORD_AFFINE;
        // note: m_endomorphism variable removed
        protected ECMultiplier m_multiplier = null;

        protected ECCurve(IFiniteField field)
        {
            this.m_field = field;
        }

        public abstract int FieldSize { get; }
        public abstract ECFieldElement FromBigInteger(BigInteger x);

        // note: Configure method removed 

        public virtual ECPoint CreatePoint(BigInteger x, BigInteger y)
        {
            return CreatePoint(x, y, false);
        }

        [Obsolete("Per-point compression property will be removed")]
        public virtual ECPoint CreatePoint(BigInteger x, BigInteger y, bool withCompression)
        {
            return CreateRawPoint(FromBigInteger(x), FromBigInteger(y), withCompression);
        }

        protected abstract ECCurve CloneCurve();

        protected internal abstract ECPoint CreateRawPoint(ECFieldElement x, ECFieldElement y, bool withCompression);

        protected internal abstract ECPoint CreateRawPoint(ECFieldElement x, ECFieldElement y, ECFieldElement[] zs, bool withCompression);

        protected virtual ECMultiplier CreateDefaultMultiplier()
        {
            // note: GLV code removed

            return new WNafL2RMultiplier();
        }

        public virtual bool SupportsCoordinateSystem(int coord)
        {
            return coord == COORD_AFFINE;
        }

        public virtual PreCompInfo GetPreCompInfo(ECPoint point, string name)
        {
            CheckPoint(point);
            lock (point)
            {
                IDictionary table = point.m_preCompTable;
                return table == null ? null : (PreCompInfo)table[name];
            }
        }

        /**
         * Adds <code>PreCompInfo</code> for a point on this curve, under a given name. Used by
         * <code>ECMultiplier</code>s to save the precomputation for this <code>ECPoint</code> for use
         * by subsequent multiplication.
         * 
         * @param point
         *            The <code>ECPoint</code> to store precomputations for.
         * @param name
         *            A <code>String</code> used to index precomputations of different types.
         * @param preCompInfo
         *            The values precomputed by the <code>ECMultiplier</code>.
         */
        public virtual void SetPreCompInfo(ECPoint point, string name, PreCompInfo preCompInfo)
        {
            CheckPoint(point);
            lock (point)
            {
                IDictionary table = point.m_preCompTable;
                if (null == table)
                {
                    point.m_preCompTable = table = Platform.CreateHashtable(4);
                }
                table[name] = preCompInfo;
            }
        }

        public virtual ECPoint ImportPoint(ECPoint p)
        {
            if (this == p.Curve)
            {
                return p;
            }
            if (p.IsInfinity)
            {
                return Infinity;
            }

            // TODO Default behaviour could be improved if the two curves have the same coordinate system by copying any Z coordinates.
            p = p.Normalize();

            return CreatePoint(p.XCoord.ToBigInteger(), p.YCoord.ToBigInteger(), p.IsCompressed);
        }

        /**
         * Normalization ensures that any projective coordinate is 1, and therefore that the x, y
         * coordinates reflect those of the equivalent point in an affine coordinate system. Where more
         * than one point is to be normalized, this method will generally be more efficient than
         * normalizing each point separately.
         * 
         * @param points
         *            An array of points that will be updated in place with their normalized versions,
         *            where necessary
         */
        public virtual void NormalizeAll(ECPoint[] points)
        {
            CheckPoints(points);

            if (this.CoordinateSystem == ECCurve.COORD_AFFINE)
            {
                return;
            }

            /*
             * Figure out which of the points actually need to be normalized
             */
            ECFieldElement[] zs = new ECFieldElement[points.Length];
            int[] indices = new int[points.Length];
            int count = 0;
            for (int i = 0; i < points.Length; ++i)
            {
                ECPoint p = points[i];
                if (null != p && !p.IsNormalized())
                {
                    zs[count] = p.GetZCoord(0);
                    indices[count++] = i;
                }
            }

            if (count == 0)
            {
                return;
            }

            ECAlgorithms.MontgomeryTrick(zs, 0, count);

            for (int j = 0; j < count; ++j)
            {
                int index = indices[j];
                points[index] = points[index].Normalize(zs[j]);
            }
        }

        public abstract ECPoint Infinity { get; }

        public virtual IFiniteField Field
        {
            get { return m_field; }
        }

        public virtual ECFieldElement A
        {
            get { return m_a; }
        }

        public virtual ECFieldElement B
        {
            get { return m_b; }
        }

        public virtual BigInteger Order
        {
            get { return m_order; }
        }

        public virtual BigInteger Cofactor
        {
            get { return m_cofactor; }
        }

        public virtual int CoordinateSystem
        {
            get { return m_coord; }
        }

        protected virtual void CheckPoint(ECPoint point)
        {
            if (null == point || (this != point.Curve))
                throw new ArgumentException("must be non-null and on this curve", "point");
        }

        protected virtual void CheckPoints(ECPoint[] points)
        {
            if (points == null)
                throw new ArgumentNullException("points");

            for (int i = 0; i < points.Length; ++i)
            {
                ECPoint point = points[i];
                if (null != point && this != point.Curve)
                    throw new ArgumentException("entries must be null or on this curve", "points");
            }
        }

        public virtual bool Equals(ECCurve other)
        {
            if (this == other)
                return true;
            if (null == other)
                return false;
            return Field.Equals(other.Field)
                && A.ToBigInteger().Equals(other.A.ToBigInteger())
                && B.ToBigInteger().Equals(other.B.ToBigInteger());
        }

        public override bool Equals(object obj)
        {
            return Equals(obj as ECCurve);
        }

        public override int GetHashCode()
        {
            return Field.GetHashCode()
                ^ Integers.RotateLeft(A.ToBigInteger().GetHashCode(), 8)
                ^ Integers.RotateLeft(B.ToBigInteger().GetHashCode(), 16);
        }

        protected abstract ECPoint DecompressPoint(int yTilde, BigInteger X1);

        // note: GetEndomorphism method removed
 
        /**
         * Sets the default <code>ECMultiplier</code>, unless already set. 
         */
        public virtual ECMultiplier GetMultiplier()
        {
            lock (this)
            {
                if (this.m_multiplier == null)
                {
                    this.m_multiplier = CreateDefaultMultiplier();
                }
                return this.m_multiplier;
            }
        }

        /**
         * Decode a point on this curve from its ASN.1 encoding. The different
         * encodings are taken account of, including point compression for
         * <code>F<sub>p</sub></code> (X9.62 s 4.2.1 pg 17).
         * @return The decoded point.
         */
        public virtual ECPoint DecodePoint(byte[] encoded)
        {
            ECPoint p = null;
            int expectedLength = (FieldSize + 7) / 8;

            switch (encoded[0])
            {
                case 0x00: // infinity
                    {
                        if (encoded.Length != 1)
                            throw new ArgumentException("Incorrect length for infinity encoding", "encoded");

                        p = Infinity;
                        break;
                    }

                case 0x02: // compressed
                case 0x03: // compressed
                    {
                        if (encoded.Length != (expectedLength + 1))
                            throw new ArgumentException("Incorrect length for compressed encoding", "encoded");

                        int yTilde = encoded[0] & 1;
                        BigInteger X1 = new BigInteger(1, encoded, 1, expectedLength);

                        p = DecompressPoint(yTilde, X1);
                        break;
                    }

                case 0x04: // uncompressed
                case 0x06: // hybrid
                case 0x07: // hybrid
                    {
                        if (encoded.Length != (2 * expectedLength + 1))
                            throw new ArgumentException("Incorrect length for uncompressed/hybrid encoding", "encoded");

                        BigInteger X1 = new BigInteger(1, encoded, 1, expectedLength);
                        BigInteger Y1 = new BigInteger(1, encoded, 1 + expectedLength, expectedLength);

                        p = CreatePoint(X1, Y1);
                        break;
                    }

                default:
                    throw new FormatException("Invalid point encoding " + encoded[0]);
            }

            return p;
        }
    }

    /**
     * Elliptic curve over Fp
     */
    public class FpCurve
        : ECCurve
    {
        private const int FP_DEFAULT_COORDS = COORD_JACOBIAN_MODIFIED;

        protected readonly BigInteger m_q, m_r;
        protected readonly FpPoint m_infinity;

        public FpCurve(BigInteger q, BigInteger a, BigInteger b)
            : this(q, a, b, null, null)
        {
        }

        public FpCurve(BigInteger q, BigInteger a, BigInteger b, BigInteger order, BigInteger cofactor)
            : base(FiniteFields.GetPrimeField(q))
        {
            this.m_q = q;
            this.m_r = FpFieldElement.CalculateResidue(q);
            this.m_infinity = new FpPoint(this, null, null);

            this.m_a = FromBigInteger(a);
            this.m_b = FromBigInteger(b);
            this.m_order = order;
            this.m_cofactor = cofactor;
            this.m_coord = FP_DEFAULT_COORDS;
        }

        protected FpCurve(BigInteger q, BigInteger r, ECFieldElement a, ECFieldElement b)
            : this(q, r, a, b, null, null)
        {
        }

        protected FpCurve(BigInteger q, BigInteger r, ECFieldElement a, ECFieldElement b, BigInteger order, BigInteger cofactor)
            : base(FiniteFields.GetPrimeField(q))
        {
            this.m_q = q;
            this.m_r = r;
            this.m_infinity = new FpPoint(this, null, null);

            this.m_a = a;
            this.m_b = b;
            this.m_order = order;
            this.m_cofactor = cofactor;
            this.m_coord = FP_DEFAULT_COORDS;
        }

        protected override ECCurve CloneCurve()
        {
            return new FpCurve(m_q, m_r, m_a, m_b, m_order, m_cofactor);
        }

        public override bool SupportsCoordinateSystem(int coord)
        {
            switch (coord)
            {
                case COORD_AFFINE:
                case COORD_HOMOGENEOUS:
                case COORD_JACOBIAN:
                case COORD_JACOBIAN_MODIFIED:
                    return true;
                default:
                    return false;
            }
        }

        public virtual BigInteger Q
        {
            get { return m_q; }
        }

        public override ECPoint Infinity
        {
            get { return m_infinity; }
        }

        public override int FieldSize
        {
            get { return m_q.BitLength; }
        }

        public override ECFieldElement FromBigInteger(BigInteger x)
        {
            return new FpFieldElement(this.m_q, this.m_r, x);
        }

        protected internal override ECPoint CreateRawPoint(ECFieldElement x, ECFieldElement y, bool withCompression)
        {
            return new FpPoint(this, x, y, withCompression);
        }

        protected internal override ECPoint CreateRawPoint(ECFieldElement x, ECFieldElement y, ECFieldElement[] zs, bool withCompression)
        {
            return new FpPoint(this, x, y, zs, withCompression);
        }

        public override ECPoint ImportPoint(ECPoint p)
        {
            if (this != p.Curve && this.CoordinateSystem == COORD_JACOBIAN && !p.IsInfinity)
            {
                switch (p.Curve.CoordinateSystem)
                {
                    case COORD_JACOBIAN:
                    case COORD_JACOBIAN_CHUDNOVSKY:
                    case COORD_JACOBIAN_MODIFIED:
                        return new FpPoint(this,
                            FromBigInteger(p.RawXCoord.ToBigInteger()),
                            FromBigInteger(p.RawYCoord.ToBigInteger()),
                            new ECFieldElement[] { FromBigInteger(p.GetZCoord(0).ToBigInteger()) },
                            p.IsCompressed);
                    default:
                        break;
                }
            }

            return base.ImportPoint(p);
        }

        protected override ECPoint DecompressPoint(int yTilde, BigInteger X1)
        {
            ECFieldElement x = FromBigInteger(X1);
            ECFieldElement alpha = x.Square().Add(m_a).Multiply(x).Add(m_b);
            ECFieldElement beta = alpha.Sqrt();

            //
            // if we can't find a sqrt we haven't got a point on the
            // curve - run!
            //
            if (beta == null)
                throw new ArithmeticException("Invalid point compression");

            if (beta.TestBitZero() != (yTilde == 1))
            {
                // Use the other root
                beta = beta.Negate();
            }

            return new FpPoint(this, x, beta, true);
        }
    }

    // note: F2mCurve class deleted
}
