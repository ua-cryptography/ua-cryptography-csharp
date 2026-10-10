using UA.Cryptography.Math;

namespace UA.Cryptography.EC;

/// <summary>Immutable point of a <see cref="BinaryCurve"/> in affine coordinates, or the point at infinity O.</summary>
public sealed class CurvePoint : IEquatable<CurvePoint>
{
    internal CurvePoint(BinaryCurve curve, FieldElement? x, FieldElement? y)
    {
        Curve = curve;
        X = x;
        Y = y;
    }

    public BinaryCurve Curve { get; }

    /// <summary>Affine x, null for the point at infinity.</summary>
    public FieldElement? X { get; }

    /// <summary>Affine y, null for the point at infinity.</summary>
    public FieldElement? Y { get; }

    public bool IsInfinity => X is null;

    /// <summary>Affine x of a finite point.</summary>
    public FieldElement AffineX => X ?? throw new InvalidOperationException("The point at infinity has no affine coordinates.");

    /// <summary>Affine y of a finite point.</summary>
    public FieldElement AffineY => Y ?? throw new InvalidOperationException("The point at infinity has no affine coordinates.");

    public CurvePoint Negate() => Curve.Negate(this);

    public CurvePoint Add(CurvePoint other) => Curve.Add(this, other);

    public CurvePoint Twice() => Curve.Double(this);

    public CurvePoint Multiply(System.Numerics.BigInteger k) => Curve.Multiply(this, k);

    public static CurvePoint operator +(CurvePoint a, CurvePoint b) => a.Add(b);

    public static CurvePoint operator -(CurvePoint a) => a.Negate();

    public static CurvePoint operator -(CurvePoint a, CurvePoint b) => a.Add(b.Negate());

    public static CurvePoint operator *(System.Numerics.BigInteger k, CurvePoint p) => p.Multiply(k);

    public bool Equals(CurvePoint? other)
    {
        if (other is null || !Curve.Equals(other.Curve))
            return false;
        if (IsInfinity || other.IsInfinity)
            return IsInfinity && other.IsInfinity;
        return X!.Equals(other.X) && Y!.Equals(other.Y);
    }

    public override bool Equals(object? obj) => obj is CurvePoint p && Equals(p);

    public override int GetHashCode() => IsInfinity ? 0 : HashCode.Combine(X, Y);

    public override string ToString() => IsInfinity ? "O" : $"({X!.ToHex()}, {Y!.ToHex()})";
}
