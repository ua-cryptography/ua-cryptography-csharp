using System.Numerics;

namespace UA.Cryptography.Math;

/// <summary>Immutable element of a <see cref="BinaryField"/>.</summary>
public sealed class FieldElement : IEquatable<FieldElement>
{
    private readonly ulong[] _value; // internal representation, owned

    internal FieldElement(BinaryField field, ulong[] value)
    {
        Field = field;
        _value = value;
    }

    public BinaryField Field { get; }

    internal ReadOnlySpan<ulong> Value => _value;

    public bool IsZero => Gf2Poly.IsZero(_value);

    public bool IsOne => Equals(Field.One);

    public static FieldElement operator +(FieldElement a, FieldElement b)
    {
        CheckSameField(a, b);
        var r = new ulong[a.Field.Words];
        BinaryField.Add(a._value, b._value, r);
        return new FieldElement(a.Field, r);
    }

    /// <summary>Subtraction equals addition in characteristic 2.</summary>
    public static FieldElement operator -(FieldElement a, FieldElement b) => a + b;

    public static FieldElement operator *(FieldElement a, FieldElement b)
    {
        CheckSameField(a, b);
        var r = new ulong[a.Field.Words];
        a.Field.Multiply(a._value, b._value, r);
        return new FieldElement(a.Field, r);
    }

    public static FieldElement operator /(FieldElement a, FieldElement b) => a * b.Invert();

    public FieldElement Square()
    {
        var r = new ulong[Field.Words];
        Field.Square(_value, r);
        return new FieldElement(Field, r);
    }

    /// <summary>this^(2^k).</summary>
    public FieldElement SquareTimes(int k)
    {
        var r = new ulong[Field.Words];
        Field.SquareTimes(_value, k, r);
        return new FieldElement(Field, r);
    }

    public FieldElement Invert()
    {
        if (IsZero)
            throw new DivideByZeroException("Zero has no inverse in a field.");
        var r = new ulong[Field.Words];
        Field.Invert(_value, r);
        return new FieldElement(Field, r);
    }

    public FieldElement Sqrt()
    {
        var r = new ulong[Field.Words];
        Field.Sqrt(_value, r);
        return new FieldElement(Field, r);
    }

    /// <summary>Trace (DSTU 4145-2002, 6.5): 0 or 1.</summary>
    public int Trace() => Field.Trace(_value);

    /// <summary>Half-trace (DSTU 4145-2002, 6.6), odd m only.</summary>
    public FieldElement HalfTrace()
    {
        var r = new ulong[Field.Words];
        Field.HalfTrace(_value, r);
        return new FieldElement(Field, r);
    }

    /// <summary>Standard representation (DSTU 4145-2002, 5.3) as a non-negative integer.</summary>
    public BigInteger ToBigInteger()
    {
        var std = new ulong[Field.StandardWords];
        Field.ToStandard(_value, std);
        return BinaryField.WordsToBigInteger(std);
    }

    /// <summary>Standard representation as hex, padded to the full field width.</summary>
    public string ToHex() => Hex.FromBigInteger(ToBigInteger(), (Field.M + 3) / 4);

    /// <summary>Bit i of the standard representation.</summary>
    public bool TestBit(int i) => !(ToBigInteger() >> i).IsEven;

    public bool Equals(FieldElement? other) =>
        other is not null && Field.Equals(other.Field) && _value.AsSpan().SequenceEqual(other._value);

    public override bool Equals(object? obj) => obj is FieldElement e && Equals(e);

    public override int GetHashCode()
    {
        var hash = new HashCode();
        foreach (ulong w in _value)
            hash.Add(w);
        return hash.ToHashCode();
    }

    public override string ToString() => ToHex();

    private static void CheckSameField(FieldElement a, FieldElement b)
    {
        if (!ReferenceEquals(a.Field, b.Field) && !a.Field.Equals(b.Field))
            throw new ArgumentException("Elements belong to different fields.");
    }
}
