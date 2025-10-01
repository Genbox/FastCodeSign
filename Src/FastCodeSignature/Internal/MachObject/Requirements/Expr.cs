using System.Formats.Asn1;
using System.Globalization;
using System.Text;
using Genbox.FastCodeSignature.Internal.MachObject.Requirements.Enums;
using static Genbox.FastCodeSignature.Internal.Helpers.ByteHelper;

namespace Genbox.FastCodeSignature.Internal.MachObject.Requirements;

// Dumper: https://github.com/apple-oss-distributions/Security/blob/3dab46a11f45f2ffdbd70e2127cc5a8ce4a1f222/OSX/libsecurity_codesigning/lib/reqdumper.cpp#L137
// Maker: https://github.com/apple-oss-distributions/Security/blob/3dab46a11f45f2ffdbd70e2127cc5a8ce4a1f222/OSX/libsecurity_codesigning/lib/reqmaker.cpp
public abstract class Expr
{
    private static readonly DateTime Epoc = new DateTime(2001, 1, 1, 0, 0, 0, DateTimeKind.Utc);

    public abstract int Size { get; }
    public abstract void Write(Span<byte> buffer);
    public new abstract string ToString();

    public static Expr False { get; } = new SimpleExpr(ExprOp.False);
    public static Expr True { get; } = new SimpleExpr(ExprOp.True);
    public static Expr AppleAnchor { get; } = new SimpleExpr(ExprOp.AppleAnchor);
    public static Expr TrustedCerts { get; } = new SimpleExpr(ExprOp.TrustedCerts);
    public static Expr AppleGenericAnchor { get; } = new SimpleExpr(ExprOp.AppleGenericAnchor);
    public static Expr Notarized { get; } = new SimpleExpr(ExprOp.Notarized);
    public static Expr LegacyDevId { get; } = new SimpleExpr(ExprOp.LegacyDevId);
    public static Expr Ident(string identifier) => new StringExpr(ExprOp.Ident, identifier);
    public static Expr AnchorHash(int certificateIndex, byte[] anchorHash) => new AnchorHashExpr(certificateIndex, anchorHash);
    public static Expr InfoKeyValue(string field, string matchValue) => new InfoKeyValueExpr(field, Encoding.ASCII.GetBytes(matchValue));
    public static Expr And(Expr left, Expr right) => new BinaryOperatorExpr(ExprOp.And, left, right);
    public static Expr Or(Expr left, Expr right) => new BinaryOperatorExpr(ExprOp.Or, left, right);
    public static Expr CdHash(byte[] codeDirectoryHash) => new CdHashExpr(codeDirectoryHash);
    public static Expr Not(Expr inner) => new UnaryOperatorExpr(ExprOp.Not, inner);
    public static Expr InfoKeyField(string field, MatchOperation matchOperation, string? matchValue = null) => new FieldMatchExpr(ExprOp.InfoKeyField, field, matchOperation, matchValue != null ? Encoding.ASCII.GetBytes(matchValue) : null);
    public static Expr CertField(int certificateIndex, string certificateField, MatchOperation matchOperation, string? matchValue = null) => new CertExpr(ExprOp.CertField, certificateIndex, Encoding.ASCII.GetBytes(certificateField), matchOperation, matchValue != null ? Encoding.ASCII.GetBytes(matchValue) : null);
    public static Expr TrustedCert(int certificateIndex) => new TrustedCertExpr(certificateIndex);
    public static Expr CertGeneric(int certificateIndex, string certificateFieldOid, MatchOperation matchOperation, string? matchValue = null) => new CertExpr(ExprOp.CertGeneric, certificateIndex, GetOidBytes(certificateFieldOid).ToArray(), matchOperation, matchValue != null ? Encoding.ASCII.GetBytes(matchValue) : null);
    public static Expr EntitlementField(string field, MatchOperation matchOperation, string? matchValue = null) => new FieldMatchExpr(ExprOp.EntitlementField, field, matchOperation, matchValue != null ? Encoding.ASCII.GetBytes(matchValue) : null);
    public static Expr NamedAnchor(string anchorName) => new NamedExpr(ExprOp.NamedAnchor, Encoding.ASCII.GetBytes(anchorName));
    public static Expr NamedCode(string code) => new NamedExpr(ExprOp.NamedCode, Encoding.ASCII.GetBytes(code));
    public static Expr Platform(MachPlatform platform) => new PlatformExpr(platform);

    private static ReadOnlySpan<byte> GetData(ReadOnlySpan<byte> expr) => expr.Slice(4, ReadInt32BigEndian(expr));

    private static ReadOnlySpan<byte> GetMatchData(ReadOnlySpan<byte> expr, MatchOperation matchOperation)
    {
        if (matchOperation != MatchOperation.Exists && matchOperation != MatchOperation.Absent)
            return GetData(expr);

        return ReadOnlySpan<byte>.Empty;
    }

    private static ReadOnlySpan<byte> GetOidBytes(string oid)
    {
        AsnWriter asnWriter = new AsnWriter(AsnEncodingRules.DER);
        asnWriter.WriteObjectIdentifier(oid);
        return asnWriter.Encode().AsSpan(2);
    }

    private static string BinaryValueToString(byte[] bytes) => $"0x{Convert.ToHexStringLower(bytes)}";

    private static string ValueToString(byte[] bytes)
    {
        bool isPrintable = Array.TrueForAll(bytes, c => !char.IsControl((char)c) && char.IsAscii((char)c));

        if (!isPrintable)
            return BinaryValueToString(bytes);

        bool needQuoting = bytes.Length == 0 || char.IsDigit((char)bytes[0]) || Array.Exists(bytes, c => !char.IsLetterOrDigit((char)c));

        if (!needQuoting)
            return Encoding.ASCII.GetString(bytes);

        StringBuilder sb = new StringBuilder();
        sb.Append('"');
        foreach (byte c in bytes)
        {
            if (c is (byte)'\\' or (byte)'"')
                sb.Append('\\');

            sb.Append((char)c);
        }

        sb.Append('"');
        return sb.ToString();
    }

    private static string CertificateSlotToString(int slot) => slot switch
    {
        0 => "leaf",
        -1 => "root",
        _ => slot.ToString(CultureInfo.InvariantCulture)
    };

    private sealed class SimpleExpr(ExprOp op) : Expr
    {
        public override int Size => 4;

        public override void Write(Span<byte> buffer)
        {
            WriteUInt32BigEndian(buffer, (uint)op);
        }

        public override string ToString() => op switch
        {
            ExprOp.False => "never",
            ExprOp.True => "always",
            ExprOp.AppleAnchor => "anchor apple",
            ExprOp.AppleGenericAnchor => "anchor apple generic",
            ExprOp.TrustedCerts => "anchor trusted",
            ExprOp.Notarized => "notarized",
            ExprOp.LegacyDevId => "legacy",
            _ => "unknown"
        };
    }

    private sealed class BinaryOperatorExpr(ExprOp op, Expr left, Expr right) : Expr
    {
        private ExprOp Operation { get; } = op;

        public override int Size => 4 + left.Size + right.Size;

        public override void Write(Span<byte> buffer)
        {
            WriteUInt32BigEndian(buffer, (uint)Operation);
            left.Write(buffer[4..]);
            right.Write(buffer[(4 + left.Size)..]);
        }

        private string WrapInnerExpression(Expr innerExpression)
        {
            if (innerExpression is BinaryOperatorExpr boe && boe.Operation != Operation)
                return $"({boe.ToString()})";

            return innerExpression.ToString();
        }

        public override string ToString() => Operation switch
        {
            ExprOp.And => $"{WrapInnerExpression(left)} and {WrapInnerExpression(right)}",
            ExprOp.Or => $"{WrapInnerExpression(left)} or {WrapInnerExpression(right)}",
            _ => "unknown"
        };
    }

    private sealed class UnaryOperatorExpr(ExprOp op, Expr inner) : Expr
    {
        public override int Size => 4 + inner.Size;

        public override void Write(Span<byte> buffer)
        {
            WriteUInt32BigEndian(buffer, (uint)op);
            inner.Write(buffer[4..]);
        }

        public override string ToString() => op switch
        {
            ExprOp.Not => $"! {inner}",
            _ => "unknown"
        };
    }

    private sealed class StringExpr(ExprOp op, string opString) : Expr
    {
        public override int Size => 8 + Align(Encoding.UTF8.GetByteCount(opString), 4);

        public override void Write(Span<byte> buffer)
        {
            byte[] opStringBytes = Encoding.UTF8.GetBytes(opString);
            WriteUInt32BigEndian(buffer, (uint)op);
            WriteInt32BigEndian(buffer[4..], opStringBytes.Length);
            opStringBytes.CopyTo(buffer.Slice(8, opStringBytes.Length));
            buffer.Slice(8 + opStringBytes.Length, Align(opStringBytes.Length, 4) - opStringBytes.Length).Clear();
        }

        public override string ToString() => op switch
        {
            ExprOp.Ident => $"identifier \"{opString}\"",
            _ => "unknown"
        };
    }

    private sealed class CdHashExpr(byte[] codeDirectoryHash) : Expr
    {
        public override int Size => 4 + codeDirectoryHash.Length;

        public override void Write(Span<byte> buffer)
        {
            WriteUInt32BigEndian(buffer, (uint)ExprOp.CdHash);
            codeDirectoryHash.CopyTo(buffer.Slice(4, codeDirectoryHash.Length));
        }

        public override string ToString() => $"cdhash H\"{Convert.ToHexString(codeDirectoryHash)}\"";
    }

    private sealed class AnchorHashExpr(int certificateIndex, byte[] anchorHash) : Expr
    {
        public override int Size => 12 + anchorHash.Length;

        public override void Write(Span<byte> buffer)
        {
            WriteUInt32BigEndian(buffer[..4], (uint)ExprOp.AnchorHash);
            WriteUInt32BigEndian(buffer.Slice(4, 4), 0);
            WriteInt32BigEndian(buffer.Slice(8, 4), anchorHash.Length);
            anchorHash.CopyTo(buffer.Slice(12, anchorHash.Length));
        }

        public override string ToString() => $"certificate {CertificateSlotToString(certificateIndex)} = H\"{Convert.ToHexStringLower(anchorHash)}\"";
    }

    private abstract class MatchExpr(MatchOperation matchOperation, byte[]? matchValue) : Expr
    {
        public override int Size => 4 + (matchValue == null ? 0 : 4 + Align(matchValue.Length, 4));

        public override void Write(Span<byte> buffer)
        {
            WriteUInt32BigEndian(buffer, (uint)matchOperation);

            if (matchValue == null)
                return;

            WriteInt32BigEndian(buffer[4..], matchValue.Length);
            matchValue.CopyTo(buffer.Slice(8, matchValue.Length));
            buffer.Slice(8 + matchValue.Length, Align(matchValue.Length, 4) - matchValue.Length).Clear();
        }

        private static string GetTimestampString(byte[] dateTime)
        {
            long tsSeconds = ReadInt64BigEndian(dateTime);
            return Epoc.AddSeconds(tsSeconds).ToString("yyyyMMddHHmmssZ", DateTimeFormatInfo.InvariantInfo);
        }

        public override string ToString() => matchOperation switch
        {
            MatchOperation.Exists => "/* exists */",
            MatchOperation.Absent => "absent",
            MatchOperation.Equal => $"= {ValueToString(matchValue!)}",
            MatchOperation.Contains => $"~ {ValueToString(matchValue!)}",
            MatchOperation.BeginsWith => $"= {ValueToString(matchValue!)}*",
            MatchOperation.EndsWith => $"= *{ValueToString(matchValue!)}",
            MatchOperation.LessThan => $"< {ValueToString(matchValue!)}",
            MatchOperation.GreaterEqual => $">= {ValueToString(matchValue!)}",
            MatchOperation.LessEqual => $"<= {ValueToString(matchValue!)}",
            MatchOperation.GreaterThan => $">= {ValueToString(matchValue!)}",
            MatchOperation.On => $"= timestamp \"{GetTimestampString(matchValue!)}\"",
            MatchOperation.Before => $"< timestamp \"{GetTimestampString(matchValue!)}\"",
            MatchOperation.After => $"> timestamp \"{GetTimestampString(matchValue!)}\"",
            MatchOperation.OnOrBefore => $"<= timestamp \"{GetTimestampString(matchValue!)}\"",
            MatchOperation.OnOrAfter => $">= timestamp \"{GetTimestampString(matchValue!)}\"",
            _ => "unknown"
        };
    }

    private sealed class FieldMatchExpr(ExprOp op, string field, MatchOperation matchOperation, byte[]? matchValue) : MatchExpr(matchOperation, matchValue)
    {
        private readonly object _field = field;
        private readonly byte[] _fieldBytes = Encoding.ASCII.GetBytes(field);

        public override int Size => 8 + Align(_fieldBytes.Length, 4) + base.Size;

        public override void Write(Span<byte> buffer)
        {
            WriteUInt32BigEndian(buffer[..4], (uint)op);
            WriteInt32BigEndian(buffer.Slice(4, 4), _fieldBytes.Length);
            _fieldBytes.CopyTo(buffer.Slice(8, _fieldBytes.Length));
            buffer.Slice(8 + _fieldBytes.Length, Align(_fieldBytes.Length, 4) - _fieldBytes.Length).Clear();
            base.Write(buffer[(8 + Align(_fieldBytes.Length, 4))..]);
        }

        public override string ToString() => op switch
        {
            ExprOp.InfoKeyField => $"info[{_field}] {base.ToString()}",
            ExprOp.EntitlementField => $"entitlement[{_field}] {base.ToString()}",
            _ => "unknown"
        };
    }

    private sealed class CertExpr(ExprOp op, int certificateIndex, byte[] certificateField, MatchOperation matchOperation, byte[]? matchValue) : MatchExpr(matchOperation, matchValue)
    {
        public override int Size => 12 + Align(certificateField.Length, 4) + base.Size;

        private static string GetOidString(byte[] oid)
        {
            byte[] oidBytes = new byte[oid.Length + 2];
            oidBytes[0] = 6;
            oidBytes[1] = (byte)oid.Length;
            oid.CopyTo(oidBytes.AsSpan(2));
            return AsnDecoder.ReadObjectIdentifier(oidBytes, AsnEncodingRules.DER, out _);
        }

        public override void Write(Span<byte> buffer)
        {
            WriteUInt32BigEndian(buffer, (uint)op);
            WriteInt32BigEndian(buffer[4..], certificateIndex);
            WriteInt32BigEndian(buffer[8..], certificateField.Length);
            certificateField.CopyTo(buffer.Slice(12, certificateField.Length));
            buffer.Slice(12 + certificateField.Length, Align(certificateField.Length, 4) - certificateField.Length).Clear();
            base.Write(buffer[(12 + Align(certificateField.Length, 4))..]);
        }

        public override string ToString() => op switch
        {
            ExprOp.CertField => $"certificate {CertificateSlotToString(certificateIndex)}[{Encoding.ASCII.GetString(certificateField)}] {base.ToString()}",
            ExprOp.CertGeneric => $"certificate {CertificateSlotToString(certificateIndex)}[field.{GetOidString(certificateField)}] {base.ToString()}",
            ExprOp.CertPolicy => $"certificate {CertificateSlotToString(certificateIndex)}[policy.{GetOidString(certificateField)}] {base.ToString()}",
            ExprOp.CertFieldDate => $"certificate {CertificateSlotToString(certificateIndex)}[timestamp.{GetOidString(certificateField)}] {base.ToString()}",
            _ => "unknown"
        };
    }

    private sealed class InfoKeyValueExpr(string field, byte[] matchValue) : Expr
    {
        private readonly object _field = field;
        private readonly byte[] _fieldBytes = Encoding.ASCII.GetBytes(field);

        public override int Size => 12 + Align(_fieldBytes.Length, 4) + Align(matchValue.Length, 4);

        public override void Write(Span<byte> buffer)
        {
            WriteUInt32BigEndian(buffer[..4], (uint)ExprOp.InfoKeyValue);
            WriteInt32BigEndian(buffer.Slice(4, 4), _fieldBytes.Length);
            _fieldBytes.CopyTo(buffer.Slice(8, _fieldBytes.Length));
            buffer.Slice(8 + _fieldBytes.Length, Align(_fieldBytes.Length, 4) - _fieldBytes.Length).Clear();

            int offset = 8 + Align(_fieldBytes.Length, 4);
            WriteInt32BigEndian(buffer.Slice(offset, 4), matchValue.Length);
            _fieldBytes.CopyTo(buffer.Slice(offset + 4, matchValue.Length));
            buffer.Slice(4 + offset + matchValue.Length, Align(matchValue.Length, 4) - matchValue.Length).Clear();
        }

        public override string ToString() => $"info[{_field}] = {ValueToString(matchValue)}";
    }

    private sealed class NamedExpr(ExprOp op, byte[] name) : Expr
    {
        public override int Size => 8 + Align(name.Length, 4);

        public override void Write(Span<byte> buffer)
        {
            WriteUInt32BigEndian(buffer[..4], (uint)op);
            WriteInt32BigEndian(buffer.Slice(4, 4), name.Length);
            name.CopyTo(buffer.Slice(8, name.Length));
            buffer.Slice(8 + name.Length, Align(name.Length, 4) - name.Length).Clear();
        }

        public override string ToString() => op switch
        {
            ExprOp.NamedAnchor => $"anchor apple {ValueToString(name)}",
            ExprOp.NamedCode => $"({ValueToString(name)})",
            _ => "unknown"
        };
    }

    private sealed class TrustedCertExpr(int certificateIndex) : Expr
    {
        public override int Size => 8;

        public override void Write(Span<byte> buffer)
        {
            WriteUInt32BigEndian(buffer, (uint)ExprOp.TrustedCert);
            WriteInt32BigEndian(buffer[4..], certificateIndex);
        }

        public override string ToString() => $"certificate {CertificateSlotToString(certificateIndex)} trusted";
    }

    private sealed class PlatformExpr(MachPlatform platform) : Expr
    {
        public override int Size => 8;

        public override void Write(Span<byte> buffer)
        {
            WriteUInt32BigEndian(buffer, (uint)ExprOp.Platform);
            WriteUInt32BigEndian(buffer[4..], (uint)platform);
        }

        public override string ToString() => $"platform = {platform}";
    }
}