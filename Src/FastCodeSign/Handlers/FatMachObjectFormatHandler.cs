using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;
using Genbox.FastCodeSign.Abstracts;
using Genbox.FastCodeSign.Helpers;
using Genbox.FastCodeSign.Internal.MachObject;
using Genbox.FastCodeSign.Internal.MachObject.Headers.Enums;
using Genbox.FastCodeSign.Models;

namespace Genbox.FastCodeSign.Handlers;

internal sealed class FatMachObjectFormatHandler : IFormatHandler
{
    private static readonly IFormatHandler SliceHandler = new MachObjectFormatHandler();

    public int MinValidSize => 12;
    public string[] ValidExt => [];

    public bool IsValidHeader(ReadOnlySpan<byte> data)
    {
        uint magic = ReadUInt32BigEndian(data);
        return magic is (uint)MachMagic.FatMagicBE or (uint)MachMagic.FatMagicLE or (uint)MachMagic.FatMagic64BE or (uint)MachMagic.FatMagic64LE;
    }

    public IContext GetContext(ReadOnlySpan<byte> data)
    {
        MachObject[] slices = MachObjectHelper.GetMachObjects(data);
        IContext[] contexts = new IContext[slices.Length];
        bool isSigned = false;
        bool hasUnsignedSlice = false;

        for (int i = 0; i < slices.Length; i++)
        {
            contexts[i] = SliceHandler.GetContext(slices[i].GetSpan(data));
            isSigned |= contexts[i].IsSigned;
            hasUnsignedSlice |= !contexts[i].IsSigned;
        }

        return new FatMachObjectContext(slices, contexts, isSigned, isSigned && hasUnsignedSlice);
    }

    public ReadOnlySpan<byte> ExtractSignature(IContext context, ReadOnlySpan<byte> data)
    {
        FatMachObjectContext fatContext = (FatMachObjectContext)context;
        fatContext.EnsureUniformSignatureState();
        return SliceHandler.ExtractSignature(fatContext.SliceContexts[0], fatContext.Slices[0].GetSpan(data));
    }

    public IReadOnlyList<byte[]> ExtractSignatures(IContext context, ReadOnlySpan<byte> data)
    {
        FatMachObjectContext fatContext = (FatMachObjectContext)context;
        fatContext.EnsureUniformSignatureState();
        byte[][] signatures = new byte[fatContext.Slices.Length][];
        for (int i = 0; i < signatures.Length; i++)
            signatures[i] = SliceHandler.ExtractSignature(fatContext.SliceContexts[i], fatContext.Slices[i].GetSpan(data)).ToArray();
        return signatures;
    }

    public byte[] ComputeHash(IContext context, ReadOnlySpan<byte> data, HashAlgorithmName hashAlgorithm)
    {
        FatMachObjectContext fatContext = (FatMachObjectContext)context;
        fatContext.EnsureUniformSignatureState();
        return SliceHandler.ComputeHash(fatContext.SliceContexts[0], fatContext.Slices[0].GetSpan(data), hashAlgorithm);
    }

    public byte[] ComputeHash(IContext context, ReadOnlySpan<byte> data, HashAlgorithmName hashAlgorithm, int signatureIndex)
    {
        FatMachObjectContext fatContext = (FatMachObjectContext)context;
        fatContext.EnsureUniformSignatureState();
        return SliceHandler.ComputeHash(fatContext.SliceContexts[signatureIndex], fatContext.Slices[signatureIndex].GetSpan(data), hashAlgorithm);
    }

    public long RemoveSignature(IContext context, Span<byte> data) => throw new NotSupportedException("Universal Mach-O signatures require an allocation so slices can be rebuilt.");

    public long RemoveSignature(IContext context, IAllocation allocation)
    {
        FatMachObjectContext fatContext = (FatMachObjectContext)context;
        int oldLength = allocation.GetSpan().Length;
        MachObjectSignatureHelper.RemoveSignatures(allocation, fatContext.Slices);
        return oldLength - allocation.GetSpan().Length;
    }

    public Signature CreateSignature(IContext context, ReadOnlySpan<byte> data, SignOptions signOptions, IFormatOptions? formatOptions = null, Action<CmsSigner>? configureSigner = null)
    {
        FatMachObjectContext fatContext = (FatMachObjectContext)context;
        MachObjectFormatOptions options = formatOptions as MachObjectFormatOptions ?? throw new InvalidOperationException("You must set Mach-O format options with a valid identifier.");
        Signature[] signatures = new Signature[fatContext.Slices.Length];

        for (int i = 0; i < signatures.Length; i++)
            signatures[i] = SliceHandler.CreateSignature(fatContext.SliceContexts[i], fatContext.Slices[i].GetSpan(data), signOptions, options, configureSigner);

        return new Signature(signatures[0].SignedCms, signatures.Select(signature => signature.SignedCms).ToArray(), new FatMachObjectInfo(signatures));
    }

    public void WriteSignature(IContext context, IAllocation allocation, Signature signature)
    {
        FatMachObjectContext fatContext = (FatMachObjectContext)context;
        FatMachObjectInfo info = signature.SignatureInfo as FatMachObjectInfo ?? throw new InvalidOperationException("The signature was not created for a universal Mach-O file.");
        MachObjectSignatureHelper.WriteSignatures(allocation, fatContext.Slices, info.Signatures);
    }

    public void CheckSignature(IContext context, ReadOnlySpan<byte> data, SignedCms signedCms)
    {
        FatMachObjectContext fatContext = (FatMachObjectContext)context;
        fatContext.EnsureUniformSignatureState();
        byte[] encoded = signedCms.Encode();

        for (int i = 0; i < fatContext.Slices.Length; i++)
        {
            ReadOnlySpan<byte> signature = SliceHandler.ExtractSignature(fatContext.SliceContexts[i], fatContext.Slices[i].GetSpan(data));

            if (signature.SequenceEqual(encoded))
            {
                SliceHandler.CheckSignature(fatContext.SliceContexts[i], fatContext.Slices[i].GetSpan(data), signedCms);
                return;
            }
        }

        throw new CryptographicException("The CMS does not belong to this universal Mach-O file.");
    }

    public bool ExtractHashFromSignedCms(SignedCms signedCms, [NotNullWhen(true)]out byte[]? digest, out HashAlgorithmName algo)
        => SliceHandler.ExtractHashFromSignedCms(signedCms, out digest, out algo);

    private sealed class FatMachObjectContext(MachObject[] slices, IContext[] sliceContexts, bool isSigned, bool hasMixedSignatureState) : IContext
    {
        public MachObject[] Slices { get; } = slices;
        public IContext[] SliceContexts { get; } = sliceContexts;
        public bool HasMixedSignatureState { get; } = hasMixedSignatureState;
        public bool IsSigned { get; } = isSigned;

        public void EnsureUniformSignatureState()
        {
            if (HasMixedSignatureState)
                throw new InvalidDataException("The universal Mach-O file has a partial signature.");
            if (!IsSigned)
                throw new InvalidDataException("The universal Mach-O file is not signed.");
        }
    }

    private sealed class FatMachObjectInfo(Signature[] signatures)
    {
        public Signature[] Signatures { get; } = signatures;
    }
}