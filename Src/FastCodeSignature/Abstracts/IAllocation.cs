namespace Genbox.FastCodeSignature.Abstracts;

/// <summary>This is an abstraction that functions as a factory to produce a Span over a section of memory.</summary>
public interface IAllocation
{
    Span<byte> GetData();
    Span<byte> CreateExtension(uint size);
    Span<byte> GetExtension();
    void TruncateDataTo(uint newLength);
}