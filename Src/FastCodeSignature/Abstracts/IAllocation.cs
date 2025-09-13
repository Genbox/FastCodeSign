namespace Genbox.FastCodeSignature.Abstracts;

/// <summary>This is an abstraction that functions as a factory to produce a Span over a section of memory.</summary>
public interface IAllocation : IDisposable
{
    Span<byte> GetSpan();
    void SetLength(uint length);
}