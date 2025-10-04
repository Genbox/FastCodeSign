using System.Runtime.InteropServices;

namespace Genbox.FastCodeSignature.Internal.WinPe;

[StructLayout(LayoutKind.Auto)]
internal readonly record struct PeSection(uint SizeOfRawData, uint PointerToRawData);