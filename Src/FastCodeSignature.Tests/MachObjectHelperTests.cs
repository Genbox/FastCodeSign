using Genbox.FastCodeSignature.Helpers;
using Genbox.FastCodeSignature.Models;
using Genbox.FastCodeSignature.Tests.Code;

namespace Genbox.FastCodeSignature.Tests;

public class MachObjectHelperTests
{
    private const int CPU_ARCH_ABI64 = 0x01000000;
    private const int CPU_TYPE_X86 = 7;
    private const int CPU_TYPE_ARM = 12;
    private const uint CPU_TYPE_X86_64 = CPU_TYPE_X86 | CPU_ARCH_ABI64; // 0x01000007
    private const uint CPU_TYPE_ARM64 = CPU_TYPE_ARM | CPU_ARCH_ABI64; // 0x0100000C
    private const uint CPU_SUBTYPE_ALL = 0;

    [Fact]
    private void GetThinMachObjects32Test()
    {
        FatObject[] slices = MachObjectHelper.GetThinMachObjects(File.ReadAllBytes(Path.Combine(Constants.FilesDir, "Misc/fat32_3slices.dat")));
        Assert.Equal(3, slices.Length);

        Assert.Equal(CPU_TYPE_ARM64, slices[0].CpuType);
        Assert.Equal(CPU_SUBTYPE_ALL, slices[0].CpuSubType);
        Assert.Equal(96UL, slices[0].Offset);
        Assert.Equal(160UL, slices[0].Size);
        Assert.Equal(5U, slices[0].Align);

        Assert.Equal(CPU_TYPE_X86_64, slices[1].CpuType);
        Assert.Equal(CPU_SUBTYPE_ALL, slices[1].CpuSubType);
        Assert.Equal(256UL, slices[1].Offset);
        Assert.Equal(288UL, slices[1].Size);
        Assert.Equal(5U, slices[1].Align);

        Assert.Equal(CPU_TYPE_ARM64, slices[2].CpuType);
        Assert.Equal(CPU_SUBTYPE_ALL, slices[2].CpuSubType);
        Assert.Equal(544UL, slices[2].Offset);
        Assert.Equal(96UL, slices[2].Size);
        Assert.Equal(5U, slices[2].Align);
    }

    [Fact]
    public void GetThinMachObjects64Test()
    {
        FatObject[] slices = MachObjectHelper.GetThinMachObjects(File.ReadAllBytes(Path.Combine(Constants.FilesDir, "Misc/fat64_3slices.dat")));
        Assert.Equal(3, slices.Length);

        Assert.Equal(CPU_TYPE_ARM64, slices[0].CpuType);
        Assert.Equal(CPU_SUBTYPE_ALL, slices[0].CpuSubType);
        Assert.Equal(128UL, slices[0].Offset);
        Assert.Equal(200UL, slices[0].Size);
        Assert.Equal(5U, slices[0].Align);

        Assert.Equal(CPU_TYPE_X86_64, slices[1].CpuType);
        Assert.Equal(CPU_SUBTYPE_ALL, slices[1].CpuSubType);
        Assert.Equal(352UL, slices[1].Offset);
        Assert.Equal(320UL, slices[1].Size);
        Assert.Equal(5U, slices[1].Align);

        Assert.Equal(CPU_TYPE_ARM64, slices[2].CpuType);
        Assert.Equal(CPU_SUBTYPE_ALL, slices[2].CpuSubType);
        Assert.Equal(672UL, slices[2].Offset);
        Assert.Equal(150UL, slices[2].Size);
        Assert.Equal(5U, slices[2].Align);
    }
}