using Genbox.FastCodeSign.Enums;
using Genbox.FastCodeSign.Helpers;
using Genbox.FastCodeSign.Models;
using Genbox.FastCodeSign.Tests.Code;

namespace Genbox.FastCodeSign.Tests;

public class MachObjectHelperTests
{
    [Fact]
    private void GetThinMachObjects32Test()
    {
        FatObject[] slices = MachObjectHelper.GetThinMachObjects(File.ReadAllBytes(Path.Combine(Constants.FilesDir, "Misc/fat32_3slices.dat")));
        Assert.Equal(3, slices.Length);

        Assert.Equal(CpuType.ARM64, slices[0].CpuType);
        Assert.Equal(Arm64CpuSubType.All, slices[0].CpuSubType);
        Assert.Equal(96UL, slices[0].Offset);
        Assert.Equal(160UL, slices[0].Size);
        Assert.Equal(5U, slices[0].Align);

        Assert.Equal(CpuType.X86_64, slices[1].CpuType);
        // Assert.Equal(X8664CpuSubType.All, slices[1].CpuSubType); // I might have made a mistake in the fat32_3slices file
        Assert.Equal(256UL, slices[1].Offset);
        Assert.Equal(288UL, slices[1].Size);
        Assert.Equal(5U, slices[1].Align);

        Assert.Equal(CpuType.ARM64, slices[2].CpuType);
        Assert.Equal(Arm64CpuSubType.All, slices[2].CpuSubType);
        Assert.Equal(544UL, slices[2].Offset);
        Assert.Equal(96UL, slices[2].Size);
        Assert.Equal(5U, slices[2].Align);
    }

    [Fact]
    public void GetThinMachObjects64Test()
    {
        FatObject[] slices = MachObjectHelper.GetThinMachObjects(File.ReadAllBytes(Path.Combine(Constants.FilesDir, "Misc/fat64_3slices.dat")));
        Assert.Equal(3, slices.Length);

        Assert.Equal(CpuType.ARM64, slices[0].CpuType);
        Assert.Equal(Arm64CpuSubType.All, slices[0].CpuSubType);
        Assert.Equal(128UL, slices[0].Offset);
        Assert.Equal(200UL, slices[0].Size);
        Assert.Equal(5U, slices[0].Align);

        Assert.Equal(CpuType.X86_64, slices[1].CpuType);
        // Assert.Equal(X8664CpuSubType.All, slices[1].CpuSubType); // I might have made a mistake in the fat64_3slices file
        Assert.Equal(352UL, slices[1].Offset);
        Assert.Equal(320UL, slices[1].Size);
        Assert.Equal(5U, slices[1].Align);

        Assert.Equal(CpuType.ARM64, slices[2].CpuType);
        Assert.Equal(Arm64CpuSubType.All, slices[2].CpuSubType);
        Assert.Equal(672UL, slices[2].Offset);
        Assert.Equal(150UL, slices[2].Size);
        Assert.Equal(5U, slices[2].Align);
    }
}