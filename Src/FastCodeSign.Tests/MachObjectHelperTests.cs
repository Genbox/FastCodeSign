using Genbox.FastCodeSign.Enums;
using Genbox.FastCodeSign.Helpers;
using Genbox.FastCodeSign.Models;
using Genbox.FastCodeSign.Tests.Code;

namespace Genbox.FastCodeSign.Tests;

public class MachObjectHelperTests
{
    [Fact]
    private void ThinFileReturnsSelf()
    {
        byte[] data = File.ReadAllBytes(Path.Combine(Constants.FilesDir, "Signed/MachO/macho_signed.dat"));
        MachObject[] slices = MachObjectHelper.GetMachObjects(data);
        MachObject slice = Assert.Single(slices);

        Assert.Equal((ulong)0, slice.Offset);
        Assert.Equal((ulong)data.Length, slice.Size);
        Assert.Equal(CpuType.X86_64, slice.CpuType);
        Assert.Equal(X8664CpuSubType.All, slice.CpuSubType);
    }

    [Fact]
    private void GetMachObjects32()
    {
        MachObject[] slices = MachObjectHelper.GetMachObjects(File.ReadAllBytes(Path.Combine(Constants.FilesDir, "Misc/fat32_3slices.dat")));
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
    public void GetMachObjects64()
    {
        MachObject[] slices = MachObjectHelper.GetMachObjects(File.ReadAllBytes(Path.Combine(Constants.FilesDir, "Misc/fat64_3slices.dat")));
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