using System.Collections.ObjectModel;
using System.Reflection;
using Genbox.FastCodeSign.BundleHandlers;
using Genbox.FastCodeSign.Enums;
using Genbox.FastCodeSign.Models;
using Genbox.FastCodeSign.Tests.Code;
using Xunit.Sdk;
using Xunit.v3;

namespace Genbox.FastCodeSign.Tests;

public class CodeSignBundleProviderTests
{
    [Theory, TestNameData]
    private void Sign(BundleTestCase tc)
    {
        using (tc)
        {
            CodeSignBundleProvider provider = tc.ProviderFactory(tc.UnpackBundle());

            using var certificate = Constants.GetCert();
            SignOptions options = new SignOptions { Certificate = certificate };

            if (!tc.IsSigned)
            {
                provider.RemoveSignature();
                provider.CreateSignature(options);
            }
            else
                Assert.Throws<InvalidOperationException>(() => provider.CreateSignature(options));
        }
    }

    [Theory, TestNameData]
    private void WriteSignature(BundleTestCase tc)
    {
        using (tc)
        {
            CodeSignBundleProvider provider = tc.ProviderFactory(tc.UnpackBundle());

            using var certificate = Constants.GetCert();
            SignOptions options = new SignOptions { Certificate = certificate };

            if (!tc.IsSigned)
            {
                provider.RemoveSignature();
                BundleSignature sig = provider.CreateSignature(options);
                provider.WriteSignature(sig);
            }
            else
                Assert.Throws<InvalidOperationException>(() => provider.CreateSignature(options));
        }
    }

    [Theory, TestNameData]
    private void RemoveSignatures(BundleTestCase tc)
    {
        using (tc)
        {
            CodeSignBundleProvider provider = tc.ProviderFactory(tc.UnpackBundle());

            SignatureComponent removed = provider.RemoveSignature();

            Assert.Equal(tc.SignatureComponents, removed);
        }
    }

    [Theory, TestNameData]
    private void HasValidSignature(BundleTestCase tc)
    {
        using (tc)
        {
            CodeSignBundleProvider provider = tc.ProviderFactory(tc.UnpackBundle());
            Assert.Equal(tc.IsSigned, provider.HasValidSignature());
        }
    }

    private sealed class TestNameDataAttribute : DataAttribute
    {
        public override ValueTask<IReadOnlyCollection<ITheoryDataRow>> GetData(MethodInfo testMethod, DisposalTracker disposalTracker)
        {
            var cases = new[]
            {
                BundleTestCase.Create(new AppBundleHandler(), "Signed/AppBundle/Discord.dat", true, SignatureComponent.CodeResourcesFile | SignatureComponent.LegacyCodeResourcesFile | SignatureComponent.CodeSignatureFolder | SignatureComponent.MachObjectSignature, testMethod.Name),
                BundleTestCase.Create(new AppBundleHandler(), "Unsigned/AppBundle/MyApp.dat", false, SignatureComponent.MachObjectSignature, testMethod.Name),
            };

            var rows = new ReadOnlyCollection<ITheoryDataRow>(cases
                                                              .Select(ITheoryDataRow (testCase) => new TheoryDataRow<BundleTestCase>(testCase))
                                                              .ToList());

            return new ValueTask<IReadOnlyCollection<ITheoryDataRow>>(rows);
        }

        public override bool SupportsDiscoveryEnumeration() => true;
    }
}