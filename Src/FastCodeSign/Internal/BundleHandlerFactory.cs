using Genbox.FastCodeSign.Abstracts;
using Genbox.FastCodeSign.BundleHandlers;

namespace Genbox.FastCodeSign.Internal;

internal static class BundleHandlerFactory
{
    private static readonly IBundleHandler[] Handlers =
    [
        new AppBundleHandler()
    ];

    public static IBundleHandler? Get(string path)
    {
        foreach (IBundleHandler handler in Handlers)
        {
            if (!handler.IsBundlePath(path))
                continue;

            return handler;
        }

        return null;
    }
}