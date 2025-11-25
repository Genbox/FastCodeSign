using Genbox.FastCodeSign.Abstracts;
using Genbox.FastCodeSign.BundleHandlers;

namespace Genbox.FastCodeSign.Internal;

internal static class BundleHandlerFactory
{
    public static IBundleHandler? Get(string path)
    {
        IBundleHandler[] handlers =
        [
            new AppBundleHandler(),
        ];

        foreach (IBundleHandler handler in handlers)
        {
            if (!handler.IsBundlePath(path))
                continue;

            return handler;
        }

        return null;
    }
}