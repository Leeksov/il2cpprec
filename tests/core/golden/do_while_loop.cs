public static class RecoveredMethods_DoWhileLoop
{
    public readonly struct __UnsupportedValue
    {
    }

    public readonly struct __UnsupportedVector128
    {
        public const int Bits = 128;
    }

    private sealed class __RecoveryUnsupportedException : global::System.Exception
    {
        public __RecoveryUnsupportedException(string message) : base(message)
        {
        }
    }

    private static T __Unsupported<T>(string operation, params object[] arguments)
    {
        throw new __RecoveryUnsupportedException(operation);
    }

    private static void __Discard<T>(T value)
    {
    }

    public static ulong DoWhileLoop(ulong rcx, ulong rdx, ulong r8, ulong r9)
    {
        ulong x0 = default(ulong);
        do
        {
            label_0x4000:
            ;
            x0 = unchecked((ulong)((x0) + (0x1UL)));
        } while ((x0 < 0xAUL));
        return x0;
        return default(ulong);
    }
}
