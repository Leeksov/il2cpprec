public static class RecoveredMethods_EarlyReturn
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

    public static ulong EarlyReturn(ulong rcx, ulong rdx, ulong r8, ulong r9)
    {
        ulong x0 = default(ulong);
        if ((x0 == 0x0UL))
        {
            label_0x2010:
            ;
            return 0x2UL;
        }
        else
        {
            return 0x1UL;
        }
        return default(ulong);
    }
}
