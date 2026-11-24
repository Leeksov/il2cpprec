public static class RecoveredMethods_SharedJoin
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

    public static ulong SharedJoin(ulong rcx, ulong rdx, ulong r8, ulong r9)
    {
        ulong x0 = default(ulong);
        ulong x1 = default(ulong);
        if ((x0 == 0x0UL))
        {
            label_0x5010:
            ;
            x1 = 0x2UL;
        }
        else
        {
            x1 = 0x1UL;
        }
        label_0x5020:
        ;
        if ((x1 == 0x0UL))
        {
            label_0x5030:
            ;
            x0 = 0x4UL;
        }
        else
        {
            x0 = 0x3UL;
        }
        label_0x5040:
        ;
        return x1;
        return default(ulong);
    }
}
