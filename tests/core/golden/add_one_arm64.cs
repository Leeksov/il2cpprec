public static class RecoveredMethods_AddOneArm64
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

    public static ulong AddOneArm64(ulong x0, ulong x1, ulong x2, ulong x3, ulong x4, ulong x5, ulong x6, ulong x7)
    {
        x0 = x1;
        x0 = unchecked((ulong)((x0) + (unchecked((ulong)((0x0UL) << (int)(unchecked((int)(0xCUL))))))));
        return x0;
        return default(ulong);
    }
}
