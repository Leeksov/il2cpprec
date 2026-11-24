public static class RecoveredMethods_AddOneX64
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

    public static ulong AddOneX64(ulong rcx, ulong rdx, ulong r8, ulong r9)
    {
        ulong rax = default(ulong);
        rax = rcx;
        rax = unchecked((ulong)((rax) + (0x1UL)));
        return rax;
        return default(ulong);
    }
}
