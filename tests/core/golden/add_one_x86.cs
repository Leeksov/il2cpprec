public static class RecoveredMethods_AddOneX86
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

    public static uint AddOneX86(uint ecx, uint edx)
    {
        uint eax = default(uint);
        eax = ecx;
        eax = unchecked((uint)((eax) + (unchecked((uint)0x1UL))));
        return eax;
        return default(uint);
    }
}
