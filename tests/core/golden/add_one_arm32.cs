public static class RecoveredMethods_AddOneArm32
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

    public static uint AddOneArm32(uint r0, uint r1, uint r2, uint r3)
    {
        r0 = unchecked((uint)((r0) + (unchecked((uint)((r0) << (int)(unchecked((int)(unchecked((uint)0x1UL)))))))));
        r0 = unchecked((uint)((r0) - (unchecked((uint)0x1UL))));
        return r0;
        return default(uint);
    }
}
