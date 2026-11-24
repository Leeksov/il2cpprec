using System;
using System.Globalization;

public static class ModernOracle
{
    private static int failures;

    private static uint Bits(float value)
    {
        return BitConverter.ToUInt32(BitConverter.GetBytes(value), 0);
    }

    private static void Check(string name, float actual, string expectedText)
    {
        uint expected = uint.Parse(expectedText.Substring(2), NumberStyles.HexNumber,
            CultureInfo.InvariantCulture);
        uint observed = Bits(actual);
        if (observed == expected)
        {
            Console.WriteLine("PASS oracle " + name);
            return;
        }
        ++failures;
        Console.WriteLine("FAIL oracle " + name + ": native=0x" + expected.ToString("X8") +
            " managed=0x" + observed.ToString("X8"));
    }

    public static int Main(string[] args)
    {
        if (args.Length != 6)
            throw new ArgumentException("Six native FP/vector oracle values are required.");
        float left = 3.0F;
        float right = 4.0F;
        Check("float_add", left + right, args[0]);
        Check("float_sqrt", (float)Math.Sqrt(right), args[1]);
        float[] vectorLeft = {1.25F, 2.5F, -3.75F, 4.0F};
        float[] vectorRight = {0.5F, -1.25F, 2.0F, 0.25F};
        for (int lane = 0; lane < 4; ++lane)
            Check("vector_add_" + lane, vectorLeft[lane] + vectorRight[lane], args[2 + lane]);
        Console.WriteLine("MODERN_ORACLE SUMMARY comparisons=6 failed=" + failures);
        return failures == 0 ? 0 : 1;
    }
}
