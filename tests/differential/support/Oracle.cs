using System;

public static class Oracle
{
    public static ulong SignedDiv(uint left, uint right)
    {
        int result = unchecked((int)left) / unchecked((int)right);
        return unchecked((uint)result);
    }

    public static ulong FloatAdd(uint left, uint right)
    {
        float leftFloat = unchecked((float)unchecked((int)left));
        float rightFloat = unchecked((float)unchecked((int)right));
        float result = leftFloat + rightFloat;
        return BitConverter.ToUInt32(BitConverter.GetBytes(result), 0);
    }

    public static ulong ThumbAddSub(uint left, uint right)
    {
        return unchecked(left + right - 1U);
    }

    public static ulong LoopSum(uint count)
    {
        uint sum = 0;
        for (uint i = 0; unchecked((int)i) < unchecked((int)count); ++i)
            sum = unchecked(sum + i);
        return sum;
    }

    public static byte[] MemoryBuffer(uint initial, uint delta)
    {
        byte[] result = new byte[16];
        for (int i = 0; i < result.Length; ++i)
            result[i] = 0xA5;
        WriteUInt32(result, 0, initial);
        WriteUInt32(result, 4, unchecked(initial + delta));
        return result;
    }

    private static void WriteUInt32(byte[] buffer, int offset, uint value)
    {
        byte[] bytes = BitConverter.GetBytes(value);
        System.Buffer.BlockCopy(bytes, 0, buffer, offset, bytes.Length);
    }
}
