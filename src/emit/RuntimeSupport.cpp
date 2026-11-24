#include <il2cpprec/emit/RuntimeSupport.hpp>

#include <il2cpprec/ida/SourceProfile.hpp>

#include <sstream>
#include <stdexcept>
#include <string_view>

namespace il2cpprec {
namespace {

std::string configureRuntime(
    std::string generated,
    const ida::SourceLayoutSelection& selection,
    const RuntimeSupportOptions& options);

}

std::string RuntimeSupportGenerator::generate(Architecture architecture) const {
    return generate(architecture, {});
}

std::string RuntimeSupportGenerator::generate(Architecture architecture, const RuntimeSupportOptions& options) const {
    const size_t pointerSize = architecture == Architecture::Arm64 || architecture == Architecture::X64 ? 8 : 4;
    return generate(ida::unity2017_4_11f1Profile().resolve(24.1, pointerSize), options);
}

std::string RuntimeSupportGenerator::generate(const ida::SourceLayoutSelection& selection, const RuntimeSupportOptions& options) const {
    if (!selection.supported)
        throw std::invalid_argument("Cannot generate runtime support for an unsupported source layout.");
    const auto errors = ida::validateSourceLayout(selection);
    if (!errors.empty())
        throw std::invalid_argument(errors.front());
    const bool is64Bit = selection.pointerSize == 8;

    std::ostringstream output;
    output << "using global::System;\n"
              "using global::System.Globalization;\n"
              "using global::System.Reflection;\n"
              "using global::System.Runtime.CompilerServices;\n"
              "using global::System.Runtime.InteropServices;\n"
              "using ArgumentException = global::System.ArgumentException;\n"
              "using ArgumentNullException = global::System.ArgumentNullException;\n"
              "using ArgumentOutOfRangeException = global::System.ArgumentOutOfRangeException;\n"
              "using DivideByZeroException = global::System.DivideByZeroException;\n"
              "using IndexOutOfRangeException = global::System.IndexOutOfRangeException;\n"
              "using InvalidCastException = global::System.InvalidCastException;\n"
              "using InvalidOperationException = global::System.InvalidOperationException;\n"
              "using MissingMethodException = global::System.MissingMethodException;\n"
              "using NotSupportedException = global::System.NotSupportedException;\n"
              "using NullReferenceException = global::System.NullReferenceException;\n"
              "using OverflowException = global::System.OverflowException;\n"
           << (is64Bit
                ? "using NativeUInt = global::System.UInt64;\nusing NativeInt = global::System.Int64;\n\n"
                : "using NativeUInt = global::System.UInt32;\nusing NativeInt = global::System.Int32;\n\n");
    output << R"CS([global::System.Runtime.InteropServices.StructLayoutAttribute(global::System.Runtime.InteropServices.LayoutKind.Sequential)]
public unsafe struct RuntimeVector128
{
    public const int Size = 16;
    public ulong Low;
    public ulong High;

    public RuntimeVector128(ulong low, ulong high)
    {
        Low = low;
        High = high;
    }

    public static RuntimeVector128 Zero => default;

    public static RuntimeVector128 FromUInt32(uint lane0, uint lane1, uint lane2, uint lane3) =>
        new RuntimeVector128(
            lane0 | ((ulong)lane1 << 32),
            lane2 | ((ulong)lane3 << 32));

    public static RuntimeVector128 FromSingle(float lane0, float lane1, float lane2, float lane3) =>
        FromUInt32(
            RuntimeCalls.SingleToUInt32Bits(lane0),
            RuntimeCalls.SingleToUInt32Bits(lane1),
            RuntimeCalls.SingleToUInt32Bits(lane2),
            RuntimeCalls.SingleToUInt32Bits(lane3));

    public static RuntimeVector128 FromDouble(double lane0, double lane1) =>
        new RuntimeVector128(RuntimeCalls.DoubleToUInt64Bits(lane0), RuntimeCalls.DoubleToUInt64Bits(lane1));

    public static RuntimeVector128 FromBytes(byte[] value)
    {
        if (value == null)
            throw new ArgumentNullException(nameof(value));
        if (value.Length != Size)
            throw new ArgumentException("A vector128 bit representation must contain exactly 16 bytes.", nameof(value));
        RuntimeVector128 result;
        fixed (byte* source = value)
            global::System.Buffer.MemoryCopy(source, &result, Size, Size);
        return result;
    }

    public static RuntimeVector128 FromLanes<T>(T[] lanes) where T : unmanaged
    {
        if (lanes == null)
            throw new ArgumentNullException(nameof(lanes));
        int count = GetLaneCount<T>();
        if (lanes.Length != count)
            throw new ArgumentException($"Expected exactly {count} lanes of {typeof(T).FullName}.", nameof(lanes));
        RuntimeVector128 result = default;
        for (int i = 0; i < count; ++i)
            result = result.WithLane(i, lanes[i]);
        return result;
    }

    public byte[] ToBytes()
    {
        byte[] result = new byte[Size];
        RuntimeVector128 value = this;
        fixed (byte* destination = result)
            global::System.Buffer.MemoryCopy(&value, destination, Size, Size);
        return result;
    }

    public T[] ToLanes<T>() where T : unmanaged
    {
        int count = GetLaneCount<T>();
        T[] result = new T[count];
        for (int i = 0; i < count; ++i)
            result[i] = GetLane<T>(i);
        return result;
    }

    public static int GetLaneCount<T>() where T : unmanaged
    {
        int size = sizeof(T);
        if (size <= 0 || size > Size || Size % size != 0)
            throw new NotSupportedException($"Type {typeof(T).FullName} cannot be a vector128 lane.");
        return Size / size;
    }

    public T GetLane<T>(int index) where T : unmanaged
    {
        int count = GetLaneCount<T>();
        if ((uint)index >= (uint)count)
            throw new ArgumentOutOfRangeException(nameof(index));
        RuntimeVector128 source = this;
        T result;
        int offset = index * sizeof(T);
        global::System.Buffer.MemoryCopy((byte*)&source + offset, &result, sizeof(T), sizeof(T));
        return result;
    }

    public RuntimeVector128 WithLane<T>(int index, T lane) where T : unmanaged
    {
        int count = GetLaneCount<T>();
        if ((uint)index >= (uint)count)
            throw new ArgumentOutOfRangeException(nameof(index));
        RuntimeVector128 result = this;
        int offset = index * sizeof(T);
        global::System.Buffer.MemoryCopy(&lane, (byte*)&result + offset, sizeof(T), sizeof(T));
        return result;
    }

    public RuntimeVector128 SetLane<T>(int index, T lane) where T : unmanaged => WithLane(index, lane);
    public T GetElement<T>(int index) where T : unmanaged => GetLane<T>(index);
    public RuntimeVector128 WithElement<T>(int index, T lane) where T : unmanaged => WithLane(index, lane);

    public uint GetUInt32(int index) => GetLane<uint>(index);
    public RuntimeVector128 WithUInt32(int index, uint lane) => WithLane(index, lane);
    public ulong GetUInt64(int index) => GetLane<ulong>(index);
    public RuntimeVector128 WithUInt64(int index, ulong lane) => WithLane(index, lane);
    public float GetSingle(int index) => GetLane<float>(index);
    public RuntimeVector128 WithSingle(int index, float lane) => WithLane(index, lane);
    public double GetDouble(int index) => GetLane<double>(index);
    public RuntimeVector128 WithDouble(int index, double lane) => WithLane(index, lane);

    public static RuntimeVector128 And(RuntimeVector128 left, RuntimeVector128 right) => left & right;
    public static RuntimeVector128 Or(RuntimeVector128 left, RuntimeVector128 right) => left | right;
    public static RuntimeVector128 Xor(RuntimeVector128 left, RuntimeVector128 right) => left ^ right;
    public static RuntimeVector128 Not(RuntimeVector128 value) => ~value;
    public static RuntimeVector128 AndNot(RuntimeVector128 left, RuntimeVector128 right) => left & ~right;

    public static RuntimeVector128 operator &(RuntimeVector128 left, RuntimeVector128 right) =>
        new RuntimeVector128(left.Low & right.Low, left.High & right.High);

    public static RuntimeVector128 operator |(RuntimeVector128 left, RuntimeVector128 right) =>
        new RuntimeVector128(left.Low | right.Low, left.High | right.High);

    public static RuntimeVector128 operator ^(RuntimeVector128 left, RuntimeVector128 right) =>
        new RuntimeVector128(left.Low ^ right.Low, left.High ^ right.High);

    public static RuntimeVector128 operator ~(RuntimeVector128 value) =>
        new RuntimeVector128(~value.Low, ~value.High);

    public static bool operator ==(RuntimeVector128 left, RuntimeVector128 right) =>
        left.Low == right.Low && left.High == right.High;

    public static bool operator !=(RuntimeVector128 left, RuntimeVector128 right) => !(left == right);

    public RuntimeVector128 ShiftLeftLogical(int count)
    {
        if (count < 0)
            throw new ArgumentOutOfRangeException(nameof(count));
        if (count == 0)
            return this;
        if (count >= Size * 8)
            return default;
        if (count >= 64)
            return new RuntimeVector128(0, Low << (count - 64));
        return new RuntimeVector128((Low << count) | (High >> (64 - count)), High << count);
    }

    public RuntimeVector128 ShiftRightLogical(int count)
    {
        if (count < 0)
            throw new ArgumentOutOfRangeException(nameof(count));
        if (count == 0)
            return this;
        if (count >= Size * 8)
            return default;
        if (count >= 64)
            return new RuntimeVector128(High >> (count - 64), 0);
        return new RuntimeVector128(Low >> count, (High >> count) | (Low << (64 - count)));
    }

    public RuntimeVector128 ShiftLeft(int count) => ShiftLeftLogical(count);
    public RuntimeVector128 ShiftRight(int count) => ShiftRightLogical(count);

    public bool Equals(RuntimeVector128 other) => this == other;
    public override bool Equals(object other) => other is RuntimeVector128 && this == (RuntimeVector128)other;

    public override int GetHashCode()
    {
        unchecked
        {
            int hash = 17;
            hash = hash * 31 + Low.GetHashCode();
            return hash * 31 + High.GetHashCode();
        }
    }

    public override string ToString() => $"0x{High:X16}{Low:X16}";
}

public unsafe delegate void RuntimeMemoryReadHandler(NativeUInt address, void* destination, int size);
public unsafe delegate void RuntimeMemoryWriteHandler(NativeUInt address, void* source, int size);

public static unsafe class RuntimeMemory
{
    public static int PointerSize => sizeof(NativeUInt);
    public static RuntimeMemoryReadHandler ReadHandler { get; set; }
    public static RuntimeMemoryWriteHandler WriteHandler { get; set; }

    public static T Read<T>(NativeUInt address) where T : unmanaged
    {
        T value;
        if (ReadHandler != null)
            ReadHandler(address, &value, sizeof(T));
        else
            global::System.Buffer.MemoryCopy((void*)address, &value, sizeof(T), sizeof(T));
        return value;
    }

    public static void Write<T>(NativeUInt address, T value) where T : unmanaged
    {
        if (WriteHandler != null)
            WriteHandler(address, &value, sizeof(T));
        else
            global::System.Buffer.MemoryCopy(&value, (void*)address, sizeof(T), sizeof(T));
    }

    public static bool ReadBoolean(NativeUInt address) => ReadU8(address) != 0;
    public static bool ReadU1(NativeUInt address) => ReadBoolean(address);
    public static byte ReadU8(NativeUInt address) => Read<byte>(address);
    public static ushort ReadU16(NativeUInt address) => Read<ushort>(address);
    public static uint ReadU32(NativeUInt address) => Read<uint>(address);
    public static ulong ReadU64(NativeUInt address) => Read<ulong>(address);
    public static sbyte ReadS8(NativeUInt address) => Read<sbyte>(address);
    public static short ReadS16(NativeUInt address) => Read<short>(address);
    public static int ReadS32(NativeUInt address) => Read<int>(address);
    public static long ReadS64(NativeUInt address) => Read<long>(address);
    public static float ReadF32(NativeUInt address) => Read<float>(address);
    public static double ReadF64(NativeUInt address) => Read<double>(address);
    public static RuntimeVector128 ReadVector128(NativeUInt address) => Read<RuntimeVector128>(address);
    public static RuntimeVector128 ReadV128(NativeUInt address) => ReadVector128(address);
    public static RuntimeVector128 LoadVector128(NativeUInt address) => ReadVector128(address);

    public static NativeUInt ReadPtr(NativeUInt address)
    {
        if (PointerSize == 4)
            return (NativeUInt)ReadU32(address);
        return (NativeUInt)ReadU64(address);
    }

    public static void WriteBoolean(NativeUInt address, bool value) => WriteU8(address, value ? (byte)1 : (byte)0);
    public static void WriteU1(NativeUInt address, bool value) => WriteBoolean(address, value);
    public static void WriteU8(NativeUInt address, byte value) => Write(address, value);
    public static void WriteU16(NativeUInt address, ushort value) => Write(address, value);
    public static void WriteU32(NativeUInt address, uint value) => Write(address, value);
    public static void WriteU64(NativeUInt address, ulong value) => Write(address, value);
    public static void WriteS8(NativeUInt address, sbyte value) => Write(address, value);
    public static void WriteS16(NativeUInt address, short value) => Write(address, value);
    public static void WriteS32(NativeUInt address, int value) => Write(address, value);
    public static void WriteS64(NativeUInt address, long value) => Write(address, value);
    public static void WriteF32(NativeUInt address, float value) => Write(address, value);
    public static void WriteF64(NativeUInt address, double value) => Write(address, value);
    public static void WriteVector128(NativeUInt address, RuntimeVector128 value) => Write(address, value);
    public static void WriteV128(NativeUInt address, RuntimeVector128 value) => WriteVector128(address, value);
    public static void StoreVector128(NativeUInt address, RuntimeVector128 value) => WriteVector128(address, value);

    public static void WritePtr(NativeUInt address, NativeUInt value)
    {
        if (PointerSize == 4)
            WriteU32(address, (uint)value);
        else
            WriteU64(address, value);
    }

    public static NativeUInt Allocate(int size)
    {
        if (size < 0)
            throw new ArgumentOutOfRangeException(nameof(size));

        global::System.IntPtr allocation = global::System.Runtime.InteropServices.Marshal.AllocHGlobal(size);
        NativeUInt address = unchecked((NativeUInt)(ulong)allocation.ToInt64());
        if (size != 0)
            Zero(address, size);
        return address;
    }

    public static void Free(NativeUInt address)
    {
        if (address != 0)
            global::System.Runtime.InteropServices.Marshal.FreeHGlobal((global::System.IntPtr)(ulong)address);
    }

    public static void Copy(NativeUInt source, NativeUInt destination, int size)
    {
        if (size < 0)
            throw new ArgumentOutOfRangeException(nameof(size));
        global::System.Buffer.MemoryCopy((void*)source, (void*)destination, size, size);
    }

    public static void Zero(NativeUInt address, int size)
    {
        if (size < 0)
            throw new ArgumentOutOfRangeException(nameof(size));
        for (int i = 0; i < size; ++i)
            WriteU8(address + (NativeUInt)i, 0);
    }
}

public delegate NativeUInt RuntimeCallHandler(NativeUInt target, NativeUInt[] arguments);

public static partial class RuntimeCalls
{
    public static RuntimeCallHandler DirectCallHandler { get; set; }
    public static RuntimeCallHandler IndirectCallHandler { get; set; }
    public static global::System.Func<string, NativeUInt, NativeUInt> UnsupportedInstructionHandler { get; set; }

    public static NativeUInt InvokeDirect(NativeUInt target, params NativeUInt[] arguments)
    {
        RuntimeCallHandler handler = DirectCallHandler ?? IndirectCallHandler;
        if (handler == null)
            throw new MissingMethodException($"No direct-call handler is registered for 0x{target:X}.");
        return handler(target, arguments ?? global::System.Array.Empty<NativeUInt>());
    }

    public static T InvokeDirect<T>(NativeUInt target, params NativeUInt[] arguments) =>
        RuntimeAbi.FromNative<T>(InvokeDirect(target, arguments));

    public static NativeUInt Invoke(NativeUInt target, params NativeUInt[] arguments) =>
        InvokeDirect(target, arguments);

    public static T Invoke<T>(NativeUInt target, params NativeUInt[] arguments) =>
        InvokeDirect<T>(target, arguments);

    public static NativeUInt InvokeIndirect(NativeUInt target, params NativeUInt[] arguments)
    {
        RuntimeCallHandler handler = IndirectCallHandler ?? DirectCallHandler;
        if (handler == null)
            throw new MissingMethodException($"No indirect-call handler is registered for 0x{target:X}.");
        return handler(target, arguments ?? global::System.Array.Empty<NativeUInt>());
    }

    public static T InvokeIndirect<T>(NativeUInt target, params NativeUInt[] arguments) =>
        RuntimeAbi.FromNative<T>(InvokeIndirect(target, arguments));

    public static NativeUInt Unsupported(string instruction, NativeUInt address)
    {
        if (UnsupportedInstructionHandler != null)
            return UnsupportedInstructionHandler(instruction, address);
        throw new NotSupportedException($"Unsupported instruction '{instruction}' at 0x{address:X}.");
    }

    public static NativeUInt UnsupportedInstruction(string instruction, NativeUInt address) =>
        Unsupported(instruction, address);

    public static NativeUInt UnsupportedUnary(string operation, NativeUInt value) =>
        throw new NotSupportedException($"Unsupported unary operation '{operation}' for {typeof(NativeUInt).FullName}; operand=0x{value:X}.");

    public static T UnsupportedUnary<T>(string operation, T value) =>
        throw new NotSupportedException($"Unsupported unary operation '{operation}' for {typeof(T).FullName} operand {Describe(value)}.");

    public static TResult UnsupportedUnary<TResult, TValue>(string operation, TValue value) =>
        throw new NotSupportedException($"Unsupported unary operation '{operation}' from {typeof(TValue).FullName} to {typeof(TResult).FullName}; operand {Describe(value)}.");

    public static NativeUInt UnsupportedBinary(string operation, NativeUInt left, NativeUInt right) =>
        throw new NotSupportedException($"Unsupported binary operation '{operation}' for {typeof(NativeUInt).FullName}; left=0x{left:X}, right=0x{right:X}.");

    public static T UnsupportedBinary<T>(string operation, T left, T right) =>
        throw new NotSupportedException($"Unsupported binary operation '{operation}' for {typeof(T).FullName}; left={Describe(left)}, right={Describe(right)}.");

    public static TResult UnsupportedBinary<TResult, TLeft, TRight>(string operation, TLeft left, TRight right) =>
        throw new NotSupportedException($"Unsupported binary operation '{operation}' from ({typeof(TLeft).FullName}, {typeof(TRight).FullName}) to {typeof(TResult).FullName}; left={Describe(left)}, right={Describe(right)}.");

    public static NativeUInt UnsupportedLoad(string type, NativeUInt address) =>
        Unsupported("load " + type, address);

    public static T UnsupportedLoad<T>(string type, NativeUInt address) =>
        throw new NotSupportedException($"Unsupported load '{type}' as {typeof(T).FullName} at 0x{address:X}.");

    public static void UnsupportedStore(string type, NativeUInt address, NativeUInt value) =>
        throw new NotSupportedException($"Unsupported store '{type}' at 0x{address:X}; value=0x{value:X}.");

    public static void UnsupportedStore<T>(string type, NativeUInt address, T value) =>
        throw new NotSupportedException($"Unsupported store '{type}' of {typeof(T).FullName} at 0x{address:X}; value={Describe(value)}.");

    public static byte RotateLeft(byte value, int count)
    {
        count &= 7;
        return unchecked((byte)((value << count) | (value >> ((8 - count) & 7))));
    }

    public static ushort RotateLeft(ushort value, int count)
    {
        count &= 15;
        return unchecked((ushort)((value << count) | (value >> ((16 - count) & 15))));
    }

    public static uint RotateLeft(uint value, int count)
    {
        count &= 31;
        return (value << count) | (value >> ((32 - count) & 31));
    }

    public static ulong RotateLeft(ulong value, int count)
    {
        count &= 63;
        return (value << count) | (value >> ((64 - count) & 63));
    }

    public static sbyte RotateLeft(sbyte value, int count) => unchecked((sbyte)RotateLeft((byte)value, count));
    public static short RotateLeft(short value, int count) => unchecked((short)RotateLeft((ushort)value, count));
    public static int RotateLeft(int value, int count) => unchecked((int)RotateLeft((uint)value, count));
    public static long RotateLeft(long value, int count) => unchecked((long)RotateLeft((ulong)value, count));

    public static byte RotateRight(byte value, int count)
    {
        count &= 7;
        return unchecked((byte)((value >> count) | (value << ((8 - count) & 7))));
    }

    public static ushort RotateRight(ushort value, int count)
    {
        count &= 15;
        return unchecked((ushort)((value >> count) | (value << ((16 - count) & 15))));
    }

    public static uint RotateRight(uint value, int count)
    {
        count &= 31;
        return (value >> count) | (value << ((32 - count) & 31));
    }

    public static ulong RotateRight(ulong value, int count)
    {
        count &= 63;
        return (value >> count) | (value << ((64 - count) & 63));
    }

    public static sbyte RotateRight(sbyte value, int count) => unchecked((sbyte)RotateRight((byte)value, count));
    public static short RotateRight(short value, int count) => unchecked((short)RotateRight((ushort)value, count));
    public static int RotateRight(int value, int count) => unchecked((int)RotateRight((uint)value, count));
    public static long RotateRight(long value, int count) => unchecked((long)RotateRight((ulong)value, count));

    public static bool Ordered(float left, float right) => !float.IsNaN(left) && !float.IsNaN(right);
    public static bool Ordered(double left, double right) => !double.IsNaN(left) && !double.IsNaN(right);
    public static bool Unordered(float left, float right) => float.IsNaN(left) || float.IsNaN(right);
    public static bool Unordered(double left, double right) => double.IsNaN(left) || double.IsNaN(right);

    public static bool OrderedEqual(float left, float right) => Ordered(left, right) && left == right;
    public static bool OrderedEqual(double left, double right) => Ordered(left, right) && left == right;
    public static bool OrderedNotEqual(float left, float right) => Ordered(left, right) && left != right;
    public static bool OrderedNotEqual(double left, double right) => Ordered(left, right) && left != right;
    public static bool OrderedLessThan(float left, float right) => Ordered(left, right) && left < right;
    public static bool OrderedLessThan(double left, double right) => Ordered(left, right) && left < right;
    public static bool OrderedLessThanOrEqual(float left, float right) => Ordered(left, right) && left <= right;
    public static bool OrderedLessThanOrEqual(double left, double right) => Ordered(left, right) && left <= right;
    public static bool OrderedGreaterThan(float left, float right) => Ordered(left, right) && left > right;
    public static bool OrderedGreaterThan(double left, double right) => Ordered(left, right) && left > right;
    public static bool OrderedGreaterThanOrEqual(float left, float right) => Ordered(left, right) && left >= right;
    public static bool OrderedGreaterThanOrEqual(double left, double right) => Ordered(left, right) && left >= right;

    public static bool UnorderedEqual(float left, float right) => Unordered(left, right) || left == right;
    public static bool UnorderedEqual(double left, double right) => Unordered(left, right) || left == right;
    public static bool UnorderedNotEqual(float left, float right) => Unordered(left, right) || left != right;
    public static bool UnorderedNotEqual(double left, double right) => Unordered(left, right) || left != right;
    public static bool UnorderedLessThan(float left, float right) => Unordered(left, right) || left < right;
    public static bool UnorderedLessThan(double left, double right) => Unordered(left, right) || left < right;
    public static bool UnorderedLessThanOrEqual(float left, float right) => Unordered(left, right) || left <= right;
    public static bool UnorderedLessThanOrEqual(double left, double right) => Unordered(left, right) || left <= right;
    public static bool UnorderedGreaterThan(float left, float right) => Unordered(left, right) || left > right;
    public static bool UnorderedGreaterThan(double left, double right) => Unordered(left, right) || left > right;
    public static bool UnorderedGreaterThanOrEqual(float left, float right) => Unordered(left, right) || left >= right;
    public static bool UnorderedGreaterThanOrEqual(double left, double right) => Unordered(left, right) || left >= right;

    public static bool Unordered(NativeUInt left, NativeUInt right)
    {
        if (RuntimeMemory.PointerSize == 4)
            return Unordered(global::System.BitConverter.Int32BitsToSingle((int)left), global::System.BitConverter.Int32BitsToSingle((int)right));
        return Unordered(global::System.BitConverter.Int64BitsToDouble((long)left), global::System.BitConverter.Int64BitsToDouble((long)right));
    }

    public static bool Ordered(NativeUInt left, NativeUInt right) => !Unordered(left, right);

    public static T UnsupportedAbi<T>(T value) =>
        throw new NotSupportedException($"The value cannot be represented by the supported scalar ABI: {Describe(value)}.");

    public static NativeUInt ObjectToNativePointer<T>(T value) => RuntimeAbi.ToNative(value);
    public static T NativePointerToObject<T>(NativeUInt value) => RuntimeAbi.FromNative<T>(value);
    public static float UInt32BitsToSingle(uint value) => global::System.BitConverter.Int32BitsToSingle(unchecked((int)value));
    public static double UInt64BitsToDouble(ulong value) => global::System.BitConverter.Int64BitsToDouble(unchecked((long)value));
    public static uint SingleToUInt32Bits(float value) => unchecked((uint)global::System.BitConverter.SingleToInt32Bits(value));
    public static ulong DoubleToUInt64Bits(double value) => unchecked((ulong)global::System.BitConverter.DoubleToInt64Bits(value));
    public static float Int32BitsToSingle(int value) => global::System.BitConverter.Int32BitsToSingle(value);
    public static double Int64BitsToDouble(long value) => global::System.BitConverter.Int64BitsToDouble(value);
    public static int SingleToInt32Bits(float value) => global::System.BitConverter.SingleToInt32Bits(value);
    public static long DoubleToInt64Bits(double value) => global::System.BitConverter.DoubleToInt64Bits(value);
    public static double ConvertSingleToDouble(float value) => value;
    public static float ConvertDoubleToSingle(double value) => (float)value;

    public static RuntimeVector128 LoadVector128(NativeUInt address) => RuntimeMemory.ReadVector128(address);
    public static void StoreVector128(NativeUInt address, RuntimeVector128 value) => RuntimeMemory.WriteVector128(address, value);
    public static RuntimeVector128 Vector128FromUInt32(uint lane0, uint lane1, uint lane2, uint lane3) => RuntimeVector128.FromUInt32(lane0, lane1, lane2, lane3);
    public static RuntimeVector128 Vector128FromSingle(float lane0, float lane1, float lane2, float lane3) => RuntimeVector128.FromSingle(lane0, lane1, lane2, lane3);
    public static RuntimeVector128 Vector128FromDouble(double lane0, double lane1) => RuntimeVector128.FromDouble(lane0, lane1);
    public static RuntimeVector128 Vector128FromBytes(byte[] value) => RuntimeVector128.FromBytes(value);
    public static RuntimeVector128 Vector128FromLanes<T>(T[] lanes) where T : unmanaged => RuntimeVector128.FromLanes(lanes);
    public static byte[] Vector128ToBytes(RuntimeVector128 value) => value.ToBytes();
    public static T[] Vector128ToLanes<T>(RuntimeVector128 value) where T : unmanaged => value.ToLanes<T>();
    public static T Vector128GetLane<T>(RuntimeVector128 value, int index) where T : unmanaged => value.GetLane<T>(index);
    public static RuntimeVector128 Vector128WithLane<T>(RuntimeVector128 value, int index, T lane) where T : unmanaged => value.WithLane(index, lane);
    public static RuntimeVector128 Vector128And(RuntimeVector128 left, RuntimeVector128 right) => left & right;
    public static RuntimeVector128 Vector128Or(RuntimeVector128 left, RuntimeVector128 right) => left | right;
    public static RuntimeVector128 Vector128Xor(RuntimeVector128 left, RuntimeVector128 right) => left ^ right;
    public static RuntimeVector128 Vector128Not(RuntimeVector128 value) => ~value;
    public static RuntimeVector128 Vector128AndNot(RuntimeVector128 left, RuntimeVector128 right) => left & ~right;
    public static RuntimeVector128 Vector128ShiftLeftLogical(RuntimeVector128 value, int count) => value.ShiftLeftLogical(count);
    public static RuntimeVector128 Vector128ShiftRightLogical(RuntimeVector128 value, int count) => value.ShiftRightLogical(count);

    public static RuntimeVector128 UnsupportedPackedUnary(string operation, RuntimeVector128 value) =>
        throw new NotSupportedException($"Unsupported packed unary operation '{operation}' for vector128 operand {value}.");

    public static RuntimeVector128 UnsupportedPackedUnary<T>(string operation, RuntimeVector128 value) where T : unmanaged =>
        throw new NotSupportedException($"Unsupported packed unary operation '{operation}' for vector128<{typeof(T).FullName}> operand {value}.");

    public static RuntimeVector128 UnsupportedPackedBinary(string operation, RuntimeVector128 left, RuntimeVector128 right) =>
        throw new NotSupportedException($"Unsupported packed binary operation '{operation}'; left={left}, right={right}.");

    public static RuntimeVector128 UnsupportedPackedBinary<T>(string operation, RuntimeVector128 left, RuntimeVector128 right) where T : unmanaged =>
        throw new NotSupportedException($"Unsupported packed binary operation '{operation}' for vector128<{typeof(T).FullName}>; left={left}, right={right}.");

    public static bool UnsupportedPackedCompare(string operation, RuntimeVector128 left, RuntimeVector128 right) =>
        throw new NotSupportedException($"Unsupported packed comparison '{operation}'; left={left}, right={right}.");

    public static bool UnsupportedPackedCompare<T>(string operation, RuntimeVector128 left, RuntimeVector128 right) where T : unmanaged =>
        throw new NotSupportedException($"Unsupported packed comparison '{operation}' for vector128<{typeof(T).FullName}>; left={left}, right={right}.");

    public static RuntimeVector128 PackedAdd(RuntimeVector128 left, RuntimeVector128 right) => UnsupportedPackedBinary("add", left, right);
    public static RuntimeVector128 PackedSubtract(RuntimeVector128 left, RuntimeVector128 right) => UnsupportedPackedBinary("subtract", left, right);
    public static RuntimeVector128 PackedMultiply(RuntimeVector128 left, RuntimeVector128 right) => UnsupportedPackedBinary("multiply", left, right);
    public static RuntimeVector128 PackedDivide(RuntimeVector128 left, RuntimeVector128 right) => UnsupportedPackedBinary("divide", left, right);
    public static RuntimeVector128 PackedMin(RuntimeVector128 left, RuntimeVector128 right) => UnsupportedPackedBinary("min", left, right);
    public static RuntimeVector128 PackedMax(RuntimeVector128 left, RuntimeVector128 right) => UnsupportedPackedBinary("max", left, right);
    public static RuntimeVector128 PackedAddSaturate(RuntimeVector128 left, RuntimeVector128 right) => UnsupportedPackedBinary("add-saturate", left, right);
    public static RuntimeVector128 PackedSubtractSaturate(RuntimeVector128 left, RuntimeVector128 right) => UnsupportedPackedBinary("subtract-saturate", left, right);
    public static RuntimeVector128 PackedSqrt(RuntimeVector128 value) => UnsupportedPackedUnary("sqrt", value);
    public static RuntimeVector128 PackedReciprocal(RuntimeVector128 value) => UnsupportedPackedUnary("reciprocal", value);
    public static RuntimeVector128 PackedReciprocalSquareRoot(RuntimeVector128 value) => UnsupportedPackedUnary("reciprocal-square-root", value);
    public static bool PackedCompareEqual(RuntimeVector128 left, RuntimeVector128 right) => UnsupportedPackedCompare("equal", left, right);
    public static bool PackedCompareLessThan(RuntimeVector128 left, RuntimeVector128 right) => UnsupportedPackedCompare("less-than", left, right);
    public static bool PackedCompareGreaterThan(RuntimeVector128 left, RuntimeVector128 right) => UnsupportedPackedCompare("greater-than", left, right);

    public static void NullCheck(NativeUInt value) => RuntimeChecks.NullCheck(value);
    public static void DivideByZeroCheck(long denominator) => RuntimeChecks.DivideByZeroCheck(denominator);
    public static void DivideByZeroCheck(ulong denominator) => RuntimeChecks.DivideByZeroCheck(denominator);
    public static void OverflowCheck(bool overflow) => RuntimeChecks.OverflowCheck(overflow);
    public static NativeUInt IsInst(NativeUInt objectAddress, NativeUInt targetType) => RuntimeObject.IsInst(objectAddress, targetType);
    public static NativeUInt Castclass(NativeUInt objectAddress, NativeUInt targetType) => RuntimeObject.Castclass(objectAddress, targetType);
    public static NativeUInt CastClass(NativeUInt objectAddress, NativeUInt targetType) => RuntimeObject.Castclass(objectAddress, targetType);
    public static NativeUInt UnBox(NativeUInt objectAddress) => RuntimeObject.UnBox(objectAddress);
    public static NativeUInt UnBox(NativeUInt objectAddress, NativeUInt expectedType) => RuntimeObject.UnBox(objectAddress, expectedType);
    public static NativeUInt GetStaticFieldAddress(NativeUInt typeHandle, int fieldOffset) => RuntimeClass.GetStaticFieldAddress(typeHandle, fieldOffset);
    public static NativeUInt GetThreadStaticFieldAddress(NativeUInt typeHandle, int fieldOffset) => RuntimeClass.GetThreadStaticFieldAddress(typeHandle, fieldOffset);
    public static void RuntimeClassInit(NativeUInt typeHandle) => RuntimeClass.RuntimeClassInit(typeHandle);
    public static RuntimeDelegateInvokeData GetDelegateInvokeData(NativeUInt delegateAddress) => RuntimeDelegate.GetInvokeData(delegateAddress);
    public static int GetArrayLength(NativeUInt arrayAddress) => RuntimeArray.GetLength(arrayAddress);
    public static NativeUInt GetArrayElementAddress(NativeUInt arrayAddress, int index, int elementSize) => RuntimeArray.GetElementAddress(arrayAddress, index, elementSize);
    public static NativeUInt GetArrayElementAddress(NativeUInt arrayAddress, int[] indices, int elementSize) => RuntimeArray.GetElementAddress(arrayAddress, indices, elementSize);
    public static NativeUInt GetStringCharsAddress(NativeUInt stringAddress) => RuntimeString.GetCharsAddress(stringAddress);
    public static string ReadUtf16String(NativeUInt stringAddress) => RuntimeString.ReadString(stringAddress);

    private static string Describe<T>(T value)
    {
        if ((object)value == null)
            return "null";
        return global::System.Convert.ToString(value, global::System.Globalization.CultureInfo.InvariantCulture);
    }
}

public static class RuntimeAbi
{
    public static global::System.Func<object, NativeUInt> ManagedToNativeHandler { get; set; }
    public static global::System.Func<NativeUInt, global::System.Type, object> NativeToManagedHandler { get; set; }
    public static global::System.Func<NativeUInt, object[], object> DirectCallHandler { get; set; }
    public static global::System.Func<NativeUInt, object[], object> IndirectCallHandler { get; set; }

    public static NativeUInt ToNative<T>(T value) => ToNative(value, typeof(T));
    public static NativeUInt FromManaged<T>(T value) => ToNative(value, typeof(T));
    public static NativeUInt ToNativeArgument<T>(T value) => ToNative(value, typeof(T));
    public static NativeUInt ToNativeReturn<T>(T value) => ToNative(value, typeof(T));
    public static ulong ToNativeBits<T>(T value) => ToNativeBits(value, typeof(T));

    public static T FromNative<T>(NativeUInt value) => (T)FromNative(value, typeof(T));
    public static T ToManaged<T>(NativeUInt value) => FromNative<T>(value);
    public static T FromNativeArgument<T>(NativeUInt value) => FromNative<T>(value);
    public static T FromNativeReturn<T>(NativeUInt value) => FromNative<T>(value);
    public static T FromNativeBits<T>(ulong value) => (T)FromNativeBits(value, typeof(T));

    public static NativeUInt ToNative(object value, global::System.Type type)
    {
        RequireNativeWidth(type);
        return unchecked((NativeUInt)ToNativeBits(value, type));
    }

    public static ulong ToNativeBits(object value, global::System.Type type)
    {
        if (type == null)
            throw new ArgumentNullException(nameof(type));
        if (type.IsEnum)
            return ToNativeBits(global::System.Convert.ChangeType(value, global::System.Enum.GetUnderlyingType(type), global::System.Globalization.CultureInfo.InvariantCulture), global::System.Enum.GetUnderlyingType(type));
        if ((object)value == null)
        {
            if (type.IsValueType)
                throw new ArgumentNullException(nameof(value));
            return 0;
        }

        if (type == typeof(bool)) return (bool)value ? 1UL : 0UL;
        if (type == typeof(byte)) return (byte)value;
        if (type == typeof(sbyte)) return unchecked((ulong)(long)(sbyte)value);
        if (type == typeof(ushort)) return (ushort)value;
        if (type == typeof(short)) return unchecked((ulong)(long)(short)value);
        if (type == typeof(char)) return (char)value;
        if (type == typeof(uint)) return (uint)value;
        if (type == typeof(int)) return unchecked((ulong)(long)(int)value);
        if (type == typeof(ulong)) return (ulong)value;
        if (type == typeof(long)) return unchecked((ulong)(long)value);
        if (type == typeof(float)) return unchecked((uint)global::System.BitConverter.SingleToInt32Bits((float)value));
        if (type == typeof(double)) return unchecked((ulong)global::System.BitConverter.DoubleToInt64Bits((double)value));
        if (type == typeof(global::System.IntPtr)) return unchecked((ulong)((global::System.IntPtr)value).ToInt64());
        if (type == typeof(global::System.UIntPtr)) return ((global::System.UIntPtr)value).ToUInt64();
        if (ManagedToNativeHandler != null)
            return ManagedToNativeHandler(value);
        throw new NotSupportedException($"No managed-to-native conversion is registered for {type.FullName}.");
    }

    public static object FromNative(NativeUInt value, global::System.Type type)
    {
        RequireNativeWidth(type);
        return FromNativeBits(value, type);
    }

    public static object FromNativeBits(ulong value, global::System.Type type)
    {
        if (type == null)
            throw new ArgumentNullException(nameof(type));
        if (type.IsEnum)
            return global::System.Enum.ToObject(type, FromNativeBits(value, global::System.Enum.GetUnderlyingType(type)));

        if (type == typeof(bool)) return value != 0;
        if (type == typeof(byte)) return unchecked((byte)value);
        if (type == typeof(sbyte)) return unchecked((sbyte)value);
        if (type == typeof(ushort)) return unchecked((ushort)value);
        if (type == typeof(short)) return unchecked((short)value);
        if (type == typeof(char)) return unchecked((char)value);
        if (type == typeof(uint)) return unchecked((uint)value);
        if (type == typeof(int)) return unchecked((int)value);
        if (type == typeof(ulong)) return value;
        if (type == typeof(long)) return unchecked((long)value);
        if (type == typeof(float)) return global::System.BitConverter.Int32BitsToSingle(unchecked((int)(uint)value));
        if (type == typeof(double)) return global::System.BitConverter.Int64BitsToDouble(unchecked((long)value));
        if (type == typeof(global::System.IntPtr))
            return RuntimeMemory.PointerSize == 4 ? new global::System.IntPtr(unchecked((int)value)) : new global::System.IntPtr(unchecked((long)value));
        if (type == typeof(global::System.UIntPtr))
            return RuntimeMemory.PointerSize == 4 ? new global::System.UIntPtr(unchecked((uint)value)) : new global::System.UIntPtr(value);
        if (value == 0 && !type.IsValueType)
            return null;
        if (NativeToManagedHandler != null)
        {
            if (RuntimeMemory.PointerSize == 4 && value > uint.MaxValue)
                throw new ArgumentOutOfRangeException(nameof(value), "A native 32-bit value cannot contain bits outside the low 32 bits.");
            return NativeToManagedHandler(unchecked((NativeUInt)value), type);
        }
        throw new NotSupportedException($"No native-to-managed conversion is registered for {type.FullName}.");
    }

    public static T InvokeDirect<T>(NativeUInt target, params object[] arguments)
    {
        global::System.Func<NativeUInt, object[], object> handler = DirectCallHandler ?? IndirectCallHandler;
        object[] managedArguments = arguments ?? global::System.Array.Empty<object>();
        if (handler != null)
            return ManagedResult<T>(handler(target, managedArguments));
        return FromNative<T>(RuntimeCalls.InvokeDirect(target, ToNativeArguments(managedArguments)));
    }

    public static T Invoke<T>(NativeUInt target, params object[] arguments) => InvokeDirect<T>(target, arguments);

    public static T InvokeIndirect<T>(NativeUInt target, params object[] arguments)
    {
        global::System.Func<NativeUInt, object[], object> handler = IndirectCallHandler ?? DirectCallHandler;
        object[] managedArguments = arguments ?? global::System.Array.Empty<object>();
        if (handler != null)
            return ManagedResult<T>(handler(target, managedArguments));
        return FromNative<T>(RuntimeCalls.InvokeIndirect(target, ToNativeArguments(managedArguments)));
    }

    public static void InvokeDirect(NativeUInt target, params object[] arguments)
    {
        global::System.Func<NativeUInt, object[], object> handler = DirectCallHandler ?? IndirectCallHandler;
        object[] managedArguments = arguments ?? global::System.Array.Empty<object>();
        if (handler != null)
            handler(target, managedArguments);
        else
            RuntimeCalls.InvokeDirect(target, ToNativeArguments(managedArguments));
    }

    public static void InvokeIndirect(NativeUInt target, params object[] arguments)
    {
        global::System.Func<NativeUInt, object[], object> handler = IndirectCallHandler ?? DirectCallHandler;
        object[] managedArguments = arguments ?? global::System.Array.Empty<object>();
        if (handler != null)
            handler(target, managedArguments);
        else
            RuntimeCalls.InvokeIndirect(target, ToNativeArguments(managedArguments));
    }

    private static NativeUInt[] ToNativeArguments(object[] arguments)
    {
        NativeUInt[] result = new NativeUInt[arguments.Length];
        for (int i = 0; i < arguments.Length; ++i)
            result[i] = ToNative(arguments[i], arguments[i]?.GetType() ?? typeof(object));
        return result;
    }

    private static T ManagedResult<T>(object value)
    {
        if (value == null && typeof(T).IsValueType)
            throw new InvalidOperationException($"A managed call returned null for value type {typeof(T).FullName}.");
        return (T)value;
    }

    private static void RequireNativeWidth(global::System.Type type)
    {
        if (type == null)
            throw new ArgumentNullException(nameof(type));
        if (type.IsEnum)
            type = global::System.Enum.GetUnderlyingType(type);
        if (RuntimeMemory.PointerSize == 4 &&
            (type == typeof(ulong) || type == typeof(long) || type == typeof(double)))
            throw new NotSupportedException($"A {type.FullName} value does not fit in one 32-bit native ABI word; use the 64-bit bits conversion or a typed call handler.");
    }
}

public static class RuntimeChecks
{
    public static void NullCheck(NativeUInt value)
    {
        if (value == 0)
            throw new NullReferenceException();
    }

    public static void NullCheck(NativeUInt value, string expression)
    {
        if (value == 0)
            throw new NullReferenceException($"Null reference while evaluating '{expression}'.");
    }

    public static void DivideByZeroCheck(long denominator)
    {
        if (denominator == 0)
            throw new DivideByZeroException();
    }

    public static void DivideByZeroCheck(ulong denominator)
    {
        if (denominator == 0)
            throw new DivideByZeroException();
    }

    public static void OverflowCheck(bool overflow)
    {
        if (overflow)
            ThrowOverflow();
    }

    public static void CheckOverflow(bool overflow) => OverflowCheck(overflow);

    public static void ThrowOverflow() =>
        throw new OverflowException("Arithmetic operation resulted in an overflow.");

    public static int AddChecked(int left, int right) => checked(left + right);
    public static uint AddChecked(uint left, uint right) => checked(left + right);
    public static long AddChecked(long left, long right) => checked(left + right);
    public static ulong AddChecked(ulong left, ulong right) => checked(left + right);
    public static int SubtractChecked(int left, int right) => checked(left - right);
    public static uint SubtractChecked(uint left, uint right) => checked(left - right);
    public static long SubtractChecked(long left, long right) => checked(left - right);
    public static ulong SubtractChecked(ulong left, ulong right) => checked(left - right);
    public static int MultiplyChecked(int left, int right) => checked(left * right);
    public static uint MultiplyChecked(uint left, uint right) => checked(left * right);
    public static long MultiplyChecked(long left, long right) => checked(left * right);
    public static ulong MultiplyChecked(ulong left, ulong right) => checked(left * right);
    public static int NegateChecked(int value) => checked(-value);
    public static long NegateChecked(long value) => checked(-value);
}

public static unsafe partial class RuntimeClass
{
    public static int StaticFieldsOffset => 23 * RuntimeMemory.PointerSize;
    public static int StaticFieldsSizeOffset => ThreadStaticFieldsOffsetFieldOffset - 8;
    public static int ThreadStaticFieldsSizeOffset => ThreadStaticFieldsOffsetFieldOffset - 4;
    public static int ThreadStaticFieldsOffsetFieldOffset => RuntimeMemory.PointerSize == 8 ? 260 : 156;
    public static int CctorFinishedOffset => 26 * RuntimeMemory.PointerSize + 8;
    public static bool StaticFieldsSupported => true;
    public static bool ThreadStaticFieldsSupported => true;

    public static global::System.Func<int, NativeUInt> ThreadStaticDataHandler { get; set; }
    public static global::System.Func<NativeUInt, NativeUInt> ThreadStaticDataResolver { get; set; }
    public static global::System.Action<NativeUInt> ClassInitHandler { get; set; }

    public static NativeUInt GetStaticFieldsAddress(NativeUInt typeHandle)
    {
        RuntimeChecks.NullCheck(typeHandle);
        if (!StaticFieldsSupported)
            throw new NotSupportedException("The reduced class layout has no static_fields pointer.");
        return RuntimeMemory.ReadPtr(typeHandle + (NativeUInt)StaticFieldsOffset);
    }

    public static NativeUInt GetStaticFieldAddress(NativeUInt typeHandle, int fieldOffset)
    {
        if (fieldOffset < 0)
            throw new ArgumentOutOfRangeException(nameof(fieldOffset));
        NativeUInt fields = GetStaticFieldsAddress(typeHandle);
        if (fields == 0)
            throw new InvalidOperationException($"Class 0x{typeHandle:X} has no static field storage.");
        return fields + (NativeUInt)fieldOffset;
    }

    public static T ReadStaticField<T>(NativeUInt typeHandle, int fieldOffset) where T : unmanaged =>
        RuntimeMemory.Read<T>(GetStaticFieldAddress(typeHandle, fieldOffset));

    public static void WriteStaticField<T>(NativeUInt typeHandle, int fieldOffset, T value) where T : unmanaged =>
        RuntimeMemory.Write(GetStaticFieldAddress(typeHandle, fieldOffset), value);

    public static int GetThreadStaticFieldsOffset(NativeUInt typeHandle)
    {
        RuntimeChecks.NullCheck(typeHandle);
        if (!ThreadStaticFieldsSupported)
            throw new NotSupportedException("The reduced class layout has no thread_static_fields_offset field.");
        int offset = RuntimeMemory.ReadS32(typeHandle + (NativeUInt)ThreadStaticFieldsOffsetFieldOffset);
        if (offset < 0)
            throw new InvalidOperationException($"Invalid thread-static data offset {offset} for class 0x{typeHandle:X}.");
        return offset;
    }

    public static NativeUInt GetThreadStaticDataAddress(NativeUInt typeHandle)
    {
        RuntimeChecks.NullCheck(typeHandle);
        if (!ThreadStaticFieldsSupported)
            throw new NotSupportedException("The reduced class layout has no thread-static field metadata.");
        if (ThreadStaticDataResolver != null)
            return ThreadStaticDataResolver(typeHandle);
        if (ThreadStaticDataHandler == null)
            throw new NotSupportedException("No thread-static data resolver is registered.");
        return ThreadStaticDataHandler(GetThreadStaticFieldsOffset(typeHandle));
    }

    public static NativeUInt GetThreadStaticFieldAddress(NativeUInt typeHandle, int fieldOffset)
    {
        if (fieldOffset < 0)
            throw new ArgumentOutOfRangeException(nameof(fieldOffset));
        NativeUInt fields = GetThreadStaticDataAddress(typeHandle);
        if (fields == 0)
            throw new InvalidOperationException($"Class 0x{typeHandle:X} has no thread-static field storage on this thread.");
        return fields + (NativeUInt)fieldOffset;
    }

    public static T ReadThreadStaticField<T>(NativeUInt typeHandle, int fieldOffset) where T : unmanaged =>
        RuntimeMemory.Read<T>(GetThreadStaticFieldAddress(typeHandle, fieldOffset));

    public static void WriteThreadStaticField<T>(NativeUInt typeHandle, int fieldOffset, T value) where T : unmanaged =>
        RuntimeMemory.Write(GetThreadStaticFieldAddress(typeHandle, fieldOffset), value);

    public static void RuntimeClassInit(NativeUInt typeHandle)
    {
        RuntimeChecks.NullCheck(typeHandle);
        if (ClassInitHandler == null)
            throw new NotSupportedException($"No runtime class initializer is registered for class 0x{typeHandle:X}.");
        ClassInitHandler(typeHandle);
    }

    public static void ClassInit(NativeUInt typeHandle) => RuntimeClassInit(typeHandle);
}

[global::System.Runtime.InteropServices.StructLayoutAttribute(global::System.Runtime.InteropServices.LayoutKind.Sequential)]
public struct RuntimeDelegateInvokeData
{
    public NativeUInt MethodPointer;
    public NativeUInt Method;

    public RuntimeDelegateInvokeData(NativeUInt methodPointer, NativeUInt method)
    {
        MethodPointer = methodPointer;
        Method = method;
    }
}

public static unsafe class RuntimeDelegate
{
    public static int MethodPointerOffset => 2 * RuntimeMemory.PointerSize;
    public static int InvokeImplOffset => 3 * RuntimeMemory.PointerSize;
    public static int TargetOffset => 4 * RuntimeMemory.PointerSize;
    public static int MethodOffset => 5 * RuntimeMemory.PointerSize;
    public static int DelegateTrampolineOffset => 6 * RuntimeMemory.PointerSize;
    public static int ExtraArgumentOffset => 7 * RuntimeMemory.PointerSize;
    public static int MethodCodeOffset => 8 * RuntimeMemory.PointerSize;
    public static int MethodInfoOffset => 9 * RuntimeMemory.PointerSize;
    public static int OriginalMethodInfoOffset => 10 * RuntimeMemory.PointerSize;
    public static int DataOffset => 11 * RuntimeMemory.PointerSize;
    public static int MethodIsVirtualOffset => 12 * RuntimeMemory.PointerSize;
    public static int MulticastDelegatesOffset => 13 * RuntimeMemory.PointerSize;
    public static int InvokeDataSize => 2 * RuntimeMemory.PointerSize;

    public static RuntimeDelegateInvokeData GetInvokeData(NativeUInt delegateAddress)
    {
        RuntimeChecks.NullCheck(delegateAddress);
        return new RuntimeDelegateInvokeData(
            RuntimeMemory.ReadPtr(delegateAddress + (NativeUInt)MethodPointerOffset),
            RuntimeMemory.ReadPtr(delegateAddress + (NativeUInt)MethodOffset));
    }

    public static RuntimeDelegateInvokeData ReadInvokeData(NativeUInt delegateAddress) => GetInvokeData(delegateAddress);

    public static NativeUInt GetInvokeImpl(NativeUInt delegateAddress) => ReadPointer(delegateAddress, InvokeImplOffset);
    public static NativeUInt GetTarget(NativeUInt delegateAddress) => ReadPointer(delegateAddress, TargetOffset);
    public static NativeUInt GetMethodPointer(NativeUInt delegateAddress) => ReadPointer(delegateAddress, MethodPointerOffset);
    public static NativeUInt GetMethod(NativeUInt delegateAddress) => ReadPointer(delegateAddress, MethodOffset);
    public static NativeUInt GetDelegateTrampoline(NativeUInt delegateAddress) => ReadPointer(delegateAddress, DelegateTrampolineOffset);
    public static NativeUInt GetExtraArgument(NativeUInt delegateAddress) => ReadPointer(delegateAddress, ExtraArgumentOffset);
    public static NativeUInt GetMethodCode(NativeUInt delegateAddress) => ReadPointer(delegateAddress, MethodCodeOffset);
    public static NativeUInt GetMethodInfo(NativeUInt delegateAddress) => ReadPointer(delegateAddress, MethodInfoOffset);
    public static NativeUInt GetOriginalMethodInfo(NativeUInt delegateAddress) => ReadPointer(delegateAddress, OriginalMethodInfoOffset);
    public static NativeUInt GetData(NativeUInt delegateAddress) => ReadPointer(delegateAddress, DataOffset);
    public static NativeUInt GetMulticastDelegates(NativeUInt delegateAddress) => ReadPointer(delegateAddress, MulticastDelegatesOffset);
    public static bool HasInvoker(NativeUInt delegateAddress) => GetInvokeImpl(delegateAddress) != 0;

    public static bool GetMethodIsVirtual(NativeUInt delegateAddress)
    {
        RuntimeChecks.NullCheck(delegateAddress);
        return RuntimeMemory.ReadU8(delegateAddress + (NativeUInt)MethodIsVirtualOffset) != 0;
    }

    private static NativeUInt ReadPointer(NativeUInt delegateAddress, int offset)
    {
        RuntimeChecks.NullCheck(delegateAddress);
        return RuntimeMemory.ReadPtr(delegateAddress + (NativeUInt)offset);
    }
}
)CS";
    output << R"CS(public static unsafe class RuntimeObject
{
    public static int ClassHandleOffset => 0;
    public static int MonitorOffset => RuntimeMemory.PointerSize;
    public static int ElementClassOffset => 8 * RuntimeMemory.PointerSize;
    public static int HeaderSize { get; set; } = 2 * RuntimeMemory.PointerSize;
    public static int BoxDataOffset { get; set; } = 2 * RuntimeMemory.PointerSize;
    public static global::System.Func<NativeUInt, int, NativeUInt> ObjectAllocator { get; set; }
    public static global::System.Func<global::System.Type, NativeUInt> ManagedObjectAllocator { get; set; }
    public static global::System.Func<global::System.Type, ulong, int, NativeUInt> BoxingHandler { get; set; }
    public static global::System.Func<NativeUInt, NativeUInt, NativeUInt> IsInstHandler { get; set; }

    public static NativeUInt NewObject(NativeUInt typeHandle)
    {
        if (ObjectAllocator == null)
            throw new NotSupportedException("An object allocator is required when the object size is unknown.");
        return ObjectAllocator(typeHandle, -1);
    }

    public static NativeUInt NewObject(global::System.Type type)
    {
        if (type == null)
            throw new ArgumentNullException(nameof(type));
        if (ManagedObjectAllocator == null)
            throw new NotSupportedException("No managed object allocator is registered.");
        return ManagedObjectAllocator(type);
    }

    public static NativeUInt NewObject(NativeUInt typeHandle, int size)
    {
        if (ObjectAllocator != null)
            return ObjectAllocator(typeHandle, size);
        if (size < HeaderSize || HeaderSize < RuntimeMemory.PointerSize)
            throw new ArgumentOutOfRangeException(nameof(size));

        NativeUInt result = RuntimeMemory.Allocate(size);
        RuntimeMemory.WritePtr(result, typeHandle);
        return result;
    }

    public static NativeUInt Allocate(NativeUInt typeHandle) => NewObject(typeHandle);
    public static NativeUInt Allocate(NativeUInt typeHandle, int size) => NewObject(typeHandle, size);

    public static NativeUInt NullCheck(NativeUInt objectAddress)
    {
        RuntimeChecks.NullCheck(objectAddress);
        return objectAddress;
    }

    public static NativeUInt GetClassHandle(NativeUInt objectAddress)
    {
        EnsureObject(objectAddress);
        return RuntimeMemory.ReadPtr(objectAddress + (NativeUInt)ClassHandleOffset);
    }

    public static NativeUInt GetMonitor(NativeUInt objectAddress)
    {
        EnsureObject(objectAddress);
        return RuntimeMemory.ReadPtr(objectAddress + (NativeUInt)MonitorOffset);
    }

    public static NativeUInt GetElementClassHandle(NativeUInt typeHandle)
    {
        RuntimeChecks.NullCheck(typeHandle);
        return RuntimeMemory.ReadPtr(typeHandle + (NativeUInt)ElementClassOffset);
    }

    public static NativeUInt GetFieldAddress(NativeUInt objectAddress, int offset)
    {
        EnsureObject(objectAddress);
        return unchecked(objectAddress + (NativeUInt)(long)offset);
    }

    public static T ReadField<T>(NativeUInt objectAddress, int offset) where T : unmanaged =>
        RuntimeMemory.Read<T>(GetFieldAddress(objectAddress, offset));

    public static void WriteField<T>(NativeUInt objectAddress, int offset, T value) where T : unmanaged =>
        RuntimeMemory.Write(GetFieldAddress(objectAddress, offset), value);

    public static NativeUInt IsInst(NativeUInt objectAddress, NativeUInt targetType)
    {
        if (objectAddress == 0)
            return 0;
        RequireTargetType(targetType);
        if (IsInstHandler == null)
            throw new NotSupportedException("No runtime IsInst handler is registered.");
        return IsInstHandler(objectAddress, targetType);
    }

    public static NativeUInt IsInstSealed(NativeUInt objectAddress, NativeUInt targetType)
    {
        if (objectAddress == 0)
            return 0;
        RequireTargetType(targetType);
        return GetClassHandle(objectAddress) == targetType ? objectAddress : 0;
    }

    public static NativeUInt Castclass(NativeUInt objectAddress, NativeUInt targetType)
    {
        if (objectAddress == 0)
            return 0;
        NativeUInt result = IsInst(objectAddress, targetType);
        if (result == 0)
            throw new InvalidCastException($"Object 0x{objectAddress:X} cannot be cast to class 0x{targetType:X}.");
        return result;
    }

    public static NativeUInt CastClass(NativeUInt objectAddress, NativeUInt targetType) => Castclass(objectAddress, targetType);

    public static NativeUInt CastclassSealed(NativeUInt objectAddress, NativeUInt targetType)
    {
        if (objectAddress == 0)
            return 0;
        NativeUInt result = IsInstSealed(objectAddress, targetType);
        if (result == 0)
            throw new InvalidCastException($"Object 0x{objectAddress:X} cannot be cast to sealed class 0x{targetType:X}.");
        return result;
    }

    public static NativeUInt Box<T>(T value) where T : unmanaged
    {
        if (BoxingHandler == null)
            throw new NotSupportedException("No boxing handler is registered.");
        return BoxingHandler(typeof(T), (ulong)&value, sizeof(T));
    }

    public static NativeUInt Box<T>(NativeUInt typeHandle, T value) where T : unmanaged
    {
        if (BoxDataOffset < 0)
            throw new InvalidOperationException("The box data offset cannot be negative.");
        NativeUInt result = NewObject(typeHandle, checked(BoxDataOffset + sizeof(T)));
        RuntimeMemory.Write(GetBoxDataAddress(result), value);
        return result;
    }

    public static NativeUInt Unbox(NativeUInt objectAddress) => GetBoxDataAddress(objectAddress);
    public static NativeUInt UnBox(NativeUInt objectAddress) => GetBoxDataAddress(objectAddress);

    public static NativeUInt UnBox(NativeUInt objectAddress, NativeUInt expectedBoxedClass)
    {
        EnsureObject(objectAddress);
        RequireTargetType(expectedBoxedClass);
        if (GetElementClassHandle(GetClassHandle(objectAddress)) != GetElementClassHandle(expectedBoxedClass))
            throw new InvalidCastException($"Object 0x{objectAddress:X} is not a box of class 0x{expectedBoxedClass:X}.");
        return GetBoxDataAddress(objectAddress);
    }

    public static T Unbox<T>(NativeUInt objectAddress) where T : unmanaged =>
        RuntimeMemory.Read<T>(GetBoxDataAddress(objectAddress));

    public static T UnBox<T>(NativeUInt objectAddress) where T : unmanaged => Unbox<T>(objectAddress);

    public static T UnBox<T>(NativeUInt objectAddress, NativeUInt expectedBoxedClass) where T : unmanaged =>
        RuntimeMemory.Read<T>(UnBox(objectAddress, expectedBoxedClass));

    public static NativeUInt GetBoxDataAddress(NativeUInt objectAddress)
    {
        EnsureObject(objectAddress);
        if (BoxDataOffset < 0)
            throw new InvalidOperationException("The box data offset cannot be negative.");
        return objectAddress + (NativeUInt)BoxDataOffset;
    }

    private static void RequireTargetType(NativeUInt targetType)
    {
        if (targetType == 0)
            throw new ArgumentNullException(nameof(targetType));
    }

    private static void EnsureObject(NativeUInt objectAddress) => RuntimeChecks.NullCheck(objectAddress);
}

public static unsafe class RuntimeString
{
    public static int LengthOffset => 2 * RuntimeMemory.PointerSize;
    public static int CharsOffset => 2 * RuntimeMemory.PointerSize + 4;

    public static int GetLength(NativeUInt stringAddress)
    {
        RuntimeChecks.NullCheck(stringAddress);
        int length = RuntimeMemory.ReadS32(stringAddress + (NativeUInt)LengthOffset);
        if (length < 0)
            throw new InvalidOperationException($"Negative UTF-16 string length {length} at 0x{stringAddress:X}.");
        return length;
    }

    public static int Length(NativeUInt stringAddress) => GetLength(stringAddress);

    public static NativeUInt GetCharsAddress(NativeUInt stringAddress)
    {
        RuntimeChecks.NullCheck(stringAddress);
        return stringAddress + (NativeUInt)CharsOffset;
    }

    public static char ReadChar(NativeUInt stringAddress, int index)
    {
        if ((uint)index >= (uint)GetLength(stringAddress))
            throw new IndexOutOfRangeException();
        return (char)RuntimeMemory.ReadU16(GetCharsAddress(stringAddress) + (NativeUInt)checked(index * 2));
    }

    public static void WriteChar(NativeUInt stringAddress, int index, char value)
    {
        if ((uint)index >= (uint)GetLength(stringAddress))
            throw new IndexOutOfRangeException();
        RuntimeMemory.WriteU16(GetCharsAddress(stringAddress) + (NativeUInt)checked(index * 2), value);
    }

    public static string ReadString(NativeUInt stringAddress)
    {
        int length = GetLength(stringAddress);
        char[] characters = new char[length];
        NativeUInt address = GetCharsAddress(stringAddress);
        for (int i = 0; i < length; ++i)
            characters[i] = (char)RuntimeMemory.ReadU16(address + (NativeUInt)(i * 2));
        return new string(characters);
    }

    public static string ToString(NativeUInt stringAddress) => ReadString(stringAddress);

    public static NativeUInt NewString(NativeUInt typeHandle, string value)
    {
        if (value == null)
            throw new ArgumentNullException(nameof(value));
        NativeUInt result = RuntimeObject.NewObject(typeHandle, checked(CharsOffset + (value.Length + 1) * 2));
        RuntimeMemory.WriteS32(result + (NativeUInt)LengthOffset, value.Length);
        for (int i = 0; i < value.Length; ++i)
            RuntimeMemory.WriteU16(GetCharsAddress(result) + (NativeUInt)(i * 2), value[i]);
        RuntimeMemory.WriteU16(GetCharsAddress(result) + (NativeUInt)(value.Length * 2), 0);
        return result;
    }

    public static NativeUInt CreateString(NativeUInt typeHandle, string value) => NewString(typeHandle, value);
}

[global::System.Runtime.InteropServices.StructLayoutAttribute(global::System.Runtime.InteropServices.LayoutKind.Sequential)]
public struct RuntimeArrayBounds
{
    public uint Length;
    public int LowerBound;

    public RuntimeArrayBounds(uint length, int lowerBound)
    {
        Length = length;
        LowerBound = lowerBound;
    }
}

public static unsafe class RuntimeArray
{
    public static int BoundsOffset => 2 * RuntimeMemory.PointerSize;
    public static int LengthOffset { get; set; } = 3 * RuntimeMemory.PointerSize;
    public static int ElementsOffset { get; set; } = 4 * RuntimeMemory.PointerSize;
    public static int BoundsSize => 8;
    public static int BoundLengthOffset => 0;
    public static int BoundLowerBoundOffset => 4;
    public static global::System.Func<NativeUInt, int, int, NativeUInt> ArrayAllocator { get; set; }
    public static global::System.Func<global::System.Type, int, NativeUInt> ManagedArrayAllocator { get; set; }

    public static NativeUInt NewArray(global::System.Type elementType, int length)
    {
        if (elementType == null)
            throw new ArgumentNullException(nameof(elementType));
        if (length < 0)
            throw new ArgumentOutOfRangeException(nameof(length));
        if (ManagedArrayAllocator == null)
            throw new NotSupportedException("No managed array allocator is registered.");
        return ManagedArrayAllocator(elementType, length);
    }

    public static NativeUInt NewArray(NativeUInt arrayTypeHandle, int length, int elementSize)
    {
        if (length < 0)
            throw new ArgumentOutOfRangeException(nameof(length));
        if (elementSize < 0)
            throw new ArgumentOutOfRangeException(nameof(elementSize));
        if (ArrayAllocator != null)
            return ArrayAllocator(arrayTypeHandle, length, elementSize);
        if (LengthOffset < 2 * RuntimeMemory.PointerSize || ElementsOffset < LengthOffset + 4)
            throw new InvalidOperationException("The array layout is invalid.");

        int size = checked(ElementsOffset + length * elementSize);
        NativeUInt result = RuntimeMemory.Allocate(size);
        RuntimeMemory.WritePtr(result, arrayTypeHandle);
        WriteLength(result, length);
        return result;
    }

    public static NativeUInt NewArray<T>(NativeUInt arrayTypeHandle, int length) where T : unmanaged =>
        NewArray(arrayTypeHandle, length, sizeof(T));

    public static NativeUInt GetLengthAddress(NativeUInt arrayAddress)
    {
        EnsureArray(arrayAddress);
        return arrayAddress + (NativeUInt)LengthOffset;
    }

    public static int GetLength(NativeUInt arrayAddress) =>
        checked((int)RuntimeMemory.ReadU32(GetLengthAddress(arrayAddress)));

    public static int Length(NativeUInt arrayAddress) => GetLength(arrayAddress);

    public static NativeUInt GetBoundsAddress(NativeUInt arrayAddress)
    {
        EnsureArray(arrayAddress);
        return RuntimeMemory.ReadPtr(arrayAddress + (NativeUInt)BoundsOffset);
    }

    public static bool HasBounds(NativeUInt arrayAddress) => GetBoundsAddress(arrayAddress) != 0;

    public static NativeUInt GetRequiredBoundsAddress(NativeUInt arrayAddress)
    {
        NativeUInt bounds = GetBoundsAddress(arrayAddress);
        if (bounds == 0)
            throw new InvalidOperationException($"Array 0x{arrayAddress:X} is a vector and has no Il2CppArrayBounds records.");
        return bounds;
    }

    public static RuntimeArrayBounds ReadBounds(NativeUInt arrayAddress, int dimension, int rank)
    {
        ValidateDimension(dimension, rank);
        NativeUInt bounds = GetRequiredBoundsAddress(arrayAddress);
        return RuntimeMemory.Read<RuntimeArrayBounds>(bounds + (NativeUInt)checked(dimension * BoundsSize));
    }

    public static int GetDimensionLength(NativeUInt arrayAddress, int dimension, int rank) =>
        checked((int)ReadBounds(arrayAddress, dimension, rank).Length);

    public static int GetLength(NativeUInt arrayAddress, int dimension, int rank) =>
        GetDimensionLength(arrayAddress, dimension, rank);

    public static int GetLowerBound(NativeUInt arrayAddress, int dimension, int rank) =>
        ReadBounds(arrayAddress, dimension, rank).LowerBound;

    public static NativeUInt GetElementAddress(NativeUInt arrayAddress, int index, int elementSize)
    {
        if (elementSize < 0)
            throw new ArgumentOutOfRangeException(nameof(elementSize));
        if ((uint)index >= (uint)GetLength(arrayAddress))
            throw new IndexOutOfRangeException();
        return checked(arrayAddress + (NativeUInt)ElementsOffset + (NativeUInt)checked(index * elementSize));
    }

    public static NativeUInt GetElementAddress(NativeUInt arrayAddress, int[] indices, int elementSize)
    {
        if (indices == null)
            throw new ArgumentNullException(nameof(indices));
        if (indices.Length == 0)
            throw new ArgumentException("At least one array index is required.", nameof(indices));
        if (elementSize < 0)
            throw new ArgumentOutOfRangeException(nameof(elementSize));

        long elementIndex = 0;
        long stride = 1;
        for (int dimension = indices.Length - 1; dimension >= 0; --dimension)
        {
            RuntimeArrayBounds bounds = ReadBounds(arrayAddress, dimension, indices.Length);
            long relativeIndex = (long)indices[dimension] - bounds.LowerBound;
            if (relativeIndex < 0 || (ulong)relativeIndex >= bounds.Length)
                throw new IndexOutOfRangeException();
            elementIndex = checked(elementIndex + relativeIndex * stride);
            stride = checked(stride * bounds.Length);
        }
        if (stride != GetLength(arrayAddress))
            throw new InvalidOperationException("The array bounds product does not match max_length.");
        return checked(arrayAddress + (NativeUInt)ElementsOffset + (NativeUInt)checked(elementIndex * elementSize));
    }

    public static T ReadElement<T>(NativeUInt arrayAddress, int index) where T : unmanaged =>
        RuntimeMemory.Read<T>(GetElementAddress(arrayAddress, index, sizeof(T)));

    public static T ReadElement<T>(NativeUInt arrayAddress, int[] indices) where T : unmanaged =>
        RuntimeMemory.Read<T>(GetElementAddress(arrayAddress, indices, sizeof(T)));

    public static void WriteElement<T>(NativeUInt arrayAddress, int index, T value) where T : unmanaged =>
        RuntimeMemory.Write(GetElementAddress(arrayAddress, index, sizeof(T)), value);

    public static void WriteElement<T>(NativeUInt arrayAddress, int[] indices, T value) where T : unmanaged =>
        RuntimeMemory.Write(GetElementAddress(arrayAddress, indices, sizeof(T)), value);

    private static void WriteLength(NativeUInt arrayAddress, int length) =>
        RuntimeMemory.WriteU32(GetLengthAddress(arrayAddress), (uint)length);

    private static void ValidateDimension(int dimension, int rank)
    {
        if (rank <= 0)
            throw new ArgumentOutOfRangeException(nameof(rank));
        if ((uint)dimension >= (uint)rank)
            throw new ArgumentOutOfRangeException(nameof(dimension));
    }

    private static void EnsureArray(NativeUInt arrayAddress) => RuntimeChecks.NullCheck(arrayAddress);
}
)CS";
    return configureRuntime(output.str(), selection, options);
}

namespace {

void replaceRequired(std::string& text, std::string_view from, std::string_view to) {
    const size_t position = text.find(from);
    if (position == std::string::npos)
        throw std::logic_error("RuntimeSupport template is missing a required profile replacement.");
    text.replace(position, from.size(), to);
}

std::string generateMethodRuntime(
    const ida::SourceLayoutSelection& selection,
    const RuntimeSupportOptions& options,
    const RuntimeClassLayout& classLayout);

RuntimeClassLayout resolveClassLayout(size_t pointerSize, const RuntimeSupportOptions& options) {
    RuntimeClassLayout result = options.classLayout;
    if (result.useLegacyDefaults) {
        result.elementClassOffset = 8 * pointerSize;
        result.staticFieldsOffset = 23 * pointerSize;
        result.threadStaticFieldsOffsetFieldOffset = pointerSize == 8 ? 260 : 156;
        result.cctorFinishedOffset = 26 * pointerSize + 8;
        result.vtableOffset = pointerSize == 8 ? 296 : 192;
        result.vtableEntrySize = 2 * pointerSize;
        result.vtableMethodPointerOffset = 0;
        result.vtableMethodInfoOffset = pointerSize;
        result.virtualMethodPointerOffset = 2 * pointerSize;
    }
    if (result.vtablePresent) {
        if (result.vtableEntrySize < pointerSize)
            throw std::invalid_argument("A present vtable requires pointer-sized entries.");
        if (result.vtableMethodPointerOffset > result.vtableEntrySize - pointerSize)
            throw std::invalid_argument("The vtable method pointer is outside its entry.");
        if (result.vtableMethodInfoPresent && result.vtableMethodInfoOffset > result.vtableEntrySize - pointerSize)
            throw std::invalid_argument("The vtable MethodInfo pointer is outside its entry.");
        if (result.virtualMethodPointerPresent && result.virtualMethodPointerOffset > result.vtableEntrySize - pointerSize)
            throw std::invalid_argument("The optional virtualMethodPointer is outside its entry.");
    }
    return result;
}

std::string configureRuntime(
    std::string generated,
    const ida::SourceLayoutSelection& selection,
    const RuntimeSupportOptions& options) {
    const size_t pointerSize = selection.pointerSize;
    if (options.methodVirtualMethodPointerPresent &&
        (options.methodVirtualMethodPointerOffset > selection.methodInfo.size ||
         pointerSize > selection.methodInfo.size - options.methodVirtualMethodPointerOffset))
        throw std::invalid_argument("The optional MethodInfo.virtualMethodPointer is outside MethodInfo.");
    const RuntimeClassLayout classLayout = resolveClassLayout(pointerSize, options);
    const auto number = [](size_t value) { return std::to_string(value); };
    const auto boolean = [](bool value) { return value ? "true" : "false"; };

    replaceRequired(generated, "ClassHandleOffset => 0", "ClassHandleOffset => " + number(selection.object.klass.offset));
    replaceRequired(generated, "MonitorOffset => RuntimeMemory.PointerSize", "MonitorOffset => " + number(selection.object.monitor.offset));
    replaceRequired(generated, "ElementClassOffset => 8 * RuntimeMemory.PointerSize", "ElementClassOffset => " + number(classLayout.elementClassOffset));
    replaceRequired(generated, "HeaderSize { get; set; } = 2 * RuntimeMemory.PointerSize", "HeaderSize { get; set; } = " + number(selection.object.size));
    replaceRequired(generated, "BoxDataOffset { get; set; } = 2 * RuntimeMemory.PointerSize", "BoxDataOffset { get; set; } = " + number(selection.object.size));

    replaceRequired(generated, "LengthOffset => 2 * RuntimeMemory.PointerSize", "LengthOffset => " + number(selection.string.length.offset));
    replaceRequired(generated, "CharsOffset => 2 * RuntimeMemory.PointerSize + 4", "CharsOffset => " + number(selection.string.chars.offset));

    replaceRequired(generated, "StaticFieldsOffset => 23 * RuntimeMemory.PointerSize", "StaticFieldsOffset => " + number(classLayout.staticFieldsOffset));
    replaceRequired(generated,
        "ThreadStaticFieldsOffsetFieldOffset => RuntimeMemory.PointerSize == 8 ? 260 : 156",
        "ThreadStaticFieldsOffsetFieldOffset => " + number(classLayout.threadStaticFieldsOffsetFieldOffset));
    replaceRequired(generated, "CctorFinishedOffset => 26 * RuntimeMemory.PointerSize + 8",
        "CctorFinishedOffset => " + number(classLayout.cctorFinishedOffset));
    replaceRequired(generated,
        "public static bool StaticFieldsSupported => true;",
        "public static bool StaticFieldsSupported => " + std::string(boolean(classLayout.staticFieldsPresent)) + ";");
    replaceRequired(generated,
        "public static bool ThreadStaticFieldsSupported => true;",
        "public static bool ThreadStaticFieldsSupported => " + std::string(boolean(classLayout.threadStaticFieldsPresent)) + ";");

    const bool pointerSizedArray = selection.array.length.size == pointerSize;
    if (!pointerSizedArray && selection.array.length.size != sizeof(std::uint32_t))
        throw std::invalid_argument("Runtime array length must be 32-bit or pointer-sized.");
    replaceRequired(generated, "BoundsOffset => 2 * RuntimeMemory.PointerSize", "BoundsOffset => " + number(selection.array.bounds.offset));
    replaceRequired(generated, "LengthOffset { get; set; } = 3 * RuntimeMemory.PointerSize",
        "LengthOffset { get; set; } = " + number(selection.array.length.offset) + ";\n    public static int ArrayLengthSize => " + number(selection.array.length.size));
    replaceRequired(generated, "ElementsOffset { get; set; } = 4 * RuntimeMemory.PointerSize",
        "ElementsOffset { get; set; } = " + number(selection.array.data.offset));
    replaceRequired(generated, "BoundsSize => 8", "BoundsSize => " + number(pointerSizedArray ? 2 * pointerSize : 8));
    replaceRequired(generated, "BoundLowerBoundOffset => 4", "BoundLowerBoundOffset => " + number(pointerSizedArray ? pointerSize : 4));
    replaceRequired(generated, "ElementsOffset < LengthOffset + 4", "ElementsOffset < LengthOffset + ArrayLengthSize");
    replaceRequired(generated, "RuntimeMemory.ReadU32(GetLengthAddress(arrayAddress))", "ReadLength(GetLengthAddress(arrayAddress))");
    replaceRequired(generated,
        "private static void WriteLength(NativeUInt arrayAddress, int length) =>\n        RuntimeMemory.WriteU32(GetLengthAddress(arrayAddress), (uint)length);",
        pointerSizedArray
            ? "private static ulong ReadLength(NativeUInt address) => RuntimeMemory.ReadPtr(address);\n\n"
              "    private static void WriteLength(NativeUInt arrayAddress, int length) =>\n        RuntimeMemory.WritePtr(GetLengthAddress(arrayAddress), (NativeUInt)length);"
            : "private static ulong ReadLength(NativeUInt address) => RuntimeMemory.ReadU32(address);\n\n"
              "    private static void WriteLength(NativeUInt arrayAddress, int length) =>\n        RuntimeMemory.WriteU32(GetLengthAddress(arrayAddress), (uint)length);");
    replaceRequired(generated, "stride = checked(stride * bounds.Length);", "stride = checked(stride * (long)bounds.Length);");
    replaceRequired(generated, "ReadBounds(arrayAddress, dimension, rank).LowerBound;", "checked((int)ReadBounds(arrayAddress, dimension, rank).LowerBound);");
    if (pointerSizedArray) {
        replaceRequired(generated, "public uint Length;", "public NativeUInt Length;");
        replaceRequired(generated, "public int LowerBound;", "public NativeInt LowerBound;");
        replaceRequired(generated, "RuntimeArrayBounds(uint length, int lowerBound)", "RuntimeArrayBounds(NativeUInt length, NativeInt lowerBound)");
    }

    generated += generateMethodRuntime(selection, options, classLayout);
    return generated;
}

void emitMethodGetter(
    std::ostringstream& output,
    std::string_view returnType,
    std::string_view name,
    const ida::NativeFieldLayout& field,
    std::string_view reader) {
    output << "    public static " << returnType << ' ' << name << "(NativeUInt methodInfo)\n    {\n";
    if (field.present) {
        output << "        RuntimeChecks.NullCheck(methodInfo);\n"
               << "        return RuntimeMemory." << reader << "(methodInfo + (NativeUInt)" << field.offset << ");\n";
    } else {
        output << "        throw new NotSupportedException(\"Reduced MethodInfo has no " << name.substr(3) << " field.\");\n";
    }
    output << "    }\n\n";
}

std::string generateMethodRuntime(
    const ida::SourceLayoutSelection& selection,
    const RuntimeSupportOptions& options,
    const RuntimeClassLayout& classLayout) {
    const auto& method = selection.methodInfo;
    const auto boolean = [](bool value) { return value ? "true" : "false"; };
    std::ostringstream output;
    output << "\npublic static unsafe class RuntimeMethodInfo\n{\n"
           << "    public static int Size => " << method.size << ";\n"
           << "    public static int Alignment => " << method.alignment << ";\n\n";
    emitMethodGetter(output, "NativeUInt", "GetMethodPointer", method.methodPointer, "ReadPtr");
    emitMethodGetter(output, "NativeUInt", "GetInvokerMethod", method.invokerMethod, "ReadPtr");
    emitMethodGetter(output, "NativeUInt", "GetNameAddress", method.name, "ReadPtr");
    emitMethodGetter(output, "NativeUInt", "GetDeclaringType", method.declaringType, "ReadPtr");
    emitMethodGetter(output, "NativeUInt", "GetReturnType", method.returnType, "ReadPtr");
    emitMethodGetter(output, "NativeUInt", "GetParameters", method.parameters, "ReadPtr");
    emitMethodGetter(output, "NativeUInt", "GetRgctxData", method.rgctxData, "ReadPtr");
    emitMethodGetter(output, "NativeUInt", "GetGenericMethod", method.genericMethod, "ReadPtr");
    emitMethodGetter(output, "uint", "GetCustomAttributeIndex", method.customAttributeIndex, "ReadU32");
    emitMethodGetter(output, "uint", "GetToken", method.token, "ReadU32");
    emitMethodGetter(output, "ushort", "GetFlags", method.flags, "ReadU16");
    emitMethodGetter(output, "ushort", "GetIFlags", method.iflags, "ReadU16");
    emitMethodGetter(output, "ushort", "GetSlot", method.slot, "ReadU16");
    emitMethodGetter(output, "byte", "GetParametersCount", method.parametersCount, "ReadU8");
    emitMethodGetter(output, "byte", "GetMethodFlags", method.methodFlags, "ReadU8");

    output << "    public static bool TryGetInvokerMethod(NativeUInt methodInfo, out NativeUInt value)\n    {\n";
    if (method.invokerMethod.present) {
        output << "        RuntimeChecks.NullCheck(methodInfo);\n"
               << "        value = RuntimeMemory.ReadPtr(methodInfo + (NativeUInt)" << method.invokerMethod.offset << ");\n"
               << "        return value != 0;\n";
    } else {
        output << "        value = 0;\n        return false;\n";
    }
    output << "    }\n\n"
           << "    public static bool TryGetVirtualMethodPointer(NativeUInt methodInfo, out NativeUInt value)\n    {\n";
    if (options.methodVirtualMethodPointerPresent) {
        output << "        RuntimeChecks.NullCheck(methodInfo);\n"
               << "        value = RuntimeMemory.ReadPtr(methodInfo + (NativeUInt)" << options.methodVirtualMethodPointerOffset << ");\n"
               << "        return value != 0;\n";
    } else {
        output << "        value = 0;\n        return false;\n";
    }
    output << "    }\n\n"
           << "    public static NativeUInt GetVirtualMethodPointer(NativeUInt methodInfo)\n"
           << "    {\n"
           << "        return TryGetVirtualMethodPointer(methodInfo, out NativeUInt value) ? value : GetMethodPointer(methodInfo);\n"
           << "    }\n"
           << "}\n\n"
           << "public struct RuntimeGeneratedMethod\n"
           << "{\n"
           << "    public NativeUInt MethodInfo;\n"
           << "    public NativeUInt MethodPointer;\n"
           << "    public NativeUInt InvokerMethod;\n"
           << "    public NativeUInt VirtualMethodPointer;\n"
           << "    public bool HasInvokerMethod;\n"
           << "    public bool HasVirtualMethodPointer;\n"
           << "}\n\n"
           << "public struct RuntimeVirtualInvokeData\n"
           << "{\n"
           << "    public NativeUInt MethodPointer;\n"
           << "    public NativeUInt MethodInfo;\n"
           << "    public NativeUInt VirtualMethodPointer;\n"
           << "    public bool HasMethodInfo;\n"
           << "    public bool HasVirtualMethodPointer;\n"
           << "}\n\n"
           << "public static unsafe partial class RuntimeClass\n"
           << "{\n"
           << "    public static int VTableOffset => " << classLayout.vtableOffset << ";\n"
           << "    public static int VTableEntrySize => " << classLayout.vtableEntrySize << ";\n"
           << "    public static int VTableMethodPointerOffset => " << classLayout.vtableMethodPointerOffset << ";\n"
           << "    public static int VTableMethodInfoOffset => " << classLayout.vtableMethodInfoOffset << ";\n"
           << "    public static int VirtualMethodPointerOffset => " << classLayout.virtualMethodPointerOffset << ";\n"
           << "    public static bool VTablePresent => " << boolean(classLayout.vtablePresent) << ";\n"
           << "    public static bool VTableInline => " << boolean(classLayout.vtableInline) << ";\n"
           << "    public static bool VTableMethodInfoPresent => " << boolean(classLayout.vtableMethodInfoPresent) << ";\n"
           << "    public static bool VirtualMethodPointerPresent => " << boolean(classLayout.virtualMethodPointerPresent) << ";\n\n"
           << "    public static RuntimeGeneratedMethod GetGeneratedMethod(NativeUInt methodInfo)\n"
           << "    {\n"
           << "        RuntimeGeneratedMethod result = default;\n"
           << "        result.MethodInfo = methodInfo;\n"
           << "        result.MethodPointer = RuntimeMethodInfo.GetMethodPointer(methodInfo);\n"
           << "        result.HasInvokerMethod = RuntimeMethodInfo.TryGetInvokerMethod(methodInfo, out result.InvokerMethod);\n"
           << "        result.HasVirtualMethodPointer = RuntimeMethodInfo.TryGetVirtualMethodPointer(methodInfo, out result.VirtualMethodPointer);\n"
           << "        return result;\n"
           << "    }\n\n"
           << "    public static RuntimeVirtualInvokeData GetVirtualInvokeData(NativeUInt typeHandle, int slot)\n"
           << "    {\n"
           << "        if (!VTablePresent)\n"
           << "            throw new NotSupportedException(\"The reduced class layout has no vtable.\");\n"
           << "        RuntimeChecks.NullCheck(typeHandle);\n"
           << "        if (slot < 0)\n"
           << "            throw new ArgumentOutOfRangeException(nameof(slot));\n"
           << "        NativeUInt table = VTableInline ? typeHandle + (NativeUInt)VTableOffset : RuntimeMemory.ReadPtr(typeHandle + (NativeUInt)VTableOffset);\n"
           << "        if (table == 0)\n"
           << "            throw new InvalidOperationException($\"Class 0x{typeHandle:X} has no vtable storage.\");\n"
           << "        NativeUInt entry = checked(table + (NativeUInt)checked(slot * VTableEntrySize));\n"
           << "        RuntimeVirtualInvokeData result = default;\n"
           << "        result.MethodPointer = RuntimeMemory.ReadPtr(entry + (NativeUInt)VTableMethodPointerOffset);\n"
           << "        if (result.MethodPointer == 0)\n"
           << "            throw new MissingMethodException($\"Virtual method pointer is null at 0x{entry:X}.\");\n"
           << "        result.HasMethodInfo = VTableMethodInfoPresent;\n"
           << "        if (VTableMethodInfoPresent)\n"
           << "            result.MethodInfo = RuntimeMemory.ReadPtr(entry + (NativeUInt)VTableMethodInfoOffset);\n"
           << "        result.HasVirtualMethodPointer = VirtualMethodPointerPresent;\n"
           << "        if (VirtualMethodPointerPresent)\n"
           << "            result.VirtualMethodPointer = RuntimeMemory.ReadPtr(entry + (NativeUInt)VirtualMethodPointerOffset);\n"
           << "        return result;\n"
           << "    }\n\n"
           << "    public static NativeUInt GetVirtualMethodPointer(RuntimeVirtualInvokeData data)\n"
           << "    {\n"
           << "        if (data.HasVirtualMethodPointer)\n"
           << "        {\n"
           << "            if (data.VirtualMethodPointer == 0)\n"
           << "                throw new MissingMethodException(\"The optional virtualMethodPointer is null.\");\n"
           << "            return data.VirtualMethodPointer;\n"
           << "        }\n"
           << "        return data.MethodPointer;\n"
           << "    }\n\n"
           << "    public static NativeUInt GetRequiredMethodInfo(RuntimeVirtualInvokeData data)\n"
           << "    {\n"
           << "        if (!data.HasMethodInfo || data.MethodInfo == 0)\n"
           << "            throw new NotSupportedException(\"The reduced virtual invoke data has no MethodInfo.\");\n"
           << "        return data.MethodInfo;\n"
           << "    }\n"
           << "}\n\n"
           << "public static partial class RuntimeCalls\n"
           << "{\n"
           << "    public static global::System.Func<RuntimeGeneratedMethod, NativeUInt[], NativeUInt> GeneratedMethodHandler { get; set; }\n"
           << "    public static global::System.Func<NativeUInt, NativeUInt, int, RuntimeVirtualInvokeData> InterfaceInvokeDataResolver { get; set; }\n"
           << "    public static global::System.Func<NativeUInt, NativeUInt, RuntimeVirtualInvokeData> GenericVirtualInvokeDataResolver { get; set; }\n"
           << "    public static global::System.Func<NativeUInt, NativeUInt, NativeUInt, int, RuntimeVirtualInvokeData> GenericInterfaceInvokeDataResolver { get; set; }\n"
           << "    public static global::System.Func<NativeUInt, NativeUInt> InflatedMethodInfoHandler { get; set; }\n"
           << "    public static global::System.Func<NativeUInt, NativeUInt> GenericMethodPointerHandler { get; set; }\n\n"
           << "    public static NativeUInt GetMethodPointer(NativeUInt methodInfo) => RuntimeMethodInfo.GetMethodPointer(methodInfo);\n"
           << "    public static NativeUInt GetInvokerMethod(NativeUInt methodInfo) => RuntimeMethodInfo.GetInvokerMethod(methodInfo);\n"
           << "    public static RuntimeGeneratedMethod GetGeneratedMethod(NativeUInt methodInfo) => RuntimeClass.GetGeneratedMethod(methodInfo);\n\n"
           << "    public static NativeUInt InvokeGenerated(RuntimeGeneratedMethod method, params NativeUInt[] arguments)\n"
           << "    {\n"
           << "        if (GeneratedMethodHandler == null)\n"
           << "            throw new MissingMethodException($\"No generated method handler is registered for 0x{method.MethodPointer:X}.\");\n"
           << "        return GeneratedMethodHandler(method, arguments ?? global::System.Array.Empty<NativeUInt>());\n"
           << "    }\n\n"
           << "    public static NativeUInt InvokeGenerated(NativeUInt methodInfo, params NativeUInt[] arguments) =>\n"
           << "        InvokeGenerated(GetGeneratedMethod(methodInfo), arguments);\n\n"
           << "    public static NativeUInt GetGenericMethodPointer(NativeUInt methodInfo)\n"
           << "    {\n"
           << "        if (GenericMethodPointerHandler == null)\n"
           << "            throw new NotSupportedException(\"No generic method pointer resolver is registered.\");\n"
           << "        return GenericMethodPointerHandler(methodInfo);\n"
           << "    }\n\n"
           << "    public static NativeUInt GetInflatedMethodInfo(NativeUInt methodInfo)\n"
           << "    {\n"
           << "        if (InflatedMethodInfoHandler == null)\n"
           << "            throw new NotSupportedException(\"No inflated MethodInfo resolver is registered.\");\n"
           << "        return InflatedMethodInfoHandler(methodInfo);\n"
           << "    }\n\n"
           << "    public static RuntimeVirtualInvokeData GetVirtualInvokeData(NativeUInt objectAddress, int slot) =>\n"
           << "        RuntimeClass.GetVirtualInvokeData(RuntimeObject.GetClassHandle(objectAddress), slot);\n\n"
           << "    public static NativeUInt ResolveVirtualMethodPointer(NativeUInt objectAddress, int slot) =>\n"
           << "        RuntimeClass.GetVirtualMethodPointer(GetVirtualInvokeData(objectAddress, slot));\n\n"
           << "    public static NativeUInt ResolveVirtualMethodInfo(NativeUInt objectAddress, int slot) =>\n"
           << "        RuntimeClass.GetRequiredMethodInfo(GetVirtualInvokeData(objectAddress, slot));\n\n"
           << "    public static NativeUInt ResolveGenericVirtualMethodPointer(NativeUInt methodInfo, NativeUInt objectAddress) =>\n"
           << "        RuntimeClass.GetVirtualMethodPointer(ResolveGenericVirtualInvokeData(methodInfo, objectAddress));\n\n"
           << "    public static NativeUInt ResolveGenericVirtualMethodInfo(NativeUInt methodInfo, NativeUInt objectAddress) =>\n"
           << "        RuntimeClass.GetRequiredMethodInfo(ResolveGenericVirtualInvokeData(methodInfo, objectAddress));\n\n"
           << "    public static RuntimeVirtualInvokeData ResolveGenericVirtualInvokeData(NativeUInt methodInfo, NativeUInt objectAddress)\n"
           << "    {\n"
           << "        if (GenericVirtualInvokeDataResolver == null)\n"
           << "            throw new NotSupportedException(\"No generic virtual invoke-data resolver is registered.\");\n"
           << "        return GenericVirtualInvokeDataResolver(methodInfo, objectAddress);\n"
           << "    }\n\n"
           << "    public static RuntimeVirtualInvokeData ResolveInterfaceInvokeData(NativeUInt objectAddress, NativeUInt declaringInterface, int slot)\n"
           << "    {\n"
           << "        if (InterfaceInvokeDataResolver == null)\n"
           << "            throw new NotSupportedException(\"No interface invoke-data resolver is registered.\");\n"
           << "        return InterfaceInvokeDataResolver(objectAddress, declaringInterface, slot);\n"
           << "    }\n\n"
           << "    public static NativeUInt ResolveInterfaceMethodPointer(NativeUInt objectAddress, NativeUInt declaringInterface, int slot) =>\n"
           << "        RuntimeClass.GetVirtualMethodPointer(ResolveInterfaceInvokeData(objectAddress, declaringInterface, slot));\n\n"
           << "    public static NativeUInt ResolveInterfaceMethodInfo(NativeUInt objectAddress, NativeUInt declaringInterface, int slot) =>\n"
           << "        RuntimeClass.GetRequiredMethodInfo(ResolveInterfaceInvokeData(objectAddress, declaringInterface, slot));\n\n"
           << "    public static RuntimeVirtualInvokeData ResolveGenericInterfaceInvokeData(NativeUInt methodInfo, NativeUInt objectAddress, NativeUInt declaringInterface, int slot)\n"
           << "    {\n"
           << "        if (GenericInterfaceInvokeDataResolver == null)\n"
           << "            throw new NotSupportedException(\"No generic interface invoke-data resolver is registered.\");\n"
           << "        return GenericInterfaceInvokeDataResolver(methodInfo, objectAddress, declaringInterface, slot);\n"
           << "    }\n\n"
           << "    public static NativeUInt ResolveGenericInterfaceMethodPointer(NativeUInt methodInfo, NativeUInt objectAddress, NativeUInt declaringInterface, int slot) =>\n"
           << "        RuntimeClass.GetVirtualMethodPointer(ResolveGenericInterfaceInvokeData(methodInfo, objectAddress, declaringInterface, slot));\n\n"
           << "    public static NativeUInt ResolveGenericInterfaceMethodInfo(NativeUInt methodInfo, NativeUInt objectAddress, NativeUInt declaringInterface, int slot) =>\n"
           << "        RuntimeClass.GetRequiredMethodInfo(ResolveGenericInterfaceInvokeData(methodInfo, objectAddress, declaringInterface, slot));\n"
           << "}\n";
    return output.str();
}

}

std::string generateRuntimeSupport(Architecture architecture) {
    return RuntimeSupportGenerator{}.generate(architecture);
}

std::string generateRuntimeSupport(Architecture architecture, const RuntimeSupportOptions& options) {
    return RuntimeSupportGenerator{}.generate(architecture, options);
}

std::string generateRuntimeSupport(const ida::SourceLayoutSelection& selection, const RuntimeSupportOptions& options) {
    return RuntimeSupportGenerator{}.generate(selection, options);
}

} // namespace il2cpprec
