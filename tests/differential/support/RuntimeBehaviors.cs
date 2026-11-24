using System;
using NativeUInt = System.UInt64;

public static class RuntimeBehaviors
{
    private static int passed;
    private static int failed;

    private static void Check(bool condition, string message)
    {
        if (!condition)
            throw new InvalidOperationException(message);
    }

    private static void Expect<TException>(Action action) where TException : Exception
    {
        try
        {
            action();
        }
        catch (TException)
        {
            return;
        }
        throw new InvalidOperationException("Expected " + typeof(TException).FullName + ".");
    }

    private static void ResetHandlers()
    {
        RuntimeAbi.DirectCallHandler = null;
        RuntimeAbi.IndirectCallHandler = null;
        RuntimeAbi.ManagedToNativeHandler = null;
        RuntimeAbi.NativeToManagedHandler = null;
        RuntimeCalls.DirectCallHandler = null;
        RuntimeCalls.IndirectCallHandler = null;
        RuntimeObject.ObjectAllocator = null;
        RuntimeObject.ManagedObjectAllocator = null;
        RuntimeObject.BoxingHandler = null;
        RuntimeArray.ArrayAllocator = null;
        RuntimeArray.ManagedArrayAllocator = null;
    }

    private static void Run(string name, Action test)
    {
        try
        {
            ResetHandlers();
            test();
            Console.WriteLine("PASS exact " + name);
            ++passed;
        }
        catch (Exception error)
        {
            Console.WriteLine("FAIL " + name + ": " + error);
            ++failed;
        }
        finally
        {
            ResetHandlers();
        }
    }

    private static void GenericCalls()
    {
        RuntimeAbi.DirectCallHandler = (target, arguments) =>
        {
            Check(target == 0x4000, "Wrong generic call target.");
            Check(arguments.Length == 1 && (int)arguments[0] == 41, "Wrong generic arguments.");
            return (int)arguments[0] + 1;
        };
        Check(RuntimeAbi.InvokeDirect<int>(0x4000, 41) == 42, "Generic call returned a wrong value.");
        RuntimeAbi.DirectCallHandler = (target, arguments) => null;
        Expect<InvalidOperationException>(() => RuntimeAbi.InvokeDirect<int>(0x4000, 41));
        ResetHandlers();
        Expect<MissingMethodException>(() => RuntimeAbi.InvokeDirect<int>(0x4000, 41));
    }

    private static void VirtualAndInterfaceDispatch()
    {
        NativeUInt expectedTarget = 0;
        RuntimeAbi.IndirectCallHandler = (target, arguments) =>
        {
            Check(target == expectedTarget, "Wrong dispatch slot.");
            Check(arguments.Length == 1, "Wrong dispatch argument count.");
            return (int)arguments[0] * 2;
        };
        expectedTarget = 24;
        Check(RuntimeAbi.InvokeIndirect<int>(expectedTarget, new object[] { 6 }) == 12, "Virtual dispatch failed.");
        expectedTarget = 40;
        Check(RuntimeAbi.InvokeIndirect<int>(expectedTarget, new object[] { 9 }) == 18, "Interface dispatch failed.");
        ResetHandlers();
        Expect<MissingMethodException>(() => RuntimeAbi.InvokeIndirect<int>(expectedTarget, new object[] { 9 }));
    }

    private static void ArrayBounds()
    {
        NativeUInt array = 0;
        try
        {
            array = RuntimeArray.NewArray<int>(0x100, 2);
            Check(RuntimeArray.GetLength(array) == 2, "Wrong array length.");
            RuntimeArray.WriteElement<int>(array, 0, 11);
            RuntimeArray.WriteElement<int>(array, 1, 31);
            Check(RuntimeArray.ReadElement<int>(array, 0) == 11, "Wrong first array element.");
            Check(RuntimeArray.ReadElement<int>(array, 1) == 31, "Wrong second array element.");
            Expect<IndexOutOfRangeException>(() => RuntimeArray.ReadElement<int>(array, 2));
            Expect<IndexOutOfRangeException>(() => RuntimeArray.WriteElement<int>(array, -1, 0));
            Expect<NullReferenceException>(() => RuntimeArray.GetLength(0));
            Expect<ArgumentOutOfRangeException>(() => RuntimeArray.NewArray<int>(0x100, -1));
        }
        finally
        {
            RuntimeMemory.Free(array);
        }
    }

    private static void StringLiterals()
    {
        RuntimeAbi.ManagedToNativeHandler = value =>
        {
            Check((string)value == "recovered literal", "Wrong managed string.");
            return 0x8000;
        };
        RuntimeAbi.NativeToManagedHandler = (value, type) =>
        {
            Check(value == 0x8000 && type == typeof(string), "Wrong native string reference.");
            return "recovered literal";
        };
        Check(RuntimeAbi.ToNative("recovered literal") == 0x8000, "String-to-native conversion failed.");
        Check(RuntimeAbi.FromNative<string>(0x8000) == "recovered literal", "Native-to-string conversion failed.");
        Check(RuntimeAbi.FromNative<string>(0) == null, "Null string literal was not preserved.");
    }

    private static void BoxingAndNullCheck()
    {
        NativeUInt boxed = 0;
        try
        {
            boxed = RuntimeObject.Box<int>(0x200, 123);
            Check(RuntimeObject.Unbox<int>(boxed) == 123, "Boxing round-trip failed.");
            Check(RuntimeObject.GetFieldAddress(boxed, 4) == boxed + 4, "Non-null field address failed.");
            Expect<NullReferenceException>(() => RuntimeObject.Unbox<int>(0));
            Expect<NullReferenceException>(() => RuntimeObject.GetFieldAddress(0, 4));
            Expect<NotSupportedException>(() => RuntimeObject.Box<int>(123));
        }
        finally
        {
            RuntimeMemory.Free(boxed);
        }
    }

    private static void ExceptionRegions()
    {
        NativeUInt array = RuntimeArray.NewArray<int>(0x100, 1);
        string trace = "";
        try
        {
            try
            {
                try
                {
                    RuntimeArray.ReadElement<int>(array, 1);
                }
                catch (IndexOutOfRangeException)
                {
                    trace += "catch;";
                }
                finally
                {
                    trace += "finally;";
                }
                RuntimeObject.GetFieldAddress(0, 0);
            }
            catch (NullReferenceException)
            {
                trace += "outer-catch;";
            }
            finally
            {
                trace += "outer-finally;";
            }
            Check(trace == "catch;finally;outer-catch;outer-finally;", "Wrong exception-region order: " + trace);
        }
        finally
        {
            RuntimeMemory.Free(array);
        }
    }

    public static int Main()
    {
        Run("GenericMethodCallRuntime", GenericCalls);
        Run("VirtualInterfaceDispatchRuntime", VirtualAndInterfaceDispatch);
        Run("ArrayBoundsRuntime", ArrayBounds);
        Run("StringLiteralRuntime", StringLiterals);
        Run("BoxingAndNullCheckRuntime", BoxingAndNullCheck);
        Run("TryCatchFinallyRuntime", ExceptionRegions);
        Console.WriteLine("BEHAVIOR_RUNTIME SUMMARY passed=" + passed + " partial=0 failed=" + failed);
        return failed == 0 ? 0 : 1;
    }
}
