using System.Reflection;
using System.Reflection.Emit;
using System.Reflection.Metadata;
using System.Reflection.Metadata.Ecma335;
using System.Reflection.PortableExecutable;
using System.Text.Json;

// A structural fingerprint. It compares observable named IL references, not full behavior.
// PEReader reads metadata without loading or executing the input assemblies.
if (args.Length != 1) {
    Console.Error.WriteLine("usage: ManagedFingerprint <managed DLL directory or DLL>");
    return 2;
}

var path = Path.GetFullPath(args[0]);
var files = Directory.Exists(path) ? Directory.GetFiles(path, "*.dll") : new[] { path };
if (files.Length == 0 || files.Any(file => !File.Exists(file))) {
    Console.Error.WriteLine("no managed DLL files found");
    return 2;
}

var opcodes = typeof(OpCodes).GetFields(BindingFlags.Public | BindingFlags.Static)
    .Where(field => field.FieldType == typeof(OpCode))
    .Select(field => (OpCode)field.GetValue(null)!)
    .GroupBy(op => unchecked((ushort)op.Value))
    .ToDictionary(group => group.Key, group => group.First());
var methods = new Dictionary<string, Fingerprint>(StringComparer.Ordinal);
var ambiguous = new HashSet<string>(StringComparer.Ordinal);

try {
    foreach (var file in files.OrderBy(file => file, StringComparer.Ordinal)) {
        using var stream = File.OpenRead(file);
        using var pe = new PEReader(stream);
        if (!pe.HasMetadata) continue;
        var metadata = pe.GetMetadataReader();
        var typeNames = new Dictionary<TypeDefinitionHandle, string>();
        var methodOwners = new Dictionary<MethodDefinitionHandle, string>();
        var fieldOwners = new Dictionary<FieldDefinitionHandle, string>();
        foreach (var typeHandle in metadata.TypeDefinitions) {
            var type = metadata.GetTypeDefinition(typeHandle);
            var ns = metadata.GetString(type.Namespace);
            var name = metadata.GetString(type.Name);
            var full = string.IsNullOrEmpty(ns) ? name : ns + "." + name;
            typeNames[typeHandle] = full;
            foreach (var method in type.GetMethods()) methodOwners[method] = full;
            foreach (var field in type.GetFields()) fieldOwners[field] = full;
        }

        string TypeName(EntityHandle handle) => handle.Kind switch {
            HandleKind.TypeDefinition => typeNames[(TypeDefinitionHandle)handle],
            HandleKind.TypeReference => ReferenceName((TypeReferenceHandle)handle),
            _ => handle.Kind.ToString(),
        };

        string ReferenceName(TypeReferenceHandle handle) {
            var type = metadata.GetTypeReference(handle);
            var ns = metadata.GetString(type.Namespace);
            var name = metadata.GetString(type.Name);
            return string.IsNullOrEmpty(ns) ? name : ns + "." + name;
        }

        string MemberName(EntityHandle handle) => handle.Kind switch {
            HandleKind.MethodDefinition => methodOwners[(MethodDefinitionHandle)handle] + "::" +
                metadata.GetString(metadata.GetMethodDefinition((MethodDefinitionHandle)handle).Name),
            HandleKind.FieldDefinition => fieldOwners[(FieldDefinitionHandle)handle] + "::" +
                metadata.GetString(metadata.GetFieldDefinition((FieldDefinitionHandle)handle).Name),
            HandleKind.MemberReference => MemberReferenceName((MemberReferenceHandle)handle),
            HandleKind.MethodSpecification => MemberName(metadata.GetMethodSpecification((MethodSpecificationHandle)handle).Method),
            _ => handle.Kind.ToString(),
        };

        string MemberReferenceName(MemberReferenceHandle handle) {
            var member = metadata.GetMemberReference(handle);
            return TypeName(member.Parent) + "::" + metadata.GetString(member.Name);
        }

        foreach (var handle in metadata.MethodDefinitions) {
            var definition = metadata.GetMethodDefinition(handle);
            if (definition.RelativeVirtualAddress == 0) continue;
            var parameterCount = definition.GetParameters()
                .Count(parameter => metadata.GetParameter(parameter).SequenceNumber > 0);
            var key = methodOwners[handle] + "::" + metadata.GetString(definition.Name) + "/" + parameterCount;
            if (ambiguous.Contains(key)) continue;
            if (methods.ContainsKey(key)) {
                methods.Remove(key);
                ambiguous.Add(key);
                continue;
            }
            var body = pe.GetMethodBody(definition.RelativeVirtualAddress).GetILBytes() ?? Array.Empty<byte>();
            var fingerprint = new Fingerprint();
            var index = 0;
            while (index < body.Length) {
                ushort value = body[index++];
                if (value == 0xfe) {
                    if (index >= body.Length) throw new InvalidDataException($"truncated two-byte opcode in {key}");
                    value = (ushort)(0xfe00 | body[index++]);
                }
                if (!opcodes.TryGetValue(value, out var opcode))
                    throw new InvalidDataException($"unknown opcode 0x{value:x} in {key}");
                var operandSize = opcode.OperandType switch {
                    OperandType.InlineNone => 0,
                    OperandType.ShortInlineBrTarget or OperandType.ShortInlineI or OperandType.ShortInlineVar => 1,
                    OperandType.InlineVar => 2,
                    OperandType.InlineI or OperandType.InlineBrTarget or OperandType.InlineField or
                    OperandType.InlineMethod or OperandType.InlineSig or OperandType.InlineString or
                    OperandType.InlineTok or OperandType.InlineType or OperandType.ShortInlineR => 4,
                    OperandType.InlineI8 or OperandType.InlineR => 8,
                    OperandType.InlineSwitch => 4,
                    _ => throw new InvalidDataException($"unsupported operand kind {opcode.OperandType}"),
                };
                if (index + operandSize > body.Length) throw new InvalidDataException($"truncated operand in {key}");
                if (opcode.OperandType == OperandType.InlineSwitch) {
                    var count = BitConverter.ToInt32(body.AsSpan(index, 4));
                    if (count < 0 || count > (body.Length - index - 4) / 4)
                        throw new InvalidDataException($"invalid switch table in {key}");
                    operandSize += count * 4;
                }
                if (opcode.OperandType == OperandType.InlineString) {
                    var token = BitConverter.ToInt32(body.AsSpan(index, 4));
                    fingerprint.Strings.Add(metadata.GetUserString(MetadataTokens.UserStringHandle(token & 0x00ffffff)));
                } else if (opcode.OperandType is OperandType.InlineMethod or OperandType.InlineField) {
                    var token = BitConverter.ToInt32(body.AsSpan(index, 4));
                    var member = MemberName(MetadataTokens.EntityHandle(token));
                    if (opcode.OperandType == OperandType.InlineMethod) fingerprint.Calls.Add(member);
                    else fingerprint.Fields.Add(member);
                }
                index += operandSize;
            }
            methods[key] = fingerprint;
        }
    }
    Console.Write(JsonSerializer.Serialize(new { methods, ambiguous = ambiguous.OrderBy(x => x).ToArray() },
        new JsonSerializerOptions { PropertyNamingPolicy = JsonNamingPolicy.CamelCase }));
    return 0;
} catch (Exception error) {
    Console.Error.WriteLine(error);
    return 1;
}

sealed class Fingerprint {
    public SortedSet<string> Calls { get; } = new(StringComparer.Ordinal);
    public SortedSet<string> Fields { get; } = new(StringComparer.Ordinal);
    public SortedSet<string> Strings { get; } = new(StringComparer.Ordinal);
}
