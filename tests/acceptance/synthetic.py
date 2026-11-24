from __future__ import annotations

import struct
from dataclasses import dataclass
from pathlib import Path


VERSIONS = ("24.0", "24.1", "24.2", "24.3", "24.4", "24.5")
ARCHITECTURES = ("x86", "x64", "arm32", "arm64")
INCLUDED_IMAGE = "Assembly-CSharp.dll"
EXCLUDED_IMAGE = "Excluded.dll"


@dataclass(frozen=True)
class Profile:
    version: str
    architecture: str

    @property
    def id(self) -> str:
        return f"{self.version}-{self.architecture}"


@dataclass(frozen=True)
class SyntheticMethod:
    name: str
    type_name: str
    image: str
    kind: str = "exact"


@dataclass(frozen=True)
class SyntheticFixture:
    profile: Profile
    methods: tuple[SyntheticMethod, ...]
    binary: bytes
    metadata: bytes

    def write(self, directory: Path) -> tuple[Path, Path]:
        directory.mkdir(parents=True, exist_ok=True)
        binary = directory / "fixture.elf"
        metadata = directory / "global-metadata.dat"
        binary.write_bytes(self.binary)
        metadata.write_bytes(self.metadata)
        return binary, metadata


def standard_methods() -> tuple[SyntheticMethod, ...]:
    return (
        SyntheticMethod("IncludedMethod", "IncludedType", INCLUDED_IMAGE),
        SyntheticMethod("ExcludedMethod", "ExcludedType", EXCLUDED_IMAGE),
    )


def quality_methods() -> tuple[SyntheticMethod, ...]:
    return (
        SyntheticMethod("ExactMethod", "ExactType", INCLUDED_IMAGE),
        SyntheticMethod("PartialMethod", "PartialType", INCLUDED_IMAGE, "partial"),
        SyntheticMethod("ErrorMethod", "ErrorType", EXCLUDED_IMAGE, "error"),
    )


class _Image:
    def __init__(self, pointer_size: int, initial_size: int = 0):
        self.pointer_size = pointer_size
        self.bytes = bytearray(initial_size)
        self.labels: dict[str, int] = {}
        self.pointer_fixups: list[tuple[int, str]] = []

    def allocate(self, name: str, size: int, alignment: int = 1) -> int:
        aligned = (len(self.bytes) + alignment - 1) // alignment * alignment
        self.bytes.extend(b"\0" * (aligned + size - len(self.bytes)))
        self.labels[name] = aligned
        return aligned

    def add(self, name: str, data: bytes, alignment: int = 1) -> int:
        offset = self.allocate(name, len(data), alignment)
        self.bytes[offset:offset + len(data)] = data
        return offset

    def offset(self, name: str) -> int:
        return self.labels[name]

    def pointer(self, offset: int, target: str) -> None:
        self.pointer_fixups.append((offset, target))

    def u32(self, offset: int, value: int) -> None:
        struct.pack_into("<I", self.bytes, offset, value)

    def u64(self, offset: int, value: int) -> None:
        struct.pack_into("<Q", self.bytes, offset, value)

    def count(self, offset: int, value: int) -> None:
        if self.pointer_size == 8:
            self.u64(offset, value)
        else:
            self.u32(offset, value)

    def resolve_pointers(self, image_base: int) -> None:
        for offset, target in self.pointer_fixups:
            value = image_base + self.labels[target]
            if self.pointer_size == 8:
                self.u64(offset, value)
            else:
                self.u32(offset, value)


def _metadata(version: str, methods: tuple[SyntheticMethod, ...]) -> bytes:
    header_size = 240 if version in ("24.0", "24.1") else 264
    type_stride = {
        "24.0": 104,
        "24.1": 100,
        "24.2": 96,
        "24.3": 96,
        "24.4": 96,
        "24.5": 88,
    }[version]
    method_stride = 56 if version == "24.0" else 52 if version == "24.1" else 32
    image_stride = 32 if version == "24.0" else 40
    assembly_stride = {
        "24.0": 68,
        "24.1": 72,
        "24.2": 68,
        "24.3": 68,
        "24.4": 64,
        "24.5": 64,
    }[version]

    image = _Image(4, header_size)
    strings = bytearray()
    string_offsets: dict[str, int] = {}

    def string_index(value: str) -> int:
        if value not in string_offsets:
            string_offsets[value] = len(strings)
            strings.extend(value.encode("utf-8") + b"\0")
        return string_offsets[value]

    namespace_index = string_index("Acceptance")
    for method in methods:
        string_index(method.type_name)
        string_index(method.name)
        string_index(method.image)

    strings_offset = image.add("strings", bytes(strings), 4)
    methods_offset = image.allocate("methods", method_stride * len(methods), 4)
    types_offset = image.allocate("types", type_stride * len(methods), 4)
    images_offset = image.allocate("images", image_stride * len(methods), 4)
    image.allocate("assemblies", assembly_stride * len(methods), 4)

    for index, method in enumerate(methods):
        base = methods_offset + index * method_stride
        image.u32(base, string_index(method.name))
        image.u32(base + 4, index)
        image.u32(base + 8, 0xFFFFFFFF)
        image.u32(base + 12, 0xFFFFFFFF)
        generic_offset = base + (20 if version == "24.0" else 16)
        image.u32(generic_offset, 0xFFFFFFFF)
        if version in ("24.0", "24.1"):
            image.u32(generic_offset + 4, index)
            token_offset = generic_offset + 24
        else:
            token_offset = generic_offset + 4
        image.u32(token_offset, 0x06000000 | (index + 1))
        struct.pack_into("<H", image.bytes, token_offset + 4, 0x0010)

        base = types_offset + index * type_stride
        image.u32(base, string_index(method.type_name))
        image.u32(base + 4, namespace_index)
        if version == "24.5":
            declaring_offset = base + 16
            generic_type_offset = base + 28
            flags_offset = base + 32
            counts_offset = base + 68
        else:
            declaring_offset = base + 20
            generic_type_offset = base + (40 if version in ("24.0", "24.1") else 32)
            flags_offset = generic_type_offset + 4
            counts_offset = flags_offset + 36
        image.u32(declaring_offset, 0xFFFFFFFF)
        image.u32(declaring_offset + 4, 0xFFFFFFFF)
        image.u32(generic_type_offset, 0xFFFFFFFF)
        image.u32(flags_offset, 0x181)
        image.u32(flags_offset + 4, 0xFFFFFFFF)
        image.u32(flags_offset + 8, index)
        struct.pack_into("<H", image.bytes, counts_offset, 1)
        struct.pack_into("<H", image.bytes, counts_offset + 4, 0)
        image.u32(counts_offset + 16, 0)

        base = images_offset + index * image_stride
        image.u32(base, string_index(method.image))
        image.u32(base + 8, index)
        image.u32(base + 12, 1)
        image.u32(base + 28, 1)

    image.u32(0, 0xFAB11BAF)
    image.u32(4, 24)
    image.u32(8, header_size)
    image.u32(24, strings_offset)
    image.u32(28, len(strings))
    image.u32(48, methods_offset)
    image.u32(52, method_stride * len(methods))
    image.u32(160, types_offset)
    image.u32(164, type_stride * len(methods))
    images_field = 176 if version in ("24.0", "24.1") else 168
    image.u32(images_field, images_offset)
    image.u32(images_field + 4, image_stride * len(methods))
    image.u32(images_field + 8, image.offset("assemblies"))
    image.u32(images_field + 12, assembly_stride * len(methods))
    return bytes(image.bytes)


def _code(architecture: str, kind: str) -> bytes:
    if architecture in ("x86", "x64"):
        return b"\x0f\x0b" if kind == "partial" else b"\xc3"
    if architecture == "arm64":
        return b"\x00\x00\x00\x00" if kind == "partial" else b"\xc0\x03\x5f\xd6"
    if architecture == "arm32":
        return b"\xf0\x00\xf0\xe7" if kind == "partial" else b"\x1e\xff\x2f\xe1"
    raise ValueError(f"unsupported architecture {architecture}")


def _elf(profile: Profile, methods: tuple[SyntheticMethod, ...]) -> bytes:
    architecture = profile.architecture
    pointer_size = 8 if architecture in ("x64", "arm64") else 4
    is64 = pointer_size == 8
    machine = {"x86": 3, "x64": 62, "arm32": 40, "arm64": 183}[architecture]
    image_base = 0x10000000 if is64 else 0x100000
    header_size = 64 if is64 else 52
    program_header_size = 56 if is64 else 32
    image = _Image(pointer_size, header_size + program_header_size)

    def table(name: str, targets: list[str | None]) -> int:
        offset = image.allocate(name, pointer_size * len(targets), pointer_size)
        for index, target in enumerate(targets):
            if target is not None:
                image.pointer(offset + index * pointer_size, target)
        return offset

    def pair(registration: int, slot: int, count: int, target: str) -> None:
        offset = registration + slot * pointer_size
        image.count(offset, count)
        image.pointer(offset + pointer_size, target)

    method_targets = [None if method.kind == "error" else f"code_{index}" for index, method in enumerate(methods)]
    table("global_methods", method_targets)
    table("generic_methods", ["code_0"])

    if profile.version in ("24.0", "24.1"):
        table("reverse_pinvoke", ["code_0"])
        registration = image.allocate("code_registration", 28 * pointer_size, pointer_size)
        pair(registration, 0, len(methods), "global_methods")
        pair(registration, 2, 1, "reverse_pinvoke")
        pair(registration, 4, 1, "generic_methods")
    else:
        if profile.version == "24.5":
            modules_slot, registration_slots = 23, 25
            module_slots, invoker_slot = 13, 5
        else:
            modules_slot = 20 if profile.version == "24.2" else 22
            registration_slots = modules_slot + 2
            module_slots, invoker_slot = 11, 3

        module_names: list[str] = []
        for index, method in enumerate(methods):
            image.add(f"image_name_{index}", method.image.encode("utf-8") + b"\0")
            table(f"image_methods_{index}", [method_targets[index]])
            invoker = image.allocate(f"invoker_{index}", 4, 4)
            image.u32(invoker, 0)
            module = image.allocate(f"module_{index}", module_slots * pointer_size, pointer_size)
            image.pointer(module, f"image_name_{index}")
            image.count(module + pointer_size, 1)
            image.pointer(module + 2 * pointer_size, f"image_methods_{index}")
            image.pointer(module + invoker_slot * pointer_size, f"invoker_{index}")
            module_names.append(f"module_{index}")
        table("modules", module_names)
        registration = image.allocate("code_registration", registration_slots * pointer_size, pointer_size)
        pair(registration, 0, len(methods), "global_methods")
        pair(registration, 2, 1, "generic_methods")
        pair(registration, modules_slot, len(methods), "modules")

    for index, method in enumerate(methods):
        image.add(f"code_{index}", _code(architecture, method.kind), pointer_size)
    image.resolve_pointers(image_base)

    ident = b"\x7fELF" + bytes((2 if is64 else 1, 1, 1, 0)) + b"\0" * 8
    image.bytes[:16] = ident
    file_size = len(image.bytes)
    if is64:
        struct.pack_into(
            "<HHIQQQIHHHHHH", image.bytes, 16,
            2, machine, 1, 0, header_size, 0, 0,
            header_size, program_header_size, 1, 0, 0, 0,
        )
        struct.pack_into(
            "<IIQQQQQQ", image.bytes, header_size,
            1, 5, 0, image_base, image_base, file_size, file_size, 0x1000,
        )
    else:
        struct.pack_into(
            "<HHIIIIIHHHHHH", image.bytes, 16,
            2, machine, 1, 0, header_size, 0, 0,
            header_size, program_header_size, 1, 0, 0, 0,
        )
        struct.pack_into(
            "<IIIIIIII", image.bytes, header_size,
            1, 0, image_base, image_base, file_size, file_size, 5, 0x1000,
        )
    return bytes(image.bytes)


def make_fixture(version: str, architecture: str, quality: bool = False) -> SyntheticFixture:
    if version not in VERSIONS:
        raise ValueError(f"unsupported synthetic metadata version {version}")
    if architecture not in ARCHITECTURES:
        raise ValueError(f"unsupported synthetic architecture {architecture}")
    profile = Profile(version, architecture)
    methods = quality_methods() if quality else standard_methods()
    return SyntheticFixture(profile, methods, _elf(profile, methods), _metadata(version, methods))
