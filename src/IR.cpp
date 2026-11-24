#include <il2cpprec/IR.hpp>
#include <il2cpprec/analysis/RuntimeHelpers.hpp>

#include <il2cpprec/flow/Structurer.hpp>

#include <algorithm>
#include <cctype>
#include <map>
#include <set>
#include <sstream>
#include <unordered_map>
#include <utility>

namespace il2cpprec {

ScalarType ScalarType::unknown() { return {}; }
ScalarType ScalarType::boolean() { return {ScalarKind::Boolean, 1}; }
ScalarType ScalarType::uintBits(uint16_t bits) { return {ScalarKind::UnsignedInteger, bits}; }
ScalarType ScalarType::intBits(uint16_t bits) { return {ScalarKind::SignedInteger, bits}; }
ScalarType ScalarType::floatBits(uint16_t bits) { return {ScalarKind::FloatingPoint, bits}; }
ScalarType ScalarType::pointer(uint16_t bits) { return {ScalarKind::Pointer, bits}; }
ScalarType ScalarType::vectorBits(uint16_t bits) { return {ScalarKind::Vector, bits}; }

namespace {

ExpressionPtr makeExpression(
    Expression::Kind kind,
    ScalarType type,
    std::string op,
    std::vector<ExpressionPtr> arguments) {
    auto result = std::make_shared<Expression>();
    result->kind = kind;
    result->type = type;
    result->op = std::move(op);
    result->arguments = std::move(arguments);
    return result;
}

std::string hexAddress(uint64_t value) {
    std::ostringstream stream;
    stream << std::hex << std::uppercase << value;
    return stream.str();
}

bool isCSharpKeyword(const std::string& value) {
    static const std::set<std::string> keywords = {
        "abstract", "as", "base", "bool", "break", "byte", "case", "catch", "char", "checked",
        "class", "const", "continue", "decimal", "default", "delegate", "do", "double", "else",
        "enum", "event", "explicit", "extern", "false", "finally", "fixed", "float", "for",
        "foreach", "goto", "if", "implicit", "in", "int", "interface", "internal", "is", "lock",
        "long", "namespace", "new", "null", "object", "operator", "out", "override", "params",
        "private", "protected", "public", "readonly", "ref", "return", "sbyte", "sealed", "short",
        "sizeof", "stackalloc", "static", "string", "struct", "switch", "this", "throw", "true",
        "try", "typeof", "uint", "ulong", "unchecked", "unsafe", "ushort", "using", "virtual",
        "void", "volatile", "while"
    };
    return keywords.contains(value);
}

std::string identifier(const std::string& value) {
    std::string result;
    result.reserve(value.size());
    for (const unsigned char c : value) {
        result.push_back(std::isalnum(c) || c == '_' ? static_cast<char>(c) : '_');
    }
    if (result.empty()) result = "_register";
    if (std::isdigit(static_cast<unsigned char>(result.front())) || isCSharpKeyword(result)) {
        result.insert(result.begin(), '_');
    }
    return result;
}

std::string stringLiteral(const std::string& value) {
    std::ostringstream output;
    output << '"';
    for (const unsigned char c : value) {
        switch (c) {
        case '\\': output << "\\\\"; break;
        case '"': output << "\\\""; break;
        case '\r': output << "\\r"; break;
        case '\n': output << "\\n"; break;
        case '\t': output << "\\t"; break;
        default:
            if (c < 0x20 || c == 0x7f) {
                const char* digits = "0123456789ABCDEF";
                output << "\\u00" << digits[c >> 4] << digits[c & 0xf];
            } else {
                output << static_cast<char>(c);
            }
            break;
        }
    }
    output << '"';
    return output.str();
}

int architecturePointerBits(Architecture architecture) {
    return architecture == Architecture::Arm64 || architecture == Architecture::X64 ? 64 : 32;
}

bool sameType(ScalarType left, ScalarType right) {
    return left.kind == right.kind && left.bits == right.bits;
}

bool isVector(ScalarType type) {
    if (type.kind == ScalarKind::Vector) return true;
    return type.bits == 128 && (type.kind == ScalarKind::Unknown ||
        type.kind == ScalarKind::UnsignedInteger || type.kind == ScalarKind::SignedInteger);
}

bool isVector128(ScalarType type) {
    return isVector(type) && type.bits == 128;
}

bool isSupportedScalar(ScalarType type, int pointerBits) {
    if (type.kind == ScalarKind::Boolean) return true;
    if (type.kind == ScalarKind::Vector || isVector(type)) return false;
    if (type.kind == ScalarKind::FloatingPoint) return type.bits == 32 || type.bits == 64;
    if (type.kind == ScalarKind::Pointer) {
        const auto bits = type.bits == 0 ? pointerBits : type.bits;
        return bits == 32 || bits == 64;
    }
    if (type.kind == ScalarKind::Unknown && type.bits == 0) return true;
    switch (type.bits) {
    case 1:
    case 8:
    case 16:
    case 32:
    case 64:
        return type.kind == ScalarKind::Unknown || type.kind == ScalarKind::UnsignedInteger ||
               type.kind == ScalarKind::SignedInteger;
    default:
        return false;
    }
}

bool isBoolean(ScalarType type) {
    return type.kind == ScalarKind::Boolean || (type.bits == 1 && type.kind != ScalarKind::Pointer &&
        type.kind != ScalarKind::FloatingPoint && type.kind != ScalarKind::Vector);
}

bool isNumeric(ScalarType type, int pointerBits) {
    return isSupportedScalar(type, pointerBits) && !isBoolean(type);
}

bool isIntegral(ScalarType type, int pointerBits) {
    return isNumeric(type, pointerBits) && type.kind != ScalarKind::FloatingPoint;
}

std::string typeName(ScalarType type, int pointerBits) {
    if (isVector(type)) return type.bits == 128 ? "RuntimeVector128" : "__UnsupportedValue";
    if (type.kind == ScalarKind::Boolean) return "bool";
    if (type.kind == ScalarKind::FloatingPoint) {
        if (type.bits == 32) return "float";
        if (type.bits == 64) return "double";
        return "__UnsupportedValue";
    }
    if (type.kind == ScalarKind::Pointer) {
        const auto bits = type.bits == 0 ? pointerBits : type.bits;
        if (bits == 32) return "uint";
        if (bits == 64) return "ulong";
        return "__UnsupportedValue";
    }
    const bool isSigned = type.kind == ScalarKind::SignedInteger;
    const auto bits = type.bits == 0 ? static_cast<uint16_t>(pointerBits) : type.bits;
    switch (bits) {
    case 1: return "bool";
    case 8: return isSigned ? "sbyte" : "byte";
    case 16: return isSigned ? "short" : "ushort";
    case 32: return isSigned ? "int" : "uint";
    case 64: return isSigned ? "long" : "ulong";
    default: return "__UnsupportedValue";
    }
}

ScalarType mergedType(ScalarType current, ScalarType incoming, bool& conflict) {
    if (sameType(current, incoming)) return current;
    if (current.kind == ScalarKind::Unknown) {
        if (current.bits == 0 || incoming.bits == 0 || current.bits == incoming.bits) return incoming;
    }
    if (incoming.kind == ScalarKind::Unknown) {
        if (incoming.bits == 0 || current.bits == 0 || current.bits == incoming.bits) return current;
    }
    if (current.bits == 0 && incoming.bits != 0 && current.kind == incoming.kind) {
        current.bits = incoming.bits;
        return current;
    }
    if (incoming.bits == 0 && current.bits != 0 && current.kind == incoming.kind) return current;
    if (current.bits != incoming.bits) {
        conflict = true;
        return current;
    }
    if ((current.kind == ScalarKind::Pointer && incoming.kind == ScalarKind::UnsignedInteger) ||
        (incoming.kind == ScalarKind::Pointer && current.kind == ScalarKind::UnsignedInteger)) {
        return ScalarType::pointer(current.bits);
    }
    if ((current.kind == ScalarKind::SignedInteger && incoming.kind == ScalarKind::UnsignedInteger) ||
        (incoming.kind == ScalarKind::SignedInteger && current.kind == ScalarKind::UnsignedInteger)) {
        return ScalarType::uintBits(current.bits);
    }
    if (current.bits == 1 && ((current.kind == ScalarKind::Boolean && incoming.kind == ScalarKind::UnsignedInteger) ||
        (incoming.kind == ScalarKind::Boolean && current.kind == ScalarKind::UnsignedInteger))) {
        return ScalarType::boolean();
    }
    conflict = true;
    return current;
}

bool isUnsupportedCallTarget(const ExpressionPtr& target) {
    return target && target->kind == Expression::Kind::Register &&
           target->name.starts_with("RuntimeCalls.Unsupported_");
}

enum class CodegenFlow {
    None,
    Leave,
    EndFinally,
    Cleanup,
    JumpTable,
    EndCleanup,
    Rethrow,
    RethrowIfUnhandled,
    Raise,
    NoReturn
};

CodegenFlow codegenFlow(const Statement& statement) {
    if (!statement.target || statement.target->kind != Expression::Kind::Register) return CodegenFlow::None;
    const auto& symbol = statement.target->name;
    const auto contains = [&symbol](const char* value) { return symbol.find(value) != std::string::npos; };
    if (contains("IL2CPP_END_FINALLY")) return CodegenFlow::EndFinally;
    if (contains("IL2CPP_END_CLEANUP")) return CodegenFlow::EndCleanup;
    if (contains("IL2CPP_JUMP_TBL")) return CodegenFlow::JumpTable;
    if (contains("IL2CPP_RETHROW_IF_UNHANDLED")) return CodegenFlow::RethrowIfUnhandled;
    if (contains("IL2CPP_CLEANUP")) return CodegenFlow::Cleanup;
    if (contains("IL2CPP_LEAVE")) return CodegenFlow::Leave;
    if (contains("IL2CPP_RETHROW") || contains("il2cpp_codegen_rethrow_exception")) return CodegenFlow::Rethrow;
    if (contains("il2cpp_codegen_no_return")) return CodegenFlow::NoReturn;
    if (contains("IL2CPP_RAISE") || contains("il2cpp_codegen_raise_exception")) return CodegenFlow::Raise;
    return CodegenFlow::None;
}

bool isNoReturn(CodegenFlow flow) {
    return flow == CodegenFlow::Rethrow || flow == CodegenFlow::Raise || flow == CodegenFlow::NoReturn;
}

class CSharpEmitter {
public:
    explicit CSharpEmitter(const RecoveredFunction& function, CSharpBodyOptions options = {})
        : function_(function), pointerBits_(architecturePointerBits(function.architecture)), options_(options),
          nativePointerType_(ScalarType::pointer(static_cast<uint16_t>(pointerBits_))) {}

    CSharpEmissionResult emit() {
        prepare();
        const auto name = identifier(function_.name.empty() ? "Method_0x" + hexAddress(function_.address) : function_.name);
        std::ostringstream body;
        emitDeclarations(body, 2, false);
        emitStructured(body, 2);
        emitFinalReturn(body, 2);

        std::ostringstream output;
        output << "public static class RecoveredMethods_" << name << "\n{\n";
        output << emitSupport();
        output << "    public static " << (voidReturn_ ? "void" : typeName(returnType_, pointerBits_)) << ' ' << name << '(';
        const auto parameters = parameterRegisters();
        for (size_t i = 0; i < parameters.size(); ++i) {
            if (i != 0) output << ", ";
            output << registerTypeName(parameters[i]) << ' ' << identifier(parameters[i]);
        }
        output << ")\n    {\n";
        output << body.str();
        output << "    }\n}\n";

        CSharpEmissionResult result;
        result.source = output.str();
        result.diagnostics = diagnostics_;
        result.partial = partial_;
        return result;
    }

    CSharpBodyEmissionResult emitBody() {
        prepare();
        std::ostringstream declarations;
        std::ostringstream body;
        emitDeclarations(declarations, 1, options_.declareNativeParameters,
                         options_.declareNativeParameters ? nullptr : &options_.externalNativeRegisters);
        emitStructured(body, 1);
        emitFinalReturn(body, 1);

        CSharpBodyEmissionResult result;
        result.declarations = declarations.str();
        result.body = body.str();
        result.supportFragments = emitSupportFragments();
        for (const auto& fragment : result.supportFragments) result.support += fragment.source;
        result.diagnostics = diagnostics_;
        result.partial = partial_;
        return result;
    }

private:
    struct RegisterInfo {
        ScalarType type;
        bool conflict = false;
    };

    enum class ExceptionPartKind {
        Prefix,
        Try,
        Handler,
        Suffix
    };

    struct ExceptionPart {
        ExceptionPartKind kind = ExceptionPartKind::Prefix;
        std::vector<BasicBlock> blocks;
        std::set<uint64_t> addresses;
        std::set<uint64_t> exits;
        std::set<uint64_t> labels;
        bool allowReturn = true;
    };

    struct ExceptionPlan {
        bool supported = false;
        ExceptionRegion region;
        ExceptionPart prefix;
        ExceptionPart tryBody;
        ExceptionPart handler;
        ExceptionPart suffix;
        std::vector<BasicBlock> cleanup;
    };

    RecoveredFunction function_;
    int pointerBits_;
    CSharpBodyOptions options_;
    ScalarType nativePointerType_;
    ScalarType returnType_;
    bool voidReturn_ = false;
    bool prepared_ = false;
    bool partial_ = false;
    bool usesRuntimeVector128_ = false;
    uint64_t currentAddress_ = 0;
    std::map<std::string, RegisterInfo> registers_;
    std::map<const Expression*, ScalarType> inferredLoadTypes_;
    std::set<const Expression*> conflictingLoads_;
    std::set<uint64_t> blockAddresses_;
    std::set<uint64_t> referencedAddresses_;
    std::set<uint64_t> inferredClassInitCalls_;
    std::vector<CSharpDiagnostic> diagnostics_;
    std::set<std::pair<uint64_t, std::string>> diagnosticKeys_;
    ExceptionPlan exceptionPlan_;
    int catchDepth_ = 0;

    static std::string indentation(int level) {
        return std::string(static_cast<size_t>(std::max(level, 0)) * 4, ' ');
    }

    void diagnose(uint64_t address, const std::string& message) {
        partial_ = true;
        if (diagnosticKeys_.insert({address, message}).second) {
            diagnostics_.push_back({address, message});
        }
    }

    std::vector<std::string> parameterRegisters() const {
        switch (function_.architecture) {
        case Architecture::Arm64: return {"x0", "x1", "x2", "x3", "x4", "x5", "x6", "x7"};
        case Architecture::X64: return {"rcx", "rdx", "r8", "r9"};
        case Architecture::Arm32: return {"r0", "r1", "r2", "r3"};
        case Architecture::X86: return {"ecx", "edx"};
        }
        return {};
    }

    static bool isBranch(const Statement& statement) {
        return statement.kind == Statement::Kind::Branch || statement.kind == Statement::Kind::ConditionalBranch;
    }

    static bool containsExceptionState(const ExpressionPtr& expression) {
        if (!expression) return false;
        if (expression->kind == Expression::Kind::Register) {
            const auto name = identifier(expression->name);
            return name == "__leave_target" || name == "__last_unhandled_exception" ||
                   name == "__exception_local" || name == "__active_exceptions";
        }
        return std::any_of(expression->arguments.begin(), expression->arguments.end(), [](const ExpressionPtr& argument) {
            return containsExceptionState(argument);
        });
    }

    static bool containsExceptionState(const Statement& statement) {
        if (containsExceptionState(statement.destination) || containsExceptionState(statement.value) ||
            containsExceptionState(statement.condition) || containsExceptionState(statement.target)) return true;
        return std::any_of(statement.arguments.begin(), statement.arguments.end(), [](const ExpressionPtr& argument) {
            return containsExceptionState(argument);
        });
    }

    static bool isExceptionAssignment(const Statement& statement, ExceptionPartKind part) {
        if (statement.kind != Statement::Kind::Assign || !statement.destination ||
            statement.destination->kind != Expression::Kind::Register) return false;
        const auto name = identifier(statement.destination->name);
        if (name == "__leave_target") return true;
        return name == "__last_unhandled_exception" &&
               (part == ExceptionPartKind::Prefix || part == ExceptionPartKind::Suffix) &&
               statement.value && statement.value->kind == Expression::Kind::Constant && statement.value->constant == 0;
    }

    std::pair<bool, uint64_t> directTarget(const Statement& statement) const {
        if (isBranch(statement) && statement.target && statement.target->kind == Expression::Kind::Constant) {
            return {true, statement.target->constant};
        }
        if (codegenFlow(statement) == CodegenFlow::Leave && statement.arguments.size() >= 2) {
            const auto& target = statement.arguments.back();
            if (target && target->kind == Expression::Kind::Constant) return {true, target->constant};
        }
        return {false, 0};
    }

    ExceptionPart makeExceptionPart(ExceptionPartKind kind, const std::vector<BasicBlock>& blocks) const {
        ExceptionPart result;
        result.kind = kind;
        result.blocks = blocks;
        for (const auto& block : blocks) result.addresses.insert(block.address);
        return result;
    }

    bool hasCleanupSyntax(const BasicBlock& block) const {
        for (const auto& statement : block.statements) {
            const auto flow = codegenFlow(statement);
            if (flow == CodegenFlow::Cleanup || flow == CodegenFlow::JumpTable ||
                flow == CodegenFlow::EndCleanup || flow == CodegenFlow::RethrowIfUnhandled) return true;
            if (containsExceptionState(statement.condition)) return true;
        }
        return false;
    }

    bool validateCleanup(const std::vector<BasicBlock>& blocks, uint64_t leaveTarget) const {
        std::set<uint64_t> addresses;
        for (const auto& block : blocks) addresses.insert(block.address);
        for (const auto& block : blocks) {
            for (const auto& statement : block.statements) {
                const auto flow = codegenFlow(statement);
                if (flow == CodegenFlow::Cleanup || flow == CodegenFlow::JumpTable ||
                    flow == CodegenFlow::EndCleanup || flow == CodegenFlow::RethrowIfUnhandled ||
                    flow == CodegenFlow::Rethrow || flow == CodegenFlow::Raise) continue;
                if (statement.kind == Statement::Kind::Assign && statement.destination &&
                    statement.destination->kind == Expression::Kind::Register) {
                    const auto name = identifier(statement.destination->name);
                    if (name == "__leave_target" || name == "__last_unhandled_exception") continue;
                }
                if (isBranch(statement)) {
                    const auto [direct, target] = directTarget(statement);
                    if (direct && (target == leaveTarget || addresses.contains(target))) continue;
                }
                return false;
            }
        }
        return true;
    }

    bool validateExceptionPart(ExceptionPart& part) const {
        for (const auto& block : part.blocks) {
            for (const auto& statement : block.statements) {
                const auto flow = codegenFlow(statement);
                if (flow == CodegenFlow::Leave) {
                    const auto [direct, target] = directTarget(statement);
                    if (statement.condition || !direct || !part.exits.contains(target)) return false;
                    continue;
                }
                if (flow == CodegenFlow::EndFinally) {
                    if (part.kind != ExceptionPartKind::Handler || exceptionPlan_.region.kind != ExceptionRegionKind::Finally) {
                        return false;
                    }
                    continue;
                }
                if (flow == CodegenFlow::Cleanup || flow == CodegenFlow::JumpTable ||
                    flow == CodegenFlow::EndCleanup || flow == CodegenFlow::RethrowIfUnhandled) return false;
                if (isExceptionAssignment(statement, part.kind)) continue;
                if (containsExceptionState(statement)) return false;
                if (statement.kind == Statement::Kind::Return && !part.allowReturn) return false;
                if (isBranch(statement)) {
                    const auto [direct, target] = directTarget(statement);
                    if (!direct) return false;
                    if (part.addresses.contains(target)) {
                        part.labels.insert(target);
                        continue;
                    }
                    if (!statement.condition && part.exits.contains(target)) continue;
                    return false;
                }
            }
        }
        return true;
    }

    void prepareExceptionRegions() {
        if (function_.exceptionRegions.empty()) return;
        exceptionPlan_.region = function_.exceptionRegions.front();
        const auto& region = exceptionPlan_.region;
        if (function_.exceptionRegions.size() != 1) {
            for (const auto& item : function_.exceptionRegions) {
                diagnose(item.tryBegin, "Multiple or nested exception regions require a partial native fallback");
            }
            return;
        }
        if (region.kind != ExceptionRegionKind::Catch && region.kind != ExceptionRegionKind::Finally) {
            diagnose(region.tryBegin, "Filter and fault exception regions require a partial native fallback");
            return;
        }
        if (function_.blocks.empty() || region.tryBegin >= region.tryEnd || region.tryEnd > region.handler ||
            region.handler >= region.leaveTarget) {
            diagnose(region.tryBegin, "Malformed exception region boundaries require a partial native fallback");
            return;
        }

        auto sorted = function_.blocks;
        std::sort(sorted.begin(), sorted.end(), [](const BasicBlock& left, const BasicBlock& right) {
            return left.address < right.address;
        });
        for (size_t i = 1; i < sorted.size(); ++i) {
            if (sorted[i - 1].address == sorted[i].address) {
                diagnose(region.tryBegin, "Duplicate blocks in an exception region require a partial native fallback");
                return;
            }
        }

        std::vector<BasicBlock> prefix;
        std::vector<BasicBlock> tryBody;
        std::vector<BasicBlock> handler;
        std::vector<BasicBlock> suffix;
        for (const auto& block : sorted) {
            if (block.address < region.tryBegin) {
                prefix.push_back(block);
            } else if (block.address < region.tryEnd) {
                tryBody.push_back(block);
            } else if (block.address < region.handler) {
                diagnose(region.tryEnd, "Unexpected blocks between try and handler require a partial native fallback");
                return;
            } else if (block.address < region.leaveTarget) {
                handler.push_back(block);
            } else {
                suffix.push_back(block);
            }
        }
        if (tryBody.empty() || tryBody.front().address != region.tryBegin || handler.empty() ||
            handler.front().address != region.handler) {
            diagnose(region.tryBegin, "Exception region does not start on recovered block boundaries");
            return;
        }

        exceptionPlan_.prefix = makeExceptionPart(ExceptionPartKind::Prefix, prefix);
        exceptionPlan_.tryBody = makeExceptionPart(ExceptionPartKind::Try, tryBody);
        exceptionPlan_.handler = makeExceptionPart(ExceptionPartKind::Handler, handler);
        exceptionPlan_.suffix = makeExceptionPart(ExceptionPartKind::Suffix, suffix);
        exceptionPlan_.tryBody.exits.insert(region.leaveTarget);
        exceptionPlan_.handler.exits.insert(region.leaveTarget);
        exceptionPlan_.handler.allowReturn = region.kind == ExceptionRegionKind::Catch;
        if (region.kind == ExceptionRegionKind::Finally) exceptionPlan_.tryBody.exits.insert(region.handler);

        auto& handlerBlocks = exceptionPlan_.handler.blocks;
        const auto cleanup = std::find_if(handlerBlocks.begin(), handlerBlocks.end(), [this](const BasicBlock& block) {
            return hasCleanupSyntax(block);
        });
        if (cleanup != handlerBlocks.end()) {
            if (region.kind != ExceptionRegionKind::Finally) {
                diagnose(region.handler, "Native cleanup in a catch handler requires a partial native fallback");
                return;
            }
            const auto cleanupAddress = cleanup->address;
            exceptionPlan_.cleanup.assign(cleanup, handlerBlocks.end());
            handlerBlocks.erase(cleanup, handlerBlocks.end());
            exceptionPlan_.handler.addresses.clear();
            for (const auto& block : handlerBlocks) exceptionPlan_.handler.addresses.insert(block.address);
            if (handlerBlocks.empty() || !validateCleanup(exceptionPlan_.cleanup, region.leaveTarget)) {
                diagnose(region.handler, "Unsupported native cleanup requires a partial native fallback");
                return;
            }
            bool entersCleanup = false;
            for (const auto& block : handlerBlocks) {
                for (const auto& statement : block.statements) {
                    const auto [direct, target] = directTarget(statement);
                    if (direct && target == cleanupAddress && !statement.condition) entersCleanup = true;
                }
            }
            if (!entersCleanup) {
                diagnose(region.handler, "Finally handler does not reach its native cleanup");
                return;
            }
            exceptionPlan_.handler.exits.insert(cleanupAddress);
        }

        if (!validateExceptionPart(exceptionPlan_.prefix) || !validateExceptionPart(exceptionPlan_.tryBody) ||
            !validateExceptionPart(exceptionPlan_.handler) || !validateExceptionPart(exceptionPlan_.suffix)) {
            diagnose(region.tryBegin, "Exception-region control flow requires a partial native fallback");
            return;
        }
        exceptionPlan_.supported = true;
        registers_.erase("__leave_target");
        registers_.erase("__last_unhandled_exception");
        registers_.erase("__exception_local");
        registers_.erase("__active_exceptions");
    }

    ExpressionPtr cloneExpression(
        const ExpressionPtr& expression,
        std::unordered_map<const Expression*, ExpressionPtr>& clones) const {
        if (!expression) return nullptr;
        const auto existing = clones.find(expression.get());
        if (existing != clones.end()) return existing->second;
        auto clone = std::make_shared<Expression>(*expression);
        clones.emplace(expression.get(), clone);
        for (auto& argument : clone->arguments) argument = cloneExpression(argument, clones);
        return clone;
    }

    void inferLoadType(const ExpressionPtr& expression, ScalarType proof) {
        if (!expression || expression->kind != Expression::Kind::Load || conflictingLoads_.contains(expression.get())) return;
        const auto previous = inferredLoadTypes_.find(expression.get());
        if (previous == inferredLoadTypes_.end() && expression->type.bits != 0) return;
        const auto original = expression->type;
        if (original.kind != ScalarKind::Unknown && original.kind != ScalarKind::UnsignedInteger &&
            original.kind != ScalarKind::SignedInteger && original.kind != ScalarKind::FloatingPoint &&
            original.kind != ScalarKind::Pointer) return;
        if (proof.kind == ScalarKind::Pointer && proof.bits == 0) proof.bits = static_cast<uint16_t>(pointerBits_);
        if (!isSupportedScalar(proof, pointerBits_) || proof.bits == 0) return;

        ScalarType candidate = proof;
        if (original.kind == ScalarKind::UnsignedInteger || original.kind == ScalarKind::SignedInteger) {
            candidate = {original.kind, proof.bits};
        } else if (original.kind == ScalarKind::FloatingPoint) {
            candidate = ScalarType::floatBits(proof.bits);
        } else if (original.kind == ScalarKind::Pointer) {
            candidate = ScalarType::pointer(proof.bits);
        }
        if (!isSupportedScalar(candidate, pointerBits_) || candidate.bits == 0) return;
        const auto [existing, inserted] = inferredLoadTypes_.emplace(expression.get(), candidate);
        if (!inserted && !sameType(existing->second, candidate)) {
            conflictingLoads_.insert(expression.get());
            expression->type = ScalarType::unknown();
            return;
        }
        expression->type = existing->second;
    }

    void normalizeLoadTypes() {
        std::unordered_map<const Expression*, ExpressionPtr> clones;
        for (auto& block : function_.blocks) {
            for (auto& statement : block.statements) {
                statement.destination = cloneExpression(statement.destination, clones);
                statement.value = cloneExpression(statement.value, clones);
                statement.condition = cloneExpression(statement.condition, clones);
                statement.target = cloneExpression(statement.target, clones);
                for (auto& argument : statement.arguments) argument = cloneExpression(argument, clones);
            }
        }
        for (auto& block : function_.blocks) {
            for (auto& statement : block.statements) {
                if (statement.kind == Statement::Kind::Assign && statement.destination &&
                    statement.destination->kind == Expression::Kind::Register && statement.value &&
                    statement.value->kind == Expression::Kind::Load) {
                    inferLoadType(statement.value, statement.destination->type);
                }
                if ((statement.kind == Statement::Kind::Call || isBranch(statement)) && statement.target &&
                    statement.target->kind == Expression::Kind::Load) {
                    inferLoadType(statement.target, nativePointerType_);
                }
            }
        }
    }

    void collectRegisters(const ExpressionPtr& expression) {
        if (!expression) return;
        if (isVector128(expression->type)) usesRuntimeVector128_ = true;
        if (expression->kind == Expression::Kind::Register) {
            const auto name = identifier(expression->name);
            auto [found, inserted] = registers_.try_emplace(name, RegisterInfo{expression->type, false});
            if (!inserted && !found->second.conflict) {
                bool conflict = false;
                found->second.type = mergedType(found->second.type, expression->type, conflict);
                found->second.conflict = conflict;
            }
        }
        for (const auto& argument : expression->arguments) collectRegisters(argument);
    }

    void prepare() {
        if (prepared_) return;
        prepared_ = true;
        for (const auto& evidence : RuntimeHelpers{}.infer(function_)) {
            if (evidence.role == RuntimeHelperRole::ClassInit) inferredClassInitCalls_.insert(evidence.callAddress);
        }
        normalizeLoadTypes();
        returnType_ = nativePointerType_;
        bool sawReturn = false;
        bool sawReturnValue = false;
        bool sawVoidReturn = false;
        bool returnConflict = false;

        for (const auto& block : function_.blocks) {
            blockAddresses_.insert(block.address);
            for (const auto& statement : block.statements) {
                collectRegisters(statement.destination);
                collectRegisters(statement.value);
                collectRegisters(statement.condition);
                if (codegenFlow(statement) == CodegenFlow::None && !isUnsupportedCallTarget(statement.target)) {
                    collectRegisters(statement.target);
                }
                for (const auto& argument : statement.arguments) collectRegisters(argument);
                if ((statement.kind == Statement::Kind::Branch || statement.kind == Statement::Kind::ConditionalBranch) &&
                    statement.target && statement.target->kind == Expression::Kind::Constant) {
                    referencedAddresses_.insert(statement.target->constant);
                }
                if (statement.kind != Statement::Kind::Return) continue;
                sawReturn = true;
                if (!statement.value) {
                    sawVoidReturn = true;
                    continue;
                }
                if (!sawReturnValue) {
                    returnType_ = statement.value->type;
                    sawReturnValue = true;
                } else if (!returnConflict) {
                    returnType_ = mergedType(returnType_, statement.value->type, returnConflict);
                }
            }
        }

        for (const auto& [name, info] : registers_) {
            if (info.conflict) {
                diagnose(function_.address, "Register '" + name + "' has conflicting types; explicit unsupported storage is used");
            } else if (!isSupportedScalar(info.type, pointerBits_) && !isVector128(info.type)) {
                diagnose(function_.address, "Register '" + name + "' has unsupported " + std::to_string(info.type.bits) +
                    "-bit storage; explicit unsupported storage is used");
            }
        }
        if (returnConflict || (sawReturnValue && sawVoidReturn)) {
            diagnose(function_.address, "Return statements have inconsistent types; the native pointer return type is used");
            returnType_ = nativePointerType_;
        }
        voidReturn_ = options_.voidReturn || (sawReturn && !sawReturnValue);
        prepareExceptionRegions();
    }

    std::string registerTypeName(const std::string& name) const {
        const auto found = registers_.find(identifier(name));
        if (found == registers_.end() || found->second.conflict) {
            return found == registers_.end() ? typeName(nativePointerType_, pointerBits_) : "__UnsupportedValue";
        }
        return typeName(found->second.type, pointerBits_);
    }

    std::string unsupported(ScalarType type, const std::string& reason, const std::vector<std::string>& operands = {}) {
        diagnose(currentAddress_, reason);
        std::ostringstream output;
        output << "__Unsupported<" << typeName(type, pointerBits_) << ">(" << stringLiteral(reason);
        for (const auto& operand : operands) output << ", " << operand;
        output << ')';
        return output.str();
    }

    std::string convert(const std::string& value, ScalarType from, ScalarType to) {
        const auto fromName = typeName(from, pointerBits_);
        const auto toName = typeName(to, pointerBits_);
        if (fromName == toName) return value;
        if (isVector128(from) && isVector128(to)) return value;
        if (isVector128(from)) {
            if (!isSupportedScalar(to, pointerBits_)) {
                return unsupported(to, "Unsupported conversion from RuntimeVector128 to " + toName, {value});
            }
            if (to.kind == ScalarKind::Boolean || to.bits == 1) return '(' + value + " != default(RuntimeVector128))";
            if (to.kind == ScalarKind::FloatingPoint && to.bits == 32) {
                return "global::System.BitConverter.ToSingle(global::System.BitConverter.GetBytes(" + value + ".GetUInt32(0)), 0)";
            }
            if (to.kind == ScalarKind::FloatingPoint && to.bits == 64) {
                return "global::System.BitConverter.Int64BitsToDouble(unchecked((long)(" + value + ".GetUInt64(0))))";
            }
            ScalarType laneType;
            std::string lane;
            switch (to.bits) {
            case 8:
                laneType = ScalarType::uintBits(8);
                lane = value + ".GetLane<byte>(0)";
                break;
            case 16:
                laneType = ScalarType::uintBits(16);
                lane = value + ".GetLane<ushort>(0)";
                break;
            case 32:
                laneType = ScalarType::uintBits(32);
                lane = value + ".GetUInt32(0)";
                break;
            case 64:
                laneType = ScalarType::uintBits(64);
                lane = value + ".GetUInt64(0)";
                break;
            default:
                return unsupported(to, "Unsupported scalar lane extraction from RuntimeVector128", {value});
            }
            return convert(lane, laneType, to);
        }
        if (isVector128(to)) {
            if (!isSupportedScalar(from, pointerBits_)) {
                return unsupported(to, "Unsupported conversion from " + fromName + " to RuntimeVector128", {value});
            }
            auto laneType = from;
            auto lane = value;
            if (from.kind == ScalarKind::FloatingPoint && from.bits == 32) {
                laneType = ScalarType::uintBits(32);
                lane = "global::System.BitConverter.ToUInt32(global::System.BitConverter.GetBytes(" + value + "), 0)";
            } else if (from.kind == ScalarKind::FloatingPoint && from.bits == 64) {
                laneType = ScalarType::uintBits(64);
                lane = "global::System.BitConverter.ToUInt64(global::System.BitConverter.GetBytes(" + value + "), 0)";
            }
            const auto bits = laneType.bits == 0 ? static_cast<uint16_t>(pointerBits_) : laneType.bits;
            const auto unsignedLaneType = laneType.kind == ScalarKind::Boolean
                ? ScalarType::boolean() : ScalarType::uintBits(bits);
            lane = convert(lane, laneType, unsignedLaneType);
            switch (bits) {
            case 1: return "RuntimeVector128.Zero.WithLane<bool>(0, " + lane + ')';
            case 8: return "RuntimeVector128.Zero.WithLane<byte>(0, " + lane + ')';
            case 16: return "RuntimeVector128.Zero.WithLane<ushort>(0, " + lane + ')';
            case 32: return "RuntimeVector128.Zero.WithUInt32(0, " + lane + ')';
            case 64: return "RuntimeVector128.Zero.WithUInt64(0, " + lane + ')';
            default: return unsupported(to, "Unsupported scalar lane insertion into RuntimeVector128", {lane});
            }
        }
        if (!isSupportedScalar(from, pointerBits_) || !isSupportedScalar(to, pointerBits_)) {
            return unsupported(to, "Unsupported conversion from " + fromName + " to " + toName, {value});
        }
        if (to.kind == ScalarKind::Boolean || to.bits == 1) {
            if (from.kind == ScalarKind::Boolean) return value;
            return '(' + value + " != default(" + fromName + "))";
        }
        if (from.kind == ScalarKind::Boolean || from.bits == 1) {
            return "unchecked((" + toName + ")(" + value + " ? 1 : 0))";
        }
        if (isNumeric(from, pointerBits_) && isNumeric(to, pointerBits_)) {
            return "unchecked((" + toName + ")(" + value + "))";
        }
        return unsupported(to, "Unsupported conversion from " + fromName + " to " + toName, {value});
    }

    std::string emitAs(const ExpressionPtr& expression, ScalarType type) {
        if (!expression) return unsupported(type, "Missing expression");
        return convert(emitExpression(expression), expression->type, type);
    }

    std::string emitCondition(const ExpressionPtr& expression) {
        if (!expression) return unsupported(ScalarType::boolean(), "Missing condition");
        if (expression->type.kind == ScalarKind::Boolean) return emitExpression(expression);
        if (isNumeric(expression->type, pointerBits_)) {
            return '(' + emitExpression(expression) + " != default(" + typeName(expression->type, pointerBits_) + "))";
        }
        return emitAs(expression, ScalarType::boolean());
    }

    std::string emitConstant(const ExpressionPtr& expression) {
        const auto type = expression->type;
        if (type.kind == ScalarKind::Boolean || (type.bits == 1 && isSupportedScalar(type, pointerBits_))) {
            return expression->constant == 0 ? "false" : "true";
        }
        const auto literal = "0x" + hexAddress(expression->constant) + "UL";
        if (type.kind == ScalarKind::FloatingPoint && type.bits == 32) {
            return "global::System.BitConverter.ToSingle(global::System.BitConverter.GetBytes(unchecked((uint)" + literal + ")), 0)";
        }
        if (type.kind == ScalarKind::FloatingPoint && type.bits == 64) {
            return "global::System.BitConverter.Int64BitsToDouble(unchecked((long)" + literal + "))";
        }
        if (isVector128(type)) return "new RuntimeVector128(" + literal + ", 0UL)";
        if (!isSupportedScalar(type, pointerBits_)) {
            return unsupported(type, "Unsupported " + std::to_string(type.bits) + "-bit constant", {literal});
        }
        const auto name = typeName(type, pointerBits_);
        if (name == "ulong") return literal;
        return "unchecked((" + name + ')' + literal + ')';
    }

    std::string emitUnary(const ExpressionPtr& expression) {
        if (expression->arguments.size() != 1 || !expression->arguments[0]) {
            return unsupported(expression->type, "Malformed unary expression");
        }
        const auto& operand = expression->arguments[0];
        const auto value = emitExpression(operand);
        const auto& op = expression->op;
        if (op == "global::System.BitConverter.UInt32BitsToSingle") {
            const auto input = convert(value, operand->type, ScalarType::uintBits(32));
            return convert("global::System.BitConverter.ToSingle(global::System.BitConverter.GetBytes(" + input + "), 0)",
                ScalarType::floatBits(32), expression->type);
        }
        if (op == "global::System.BitConverter.UInt64BitsToDouble") {
            const auto input = convert(value, operand->type, ScalarType::uintBits(64));
            return convert("global::System.BitConverter.Int64BitsToDouble(unchecked((long)(" + input + ")))",
                ScalarType::floatBits(64), expression->type);
        }
        if (op == "global::System.BitConverter.SingleToUInt32Bits") {
            const auto input = convert(value, operand->type, ScalarType::floatBits(32));
            return convert("global::System.BitConverter.ToUInt32(global::System.BitConverter.GetBytes(" + input + "), 0)",
                ScalarType::uintBits(32), expression->type);
        }
        if (op == "global::System.BitConverter.DoubleToUInt64Bits") {
            const auto input = convert(value, operand->type, ScalarType::floatBits(64));
            return convert("global::System.BitConverter.ToUInt64(global::System.BitConverter.GetBytes(" + input + "), 0)",
                ScalarType::uintBits(64), expression->type);
        }
        if (op == "global::System.Math.Round") {
            const auto input = convert(value, operand->type, ScalarType::floatBits(64));
            return convert(op + '(' + input + ')', ScalarType::floatBits(64), expression->type);
        }
        if (op == "!") {
            return convert("(!(" + emitCondition(operand) + "))", ScalarType::boolean(), expression->type);
        }
        if (isVector128(operand->type)) {
            if (op == "~") return convert("(~(" + value + "))", operand->type, expression->type);
            if (op == "mov" || op == "fmov" || op == "umov" || op == "smov") {
                return convert(value, operand->type, expression->type);
            }
            if (op == "dup32") return "RuntimeVector128.Duplicate(" + convert(value, operand->type, ScalarType::uintBits(32)) + ')';
            if (op == "dup64") return "RuntimeVector128.Duplicate(" + convert(value, operand->type, ScalarType::uintBits(64)) + ')';
            diagnose(currentAddress_, "Unsupported packed unary operation '" + op + "'");
            return convert("__UnsupportedPackedUnary(" + stringLiteral(op) + ", " + value + ')',
                operand->type, expression->type);
        }
        if (isVector128(expression->type) && (op == "dup" || op == "movi")) {
            return "RuntimeVector128.Duplicate(" + value + ')';
        }
        if (isVector128(expression->type) && op == "mov") return convert(value, operand->type, expression->type);
        if (operand->type.kind == ScalarKind::FloatingPoint && (operand->type.bits == 32 || operand->type.bits == 64)) {
            if (op == "abs" || op == "fabs") return convert("global::System.Math.Abs(" + value + ')', operand->type, expression->type);
            const auto input = convert(value, operand->type, ScalarType::floatBits(64));
            if (op == "sqrt" || op == "fsqrt") return convert("global::System.Math.Sqrt(" + input + ')', ScalarType::floatBits(64), expression->type);
            if (op == "floor" || op == "frintm") return convert("global::System.Math.Floor(" + input + ')', ScalarType::floatBits(64), expression->type);
            if (op == "ceil" || op == "frintp") return convert("global::System.Math.Ceiling(" + input + ')', ScalarType::floatBits(64), expression->type);
            if (op == "trunc" || op == "frintz") return convert("global::System.Math.Truncate(" + input + ')', ScalarType::floatBits(64), expression->type);
            if (op == "round_ties_away" || op == "frinta") {
                return convert("global::System.Math.Round(" + input + ", global::System.MidpointRounding.AwayFromZero)", ScalarType::floatBits(64), expression->type);
            }
            if (op == "round_ties_even" || op == "frintn" || op == "frinti" || op == "frintx" || op == "round_current" ||
                op == "round_current_exact") {
                return convert("global::System.Math.Round(" + input + ", global::System.MidpointRounding.ToEven)", ScalarType::floatBits(64), expression->type);
            }
        }
        auto actualType = operand->type;
        const auto operandBits = operand->type.bits == 0 ? pointerBits_ : operand->type.bits;
        if (isIntegral(operand->type, pointerBits_) && operandBits < 32) actualType = ScalarType::intBits(32);
        if (op == "~" && isIntegral(operand->type, pointerBits_) && isSupportedScalar(expression->type, pointerBits_)) {
            return convert("(~(" + value + "))", actualType, expression->type);
        }
        if ((op == "+" || op == "-") && isNumeric(operand->type, pointerBits_) &&
            isSupportedScalar(expression->type, pointerBits_)) {
            if (op == "-" && typeName(operand->type, pointerBits_) == "ulong") {
                return convert("unchecked(0UL - (" + value + "))", operand->type, expression->type);
            }
            if (op == "-" && typeName(operand->type, pointerBits_) == "uint") actualType = ScalarType::intBits(64);
            return convert('(' + op + '(' + value + "))", actualType, expression->type);
        }
        return unsupported(expression->type, "Unsupported unary operation '" + op + "'", {value});
    }

    std::string emitBinary(const ExpressionPtr& expression) {
        if (expression->arguments.size() != 2 || !expression->arguments[0] || !expression->arguments[1]) {
            return unsupported(expression->type, "Malformed binary expression");
        }
        const auto& leftExpression = expression->arguments[0];
        const auto& rightExpression = expression->arguments[1];
        const auto left = emitExpression(leftExpression);
        const auto& op = expression->op;
        if (isVector128(leftExpression->type) || isVector128(rightExpression->type)) {
            const auto vectorType = ScalarType::vectorBits(128);
            const auto vectorLeft = convert(left, leftExpression->type, vectorType);
            const auto vectorRight = emitAs(rightExpression, vectorType);
            if (op == "&" || op == "|" || op == "^") {
                return convert('(' + vectorLeft + ' ' + op + ' ' + vectorRight + ')', vectorType, expression->type);
            }
            if (op == "<<" || op == ">>") {
                const auto count = emitAs(rightExpression, ScalarType::intBits(32));
                const auto method = op == "<<" ? "ShiftLeftLogical" : "ShiftRightLogical";
                return convert(vectorLeft + '.' + method + '(' + count + ')', vectorType, expression->type);
            }
            if (op == "==" || op == "!=") {
                return convert('(' + vectorLeft + ' ' + op + ' ' + vectorRight + ')', ScalarType::boolean(), expression->type);
            }
            if (op.rfind("ext", 0) == 0) {
                const auto suffix = op.substr(3);
                const bool numeric = !suffix.empty() && std::all_of(suffix.begin(), suffix.end(), [](unsigned char c) {
                    return std::isdigit(c) != 0;
                });
                if (numeric) {
                    const auto bytes = std::stoi(suffix);
                    if (bytes == 0) return convert(vectorLeft, vectorType, expression->type);
                    if (bytes == 16) return convert(vectorRight, vectorType, expression->type);
                    if (bytes > 0 && bytes < 16) {
                        const auto joined = '(' + vectorLeft + ".ShiftRightLogical(" + std::to_string(bytes * 8) + ") | " +
                            vectorRight + ".ShiftLeftLogical(" + std::to_string((16 - bytes) * 8) + "))";
                        return convert(joined, vectorType, expression->type);
                    }
                }
            }
            static const std::set<std::string> packedComparisons = {"unordered", "<", "<=", ">", ">=", "&&", "||"};
            diagnose(currentAddress_, "Unsupported packed operation '" + op + "'");
            if (packedComparisons.contains(op)) {
                return convert("__UnsupportedPackedCompare(" + stringLiteral(op) + ", " + vectorLeft + ", " + vectorRight + ')',
                    ScalarType::boolean(), expression->type);
            }
            return convert("__UnsupportedPackedBinary(" + stringLiteral(op) + ", " + vectorLeft + ", " + vectorRight + ')',
                vectorType, expression->type);
        }
        const bool scalarFloating = leftExpression->type.kind == ScalarKind::FloatingPoint &&
            rightExpression->type.kind == ScalarKind::FloatingPoint &&
            (leftExpression->type.bits == 32 || leftExpression->type.bits == 64) &&
            leftExpression->type.bits == rightExpression->type.bits;
        if (scalarFloating && (op == "faddp" || op == "fmin" || op == "fmax" || op == "fminnm" || op == "fmaxnm" ||
            op == "min" || op == "max" || op == "minnm" || op == "maxnm")) {
            const auto right = emitAs(rightExpression, leftExpression->type);
            if (op == "faddp") return convert('(' + left + " + " + right + ')', leftExpression->type, expression->type);
            const bool maximum = op == "fmax" || op == "fmaxnm" || op == "max" || op == "maxnm";
            const bool orderedNaN = op == "fminnm" || op == "fmaxnm" || op == "minnm" || op == "maxnm";
            const auto method = maximum ? "Max" : "Min";
            if (orderedNaN) {
                return convert("global::System.Math." + std::string(method) + '(' + left + ", " + right + ')',
                    leftExpression->type, expression->type);
            }
            const auto selected = '(' + left + " != " + left + " ? " + right + " : " + right + " != " + right + " ? " + left +
                " : global::System.Math." + std::string(method) + '(' + left + ", " + right + "))";
            return convert(selected, leftExpression->type, expression->type);
        }
        if (op == "unordered") {
            const auto right = emitAs(rightExpression, leftExpression->type);
            if (!isSupportedScalar(leftExpression->type, pointerBits_) || !isSupportedScalar(rightExpression->type, pointerBits_)) {
                return unsupported(expression->type, "Unsupported unordered comparison", {left, right});
            }
            if (leftExpression->type.kind == ScalarKind::FloatingPoint) {
                return "RuntimeCalls.Unordered(" + left + ", " + right + ')';
            }
            return "RuntimeCalls.Unordered(" + convert(left, leftExpression->type, nativePointerType_) + ", " +
                   convert(right, leftExpression->type, nativePointerType_) + ')';
        }
        if (op == "&&" || op == "||") {
            return convert('(' + emitCondition(leftExpression) + ' ' + op + ' ' + emitCondition(rightExpression) + ')',
                ScalarType::boolean(), expression->type);
        }
        const auto right = emitAs(rightExpression, leftExpression->type);
        static const std::set<std::string> comparisons = {"==", "!=", "<", "<=", ">", ">="};
        if (comparisons.contains(op)) {
            const bool equality = op == "==" || op == "!=";
            const bool valid = equality
                ? isSupportedScalar(leftExpression->type, pointerBits_) && isSupportedScalar(rightExpression->type, pointerBits_)
                : isNumeric(leftExpression->type, pointerBits_) && isNumeric(rightExpression->type, pointerBits_);
            if (!valid) return unsupported(expression->type, "Unsupported comparison '" + op + "'", {left, right});
            return convert('(' + left + ' ' + op + ' ' + right + ')', ScalarType::boolean(), expression->type);
        }
        if (op == "<<" || op == ">>") {
            if (!isIntegral(leftExpression->type, pointerBits_) || leftExpression->type.kind == ScalarKind::Boolean ||
                !isSupportedScalar(expression->type, pointerBits_)) {
                return unsupported(expression->type, "Unsupported shift '" + op + "'", {left, right});
            }
            const auto count = convert(right, leftExpression->type, ScalarType::intBits(32));
            const auto shifted = "unchecked((" + typeName(leftExpression->type, pointerBits_) + ")((" + left + ") " + op + " (int)(" + count + ")))";
            return convert(shifted, leftExpression->type, expression->type);
        }
        static const std::set<std::string> arithmetic = {"+", "-", "*", "/", "%"};
        static const std::set<std::string> bitwise = {"&", "|", "^"};
        const bool isArithmetic = arithmetic.contains(op);
        const bool isBitwise = bitwise.contains(op);
        const bool validOperands = isArithmetic
            ? isNumeric(leftExpression->type, pointerBits_) && isNumeric(rightExpression->type, pointerBits_)
            : isIntegral(leftExpression->type, pointerBits_) && isIntegral(rightExpression->type, pointerBits_);
        const bool validBoolean = isBitwise && isBoolean(leftExpression->type) && isBoolean(rightExpression->type);
        if ((isArithmetic || isBitwise) && (validOperands || validBoolean) && isSupportedScalar(expression->type, pointerBits_)) {
            const auto result = "unchecked((" + typeName(leftExpression->type, pointerBits_) + ")((" + left + ") " + op + " (" + right + ")))";
            return convert(result, leftExpression->type, expression->type);
        }
        return unsupported(expression->type, "Unsupported binary operation '" + op + "'", {left, right});
    }

    std::string emitLoad(const ExpressionPtr& expression) {
        if (expression->arguments.size() != 1 || !expression->arguments[0]) {
            return unsupported(expression->type, "Malformed load expression");
        }
        const auto address = emitAs(expression->arguments[0], nativePointerType_);
        const auto type = expression->type;
        if (conflictingLoads_.contains(expression.get())) {
            return unsupported(type, "Conflicting statement/register widths for 0-bit load", {address});
        }
        if (type.bits == 0 && type.kind != ScalarKind::Pointer && type.kind != ScalarKind::Boolean) {
            return unsupported(type, "Unresolved 0-bit load without statement/register width proof", {address});
        }
        if (isVector128(type)) return "__ReadVector128(" + address + ')';
        if (!isSupportedScalar(type, pointerBits_)) {
            return unsupported(type, "Unsupported " + std::to_string(type.bits) + "-bit load", {address});
        }
        if (type.kind == ScalarKind::Boolean || type.bits == 1) return "RuntimeMemory.ReadBoolean(" + address + ')';
        if (type.kind == ScalarKind::FloatingPoint) return "RuntimeMemory.ReadF" + std::to_string(type.bits) + '(' + address + ')';
        if (type.kind == ScalarKind::Pointer) {
            const auto value = "RuntimeMemory.ReadPtr(" + address + ')';
            return convert(value, nativePointerType_, type);
        }
        const auto prefix = type.kind == ScalarKind::SignedInteger ? "ReadS" : "ReadU";
        return "RuntimeMemory." + std::string(prefix) + std::to_string(type.bits) + '(' + address + ')';
    }

    std::string emitExpression(const ExpressionPtr& expression) {
        if (!expression) return unsupported(nativePointerType_, "Missing expression");
        switch (expression->kind) {
        case Expression::Kind::Unknown:
            return unsupported(expression->type, "Unknown IR expression");
        case Expression::Kind::Constant:
            return emitConstant(expression);
        case Expression::Kind::Register: {
            const auto name = identifier(expression->name);
            const auto found = registers_.find(name);
            if (found == registers_.end()) return name;
            if (found->second.conflict) {
                return unsupported(expression->type, "Read of type-conflicting register '" + name + "'");
            }
            return convert(name, found->second.type, expression->type);
        }
        case Expression::Kind::Unary:
            return emitUnary(expression);
        case Expression::Kind::Binary:
            return emitBinary(expression);
        case Expression::Kind::Load:
            return emitLoad(expression);
        case Expression::Kind::Cast:
            if (expression->arguments.size() != 1 || !expression->arguments[0]) {
                return unsupported(expression->type, "Malformed cast expression");
            }
            return emitAs(expression->arguments[0], expression->type);
        case Expression::Kind::Select:
            if (expression->arguments.size() != 3 || !expression->arguments[0] ||
                !expression->arguments[1] || !expression->arguments[2]) {
                return unsupported(expression->type, "Malformed select expression");
            }
            return '(' + emitCondition(expression->arguments[0]) + " ? " +
                   emitAs(expression->arguments[1], expression->type) + " : " +
                   emitAs(expression->arguments[2], expression->type) + ')';
        }
        return unsupported(expression->type, "Unknown expression kind");
    }

    void emitAssignment(
        std::ostringstream& output,
        const ExpressionPtr& destination,
        const std::string& value,
        ScalarType valueType,
        int level) {
        if (!destination || destination->kind != Expression::Kind::Register) {
            output << indentation(level) << unsupported(ScalarType::intBits(32), "Assignment requires a register destination", {value}) << ";\n";
            return;
        }
        const auto name = identifier(destination->name);
        const auto found = registers_.find(name);
        if (found != registers_.end() && found->second.conflict) {
            output << indentation(level) << name << " = "
                   << unsupported(ScalarType::vectorBits(0), "Assignment to type-conflicting register '" + name + "'", {value}) << ";\n";
            return;
        }
        const auto destinationType = found == registers_.end() ? destination->type : found->second.type;
        output << indentation(level) << name << " = " << convert(value, valueType, destinationType) << ";\n";
    }

    void emitStore(std::ostringstream& output, const Statement& statement, int level) {
        if (!statement.destination || !statement.value) {
            output << indentation(level) << unsupported(ScalarType::intBits(32), "Malformed store statement") << ";\n";
            return;
        }
        const auto address = emitAs(statement.destination, nativePointerType_);
        const auto type = statement.value->type;
        const auto value = emitExpression(statement.value);
        if (isVector128(type)) {
            output << "#if IL2CPPREC_RUNTIME_VECTOR128\n";
            output << indentation(level) << "RuntimeMemory.WriteVector128(" << address << ", " << value << ");\n";
            output << "#else\n";
            output << indentation(level) << "__WriteVector128(" << address << ", " << value << ");\n";
            output << "#endif\n";
            return;
        }
        if (!isSupportedScalar(type, pointerBits_)) {
            output << indentation(level) << unsupported(ScalarType::intBits(32),
                "Unsupported " + std::to_string(type.bits) + "-bit store", {address, value}) << ";\n";
            return;
        }
        std::string method;
        ScalarType expected = type;
        if (type.kind == ScalarKind::Boolean || type.bits == 1) {
            method = "WriteBoolean";
            expected = ScalarType::boolean();
        } else if (type.kind == ScalarKind::FloatingPoint) {
            method = "WriteF" + std::to_string(type.bits);
        } else if (type.kind == ScalarKind::Pointer) {
            const auto bits = type.bits == 0 ? pointerBits_ : type.bits;
            if (bits == pointerBits_) {
                method = "WritePtr";
                expected = nativePointerType_;
            } else {
                method = "WriteU" + std::to_string(bits);
            }
        } else {
            const auto bits = type.bits == 0 ? pointerBits_ : type.bits;
            method = std::string(type.kind == ScalarKind::SignedInteger ? "WriteS" : "WriteU") + std::to_string(bits);
        }
        output << indentation(level) << "RuntimeMemory." << method << '(' << address << ", "
               << convert(value, type, expected) << ");\n";
    }

    void emitCall(std::ostringstream& output, const Statement& statement, int level) {
        if (!statement.target) {
            output << indentation(level) << unsupported(ScalarType::intBits(32), "Call without a target") << ";\n";
            return;
        }
        if (inferredClassInitCalls_.contains(statement.address)) {
            output << indentation(level) << "// Likely IL2CPP class initialization helper (guarded call).\n";
        }
        std::string invocation;
        if (isUnsupportedCallTarget(statement.target)) {
            const auto mnemonic = statement.target->name.substr(std::string("RuntimeCalls.Unsupported_").size());
            diagnose(statement.address, "Unsupported instruction '" + mnemonic + "'");
            invocation = "RuntimeCalls.Unsupported(" + stringLiteral(mnemonic) + ", " +
                emitExpression(constant(statement.address, nativePointerType_)) + ')';
        } else {
            const bool direct = statement.target->kind == Expression::Kind::Constant;
            invocation = direct ? "RuntimeCalls.InvokeDirect(" : "RuntimeCalls.InvokeIndirect(";
            invocation += emitAs(statement.target, nativePointerType_);
            for (const auto& argument : statement.arguments) {
                invocation += ", " + emitAs(argument, nativePointerType_);
            }
            invocation += ')';
        }
        if (statement.destination) {
            emitAssignment(output, statement.destination, invocation, nativePointerType_, level);
        } else {
            output << indentation(level) << invocation << ";\n";
        }
    }

    void emitReturnValue(std::ostringstream& output, const std::string& value, ScalarType type, int level) {
        if (voidReturn_) {
            output << indentation(level) << "__Discard<" << typeName(type, pointerBits_) << ">(" << value << ");\n";
            output << indentation(level) << "return;\n";
            return;
        }
        const auto converted = convert(value, type, returnType_);
        if (!options_.managedReturnReferenceType.empty()) {
            output << indentation(level) << "return RuntimeAbi.FromNativeReturn<"
                   << options_.managedReturnReferenceType << ">(unchecked(("
                   << typeName(nativePointerType_, pointerBits_) << ") ("
                   << converted << ")));\n";
        } else if (!options_.managedReturnCast.empty()) {
            output << indentation(level) << "return unchecked((" << options_.managedReturnCast
                   << ")(" << converted << "));\n";
        } else {
            output << indentation(level) << "return " << converted << ";\n";
        }
    }

    void emitReturn(std::ostringstream& output, const Statement& statement, int level) {
        if (statement.value) {
            emitReturnValue(output, emitExpression(statement.value), statement.value->type, level);
        } else if (voidReturn_) {
            output << indentation(level) << "return;\n";
        } else {
            diagnose(statement.address, "Return without a value in a value-returning function");
            output << indentation(level) << "return default("
                   << (!options_.managedReturnReferenceType.empty() ? options_.managedReturnReferenceType :
                       options_.managedReturnCast.empty() ? typeName(returnType_, pointerBits_) : options_.managedReturnCast)
                   << ");\n";
        }
    }

    void emitBranch(std::ostringstream& output, const Statement& statement, int level) {
        const bool conditional = statement.condition != nullptr;
        if (conditional) {
            output << indentation(level) << "if (" << emitCondition(statement.condition) << ")\n";
            output << indentation(level) << "{\n";
        }
        const auto bodyLevel = conditional ? level + 1 : level;
        if (statement.target && statement.target->kind == Expression::Kind::Constant &&
            blockAddresses_.contains(statement.target->constant)) {
            output << indentation(bodyLevel) << "goto label_0x" << hexAddress(statement.target->constant) << ";\n";
        } else {
            const bool direct = statement.target && statement.target->kind == Expression::Kind::Constant;
            std::string invocation = direct ? "RuntimeCalls.InvokeDirect(" : "RuntimeCalls.InvokeIndirect(";
            invocation += emitAs(statement.target, nativePointerType_) + ')';
            emitReturnValue(output, invocation, nativePointerType_, bodyLevel);
        }
        if (conditional) output << indentation(level) << "}\n";
    }

    void emitCodegenNoReturn(std::ostringstream& output, const Statement& statement, CodegenFlow flow, int level) {
        if (flow == CodegenFlow::Rethrow && catchDepth_ > 0) {
            output << indentation(level) << "throw;\n";
            return;
        }
        const auto symbol = statement.target ? statement.target->name : "no-return operation";
        diagnose(statement.address, "No-return managed exception operation requires runtime exception recovery: " + symbol);
        output << indentation(level) << unsupported(ScalarType::intBits(32),
            "Unhandled managed no-return operation '" + symbol + "'") << ";\n";
    }

    bool emitStatement(std::ostringstream& output, const Statement& statement, int level) {
        currentAddress_ = statement.address;
        const auto flow = codegenFlow(statement);
        if (isNoReturn(flow)) {
            emitCodegenNoReturn(output, statement, flow, level);
            return true;
        }
        if (flow != CodegenFlow::None) {
            const auto symbol = statement.target ? statement.target->name : "exception operation";
            diagnose(statement.address, "Native exception macro requires structured exception recovery: " + symbol);
            output << indentation(level) << unsupported(ScalarType::intBits(32),
                "Unhandled native exception macro '" + symbol + "'") << ";\n";
            return true;
        }
        switch (statement.kind) {
        case Statement::Kind::Assign:
            if (!statement.value) {
                output << indentation(level) << unsupported(ScalarType::intBits(32), "Assignment without a value") << ";\n";
            } else if (statement.destination && statement.destination->kind == Expression::Kind::Register &&
                statement.value->kind == Expression::Kind::Load && isVector128(statement.destination->type) &&
                isVector128(statement.value->type) && statement.value->arguments.size() == 1 && statement.value->arguments[0]) {
                const auto found = registers_.find(identifier(statement.destination->name));
                if (found != registers_.end() && !found->second.conflict) {
                    const auto address = emitAs(statement.value->arguments[0], nativePointerType_);
                    const auto name = identifier(statement.destination->name);
                    output << "#if IL2CPPREC_RUNTIME_VECTOR128\n";
                    output << indentation(level) << name << " = RuntimeMemory.ReadVector128(" << address << ");\n";
                    output << "#else\n";
                    output << indentation(level) << name << " = __ReadVector128(" << address << ");\n";
                    output << "#endif\n";
                } else {
                    emitAssignment(output, statement.destination, emitExpression(statement.value), statement.value->type, level);
                }
            } else {
                emitAssignment(output, statement.destination, emitExpression(statement.value), statement.value->type, level);
            }
            break;
        case Statement::Kind::Store:
            emitStore(output, statement, level);
            break;
        case Statement::Kind::Call:
            emitCall(output, statement, level);
            break;
        case Statement::Kind::Branch:
        case Statement::Kind::ConditionalBranch:
            emitBranch(output, statement, level);
            break;
        case Statement::Kind::Return:
            emitReturn(output, statement, level);
            return true;
        }
        return statement.kind == Statement::Kind::Branch && !statement.condition;
    }

    void statementPlaceholder(Statement& statement, const flow::StructuredNode& node) {
        statement.kind = Statement::Kind::Branch;
        statement.address = node.address;
        statement.target = node.targetExpression ? node.targetExpression : constant(node.target, nativePointerType_);
    }

    bool emitNode(std::ostringstream& output, const flow::StructuredNode& node, int level) {
        if (node.address != 0) currentAddress_ = node.address;
        switch (node.kind) {
        case flow::StructuredKind::Empty:
            return false;
        case flow::StructuredKind::Sequence:
            for (const auto& child : node.children) {
                if (child) emitNode(output, *child, level);
            }
            return false;
        case flow::StructuredKind::Block:
            if (node.isLabel && referencedAddresses_.contains(node.address)) {
                output << indentation(level) << "label_0x" << hexAddress(node.address) << ":\n";
                output << indentation(level) << ";\n";
            }
            for (const auto& statement : node.statements) {
                if (emitStatement(output, statement, level)) return true;
            }
            return false;
        case flow::StructuredKind::IfElse: {
            output << indentation(level) << "if (" << emitCondition(node.condition) << ")\n";
            output << indentation(level) << "{\n";
            const bool thenTerminates = node.thenBranch && emitNode(output, *node.thenBranch, level + 1);
            output << indentation(level) << "}\n";
            bool elseTerminates = false;
            if (node.elseBranch && node.elseBranch->kind != flow::StructuredKind::Empty) {
                output << indentation(level) << "else\n";
                output << indentation(level) << "{\n";
                elseTerminates = emitNode(output, *node.elseBranch, level + 1);
                output << indentation(level) << "}\n";
            }
            return thenTerminates && elseTerminates;
        }
        case flow::StructuredKind::While:
            output << indentation(level) << "while (" << emitCondition(node.condition) << ")\n";
            output << indentation(level) << "{\n";
            if (node.body) emitNode(output, *node.body, level + 1);
            output << indentation(level) << "}\n";
            return false;
        case flow::StructuredKind::DoWhile:
            output << indentation(level) << "do\n";
            output << indentation(level) << "{\n";
            if (node.body) emitNode(output, *node.body, level + 1);
            output << indentation(level) << "} while (" << emitCondition(node.condition) << ");\n";
            return false;
        case flow::StructuredKind::Goto:
            if (blockAddresses_.contains(node.target)) {
                output << indentation(level) << "goto label_0x" << hexAddress(node.target) << ";\n";
            } else {
                Statement branch;
                statementPlaceholder(branch, node);
                emitStatement(output, branch, level);
            }
            return true;
        case flow::StructuredKind::Return:
            emitStatement(output, node.returnStatement, level);
            return true;
        }
        return false;
    }

    void emitDeclarations(std::ostringstream& output, int level, bool includeNativeParameters,
                          const std::set<std::string>* externalNativeRegisters = nullptr) {
        std::set<std::string> parameters;
        if (!includeNativeParameters && !externalNativeRegisters) {
            for (const auto& name : parameterRegisters()) parameters.insert(identifier(name));
        }
        std::set<std::string> nativeParameters;
        if (externalNativeRegisters) {
            for (const auto& name : parameterRegisters()) nativeParameters.insert(identifier(name));
            for (const auto& name : *externalNativeRegisters) parameters.insert(identifier(name));
        }
        for (const auto& [name, info] : registers_) {
            if (parameters.contains(name)) continue;
            const auto type = info.conflict ? "__UnsupportedValue" : typeName(info.type, pointerBits_);
            output << indentation(level) << type << ' ' << name;
            if (externalNativeRegisters && nativeParameters.contains(name)) {
                output << ";\n";
            } else {
                output << " = default(" << type << ");\n";
            }
        }
    }

    bool skipExceptionStatement(const ExceptionPart& part, const Statement& statement) const {
        const auto flow = codegenFlow(statement);
        if (flow == CodegenFlow::Leave || flow == CodegenFlow::EndFinally) return true;
        if (isExceptionAssignment(statement, part.kind)) return true;
        if (isBranch(statement) && !statement.condition) {
            const auto [direct, target] = directTarget(statement);
            return direct && part.exits.contains(target);
        }
        return false;
    }

    void emitExceptionPart(std::ostringstream& output, ExceptionPart& part, int level) {
        for (const auto& block : part.blocks) {
            if (part.labels.contains(block.address)) {
                output << indentation(level) << "label_0x" << hexAddress(block.address) << ":\n";
                output << indentation(level) << ";\n";
            }
            for (const auto& statement : block.statements) {
                if (skipExceptionStatement(part, statement)) continue;
                if (emitStatement(output, statement, level)) break;
            }
        }
    }

    void emitExceptionPlan(std::ostringstream& output, int level) {
        emitExceptionPart(output, exceptionPlan_.prefix, level);
        output << indentation(level) << "try\n";
        output << indentation(level) << "{\n";
        emitExceptionPart(output, exceptionPlan_.tryBody, level + 1);
        output << indentation(level) << "}\n";
        if (exceptionPlan_.region.kind == ExceptionRegionKind::Catch) {
            output << indentation(level) << "catch (__RecoveryUnsupportedException)\n";
            output << indentation(level) << "{\n";
            output << indentation(level + 1) << "throw;\n";
            output << indentation(level) << "}\n";
            output << indentation(level) << "catch\n";
            output << indentation(level) << "{\n";
            ++catchDepth_;
            emitExceptionPart(output, exceptionPlan_.handler, level + 1);
            --catchDepth_;
            output << indentation(level) << "}\n";
        } else {
            output << indentation(level) << "finally\n";
            output << indentation(level) << "{\n";
            emitExceptionPart(output, exceptionPlan_.handler, level + 1);
            output << indentation(level) << "}\n";
        }
        emitExceptionPart(output, exceptionPlan_.suffix, level);
    }

    void emitStructured(std::ostringstream& output, int level) {
        if (!function_.exceptionRegions.empty() && exceptionPlan_.supported) {
            emitExceptionPlan(output, level);
            return;
        }
        if (!function_.exceptionRegions.empty()) {
            output << indentation(level) << unsupported(ScalarType::intBits(32),
                "Managed exception flow is partial; native cleanup is not a managed try/catch/finally replacement") << ";\n";
        }
        auto structured = flow::Structurer{}.structure(function_);
        if (structured.root) emitNode(output, *structured.root, level);
    }

    void emitFinalReturn(std::ostringstream& output, int level) {
        if (voidReturn_) {
            output << indentation(level) << "return;\n";
        } else {
            output << indentation(level) << "return default("
                   << (!options_.managedReturnReferenceType.empty() ? options_.managedReturnReferenceType :
                       options_.managedReturnCast.empty() ? typeName(returnType_, pointerBits_) : options_.managedReturnCast)
                   << ");\n";
        }
    }

    std::string emitVectorSupport() const {
        const auto nativeType = pointerBits_ == 64 ? "ulong" : "uint";
        std::ostringstream output;
        output << "    public struct RuntimeVector128\n"
               << "    {\n"
               << "        public const int Size = 16;\n"
               << "        public ulong Low;\n"
               << "        public ulong High;\n\n"
               << "        public RuntimeVector128(ulong low, ulong high)\n"
               << "        {\n"
               << "            Low = low;\n"
               << "            High = high;\n"
               << "        }\n\n"
               << "        public static RuntimeVector128 Zero => default;\n\n"
               << "        private static int LaneSize<T>()\n"
               << "        {\n"
               << "            var type = typeof(T);\n"
               << "            if (type == typeof(bool) || type == typeof(byte) || type == typeof(sbyte)) return 1;\n"
               << "            if (type == typeof(short) || type == typeof(ushort)) return 2;\n"
               << "            if (type == typeof(int) || type == typeof(uint) || type == typeof(float)) return 4;\n"
               << "            if (type == typeof(long) || type == typeof(ulong) || type == typeof(double)) return 8;\n"
               << "            throw new global::System.NotSupportedException();\n"
               << "        }\n\n"
               << "        private static int LaneCount<T>() => Size / LaneSize<T>();\n\n"
               << "        private static ulong LaneBits<T>(T lane)\n"
               << "        {\n"
               << "            object value = lane;\n"
               << "            var type = typeof(T);\n"
               << "            if (type == typeof(bool)) return (bool)value ? 1UL : 0UL;\n"
               << "            if (type == typeof(byte)) return (byte)value;\n"
               << "            if (type == typeof(sbyte)) return unchecked((byte)(sbyte)value);\n"
               << "            if (type == typeof(short)) return unchecked((ushort)(short)value);\n"
               << "            if (type == typeof(ushort)) return (ushort)value;\n"
               << "            if (type == typeof(int)) return unchecked((uint)(int)value);\n"
               << "            if (type == typeof(uint)) return (uint)value;\n"
               << "            if (type == typeof(long)) return unchecked((ulong)(long)value);\n"
               << "            if (type == typeof(ulong)) return (ulong)value;\n"
               << "            if (type == typeof(float)) return global::System.BitConverter.ToUInt32(global::System.BitConverter.GetBytes((float)value), 0);\n"
               << "            if (type == typeof(double)) return global::System.BitConverter.ToUInt64(global::System.BitConverter.GetBytes((double)value), 0);\n"
               << "            throw new global::System.NotSupportedException();\n"
               << "        }\n\n"
               << "        private static T LaneValue<T>(ulong bits)\n"
               << "        {\n"
               << "            object result;\n"
               << "            var type = typeof(T);\n"
               << "            if (type == typeof(bool)) result = (bits & 1) != 0;\n"
               << "            else if (type == typeof(byte)) result = (byte)bits;\n"
               << "            else if (type == typeof(sbyte)) result = unchecked((sbyte)bits);\n"
               << "            else if (type == typeof(short)) result = unchecked((short)bits);\n"
               << "            else if (type == typeof(ushort)) result = (ushort)bits;\n"
               << "            else if (type == typeof(int)) result = unchecked((int)bits);\n"
               << "            else if (type == typeof(uint)) result = (uint)bits;\n"
               << "            else if (type == typeof(long)) result = unchecked((long)bits);\n"
               << "            else if (type == typeof(ulong)) result = bits;\n"
               << "            else if (type == typeof(float)) result = global::System.BitConverter.ToSingle(global::System.BitConverter.GetBytes((uint)bits), 0);\n"
               << "            else if (type == typeof(double)) result = global::System.BitConverter.Int64BitsToDouble(unchecked((long)bits));\n"
               << "            else throw new global::System.NotSupportedException();\n"
               << "            return (T)result;\n"
               << "        }\n\n"
               << "        public T GetLane<T>(int index)\n"
               << "        {\n"
               << "            int size = LaneSize<T>();\n"
               << "            int count = LaneCount<T>();\n"
               << "            if ((uint)index >= (uint)count) throw new global::System.ArgumentOutOfRangeException(nameof(index));\n"
               << "            int offset = index * size;\n"
               << "            int shift = (offset % 8) * 8;\n"
               << "            ulong source = offset < 8 ? Low : High;\n"
               << "            ulong mask = size == 8 ? ~0UL : (1UL << (size * 8)) - 1;\n"
               << "            return LaneValue<T>((source >> shift) & mask);\n"
               << "        }\n\n"
               << "        public RuntimeVector128 WithLane<T>(int index, T lane)\n"
               << "        {\n"
               << "            int size = LaneSize<T>();\n"
               << "            int count = LaneCount<T>();\n"
               << "            if ((uint)index >= (uint)count) throw new global::System.ArgumentOutOfRangeException(nameof(index));\n"
               << "            int offset = index * size;\n"
               << "            int shift = (offset % 8) * 8;\n"
               << "            ulong mask = size == 8 ? ~0UL : (1UL << (size * 8)) - 1;\n"
               << "            ulong bits = LaneBits(lane) & mask;\n"
               << "            RuntimeVector128 result = this;\n"
               << "            if (offset < 8) result.Low = (result.Low & ~(mask << shift)) | (bits << shift);\n"
               << "            else result.High = (result.High & ~(mask << shift)) | (bits << shift);\n"
               << "            return result;\n"
               << "        }\n\n"
               << "        public static RuntimeVector128 Duplicate<T>(T lane)\n"
               << "        {\n"
               << "            RuntimeVector128 result = default;\n"
               << "            int count = LaneCount<T>();\n"
               << "            for (int i = 0; i < count; ++i) result = result.WithLane(i, lane);\n"
               << "            return result;\n"
               << "        }\n\n"
               << "        public uint GetUInt32(int index) => GetLane<uint>(index);\n"
               << "        public RuntimeVector128 WithUInt32(int index, uint lane) => WithLane(index, lane);\n"
               << "        public ulong GetUInt64(int index) => GetLane<ulong>(index);\n"
               << "        public RuntimeVector128 WithUInt64(int index, ulong lane) => WithLane(index, lane);\n"
               << "        public float GetSingle(int index) => GetLane<float>(index);\n"
               << "        public RuntimeVector128 WithSingle(int index, float lane) => WithLane(index, lane);\n"
               << "        public double GetDouble(int index) => GetLane<double>(index);\n"
               << "        public RuntimeVector128 WithDouble(int index, double lane) => WithLane(index, lane);\n\n"
               << "        public static RuntimeVector128 operator &(RuntimeVector128 left, RuntimeVector128 right) =>\n"
               << "            new RuntimeVector128(left.Low & right.Low, left.High & right.High);\n"
               << "        public static RuntimeVector128 operator |(RuntimeVector128 left, RuntimeVector128 right) =>\n"
               << "            new RuntimeVector128(left.Low | right.Low, left.High | right.High);\n"
               << "        public static RuntimeVector128 operator ^(RuntimeVector128 left, RuntimeVector128 right) =>\n"
               << "            new RuntimeVector128(left.Low ^ right.Low, left.High ^ right.High);\n"
               << "        public static RuntimeVector128 operator ~(RuntimeVector128 value) =>\n"
               << "            new RuntimeVector128(~value.Low, ~value.High);\n"
               << "        public static bool operator ==(RuntimeVector128 left, RuntimeVector128 right) =>\n"
               << "            left.Low == right.Low && left.High == right.High;\n"
               << "        public static bool operator !=(RuntimeVector128 left, RuntimeVector128 right) => !(left == right);\n\n"
               << "        public RuntimeVector128 ShiftLeftLogical(int count)\n"
               << "        {\n"
               << "            if (count < 0) throw new global::System.ArgumentOutOfRangeException(nameof(count));\n"
               << "            if (count >= 128) return default;\n"
               << "            if (count >= 64) return new RuntimeVector128(0, Low << (count - 64));\n"
               << "            return new RuntimeVector128((Low << count) | (High >> (64 - count)), High << count);\n"
               << "        }\n\n"
               << "        public RuntimeVector128 ShiftRightLogical(int count)\n"
               << "        {\n"
               << "            if (count < 0) throw new global::System.ArgumentOutOfRangeException(nameof(count));\n"
               << "            if (count >= 128) return default;\n"
               << "            if (count >= 64) return new RuntimeVector128(High >> (count - 64), 0);\n"
               << "            return new RuntimeVector128(Low >> count, (High >> count) | (Low << (64 - count)));\n"
               << "        }\n\n"
               << "        public bool Equals(RuntimeVector128 other) => this == other;\n"
               << "        public override bool Equals(object other) => other is RuntimeVector128 && this == (RuntimeVector128)other;\n"
               << "        public override int GetHashCode() => Low.GetHashCode() ^ High.GetHashCode();\n"
               << "    }\n\n"
               << "    private static RuntimeVector128 __UnsupportedPackedUnary(string operation, RuntimeVector128 value)\n"
               << "    {\n"
               << "        throw new global::System.NotSupportedException(operation);\n"
               << "    }\n\n"
               << "    private static RuntimeVector128 __UnsupportedPackedBinary(string operation, RuntimeVector128 left, RuntimeVector128 right)\n"
               << "    {\n"
               << "        throw new global::System.NotSupportedException(operation);\n"
               << "    }\n\n"
               << "    private static bool __UnsupportedPackedCompare(string operation, RuntimeVector128 left, RuntimeVector128 right)\n"
               << "    {\n"
               << "        throw new global::System.NotSupportedException(operation);\n"
               << "    }\n\n"
               << "    private static RuntimeVector128 __ReadVector128(" << nativeType << " address)\n"
               << "    {\n"
               << "#if IL2CPPREC_RUNTIME_VECTOR128\n"
               << "        return RuntimeMemory.ReadVector128(address);\n"
               << "#else\n"
               << "        return new RuntimeVector128(RuntimeMemory.ReadU64(address), RuntimeMemory.ReadU64(address + 8));\n"
               << "#endif\n"
               << "    }\n\n"
               << "    private static void __WriteVector128(" << nativeType << " address, RuntimeVector128 value)\n"
               << "    {\n"
               << "#if IL2CPPREC_RUNTIME_VECTOR128\n"
               << "        RuntimeMemory.WriteVector128(address, value);\n"
               << "#else\n"
               << "        RuntimeMemory.WriteU64(address, value.Low);\n"
               << "        RuntimeMemory.WriteU64(address + 8, value.High);\n"
               << "#endif\n"
               << "    }\n\n";
        return output.str();
    }

    std::vector<CSharpBodyEmissionResult::SupportFragment> emitSupportFragments() const {
        std::vector<CSharpBodyEmissionResult::SupportFragment> fragments;
        if (usesRuntimeVector128_) fragments.push_back({"vector128", emitVectorSupport()});
        if (usesRuntimeVector128_ && !partial_ && !voidReturn_ && function_.exceptionRegions.empty()) return fragments;
        fragments.push_back({"unsupported-value", "    public readonly struct __UnsupportedValue\n"
                                                  "    {\n"
                                                  "    }\n\n"});
        if (!usesRuntimeVector128_) {
            fragments.push_back({"unsupported-vector", "    public readonly struct __UnsupportedVector128\n"
                                                        "    {\n"
                                                        "        public const int Bits = 128;\n"
                                                        "    }\n\n"});
        }
        fragments.push_back({"unsupported-core",
            "    private sealed class __RecoveryUnsupportedException : global::System.Exception\n"
            "    {\n"
            "        public __RecoveryUnsupportedException(string message) : base(message)\n"
            "        {\n"
            "        }\n"
            "    }\n\n"
            "    private static T __Unsupported<T>(string operation, params object[] arguments)\n"
            "    {\n"
            "        throw new __RecoveryUnsupportedException(operation);\n"
            "    }\n\n"
            "    private static void __Discard<T>(T value)\n"
            "    {\n"
            "    }\n\n"});
        return fragments;
    }

    std::string emitSupport() const {
        std::string result;
        for (const auto& fragment : emitSupportFragments()) result += fragment.source;
        return result;
    }
};

} // namespace

ExpressionPtr constant(uint64_t value, ScalarType type) {
    auto result = makeExpression(Expression::Kind::Constant, type, "", {});
    result->constant = value;
    return result;
}

ExpressionPtr reg(std::string name, ScalarType type) {
    auto result = makeExpression(Expression::Kind::Register, type, "", {});
    result->name = std::move(name);
    return result;
}

ExpressionPtr unary(std::string op, ExpressionPtr value, ScalarType type) {
    return makeExpression(Expression::Kind::Unary, type, std::move(op), {std::move(value)});
}

ExpressionPtr binary(std::string op, ExpressionPtr left, ExpressionPtr right, ScalarType type) {
    return makeExpression(Expression::Kind::Binary, type, std::move(op), {std::move(left), std::move(right)});
}

ExpressionPtr load(ExpressionPtr address, ScalarType type) {
    return makeExpression(Expression::Kind::Load, type, "", {std::move(address)});
}

ExpressionPtr cast(ExpressionPtr value, ScalarType type) {
    return makeExpression(Expression::Kind::Cast, type, "", {std::move(value)});
}

ExpressionPtr select(ExpressionPtr condition, ExpressionPtr ifTrue, ExpressionPtr ifFalse, ScalarType type) {
    return makeExpression(Expression::Kind::Select, type, "", {std::move(condition), std::move(ifTrue), std::move(ifFalse)});
}

ExpressionPtr unknown(ScalarType type) {
    return makeExpression(Expression::Kind::Unknown, type, "", {});
}

std::string RecoveredFunction::toCSharp() const {
    return emitCSharp().source;
}

CSharpEmissionResult RecoveredFunction::emitCSharp() const {
    return CSharpEmitter(*this).emit();
}

CSharpBodyEmissionResult RecoveredFunction::emitCSharpBody(CSharpBodyOptions options) const {
    return CSharpEmitter(*this, options).emitBody();
}

} // namespace il2cpprec
