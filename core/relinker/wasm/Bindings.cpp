#include <relinker/pipeline/Conversion.hpp>
#include <io/NativePath.hpp>
#include <io/BufferUtils.hpp>
#include <WasmSourceStamp.hpp>
#include <emscripten/bind.h>
#include <algorithm>
#include <stdexcept>
#include <set>

namespace {

class BrowserProgress final : public Domain::IProgress {
public:
    explicit BrowserProgress(emscripten::val callback) : callback(std::move(callback)) {}

    void Report(const Domain::ProgressEvent& event) override {
        auto report = emscripten::val::object();
        report.set("stage", static_cast<unsigned>(event.Stage));
        report.set("input", event.Input);
        report.set("completed", static_cast<double>(event.Completed));
        report.set("total", static_cast<double>(event.Total));
        callback(report);
    }

    void Message(std::string_view message) override {
        auto report = emscripten::val::object();
        report.set("message", std::string(message));
        callback(report);
    }

private:
    emscripten::val callback;
};

std::vector<std::uint8_t> ReadBytes(const emscripten::val& bytes, std::size_t& remaining) {
    if (!bytes.instanceof(emscripten::val::global("Uint8Array"))) throw std::invalid_argument("Expected Uint8Array input");
    const auto length = bytes["length"].as<std::size_t>();
    if (length > remaining) throw std::invalid_argument("Executable, modules and icon exceed the 256 MiB conversion limit");
    remaining -= length;
    std::vector<std::uint8_t> result(length);
    if (length != 0) emscripten::val(emscripten::typed_memory_view(length, result.data())).call<void>("set", bytes);
    return result;
}

emscripten::val CopyBytes(const std::vector<std::uint8_t>& bytes) {
    return emscripten::val::global("Uint8Array").new_(emscripten::val(emscripten::typed_memory_view(bytes.size(), bytes.data())));
}

emscripten::val ImportReport(const Relinker::ConversionOutput& output, const std::string& executable) {
    auto report = emscripten::val::object();
    report.set("converter_commit", std::string(ANYPS5_WASM_SOURCE_COMMIT));
    if (ANYPS5_WASM_SOURCE_DIRTY < 0) report.set("converter_dirty", emscripten::val::null());
    else report.set("converter_dirty", ANYPS5_WASM_SOURCE_DIRTY != 0);
    const auto& dynamic = output.Analysis.DynamicSection;
    std::set<std::uint64_t> guestTargets;
    for (const auto* table : {&dynamic.RelaData, &dynamic.RelaPltData}) {
        for (std::size_t offset = 0; offset + 24 <= table->size(); offset += 24) {
            const auto symbol = Io::ReadU64(*table, offset + 8) >> 32;
            if (symbol >= dynamic.DynSymData.size() / 24) continue;
            const auto nameOffset = Io::ReadU32(dynamic.DynSymData, symbol * 24);
            if (nameOffset >= dynamic.DynStrData.size()) throw std::runtime_error("Invalid import symbol name offset");
            const auto start = dynamic.DynStrData.begin() + nameOffset;
            const auto end = std::find(start, dynamic.DynStrData.end(), 0);
            if (end == dynamic.DynStrData.end()) throw std::runtime_error("Unterminated import symbol name");
            const auto target = Io::ReadU64(*table, offset);
            bool guest = std::string(start, end).ends_with(Relinker::GuestSymbolSuffix);
            const auto moduleName = dynamic.ImportModules.find(target);
            if (moduleName != dynamic.ImportModules.end()) for (const auto& module : dynamic.GuestModules) {
                guest = guest || std::find(module.Names.begin(), module.Names.end(), moduleName->second) != module.Names.end();
            }
            if (guest) guestTargets.insert(target);
        }
    }
    auto imports = emscripten::val::array();
    const auto append = [&](const auto& entries, const std::string& input, bool executableImports) {
        for (const auto& entry : entries) {
            auto record = emscripten::val::object();
            record.set("nid", entry.Nid);
            record.set("library", entry.Library);
            record.set("input", input);
            record.set("guest", executableImports && guestTargets.contains(entry.TargetOffset));
            imports.call<void>("push", record);
        }
    };
    append(output.Analysis.RegistryEntries, executable, true);
    for (const auto& module : output.Modules) append(module.Imports, Io::Utf8Path(module.SourcePath.lexically_relative("/input")), false);
    report.set("imports", imports);
    auto modules = emscripten::val::array();
    for (const auto& module : dynamic.GuestModules) {
        auto record = emscripten::val::object();
        record.set("path", module.Path);
        auto names = emscripten::val::array();
        for (const auto& name : module.Names) names.call<void>("push", name);
        record.set("names", names);
        modules.call<void>("push", record);
    }
    report.set("modules", modules);
    auto needed = emscripten::val::array();
    for (std::size_t offset = 0; offset + 16 <= dynamic.DynamicSegmentData.size(); offset += 16) {
        const auto tag = Io::ReadU64(dynamic.DynamicSegmentData, offset);
        if (tag == 0) break;
        if (tag != 1) continue;
        const auto index = Io::ReadU64(dynamic.DynamicSegmentData, offset + 8);
        if (index >= dynamic.DynStrData.size()) throw std::runtime_error("Invalid dependency string offset");
        const auto start = dynamic.DynStrData.begin() + index;
        const auto end = std::find(start, dynamic.DynStrData.end(), 0);
        if (end == dynamic.DynStrData.end()) throw std::runtime_error("Unterminated dependency string");
        needed.call<void>("push", std::string(start, end));
    }
    report.set("needed", needed);
    return report;
}

emscripten::val Convert(const emscripten::val& request, const emscripten::val& callback) {
    auto result = emscripten::val::object();
    try {
        const auto target = request["target"].as<std::string>();
        if (target != "windows" && target != "linux") throw std::invalid_argument("Unknown target system");
        const auto name = request["name"].as<std::string>();
        if (name.empty() || name.find_first_of("/\\") != std::string::npos || name == "." || name == "..") throw std::invalid_argument("Invalid executable name");
        std::size_t remaining = 256 * 1024 * 1024;
        Relinker::ConversionInput input;
        input.InputPath = Io::NativePath("/input/" + name);
        input.OutputPath = Io::NativePath("/output/" + request["outputName"].as<std::string>());
        if (input.OutputPath.parent_path() != "/output") throw std::invalid_argument("Invalid output name");
        input.ModuleRoot = "/input";
        input.Executable = ReadBytes(request["executable"], remaining);
        const auto modules = request["modules"];
        const auto count = modules["length"].as<unsigned>();
        if (count > 4096) throw std::invalid_argument("Too many modules");
        for (unsigned index = 0; index < count; ++index) {
            const auto module = modules[index];
            const auto path = Io::NativePath(module["name"].as<std::string>());
            if (path.is_absolute() || path.lexically_normal() != path || path.begin() == path.end() || *path.begin() != "sce_module") throw std::invalid_argument("Invalid module path");
            input.Modules.push_back({Io::NativePath("/input") / path, ReadBytes(module["bytes"], remaining)});
        }
        input.RuntimeDirectories.push_back("/input/sce_module");
        if (!request["icon"].isNull()) input.Icon = ReadBytes(request["icon"], remaining);
        Relinker::ConversionOptions options;
        options.Target = target == "windows" ? Relinker::TargetSystem::Windows : Relinker::TargetSystem::Linux;
        options.WindowsGui = false;
        options.WindowsDiagnostics = target == "windows";
        options.ToIntel = request["toIntel"].as<bool>();
        BrowserProgress progress(callback);
        auto output = Relinker::Conversion(progress).Convert(std::move(input), options);
        result.set("audit", ImportReport(output, name));
        result.set("executable", CopyBytes(output.Executable));
        result.set("diagnostics", output.WindowsDiagnostics);
        auto artifacts = emscripten::val::array();
        for (const auto& module : output.Modules) {
            auto artifact = emscripten::val::object();
            artifact.set("name", Io::Utf8Path(module.Path.lexically_relative("/output")));
            artifact.set("bytes", CopyBytes(module.Bytes));
            artifacts.call<void>("push", artifact);
        }
        result.set("modules", artifacts);
        result.set("ok", true);
    } catch (const std::exception& error) {
        result.set("ok", false);
        result.set("error", std::string(error.what()));
    }
    return result;
}

}

EMSCRIPTEN_BINDINGS(relinker) {
    emscripten::function("Convert", &Convert);
}
