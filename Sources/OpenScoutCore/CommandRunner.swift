import Foundation

public struct CommandResult: Equatable, Sendable {
    public var exitCode: Int32
    public var stdout: String
    public var stderr: String
    public var timedOut: Bool

    public init(exitCode: Int32, stdout: String, stderr: String = "", timedOut: Bool = false) {
        self.exitCode = exitCode
        self.stdout = stdout
        self.stderr = stderr
        self.timedOut = timedOut
    }
}

/// Runs external tools (clamscan, yara, codesign, spctl). A protocol so tests never touch the system.
public protocol CommandRunner: Sendable {
    func run(_ executable: String, _ arguments: [String], timeout: TimeInterval) -> CommandResult
}

public enum CommandError: Error, Equatable {
    case notExecutable(String)
}

/// Runs a real process. Arguments are passed as an array, never through a shell,
/// so file names can't inject commands.
public struct ProcessCommandRunner: CommandRunner {
    /// Hard cap on captured output, so a misbehaving tool can't exhaust memory.
    public static let maxOutputBytes = 4 * 1024 * 1024

    public init() {}

    public func run(_ executable: String, _ arguments: [String], timeout: TimeInterval) -> CommandResult {
        guard FileManager.default.isExecutableFile(atPath: executable) else {
            return CommandResult(exitCode: 127, stdout: "", stderr: "not executable: \(executable)")
        }
        let process = Process()
        process.executableURL = URL(fileURLWithPath: executable)
        process.arguments = arguments
        let out = Pipe()
        let err = Pipe()
        process.standardOutput = out
        process.standardError = err

        let outCollector = OutputCollector(limit: Self.maxOutputBytes)
        let errCollector = OutputCollector(limit: Self.maxOutputBytes)
        out.fileHandleForReading.readabilityHandler = { outCollector.append($0.availableData) }
        err.fileHandleForReading.readabilityHandler = { errCollector.append($0.availableData) }

        let finished = DispatchSemaphore(value: 0)
        process.terminationHandler = { _ in finished.signal() }
        do {
            try process.run()
        } catch {
            return CommandResult(exitCode: 126, stdout: "", stderr: "\(error)")
        }
        var timedOut = false
        if finished.wait(timeout: .now() + timeout) == .timedOut {
            timedOut = true
            process.terminate()
            _ = finished.wait(timeout: .now() + 5)
        }
        out.fileHandleForReading.readabilityHandler = nil
        err.fileHandleForReading.readabilityHandler = nil
        outCollector.append(out.fileHandleForReading.readDataToEndOfFile())
        errCollector.append(err.fileHandleForReading.readDataToEndOfFile())
        return CommandResult(exitCode: timedOut ? -1 : process.terminationStatus,
                             stdout: outCollector.string,
                             stderr: errCollector.string,
                             timedOut: timedOut)
    }
}

final class OutputCollector: @unchecked Sendable {
    private let lock = NSLock()
    private var data = Data()
    private let limit: Int

    init(limit: Int) { self.limit = limit }

    func append(_ chunk: Data) {
        guard !chunk.isEmpty else { return }
        lock.lock()
        defer { lock.unlock() }
        let room = limit - data.count
        if room > 0 { data.append(chunk.prefix(room)) }
    }

    var string: String {
        lock.lock()
        defer { lock.unlock() }
        return String(decoding: data, as: UTF8.self)
    }
}
