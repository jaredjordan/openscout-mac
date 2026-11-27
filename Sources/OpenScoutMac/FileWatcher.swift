#if canImport(CoreServices)
import CoreServices
import Foundation

/// Watches folders with FSEvents. Used for startup item folders and Downloads.
/// FSEvents needs no special entitlement, which is why version 1 can watch these without
/// Apple's Endpoint Security approval.
public final class FileWatcher: @unchecked Sendable {
    public typealias Handler = @Sendable ([String]) -> Void

    private var stream: FSEventStreamRef?
    private let paths: [String]
    private let handler: Handler
    private let queue = DispatchQueue(label: "openscout.filewatcher")

    public init(paths: [String], handler: @escaping Handler) {
        self.paths = paths
        self.handler = handler
    }

    deinit { stop() }

    /// - Parameter latency: seconds FSEvents waits to batch changes. 1 second keeps
    ///   startup item alerts well under the 10 second target.
    public func start(latency: CFTimeInterval = 1.0) {
        guard stream == nil else { return }
        var context = FSEventStreamContext(
            version: 0,
            info: Unmanaged.passUnretained(self).toOpaque(),
            retain: nil, release: nil, copyDescription: nil)
        let callback: FSEventStreamCallback = { _, info, count, eventPaths, _, _ in
            guard let info else { return }
            let watcher = Unmanaged<FileWatcher>.fromOpaque(info).takeUnretainedValue()
            let cfArray = Unmanaged<CFArray>.fromOpaque(eventPaths).takeUnretainedValue()
            let changed = (cfArray as? [String]) ?? []
            if !changed.isEmpty && count > 0 { watcher.handler(changed) }
        }
        let flags = UInt32(kFSEventStreamCreateFlagUseCFTypes | kFSEventStreamCreateFlagFileEvents
                           | kFSEventStreamCreateFlagNoDefer)
        guard let created = FSEventStreamCreate(kCFAllocatorDefault, callback, &context,
                                                paths as CFArray,
                                                FSEventStreamEventId(kFSEventStreamEventIdSinceNow),
                                                latency, flags) else { return }
        stream = created
        FSEventStreamSetDispatchQueue(created, queue)
        FSEventStreamStart(created)
    }

    public func stop() {
        guard let stream else { return }
        FSEventStreamStop(stream)
        FSEventStreamInvalidate(stream)
        FSEventStreamRelease(stream)
        self.stream = nil
    }
}
#endif
