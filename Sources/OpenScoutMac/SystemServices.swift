#if os(macOS)
import AppKit
import Foundation
import IOKit.ps
import OpenScoutCore
import ServiceManagement
import UserNotifications

/// Registers the background helper as a login item through ServiceManagement.
/// macOS asks the user to allow it in Login Items, so first run explains that before it happens.
public enum HelperRegistration {
    public static var service: SMAppService {
        SMAppService.agent(plistName: HelperIdentity.launchAgentPlistName)
    }

    public static var status: SMAppService.Status { service.status }

    public static func register() throws { try service.register() }

    public static func unregister() throws { try service.unregister() }

    public static func openLoginItemsSettings() { SMAppService.openSystemSettingsLoginItems() }
}

/// Reads the device conditions the scan planner needs.
public enum SystemConditions {
    public static func current() -> DeviceConditions {
        DeviceConditions(onACPower: onACPower(),
                         lowPowerMode: ProcessInfo.processInfo.isLowPowerModeEnabled,
                         userIdleSeconds: idleSeconds(),
                         screenSharing: false)
    }

    static func onACPower() -> Bool {
        guard let info = IOPSCopyPowerSourcesInfo()?.takeRetainedValue(),
              let source = IOPSGetProvidingPowerSourceType(info)?.takeUnretainedValue() else {
            return true
        }
        return (source as String) == kIOPMACPowerKey
    }

    static func idleSeconds() -> TimeInterval {
        CGEventSource.secondsSinceLastEventType(.combinedSessionState, eventType: CGEventType(rawValue: ~0)!)
    }
}

/// Opens the Full Disk Access pane. macOS doesn't let apps grant it themselves.
public enum PrivacySettings {
    public static func openFullDiskAccess() {
        let url = URL(string: "x-apple.systempreferences:com.apple.preference.security?Privacy_AllFiles")!
        NSWorkspace.shared.open(url)
    }
}

/// User notifications. A new startup item gets Quarantine and Review, never Allow:
/// Allow only happens in the inspector, behind a confirmation.
public enum Notifier {
    public static let findingCategory = "OPENSCOUT_FINDING"
    public static let quarantineAction = "QUARANTINE"
    public static let reviewAction = "REVIEW"

    public static func registerCategories() {
        let quarantine = UNNotificationAction(identifier: quarantineAction, title: "Quarantine", options: [])
        let review = UNNotificationAction(identifier: reviewAction, title: "Review", options: [.foreground])
        let category = UNNotificationCategory(identifier: findingCategory, actions: [quarantine, review],
                                              intentIdentifiers: [], options: [])
        UNUserNotificationCenter.current().setNotificationCategories([category])
    }

    /// Permission is requested only when there's a real finding to show.
    public static func post(_ finding: Finding) {
        let center = UNUserNotificationCenter.current()
        center.requestAuthorization(options: [.alert, .sound]) { granted, _ in
            guard granted else { return }
            let content = UNMutableNotificationContent()
            content.title = finding.title
            content.body = finding.summary
            content.categoryIdentifier = findingCategory
            content.userInfo = ["findingID": finding.id.uuidString]
            let request = UNNotificationRequest(identifier: finding.id.uuidString, content: content, trigger: nil)
            center.add(request)
        }
    }
}
#endif
