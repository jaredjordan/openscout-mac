import Foundation
import OpenScoutMac

/// Accepts XPC connections only from the OpenScout app.
///
/// Release builds require the caller to be signed by OpenScout's team, and refuse every
/// connection if the build has no team ID: an identifier-only check can be satisfied by any
/// ad-hoc signed binary. Debug builds fall back to the identifier so development works.
final class ListenerDelegate: NSObject, NSXPCListenerDelegate {
    let service: HelperService
    let requirement: String?

    init(service: HelperService) {
        self.service = service
        let teamID = (Bundle.main.object(forInfoDictionaryKey: "OpenScoutTeamID") as? String) ?? ""
        let hasTeam = !teamID.isEmpty && !teamID.hasPrefix("$(")
            && teamID.allSatisfy { $0.isLetter || $0.isNumber }
        if hasTeam {
            requirement = "anchor apple generic and identifier \"com.jaredjordan.openscout\" and certificate leaf[subject.OU] = \"\(teamID)\""
        } else {
            #if DEBUG
            requirement = "identifier \"com.jaredjordan.openscout\""
            #else
            requirement = nil
            NSLog("OpenScout helper: built without OPENSCOUT_TEAM_ID, refusing all connections")
            #endif
        }
    }

    func listener(_ listener: NSXPCListener, shouldAcceptNewConnection connection: NSXPCConnection) -> Bool {
        guard let requirement else { return false }
        connection.setCodeSigningRequirement(requirement)
        connection.exportedInterface = .openScoutHelper
        connection.exportedObject = service
        connection.resume()
        return true
    }
}

let service = HelperService()
service.start()
let delegate = ListenerDelegate(service: service)
let listener = NSXPCListener(machServiceName: HelperIdentity.machServiceName)
listener.delegate = delegate
listener.resume()
RunLoop.main.run()
