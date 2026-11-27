import Foundation
import OpenScoutMac

/// Accepts XPC connections only from the OpenScout app. With a Team ID baked into the build,
/// the caller must be signed by that team. Development builds check the bundle identifier only.
final class ListenerDelegate: NSObject, NSXPCListenerDelegate {
    let service: HelperService

    init(service: HelperService) { self.service = service }

    func listener(_ listener: NSXPCListener, shouldAcceptNewConnection connection: NSXPCConnection) -> Bool {
        let teamID = Bundle.main.object(forInfoDictionaryKey: "OpenScoutTeamID") as? String ?? ""
        let requirement: String
        if teamID.isEmpty || teamID.hasPrefix("$(") {
            requirement = "identifier \"com.jaredjordan.openscout\""
        } else {
            requirement = "anchor apple generic and identifier \"com.jaredjordan.openscout\" and certificate leaf[subject.OU] = \"\(teamID)\""
        }
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
