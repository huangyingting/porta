import SwiftUI
#if os(iOS)
import UIKit
#else
import AppKit
#endif

/// The system clipboard's text.
enum Pasteboard {
    static var string: String? {
        get {
            #if os(iOS)
            return UIPasteboard.general.string
            #else
            return NSPasteboard.general.string(forType: .string)
            #endif
        }
        set {
            #if os(iOS)
            UIPasteboard.general.string = newValue
            #else
            NSPasteboard.general.clearContents()
            if let newValue {
                NSPasteboard.general.setString(newValue, forType: .string)
            }
            #endif
        }
    }
}

@main
struct PortaApp: App {
    @StateObject private var store = ProfileStore()

    var body: some Scene {
        WindowGroup {
            ContentView()
                .environmentObject(store)
                // porta://profile links from the downloads page's profile QR.
                .onOpenURL { store.openSetupLink($0.absoluteString) }
                #if os(macOS)
                .frame(minWidth: 420, idealWidth: 460, minHeight: 640, idealHeight: 760)
                #endif
        }
        #if os(macOS)
        .windowResizability(.contentMinSize)
        #endif
    }
}
