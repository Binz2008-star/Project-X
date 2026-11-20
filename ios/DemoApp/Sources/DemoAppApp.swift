import SwiftUI

@main
struct DemoAppApp: App {
    @StateObject private var featureStore = FeatureStore()

    var body: some Scene {
        WindowGroup {
            ContentView()
                .environmentObject(featureStore)
        }
    }
}
