import SwiftUI

struct ContentView: View {
    @EnvironmentObject private var features: FeatureStore

    var body: some View {
        NavigationStack {
            List {
                Section("Project X Demo") {
                    NavigationLink("X Settings") {
                        XSettingsView()
                    }
                }

                Section("Feature Registry") {
                    ForEach(FeatureRegistry.modules) { module in
                        Toggle(
                            module.title,
                            isOn: Binding(
                                get: { features.isEnabled(module.id) },
                                set: { features.setEnabled($0, for: module.id) }
                            )
                        )
                    }
                }

                Section("Build") {
                    LabeledContent("Configuration", value: "Unsigned simulator build")
                    Text("Compilation is verified by the isolated macOS workflow; this build is not installable on a physical iPhone.")
                        .font(.footnote)
                        .foregroundStyle(.secondary)
                }
            }
            .navigationTitle("Demo")
        }
    }
}
