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
                    LabeledContent("Verification", value: "macOS compile check")
                    Text("The CI verification binary is unsigned and was not launched. A physical-device build must be signed separately.")
                        .font(.footnote)
                        .foregroundStyle(.secondary)
                }
            }
            .navigationTitle("Demo")
        }
    }
}
