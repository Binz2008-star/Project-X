import SwiftUI

struct XSettingsView: View {
    @EnvironmentObject private var features: FeatureStore

    var body: some View {
        List {
            Section("About") {
                LabeledContent("App", value: "Project X Demo")
                LabeledContent("Purpose", value: "Owned build-verification sample")
                LabeledContent("Bundle", value: "com.projectx.demo")
            }

            Section("Feature Registry") {
                ForEach(FeatureRegistry.modules) { module in
                    VStack(alignment: .leading, spacing: 4) {
                        HStack {
                            Text(module.title)
                            Spacer()
                            if features.isEnabled(module.id) {
                                Text("On")
                                    .font(.caption.weight(.semibold))
                                    .foregroundStyle(.green)
                            }
                        }
                        Text(module.summary)
                            .font(.caption)
                            .foregroundStyle(.secondary)
                    }
                    .padding(.vertical, 2)
                }
            }

            Section("Signing") {
                Text("This binary is unsigned. Installing it on an iPhone requires an authorised signing identity, a matching provisioning profile and Developer Mode on the device. See docs/IOS_DEMO_APP.md.")
                    .font(.footnote)
                    .foregroundStyle(.secondary)
            }
        }
        .navigationTitle("X Settings")
    }
}
