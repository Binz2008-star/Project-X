import Foundation

/// Contract for an optional, independently testable feature of the demo app.
///
/// A module only declares identity and metadata. No module performs injection,
/// signing, network access or installation work in this demonstration.
protocol FeatureModule: Identifiable, Sendable {
    var id: String { get }
    var title: String { get }
    var summary: String { get }
    var isEnabledByDefault: Bool { get }
}

/// Concrete value type used by the registry and the settings UI.
struct FeatureDefinition: FeatureModule {
    let id: String
    let title: String
    let summary: String
    let isEnabledByDefault: Bool
}

/// Product-agnostic registry. Adding a feature means adding one value here;
/// the settings screen and persistence adapt automatically.
enum FeatureRegistry {
    static let modules: [FeatureDefinition] = [
        FeatureDefinition(
            id: "diagnostics",
            title: "Diagnostics",
            summary: "Shows local build and signing status. No telemetry is collected.",
            isEnabledByDefault: true
        ),
        FeatureDefinition(
            id: "appearance",
            title: "Appearance",
            summary: "Demonstrates a modular preference that can be toggled independently.",
            isEnabledByDefault: false
        ),
        FeatureDefinition(
            id: "localOptions",
            title: "Local Options",
            summary: "Reserved for owned, on-device options in a future increment.",
            isEnabledByDefault: true
        ),
    ]
}

/// Persists feature flags without coupling the UI to a storage framework.
@MainActor
final class FeatureStore: ObservableObject {
    @Published private(set) var enabled: Set<String>

    private let defaults: UserDefaults
    private let storageKey = "projectx.demo.enabledFeatures"

    init(defaults: UserDefaults = .standard) {
        self.defaults = defaults
        if let saved = defaults.array(forKey: storageKey) as? [String] {
            self.enabled = Set(saved)
        } else {
            self.enabled = Set(
                FeatureRegistry.modules
                    .filter { $0.isEnabledByDefault }
                    .map(\.id)
            )
        }
    }

    func isEnabled(_ id: String) -> Bool {
        enabled.contains(id)
    }

    func setEnabled(_ value: Bool, for id: String) {
        if value {
            enabled.insert(id)
        } else {
            enabled.remove(id)
        }
        defaults.set(enabled.sorted(), forKey: storageKey)
    }
}
