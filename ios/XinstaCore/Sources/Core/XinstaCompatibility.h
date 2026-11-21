#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

typedef BOOL (^XinstaSymbolAvailability)(NSString *symbolName);

/// Stable identifier for the exact, read-only IG456 adapter binding.
extern NSString * const XinstaAdapterIdentifierIG456;

extern NSString * const XinstaCompatibilityReasonNotChecked;
extern NSString * const XinstaCompatibilityReasonAccepted;
extern NSString * const XinstaCompatibilityReasonMissingBundleIdentifier;
extern NSString * const XinstaCompatibilityReasonBundleIdentifierMismatch;
extern NSString * const XinstaCompatibilityReasonVersionMismatch;
extern NSString * const XinstaCompatibilityReasonBuildMismatch;
extern NSString * const XinstaCompatibilityReasonTargetUnavailable;
extern NSString * const XinstaCompatibilityReasonSymbolsUnavailable;

/// Stable, non-host-controlled outcome codes suitable for logging.
@interface XinstaCompatibilityReport : NSObject

@property (nonatomic, assign, readonly) BOOL supported;
@property (nonatomic, copy, readonly) NSString *reasonCode;
@property (nonatomic, copy, readonly) NSString *reason;
@property (nonatomic, copy, readonly) NSArray<NSString *> *missingSymbols;

- (instancetype)initWithSupported:(BOOL)supported
                        reasonCode:(NSString *)reasonCode
                            reason:(NSString *)reason
                   missingSymbols:(NSArray<NSString *> *)missingSymbols NS_DESIGNATED_INITIALIZER;
- (instancetype)init NS_UNAVAILABLE;

@end

/// Read-only compatibility gate for the Instagram 456.0.0 adapter.
///
/// This class compares host metadata and confirms that required Objective-C
/// names are visible at runtime. It performs no method modification; passing
/// this gate only records that a future, separately reviewed capability could
/// be considered for this exact host.
@interface XinstaCompatibility : NSObject

+ (NSString *)adapterIdentifier;
+ (NSString *)supportedBundleIdentifier;
+ (NSString *)supportedVersion;
+ (NSString *)supportedBuild;

/// Development-only private pilot identity. Accepting the pilot does not
/// change the production adapter identifier and does not authorize hooks,
/// installation, or device actions.
+ (NSString *)privatePilotBundleIdentifier;
+ (NSString *)privatePilotAdapterIdentifier;

/// The single host class this adapter is allowed to inspect. No other target
/// class may be introduced without a new, separately reviewed adapter.
+ (NSString *)targetClassName;

/// Selectors required on the target class for this exact version.
+ (NSArray<NSString *> *)requiredSelectors;

/// Target class plus required selectors. Kept for the fail-closed symbol gate.
+ (NSArray<NSString *> *)requiredSymbols;

+ (XinstaCompatibilityReport *)checkBundleIdentifier:(nullable NSString *)bundleIdentifier
                                               version:(nullable NSString *)version
                                                 build:(nullable NSString *)build
                                     symbolAvailability:(nullable XinstaSymbolAvailability)availability;

@end

NS_ASSUME_NONNULL_END
