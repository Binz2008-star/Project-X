#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

/// Binding identifier for the development-only private pilot. It is distinct
/// from the production Instagram binding and must never be substituted into a
/// production adapter or feature registry.
extern NSString * const XinstaAdapterIdentifierPrivatePilot;

extern NSString * const XinstaBundleIdentifierPrivatePilot;
extern NSString * const XinstaPrivatePilotVersion;
extern NSString * const XinstaPrivatePilotBuild;

/// Maps an exact host identity to one of two reviewed bindings.
///
/// Only the pinned production Instagram identity and the pinned private pilot
/// identity have a binding. Every other combination returns nil so callers fail
/// closed. This class reads no signing material, contacts no device, and does
/// not weaken the production gate.
@interface XinstaIdentityPolicy : NSObject

+ (nullable NSString *)adapterIdentifierForBundleIdentifier:(nullable NSString *)bundleIdentifier
                                                     version:(nullable NSString *)version
                                                       build:(nullable NSString *)build;

+ (BOOL)isPilotBundleIdentifier:(nullable NSString *)bundleIdentifier;

- (instancetype)init NS_UNAVAILABLE;

@end

NS_ASSUME_NONNULL_END
