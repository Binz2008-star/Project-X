#import <Foundation/Foundation.h>
#import "XinstaFeature.h"

NS_ASSUME_NONNULL_BEGIN

/// Stores only explicit user overrides for features bound to one adapter.
/// Defaults are evaluated from the registry at read time, so every state read
/// is fresh and a newly registered default-enabled feature works without
/// clearing preferences from an earlier build.
@interface XinstaFeatureRegistry : NSObject

@property (nonatomic, copy, readonly) NSString *adapterIdentifier;
@property (nonatomic, copy, readonly) NSArray<XinstaFeature *> *features;

- (instancetype)initWithFeatures:(NSArray<XinstaFeature *> *)features
                      userDefaults:(NSUserDefaults *)userDefaults
                 adapterIdentifier:(NSString *)adapterIdentifier NS_DESIGNATED_INITIALIZER;
- (instancetype)init NS_UNAVAILABLE;

+ (instancetype)sharedRegistry;

/// Returns the registry bound to one reviewed adapter identifier. Unknown or
/// empty bindings return nil; each accepted binding has its own registry so a
/// production feature can never be exposed in the private pilot and vice versa.
+ (nullable instancetype)sharedRegistryForAdapterIdentifier:(nullable NSString *)adapterIdentifier;

- (BOOL)isEnabledForIdentifier:(NSString *)identifier;
- (void)setEnabled:(BOOL)enabled forIdentifier:(NSString *)identifier;
- (NSDictionary<NSString *, NSNumber *> *)effectiveStates;

@end

NS_ASSUME_NONNULL_END
