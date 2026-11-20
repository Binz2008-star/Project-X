#import <Foundation/Foundation.h>
#import "XinstaFeature.h"

NS_ASSUME_NONNULL_BEGIN

/// Stores only explicit user overrides. Defaults are evaluated from the
/// registry at read time, so a newly registered default-enabled feature works
/// without clearing preferences from an earlier build.
@interface XinstaFeatureRegistry : NSObject

@property (nonatomic, copy, readonly) NSArray<XinstaFeature *> *features;

- (instancetype)initWithFeatures:(NSArray<XinstaFeature *> *)features
                     userDefaults:(NSUserDefaults *)userDefaults NS_DESIGNATED_INITIALIZER;
- (instancetype)init NS_UNAVAILABLE;

+ (instancetype)sharedRegistry;

- (BOOL)isEnabledForIdentifier:(NSString *)identifier;
- (void)setEnabled:(BOOL)enabled forIdentifier:(NSString *)identifier;
- (NSDictionary<NSString *, NSNumber *> *)effectiveStates;

@end

NS_ASSUME_NONNULL_END
