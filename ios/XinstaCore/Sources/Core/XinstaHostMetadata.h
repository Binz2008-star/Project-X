#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

/// Immutable host application metadata used by the compatibility gate.
/// Keeping this as a value object lets tests inject exact values without a
/// real Instagram process.
@interface XinstaHostMetadata : NSObject

@property (nonatomic, copy, readonly, nullable NSString *)bundleIdentifier;
@property (nonatomic, copy, readonly, nullable NSString *)version;
@property (nonatomic, copy, readonly, nullable NSString *)build;

+ (instancetype)metadataWithBundle:(NSBundle *)bundle;

- (instancetype)initWithBundleIdentifier:(nullable NSString *)bundleIdentifier
                                 version:(nullable NSString *)version
                                   build:(nullable NSString *)build NS_DESIGNATED_INITIALIZER;
- (instancetype)init NS_UNAVAILABLE;

@end

NS_ASSUME_NONNULL_END
