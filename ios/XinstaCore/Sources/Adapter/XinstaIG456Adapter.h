#import <Foundation/Foundation.h>
#import "XinstaCompatibility.h"

NS_ASSUME_NONNULL_BEGIN

/// Version-specific bridge between Instagram 456.0.0 and Xinsta Core.
///
/// This adapter is inert until `installIfSupported` verifies both the app
/// version and the runtime presence of the required Objective-C symbols.
@interface XinstaIG456Adapter : NSObject

+ (instancetype)sharedAdapter;

@property (nonatomic, strong, readonly) XinstaCompatibilityReport *compatibilityReport;
@property (nonatomic, assign, readonly) BOOL installed;

- (BOOL)installIfSupported;

@end

NS_ASSUME_NONNULL_END
