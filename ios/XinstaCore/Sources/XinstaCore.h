#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

/// Dylib load entry point, exposed for deterministic tests.
@interface XinstaCore : NSObject

/// Evaluates the IG456 compatibility gate using the production shared adapter.
/// Performs no hooking, injection, installation, or UI presentation.
+ (void)evaluateAtLoad;

@end

NS_ASSUME_NONNULL_END
