#import <Foundation/Foundation.h>
#import "XinstaIG456Adapter.h"
#import "XinstaFeatureRegistry.h"

NS_ASSUME_NONNULL_BEGIN

/// Fixed outcomes for the load-time initialization check. No host-controlled
/// string is ever included in a diagnostic code or log line.
typedef NS_ENUM(NSUInteger, XinstaInitializationStatus) {
    XinstaInitializationStatusInvalidInput = 0,
    XinstaInitializationStatusAdapterNotAccepted,
    XinstaInitializationStatusTargetUnavailable,
    XinstaInitializationStatusBindingMismatch,
    XinstaInitializationStatusNoBoundFeatures,
    XinstaInitializationStatusReady,
};

@interface XinstaDiagnostic : NSObject

/// Crash-safe: any unexpected exception returns `InvalidInput`.
+ (XinstaInitializationStatus)statusForAdapter:(nullable XinstaIG456Adapter *)adapter
                                       registry:(nullable XinstaFeatureRegistry *)registry;

+ (NSString *)codeForStatus:(XinstaInitializationStatus)status;

@end

NS_ASSUME_NONNULL_END
