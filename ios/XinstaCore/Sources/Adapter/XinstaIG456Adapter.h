#import <Foundation/Foundation.h>
#import "XinstaCompatibility.h"
#import "XinstaHostMetadata.h"

NS_ASSUME_NONNULL_BEGIN

/// Read-only bridge between Instagram 456.0.0 metadata and Xinsta Core.
///
/// This adapter never swizzles, injects, installs, or modifies another app.
/// `compatibilityAccepted == YES` means only "the exact host metadata and
/// required runtime symbols were observed". It does not mean Instagram was
/// hooked, that a tweak was loaded, or that any UI was shown inside Instagram.
@interface XinstaIG456Adapter : NSObject

+ (instancetype)sharedAdapter;

/// Read-only symbol lookup used by the production adapter. Exposed so the
/// metadata inspection can be tested directly with ordinary Foundation classes.
+ (BOOL)runtimeSymbolAvailable:(NSString *)symbolName
                targetClassName:(NSString *)className;
+ (XinstaSymbolAvailability)runtimeSymbolAvailability;

- (instancetype)initWithHostMetadata:(XinstaHostMetadata *)hostMetadata
                  symbolAvailability:(nullable XinstaSymbolAvailability)symbolAvailability NS_DESIGNATED_INITIALIZER;
- (instancetype)init NS_UNAVAILABLE;

@property (nonatomic, strong, readonly) XinstaCompatibilityReport *compatibilityReport;
@property (nonatomic, assign, readonly) BOOL compatibilityAccepted;

/// Evaluates the gate once. Despite the older design, this method performs no
/// installation step; it only records compatibility state. Repeated calls
/// after acceptance are idempotent and do not re-run the symbol resolver.
- (BOOL)evaluateCompatibility;

@end

NS_ASSUME_NONNULL_END
