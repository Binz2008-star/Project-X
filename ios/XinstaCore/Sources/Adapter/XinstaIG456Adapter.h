#import <Foundation/Foundation.h>
#import "XinstaCompatibility.h"
#import "XinstaHostMetadata.h"

NS_ASSUME_NONNULL_BEGIN

/// Read-only bridge between Instagram 456.0.0 metadata and Xinsta Core.
///
/// This adapter never swizzles, injects, installs, or modifies another app.
/// `compatibilityAccepted == YES` means only "the exact host metadata and
/// required runtime capabilities were observed". It does not mean Instagram was
/// hooked, that a tweak was loaded, or that any UI was shown inside Instagram.
@interface XinstaIG456Adapter : NSObject

+ (instancetype)sharedAdapter;

/// Stable binding identifier used by feature registration and diagnostics.
+ (NSString *)adapterIdentifier;

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

/// YES only after the version-specific target class has been observed by the
/// same evaluation that accepted the adapter. Never inferred from a string.
@property (nonatomic, assign, readonly) BOOL targetRuntimeVerified;

/// Evaluates the gate once. Despite the older design, this method performs no
/// installation step; it only records compatibility state. Repeated calls
/// after acceptance are idempotent and do not re-run the symbol resolver.
- (BOOL)evaluateCompatibility;

@end

NS_ASSUME_NONNULL_END
