#import "XinstaCore.h"

#import "XinstaIG456Adapter.h"
#import "XinstaFeatureRegistry.h"
#import "XinstaDiagnostic.h"

@implementation XinstaCore

+ (void)evaluateAtLoad {
    @try {
        XinstaIG456Adapter *adapter = [XinstaIG456Adapter sharedAdapter];
        BOOL accepted = [adapter evaluateCompatibility];
        NSString *binding = adapter.adapterIdentifier;
        XinstaFeatureRegistry *registry = [XinstaFeatureRegistry sharedRegistryForAdapterIdentifier:binding];
        XinstaInitializationStatus status = [XinstaDiagnostic statusForAdapter:adapter
                                                                      registry:registry];
        // Fixed codes and a count only; never echo host-controlled strings or
        // exception contents into logs.
        NSLog(@"[XinstaCore] init=%@ features=%lu accepted=%d",
              [XinstaDiagnostic codeForStatus:status],
              (unsigned long)registry.features.count,
              accepted);
    } @catch (NSException *exception) {
        (void)exception;
        NSLog(@"[XinstaCore] init=%@", [XinstaDiagnostic codeForStatus:XinstaInitializationStatusInvalidInput]);
    }
}

@end

/// Runs once when the library is loaded. All Foundation work is inside an
/// autorelease pool because no host run-loop pool is guaranteed at load time.
__attribute__((constructor))
static void XinstaCoreLoad(void) {
    @autoreleasepool {
        [XinstaCore evaluateAtLoad];
    }
}
