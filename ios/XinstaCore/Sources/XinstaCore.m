#import "XinstaCore.h"

#import "XinstaIG456Adapter.h"

@implementation XinstaCore

+ (void)evaluateAtLoad {
    XinstaIG456Adapter *adapter = [XinstaIG456Adapter sharedAdapter];
    BOOL accepted = [adapter evaluateCompatibility];
    XinstaCompatibilityReport *report = adapter.compatibilityReport;
    // Log a stable code only; never echo host-controlled version/build strings.
    NSLog(@"[XinstaCore] compatibilityAccepted=%d reasonCode=%@", accepted, report.reasonCode);
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
