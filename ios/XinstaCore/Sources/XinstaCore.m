#import <Foundation/Foundation.h>
#import "XinstaIG456Adapter.h"

/// Dylib load entry point. This runs once when the library is injected, but it
/// only reads metadata and records a compatibility decision. No Instagram
/// method is modified in this increment.
__attribute__((constructor))
static void XinstaCoreLoad(void) {
    XinstaIG456Adapter *adapter = [XinstaIG456Adapter sharedAdapter];
    BOOL installed = [adapter installIfSupported];
    XinstaCompatibilityReport *report = adapter.compatibilityReport;
    NSLog(@"[XinstaCore] installed=%d supported=%d reason=%@",
          installed, report.supported, report.reason);
}
