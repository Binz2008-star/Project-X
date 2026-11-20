#import "XinstaIG456Adapter.h"

#import <objc/runtime.h>

@implementation XinstaIG456Adapter

+ (instancetype)sharedAdapter {
    static XinstaIG456Adapter *adapter;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        adapter = [[self alloc] init];
    });
    return adapter;
}

- (instancetype)init {
    self = [super init];
    if (self) {
        _compatibilityReport = [[XinstaCompatibilityReport alloc] initWithSupported:NO
                                                                            reason:@"Not checked"
                                                                   missingSymbols:@[]];
        _installed = NO;
    }
    return self;
}

/// Runtime symbol lookup. This is the single place where Objective-C runtime
/// presence is confirmed. It never writes to any Instagram class; it only
/// reads metadata. A nil result for any required symbol fails the whole gate.
static BOOL XinstaRuntimeSymbolAvailable(NSString *symbolName) {
    if (symbolName.length == 0) {
        return NO;
    }
    const char *name = symbolName.UTF8String;
    if ([symbolName isEqualToString:@"IGProfileSheetTableViewController"]) {
        return objc_getClass(name) != NULL;
    }
    Class target = objc_getClass("IGProfileSheetTableViewController");
    if (!target) {
        return NO;
    }
    SEL selector = sel_registerName(name);
    return class_getInstanceMethod(target, selector) != NULL;
}

- (BOOL)installIfSupported {
    if (_installed) {
        return YES;
    }

    NSBundle *main = [NSBundle mainBundle];
    NSString *version = [main objectForInfoDictionaryKey:@"CFBundleShortVersionString"] ?: @"";
    NSString *build = [main objectForInfoDictionaryKey:@"CFBundleVersion"] ?: @"";

    XinstaCompatibilityReport *report = [XinstaCompatibility checkVersion:version
                                                                    build:build
                                                        symbolAvailability:^BOOL(NSString *symbolName) {
                                                            return XinstaRuntimeSymbolAvailable(symbolName);
                                                        }];
    _compatibilityReport = report;

    if (!report.supported) {
        // Fail closed: leave every Instagram class untouched when the app is
        // not exactly the analysed build or a symbol is missing at runtime.
        return NO;
    }

    // This increment registers the adapter as installed but performs no
    // swizzling. Method replacement requires separate review and device QA
    // before it can be enabled; reporting `supported` is not a hook claim.
    _installed = YES;
    return YES;
}

@end
