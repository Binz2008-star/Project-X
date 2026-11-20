#import "XinstaIG456Adapter.h"

#import <objc/runtime.h>

@interface XinstaIG456Adapter ()
@property (nonatomic, strong) XinstaHostMetadata *hostMetadata;
@property (nonatomic, copy, nullable XinstaSymbolAvailability) symbolAvailability;
@property (nonatomic, strong) NSLock *stateLock;
@end

@implementation XinstaIG456Adapter

@synthesize compatibilityReport = _compatibilityReport;
@synthesize compatibilityAccepted = _compatibilityAccepted;

+ (instancetype)sharedAdapter {
    static XinstaIG456Adapter *adapter;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        XinstaHostMetadata *metadata = [XinstaHostMetadata metadataWithBundle:[NSBundle mainBundle]];
        adapter = [[self alloc] initWithHostMetadata:metadata
                                 symbolAvailability:[self runtimeSymbolAvailability]];
    });
    return adapter;
}

+ (BOOL)runtimeSymbolAvailable:(NSString *)symbolName
                targetClassName:(NSString *)className {
    if (symbolName.length == 0 || className.length == 0) {
        return NO;
    }
    Class target = objc_getClass(className.UTF8String);
    if (!target) {
        return NO;
    }
    if ([symbolName isEqualToString:className]) {
        return YES;
    }
    SEL selector = sel_registerName(symbolName.UTF8String);
    return class_getInstanceMethod(target, selector) != NULL;
}

+ (XinstaSymbolAvailability)runtimeSymbolAvailability {
    return ^BOOL(NSString *symbolName) {
        return [XinstaIG456Adapter runtimeSymbolAvailable:symbolName
                                          targetClassName:@"IGProfileSheetTableViewController"];
    };
}

- (instancetype)initWithHostMetadata:(XinstaHostMetadata *)hostMetadata
                  symbolAvailability:(XinstaSymbolAvailability)symbolAvailability {
    self = [super init];
    if (self) {
        _hostMetadata = hostMetadata;
        _symbolAvailability = [symbolAvailability copy];
        _stateLock = [[NSLock alloc] init];
        _compatibilityAccepted = NO;
        _compatibilityReport = [[XinstaCompatibilityReport alloc] initWithSupported:NO
                                                                         reasonCode:XinstaCompatibilityReasonNotChecked
                                                                             reason:@"Compatibility has not been checked"
                                                                    missingSymbols:@[]];
    }
    return self;
}

- (XinstaCompatibilityReport *)compatibilityReport {
    [self.stateLock lock];
    XinstaCompatibilityReport *report = _compatibilityReport;
    [self.stateLock unlock];
    return report;
}

- (BOOL)compatibilityAccepted {
    [self.stateLock lock];
    BOOL accepted = _compatibilityAccepted;
    [self.stateLock unlock];
    return accepted;
}

- (BOOL)evaluateCompatibility {
    [self.stateLock lock];
    if (_compatibilityAccepted) {
        [self.stateLock unlock];
        return YES;
    }

    XinstaCompatibilityReport *report = [XinstaCompatibility checkBundleIdentifier:self.hostMetadata.bundleIdentifier
                                                                           version:self.hostMetadata.version
                                                                             build:self.hostMetadata.build
                                                                 symbolAvailability:self.symbolAvailability];
    _compatibilityReport = report;
    _compatibilityAccepted = report.supported;
    BOOL accepted = report.supported;
    [self.stateLock unlock];
    return accepted;
}

@end
