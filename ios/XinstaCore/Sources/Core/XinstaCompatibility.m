#import "XinstaCompatibility.h"

@implementation XinstaCompatibilityReport

- (instancetype)initWithSupported:(BOOL)supported
                           reason:(NSString *)reason
                  missingSymbols:(NSArray<NSString *> *)missingSymbols {
    self = [super init];
    if (self) {
        _supported = supported;
        _reason = [reason copy];
        _missingSymbols = [missingSymbols copy];
    }
    return self;
}

@end

@implementation XinstaCompatibility

+ (NSString *)supportedVersion {
    return @"456.0.0";
}

+ (NSString *)supportedBuild {
    return @"1114925422";
}

+ (NSArray<NSString *> *)requiredSymbols {
    return @[
        @"IGProfileSheetTableViewController",
        @"tableView:numberOfRowsInSection:",
        @"tableView:cellForRowAtIndexPath:",
        @"tableView:didSelectRowAtIndexPath:",
    ];
}

+ (XinstaCompatibilityReport *)checkVersion:(NSString *)version
                                       build:(NSString *)build
                           symbolAvailability:(XinstaSymbolAvailability)availability {
    if (![version isEqualToString:self.supportedVersion]) {
        return [[XinstaCompatibilityReport alloc] initWithSupported:NO
                                                             reason:[NSString stringWithFormat:@"Unsupported version %@; adapter targets %@", version, self.supportedVersion]
                                                    missingSymbols:@[]];
    }
    if (![build isEqualToString:self.supportedBuild]) {
        return [[XinstaCompatibilityReport alloc] initWithSupported:NO
                                                             reason:[NSString stringWithFormat:@"Unsupported build %@; adapter targets %@", build, self.supportedBuild]
                                                    missingSymbols:@[]];
    }

    NSMutableArray *missing = [NSMutableArray array];
    for (NSString *symbol in self.requiredSymbols) {
        if (!availability || !availability(symbol)) {
            [missing addObject:symbol];
        }
    }
    if (missing.count > 0) {
        return [[XinstaCompatibilityReport alloc] initWithSupported:NO
                                                             reason:@"Required runtime symbols are unavailable"
                                                    missingSymbols:[missing copy]];
    }
    return [[XinstaCompatibilityReport alloc] initWithSupported:YES
                                                         reason:@"Version and required symbols match the 456.0.0 adapter"
                                                missingSymbols:@[]];
}

@end
