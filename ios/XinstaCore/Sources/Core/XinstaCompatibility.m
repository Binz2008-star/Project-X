#import "XinstaCompatibility.h"

#import "XinstaIdentityPolicy.h"

NSString * const XinstaAdapterIdentifierIG456 = @"com.burbn.instagram@456.0.0@1114925422";

NSString * const XinstaCompatibilityReasonNotChecked = @"not_checked";
NSString * const XinstaCompatibilityReasonAccepted = @"accepted";
NSString * const XinstaCompatibilityReasonMissingBundleIdentifier = @"missing_bundle_identifier";
NSString * const XinstaCompatibilityReasonBundleIdentifierMismatch = @"bundle_identifier_mismatch";
NSString * const XinstaCompatibilityReasonVersionMismatch = @"version_mismatch";
NSString * const XinstaCompatibilityReasonBuildMismatch = @"build_mismatch";
NSString * const XinstaCompatibilityReasonTargetUnavailable = @"target_unavailable";
NSString * const XinstaCompatibilityReasonSymbolsUnavailable = @"symbols_unavailable";

@implementation XinstaCompatibilityReport

- (instancetype)initWithSupported:(BOOL)supported
                        reasonCode:(NSString *)reasonCode
                            reason:(NSString *)reason
                   missingSymbols:(NSArray<NSString *> *)missingSymbols {
    self = [super init];
    if (self) {
        _supported = supported;
        _reasonCode = [reasonCode copy];
        _reason = [reason copy];
        _missingSymbols = [missingSymbols copy];
    }
    return self;
}

@end

@implementation XinstaCompatibility

+ (NSString *)adapterIdentifier {
    return XinstaAdapterIdentifierIG456;
}

+ (NSString *)supportedBundleIdentifier {
    return @"com.burbn.instagram";
}

+ (NSString *)supportedVersion {
    return @"456.0.0";
}

+ (NSString *)supportedBuild {
    return @"1114925422";
}

+ (NSString *)privatePilotBundleIdentifier {
    return XinstaBundleIdentifierPrivatePilot;
}

+ (NSString *)privatePilotAdapterIdentifier {
    return XinstaAdapterIdentifierPrivatePilot;
}

+ (NSString *)targetClassName {
    return @"IGProfileSheetTableViewController";
}

+ (NSArray<NSString *> *)requiredSelectors {
    return @[
        @"tableView:numberOfRowsInSection:",
        @"tableView:cellForRowAtIndexPath:",
        @"tableView:didSelectRowAtIndexPath:",
    ];
}

+ (NSArray<NSString *> *)requiredSymbols {
    NSMutableArray<NSString *> *symbols = [NSMutableArray arrayWithObject:[self targetClassName]];
    [symbols addObjectsFromArray:[self requiredSelectors]];
    return [symbols copy];
}

+ (XinstaCompatibilityReport *)rejectedWithReasonCode:(NSString *)reasonCode
                                                reason:(NSString *)reason {
    return [self rejectedWithReasonCode:reasonCode reason:reason missingSymbols:@[]];
}

+ (XinstaCompatibilityReport *)rejectedWithReasonCode:(NSString *)reasonCode
                                                reason:(NSString *)reason
                                        missingSymbols:(NSArray<NSString *> *)missingSymbols {
    return [[XinstaCompatibilityReport alloc] initWithSupported:NO
                                                      reasonCode:reasonCode
                                                          reason:reason
                                                 missingSymbols:missingSymbols];
}

+ (XinstaCompatibilityReport *)checkBundleIdentifier:(nullable NSString *)bundleIdentifier
                                               version:(nullable NSString *)version
                                                 build:(nullable NSString *)build
                                     symbolAvailability:(nullable XinstaSymbolAvailability)availability {
    if (bundleIdentifier.length == 0) {
        return [self rejectedWithReasonCode:XinstaCompatibilityReasonMissingBundleIdentifier
                                      reason:@"Host bundle identifier is missing"];
    }
    BOOL production = [bundleIdentifier isEqualToString:self.supportedBundleIdentifier];
    BOOL pilot = [XinstaIdentityPolicy isPilotBundleIdentifier:bundleIdentifier];
    if (!production && !pilot) {
        return [self rejectedWithReasonCode:XinstaCompatibilityReasonBundleIdentifierMismatch
                                      reason:@"Host bundle identifier is not an allowlisted adapter identity"];
    }
    NSString *expectedVersion = pilot ? XinstaPrivatePilotVersion : self.supportedVersion;
    NSString *expectedBuild = pilot ? XinstaPrivatePilotBuild : self.supportedBuild;
    if (![version isEqualToString:expectedVersion]) {
        return [self rejectedWithReasonCode:XinstaCompatibilityReasonVersionMismatch
                                      reason:@"Host version does not match the pinned adapter"];
    }
    if (![build isEqualToString:expectedBuild]) {
        return [self rejectedWithReasonCode:XinstaCompatibilityReasonBuildMismatch
                                      reason:@"Host build does not match the pinned adapter"];
    }

    NSMutableArray<NSString *> *required = [NSMutableArray array];
    [required addObject:[self targetClassName]];
    [required addObjectsFromArray:[self requiredSelectors]];

    NSMutableArray<NSString *> *missing = [NSMutableArray array];
    for (NSString *symbol in required) {
        if (!availability || !availability(symbol)) {
            [missing addObject:symbol];
        }
    }
    if (missing.count > 0) {
        BOOL targetMissing = [missing containsObject:[self targetClassName]];
        return [self rejectedWithReasonCode:targetMissing
                                                   ? XinstaCompatibilityReasonTargetUnavailable
                                                   : XinstaCompatibilityReasonSymbolsUnavailable
                                                  reason:targetMissing
                                                       ? @"The version-specific target class is unavailable"
                                                       : @"Required runtime capabilities are unavailable"
                                          missingSymbols:[missing copy]];
    }
    return [[XinstaCompatibilityReport alloc] initWithSupported:YES
                                                      reasonCode:XinstaCompatibilityReasonAccepted
                                                          reason:@"Metadata and required capabilities match the pinned adapter"
                                                 missingSymbols:@[]];
}

@end
