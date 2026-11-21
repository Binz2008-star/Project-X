#import "XinstaIdentityPolicy.h"

#import "XinstaCompatibility.h"

NSString * const XinstaAdapterIdentifierPrivatePilot = @"com.projectx.xinsta.pilot@456.0.0@1114925422";

NSString * const XinstaBundleIdentifierPrivatePilot = @"com.projectx.xinsta.pilot";
NSString * const XinstaPrivatePilotVersion = @"456.0.0";
NSString * const XinstaPrivatePilotBuild = @"1114925422";

@implementation XinstaIdentityPolicy

+ (nullable NSString *)adapterIdentifierForBundleIdentifier:(nullable NSString *)bundleIdentifier
                                                     version:(nullable NSString *)version
                                                       build:(nullable NSString *)build {
    if ([bundleIdentifier isEqualToString:[XinstaCompatibility supportedBundleIdentifier]] &&
        [version isEqualToString:[XinstaCompatibility supportedVersion]] &&
        [build isEqualToString:[XinstaCompatibility supportedBuild]]) {
        return XinstaAdapterIdentifierIG456;
    }
    if ([self isPilotBundleIdentifier:bundleIdentifier] &&
        [version isEqualToString:XinstaPrivatePilotVersion] &&
        [build isEqualToString:XinstaPrivatePilotBuild]) {
        return XinstaAdapterIdentifierPrivatePilot;
    }
    return nil;
}

+ (BOOL)isPilotBundleIdentifier:(nullable NSString *)bundleIdentifier {
    return [bundleIdentifier isEqualToString:XinstaBundleIdentifierPrivatePilot];
}

@end
