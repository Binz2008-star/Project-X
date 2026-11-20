#import "XinstaFeatureRegistry.h"

static NSString *const XinstaFeatureOverrideKey = @"xinsta.core.featureOverrides";

@interface XinstaFeatureRegistry ()
@property (nonatomic, strong) NSUserDefaults *userDefaults;
@end

@implementation XinstaFeatureRegistry

+ (instancetype)sharedRegistry {
    static XinstaFeatureRegistry *registry;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        NSArray *features = @[
            [[XinstaFeature alloc] initWithIdentifier:@"info"
                                                title:@"Build Information"
                                          description:@"Shows the verified version and adapter state."
                                     enabledByDefault:YES],
            [[XinstaFeature alloc] initWithIdentifier:@"demo.toggle"
                                                title:@"Demo Option"
                                          description:@"Harmless local toggle used to validate registry persistence."
                                     enabledByDefault:NO],
            [[XinstaFeature alloc] initWithIdentifier:@"accessibility"
                                                title:@"Accessibility Labels"
                                          description:@"Reserved for owned enhancements; no effect in this increment."
                                     enabledByDefault:YES],
        ];
        registry = [[self alloc] initWithFeatures:features userDefaults:[NSUserDefaults standardUserDefaults]];
    });
    return registry;
}

- (instancetype)initWithFeatures:(NSArray<XinstaFeature *> *)features
                     userDefaults:(NSUserDefaults *)userDefaults {
    self = [super init];
    if (self) {
        _features = [features copy];
        _userDefaults = userDefaults;
    }
    return self;
}

- (NSDictionary<NSString *, NSNumber *> *)effectiveStates {
    NSDictionary *overrides = [self.userDefaults dictionaryForKey:XinstaFeatureOverrideKey] ?: @{};
    NSMutableDictionary *states = [NSMutableDictionary dictionary];
    for (XinstaFeature *feature in self.features) {
        NSNumber *override = overrides[feature.identifier];
        BOOL enabled = override ? override.boolValue : feature.isEnabledByDefault;
        states[feature.identifier] = @(enabled);
    }
    return [states copy];
}

- (BOOL)isEnabledForIdentifier:(NSString *)identifier {
    return [self.effectiveStates[identifier] boolValue];
}

- (void)setEnabled:(BOOL)enabled forIdentifier:(NSString *)identifier {
    NSMutableDictionary *overrides = [[self.userDefaults dictionaryForKey:XinstaFeatureOverrideKey] mutableCopy] ?: [NSMutableDictionary dictionary];
    overrides[identifier] = @(enabled);
    [self.userDefaults setObject:[overrides copy] forKey:XinstaFeatureOverrideKey];
}

@end
