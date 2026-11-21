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
                                     enabledByDefault:YES
                                    adapterIdentifier:XinstaAdapterIdentifierIG456],
            [[XinstaFeature alloc] initWithIdentifier:@"demo.toggle"
                                                title:@"Demo Option"
                                          description:@"Harmless local toggle used to validate registry persistence."
                                     enabledByDefault:NO
                                    adapterIdentifier:XinstaAdapterIdentifierIG456],
            [[XinstaFeature alloc] initWithIdentifier:@"accessibility"
                                                title:@"Accessibility Labels"
                                          description:@"Reserved for owned enhancements; no effect in this increment."
                                     enabledByDefault:YES
                                    adapterIdentifier:XinstaAdapterIdentifierIG456],
        ];
        registry = [[self alloc] initWithFeatures:features
                                      userDefaults:[NSUserDefaults standardUserDefaults]
                                 adapterIdentifier:XinstaAdapterIdentifierIG456];
    });
    return registry;
}

- (instancetype)initWithFeatures:(NSArray<XinstaFeature *> *)features
                      userDefaults:(NSUserDefaults *)userDefaults
                 adapterIdentifier:(NSString *)adapterIdentifier {
    self = [super init];
    if (self) {
        _adapterIdentifier = [adapterIdentifier copy];
        NSMutableArray<XinstaFeature *> *bound = [NSMutableArray array];
        for (XinstaFeature *feature in features) {
            if ([feature isKindOfClass:[XinstaFeature class]] &&
                [feature.adapterIdentifier isEqualToString:_adapterIdentifier]) {
                [bound addObject:feature];
            }
        }
        _features = [bound copy];
        _userDefaults = userDefaults;
    }
    return self;
}

- (BOOL)isKnownIdentifier:(NSString *)identifier {
    if (identifier.length == 0) {
        return NO;
    }
    for (XinstaFeature *feature in self.features) {
        if ([feature.identifier isEqualToString:identifier]) {
            return YES;
        }
    }
    return NO;
}

/// Returns only well-typed values for currently registered, bound identifiers.
/// Malformed defaults and stale keys are ignored, never propagated.
- (NSDictionary<NSString *, NSNumber *> *)validatedOverrides {
    id stored = [self.userDefaults objectForKey:XinstaFeatureOverrideKey];
    if (![stored isKindOfClass:[NSDictionary class]]) {
        return @{};
    }
    NSDictionary *candidates = (NSDictionary *)stored;
    NSMutableDictionary *valid = [NSMutableDictionary dictionary];
    for (XinstaFeature *feature in self.features) {
        id value = candidates[feature.identifier];
        if ([value isKindOfClass:[NSNumber class]]) {
            valid[feature.identifier] = (NSNumber *)value;
        }
    }
    return [valid copy];
}

- (NSDictionary<NSString *, NSNumber *> *)effectiveStates {
    @synchronized (self) {
        NSDictionary<NSString *, NSNumber *> *overrides = [self validatedOverrides];
        NSMutableDictionary *states = [NSMutableDictionary dictionary];
        for (XinstaFeature *feature in self.features) {
            NSNumber *override = overrides[feature.identifier];
            BOOL enabled = override ? override.boolValue : feature.isEnabledByDefault;
            states[feature.identifier] = @(enabled);
        }
        return [states copy];
    }
}

- (BOOL)isEnabledForIdentifier:(NSString *)identifier {
    return [self.effectiveStates[identifier] boolValue];
}

- (void)setEnabled:(BOOL)enabled forIdentifier:(NSString *)identifier {
    @synchronized (self) {
        if (![self isKnownIdentifier:identifier]) {
            return;
        }
        NSMutableDictionary *overrides = [[self validatedOverrides] mutableCopy];
        overrides[identifier] = @(enabled);
        [self.userDefaults setObject:[overrides copy] forKey:XinstaFeatureOverrideKey];
    }
}

@end
