#import "XinstaSettingsDataSource.h"

@interface XinstaSettingsDataSource ()
@property (nonatomic, strong) XinstaFeatureRegistry *registry;
@end

@implementation XinstaSettingsDataSource

- (instancetype)initWithRegistry:(XinstaFeatureRegistry *)registry {
    self = [super init];
    if (self) {
        _registry = registry;
    }
    return self;
}

- (NSArray<XinstaFeature *> *)features {
    return self.registry.features;
}

- (NSUInteger)numberOfRows {
    return self.features.count;
}

- (XinstaFeature *)featureAtIndex:(NSUInteger)index {
    if (index >= self.features.count) {
        return nil;
    }
    return self.features[index];
}

- (BOOL)isEnabledAtIndex:(NSUInteger)index {
    XinstaFeature *feature = [self featureAtIndex:index];
    return feature ? [self.registry isEnabledForIdentifier:feature.identifier] : NO;
}

- (void)setEnabled:(BOOL)enabled atIndex:(NSUInteger)index {
    XinstaFeature *feature = [self featureAtIndex:index];
    if (feature) {
        [self.registry setEnabled:enabled forIdentifier:feature.identifier];
    }
}

- (NSString *)statusTextForReport:(XinstaCompatibilityReport *)report {
    if (!report) {
        return @"Adapter unavailable";
    }
    return report.supported ? [NSString stringWithFormat:@"Ready: %@", report.reason]
                            : [NSString stringWithFormat:@"Inactive: %@", report.reason];
}

@end
