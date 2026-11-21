#import "XinstaFeature.h"

@implementation XinstaFeature

- (instancetype)initWithIdentifier:(NSString *)identifier
                              title:(NSString *)title
                        description:(NSString *)featureDescription
                   enabledByDefault:(BOOL)enabledByDefault
                  adapterIdentifier:(NSString *)adapterIdentifier {
    self = [super init];
    if (self) {
        _identifier = [identifier copy];
        _title = [title copy];
        _featureDescription = [featureDescription copy];
        _enabledByDefault = enabledByDefault;
        _adapterIdentifier = [adapterIdentifier copy];
    }
    return self;
}

- (NSString *)debugDescription {
    return [NSString stringWithFormat:@"<%@ %@ boundTo=%@>",
            NSStringFromClass(self.class), self.identifier, self.adapterIdentifier];
}

@end
