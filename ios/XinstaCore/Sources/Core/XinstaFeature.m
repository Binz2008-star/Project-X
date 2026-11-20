#import "XinstaFeature.h"

@implementation XinstaFeature

- (instancetype)initWithIdentifier:(NSString *)identifier
                             title:(NSString *)title
                       description:(NSString *)featureDescription
                  enabledByDefault:(BOOL)enabledByDefault {
    self = [super init];
    if (self) {
        _identifier = [identifier copy];
        _title = [title copy];
        _featureDescription = [featureDescription copy];
        _enabledByDefault = enabledByDefault;
    }
    return self;
}

- (NSString *)debugDescription {
    return [NSString stringWithFormat:@"<%@ %@>", NSStringFromClass(self.class), self.identifier];
}

@end
