#import "XinstaHostMetadata.h"

@implementation XinstaHostMetadata

+ (instancetype)metadataWithBundle:(NSBundle *)bundle {
    return [[self alloc] initWithBundleIdentifier:[bundle objectForInfoDictionaryKey:@"CFBundleIdentifier"]
                                          version:[bundle objectForInfoDictionaryKey:@"CFBundleShortVersionString"]
                                            build:[bundle objectForInfoDictionaryKey:@"CFBundleVersion"]];
}

- (instancetype)initWithBundleIdentifier:(NSString *)bundleIdentifier
                                 version:(NSString *)version
                                   build:(NSString *)build {
    self = [super init];
    if (self) {
        _bundleIdentifier = [bundleIdentifier copy];
        _version = [version copy];
        _build = [build copy];
    }
    return self;
}

@end
