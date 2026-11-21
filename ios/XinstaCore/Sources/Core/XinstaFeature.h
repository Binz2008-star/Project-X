#import <Foundation/Foundation.h>
#import "XinstaCompatibility.h"

NS_ASSUME_NONNULL_BEGIN

/// A single, inert capability registered by Xinsta Core.
///
/// Features are data only. Every feature must declare the adapter it is bound
/// to. A feature that is not bound to the accepted adapter is never exposed to
/// settings or presentation code. No feature performs injection, networking,
/// installation, or modification of another application in this increment.
@interface XinstaFeature : NSObject

@property (nonatomic, copy, readonly) NSString *identifier;
@property (nonatomic, copy, readonly) NSString *title;
@property (nonatomic, copy, readonly) NSString *featureDescription;
@property (nonatomic, assign, readonly, getter=isEnabledByDefault) BOOL enabledByDefault;
@property (nonatomic, copy, readonly) NSString *adapterIdentifier;

- (instancetype)initWithIdentifier:(NSString *)identifier
                              title:(NSString *)title
                        description:(NSString *)featureDescription
                   enabledByDefault:(BOOL)enabledByDefault
                  adapterIdentifier:(NSString *)adapterIdentifier NS_DESIGNATED_INITIALIZER;
- (instancetype)init NS_UNAVAILABLE;

@end

NS_ASSUME_NONNULL_END
