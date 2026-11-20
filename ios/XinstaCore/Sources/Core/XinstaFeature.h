#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

/// A single, inert capability registered by Xinsta Core.
///
/// Features are data only. No feature performs injection, networking,
/// installation, or modification of another application in this increment.
@interface XinstaFeature : NSObject

@property (nonatomic, copy, readonly) NSString *identifier;
@property (nonatomic, copy, readonly) NSString *title;
@property (nonatomic, copy, readonly) NSString *featureDescription;
@property (nonatomic, assign, readonly, getter=isEnabledByDefault) BOOL enabledByDefault;

- (instancetype)initWithIdentifier:(NSString *)identifier
                             title:(NSString *)title
                       description:(NSString *)featureDescription
                  enabledByDefault:(BOOL)enabledByDefault NS_DESIGNATED_INITIALIZER;
- (instancetype)init NS_UNAVAILABLE;

@end

NS_ASSUME_NONNULL_END
