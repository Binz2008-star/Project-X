#import <Foundation/Foundation.h>
#import "XinstaFeatureRegistry.h"
#import "XinstaCompatibility.h"

NS_ASSUME_NONNULL_BEGIN

/// Foundation-only model behind the X Settings screen. Kept free of UIKit so
/// feature registration and toggle behaviour can be tested on macOS as well
/// as compiled into the iOS dylib.
@interface XinstaSettingsDataSource : NSObject

- (instancetype)initWithRegistry:(XinstaFeatureRegistry *)registry NS_DESIGNATED_INITIALIZER;
- (instancetype)init NS_UNAVAILABLE;

@property (nonatomic, copy, readonly) NSArray<XinstaFeature *> *features;

- (NSUInteger)numberOfRows;
- (nullable XinstaFeature *)featureAtIndex:(NSUInteger)index;
- (BOOL)isEnabledAtIndex:(NSUInteger)index;
- (void)setEnabled:(BOOL)enabled atIndex:(NSUInteger)index;
- (NSString *)statusTextForReport:(nullable XinstaCompatibilityReport *)report;

@end

NS_ASSUME_NONNULL_END
