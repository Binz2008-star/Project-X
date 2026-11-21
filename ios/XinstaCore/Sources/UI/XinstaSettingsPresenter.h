#import <UIKit/UIKit.h>
#import "XinstaSettingsDataSource.h"
#import "XinstaIG456Adapter.h"
#import "XinstaSettingsViewController.h"

NS_ASSUME_NONNULL_BEGIN

/// Explicit, caller-driven presentation mechanism for X Settings.
///
/// This class does not swizzle, hook, inject, or discover a host view
/// controller. A future host integration must supply its own validated
/// `UIViewController`; presentation is refused unless the accepted adapter,
/// verified target runtime, and feature binding all match.
@interface XinstaSettingsPresenter : NSObject

- (instancetype)initWithAdapter:(XinstaIG456Adapter *)adapter
                     dataSource:(XinstaSettingsDataSource *)dataSource NS_DESIGNATED_INITIALIZER;
- (instancetype)init NS_UNAVAILABLE;

@property (nonatomic, assign, readonly) BOOL canPresent;

- (nullable XinstaSettingsViewController *)makeSettingsViewController;

/// Presents a navigation controller containing X Settings. Returns NO and does
/// nothing when the current context is not safe for presentation.
- (BOOL)presentFromViewController:(UIViewController *)presenter
                         animated:(BOOL)animated
                       completion:(nullable void (^)(void))completion;

@end

NS_ASSUME_NONNULL_END
