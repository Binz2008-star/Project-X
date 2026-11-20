#import <UIKit/UIKit.h>
#import "XinstaSettingsDataSource.h"
#import "XinstaIG456Adapter.h"

NS_ASSUME_NONNULL_BEGIN

/// Standalone X Settings screen. In a future increment, the version adapter
/// may present this controller from Instagram's own settings; this class makes
/// no assumptions about how it is shown and touches no Instagram object.
@interface XinstaSettingsViewController : UITableViewController

/// The only supported initializer. Inherited initializers are unavailable so
/// the screen can never be built without a data source and adapter.
- (instancetype)initWithDataSource:(XinstaSettingsDataSource *)dataSource
                           adapter:(XinstaIG456Adapter *)adapter;

- (instancetype)initWithStyle:(UITableViewStyle)style NS_UNAVAILABLE;
- (instancetype)initWithCoder:(NSCoder *)coder NS_UNAVAILABLE;
- (instancetype)initWithNibName:(nullable NSString *)nibNameOrNil
                         bundle:(nullable NSBundle *)nibBundleOrNil NS_UNAVAILABLE;

@end

NS_ASSUME_NONNULL_END
