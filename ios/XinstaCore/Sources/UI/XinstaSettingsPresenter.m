#import "XinstaSettingsPresenter.h"

@interface XinstaSettingsPresenter ()
@property (nonatomic, strong) XinstaIG456Adapter *adapter;
@property (nonatomic, strong) XinstaSettingsDataSource *dataSource;
@end

@implementation XinstaSettingsPresenter

- (instancetype)initWithAdapter:(XinstaIG456Adapter *)adapter
                     dataSource:(XinstaSettingsDataSource *)dataSource {
    self = [super init];
    if (self) {
        _adapter = adapter;
        _dataSource = dataSource;
    }
    return self;
}

- (BOOL)canPresent {
    if (![NSThread isMainThread]) {
        return NO;
    }
    if (!self.adapter.compatibilityAccepted || !self.adapter.targetRuntimeVerified) {
        return NO;
    }
    if (![self.dataSource.adapterIdentifier isEqualToString:[XinstaIG456Adapter adapterIdentifier]]) {
        return NO;
    }
    NSArray<XinstaFeature *> *features = self.dataSource.features;
    if (features.count == 0) {
        return NO;
    }
    for (XinstaFeature *feature in features) {
        if (![feature.adapterIdentifier isEqualToString:[XinstaIG456Adapter adapterIdentifier]]) {
            return NO;
        }
    }
    return YES;
}

- (nullable XinstaSettingsViewController *)makeSettingsViewController {
    if (!self.canPresent) {
        return nil;
    }
    return [[XinstaSettingsViewController alloc] initWithDataSource:self.dataSource
                                                            adapter:self.adapter];
}

- (BOOL)presentFromViewController:(UIViewController *)presenter
                         animated:(BOOL)animated
                       completion:(nullable void (^)(void))completion {
    if (![self canPresent] || !presenter || presenter.presentedViewController) {
        return NO;
    }
    XinstaSettingsViewController *settings = [self makeSettingsViewController];
    if (!settings) {
        return NO;
    }
    UINavigationController *navigation =
        [[UINavigationController alloc] initWithRootViewController:settings];
    [presenter presentViewController:navigation animated:animated completion:completion];
    return YES;
}

@end
