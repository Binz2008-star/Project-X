#import <XCTest/XCTest.h>
#import <UIKit/UIKit.h>
#import <objc/message.h>

#import "XinstaCompatibility.h"
#import "XinstaFeature.h"
#import "XinstaFeatureRegistry.h"
#import "XinstaHostMetadata.h"
#import "XinstaSettingsDataSource.h"
#import "XinstaIG456Adapter.h"
#import "XinstaSettingsViewController.h"
#import "XinstaSettingsPresenter.h"

@interface XinstaSettingsViewController (XinstaTesting)
- (void)toggleChanged:(UISwitch *)sender;
@end

@interface XinstaSettingsViewControllerTests : XCTestCase

@property (nonatomic, copy) NSString *suiteName;
@property (nonatomic, strong) NSUserDefaults *defaults;
@property (nonatomic, strong) XinstaFeatureRegistry *registry;
@property (nonatomic, strong) XinstaSettingsDataSource *dataSource;
@property (nonatomic, strong) XinstaIG456Adapter *adapter;
@property (nonatomic, strong) XinstaSettingsViewController *controller;
@property (nonatomic, strong) UIWindow *window;
@property (nonatomic, strong) UIViewController *presenter;

@end

@implementation XinstaSettingsViewControllerTests

- (void)setUp {
    [super setUp];

    self.suiteName = [NSString stringWithFormat:@"XinstaUIKitTests.%@", [NSUUID UUID].UUIDString];
    self.defaults = [[NSUserDefaults alloc] initWithSuiteName:self.suiteName];

    NSArray *features = @[
        [[XinstaFeature alloc] initWithIdentifier:@"info"
                                            title:@"Build Information"
                                      description:@"Build information row"
                                 enabledByDefault:YES
                                adapterIdentifier:XinstaAdapterIdentifierIG456],
        [[XinstaFeature alloc] initWithIdentifier:@"demo.toggle"
                                            title:@"Demo Option"
                                      description:@"Demo toggle row"
                                 enabledByDefault:NO
                                adapterIdentifier:XinstaAdapterIdentifierIG456],
    ];
    self.registry = [[XinstaFeatureRegistry alloc] initWithFeatures:features
                                                        userDefaults:self.defaults
                                                   adapterIdentifier:XinstaAdapterIdentifierIG456];
    self.dataSource = [[XinstaSettingsDataSource alloc] initWithRegistry:self.registry];

    XinstaHostMetadata *metadata = [[XinstaHostMetadata alloc]
        initWithBundleIdentifier:[XinstaCompatibility supportedBundleIdentifier]
                         version:[XinstaCompatibility supportedVersion]
                           build:[XinstaCompatibility supportedBuild]];
    self.adapter = [[XinstaIG456Adapter alloc] initWithHostMetadata:metadata
                                                 symbolAvailability:^BOOL(NSString *symbolName) {
                                                     return symbolName.length > 0;
                                                 }];
    self.controller = [[XinstaSettingsViewController alloc] initWithDataSource:self.dataSource
                                                                        adapter:self.adapter];

    self.presenter = [[UIViewController alloc] init];
    self.window = [[UIWindow alloc] initWithFrame:[UIScreen mainScreen].bounds];
    self.window.rootViewController = self.presenter;
    [self.window makeKeyAndVisible];
}

- (void)tearDown {
    [self.defaults removePersistentDomainForName:self.suiteName];
    self.window.hidden = YES;
    self.window = nil;
    self.presenter = nil;
    self.controller = nil;
    self.adapter = nil;
    self.dataSource = nil;
    self.registry = nil;
    self.defaults = nil;
    [super tearDown];
}

- (void)testDesignatedInitializerAndFooterText {
    XCTAssertEqualObjects(self.controller.title, @"X Settings");
    [self.controller loadViewIfNeeded];

    UIView *footer = self.controller.tableView.tableFooterView;
    XCTAssertNotNil(footer);

    UILabel *statusLabel = nil;
    for (UIView *subview in footer.subviews) {
        if ([subview isKindOfClass:[UILabel class]]) {
            statusLabel = (UILabel *)subview;
            break;
        }
    }
    XCTAssertNotNil(statusLabel);
    XCTAssertEqualObjects(statusLabel.text,
                           [self.dataSource statusTextForReport:self.adapter.compatibilityReport]);
}

- (void)testRowCountAndCellConfiguration {
    [self.controller loadViewIfNeeded];

    NSInteger rows = [self.controller tableView:self.controller.tableView
                           numberOfRowsInSection:0];
    XCTAssertEqual(rows, (NSInteger)self.dataSource.numberOfRows);

    NSIndexPath *firstRow = [NSIndexPath indexPathForRow:0 inSection:0];
    UITableViewCell *cell = [self.controller tableView:self.controller.tableView
                                   cellForRowAtIndexPath:firstRow];
    XCTAssertNotNil(cell);
    XCTAssertEqualObjects(cell.textLabel.text, @"Build Information");
    XCTAssertTrue([cell.accessoryView isKindOfClass:[UISwitch class]]);
}

- (void)testToggleChangesDataSourceAndPersists {
    [self.controller loadViewIfNeeded];

    UISwitch *toggle = [[UISwitch alloc] init];
    toggle.tag = 1;
    toggle.on = YES;
    [self.controller toggleChanged:toggle];
    XCTAssertTrue([self.dataSource isEnabledAtIndex:1]);
    NSDictionary *stored = [self.defaults objectForKey:@"xinsta.core.featureOverrides"];
    XCTAssertTrue([stored[@"demo.toggle"] boolValue]);

    toggle.on = NO;
    [self.controller toggleChanged:toggle];
    XCTAssertFalse([self.dataSource isEnabledAtIndex:1]);
}

- (void)testOutOfRangeRowsAreSafe {
    [self.controller loadViewIfNeeded];

    XCTAssertNil([self.dataSource featureAtIndex:99]);
    XCTAssertFalse([self.dataSource isEnabledAtIndex:99]);

    NSIndexPath *outOfRange = [NSIndexPath indexPathForRow:99 inSection:0];
    UITableViewCell *cell = nil;
    XCTAssertNoThrow(cell = [self.controller tableView:self.controller.tableView
                                  cellForRowAtIndexPath:outOfRange]);
    XCTAssertNotNil(cell);
    XCTAssertEqualObjects(cell.textLabel.text, @"");
    XCTAssertNil(cell.accessoryView);
}

- (void)testPresenterFailsClosedBeforeAdapterAcceptance {
    XinstaSettingsPresenter *presenter =
        [[XinstaSettingsPresenter alloc] initWithAdapter:self.adapter
                                              dataSource:self.dataSource];
    XCTAssertFalse(presenter.canPresent);
    XCTAssertNil([presenter makeSettingsViewController]);
    XCTAssertFalse([presenter presentFromViewController:self.presenter
                                              animated:NO
                                            completion:nil]);
    XCTAssertNil(self.presenter.presentedViewController);
}

- (void)testPresenterShowsSettingsAfterAcceptance {
    XCTAssertTrue([self.adapter evaluateCompatibility]);
    XinstaSettingsPresenter *presenter =
        [[XinstaSettingsPresenter alloc] initWithAdapter:self.adapter
                                              dataSource:self.dataSource];
    XCTAssertTrue(presenter.canPresent);
    XCTAssertTrue([presenter presentFromViewController:self.presenter
                                              animated:NO
                                            completion:nil]);
    XCTAssertTrue([self.presenter.presentedViewController isKindOfClass:[UINavigationController class]]);
    UINavigationController *navigation = (UINavigationController *)self.presenter.presentedViewController;
    XCTAssertTrue([navigation.topViewController isKindOfClass:[XinstaSettingsViewController class]]);
}

- (void)testPresenterFailsClosedWhenTargetIsMissing {
    XinstaHostMetadata *metadata = [[XinstaHostMetadata alloc]
        initWithBundleIdentifier:[XinstaCompatibility supportedBundleIdentifier]
                         version:[XinstaCompatibility supportedVersion]
                           build:[XinstaCompatibility supportedBuild]];
    XinstaIG456Adapter *missingTarget = [[XinstaIG456Adapter alloc]
        initWithHostMetadata:metadata
           symbolAvailability:^BOOL(NSString *symbolName) {
               return ![symbolName isEqualToString:[XinstaCompatibility targetClassName]];
           }];
    XCTAssertFalse([missingTarget evaluateCompatibility]);
    XinstaSettingsPresenter *presenter =
        [[XinstaSettingsPresenter alloc] initWithAdapter:missingTarget
                                              dataSource:self.dataSource];
    XCTAssertFalse(presenter.canPresent);
    XCTAssertFalse([presenter presentFromViewController:self.presenter
                                              animated:NO
                                            completion:nil]);
    XCTAssertNil(self.presenter.presentedViewController);
}

- (void)testInheritedInitializersAreRejected {
    [self assertInvalidArgumentRaisedBy:^{
        id (*send)(id, SEL, UITableViewStyle) =
            (id (*)(id, SEL, UITableViewStyle))objc_msgSend;
        __unused id result = send([XinstaSettingsViewController alloc],
                                  NSSelectorFromString(@"initWithStyle:"),
                                  UITableViewStylePlain);
    } description:@"initWithStyle: must be rejected"];

    [self assertInvalidArgumentRaisedBy:^{
        id (*send)(id, SEL, id) = (id (*)(id, SEL, id))objc_msgSend;
        __unused id result = send([XinstaSettingsViewController alloc],
                                  NSSelectorFromString(@"initWithCoder:"),
                                  nil);
    } description:@"initWithCoder: must be rejected"];

    [self assertInvalidArgumentRaisedBy:^{
        id (*send)(id, SEL, id, id) = (id (*)(id, SEL, id, id))objc_msgSend;
        __unused id result = send([XinstaSettingsViewController alloc],
                                  NSSelectorFromString(@"initWithNibName:bundle:"),
                                  nil,
                                  nil);
    } description:@"initWithNibName:bundle: must be rejected"];
}

- (void)assertInvalidArgumentRaisedBy:(void (^)(void))block
                           description:(NSString *)description {
    BOOL raisedExpectedException = NO;
    @try {
        block();
    } @catch (NSException *exception) {
        raisedExpectedException = [exception.name isEqualToString:NSInvalidArgumentException];
    }
    XCTAssertTrue(raisedExpectedException, @"%@", description);
}

@end
