#import <XCTest/XCTest.h>
#import <UIKit/UIKit.h>
#import <objc/message.h>

#import <XinstaCore/XinstaCompatibility.h>
#import <XinstaCore/XinstaFeature.h>
#import <XinstaCore/XinstaFeatureRegistry.h>
#import <XinstaCore/XinstaHostMetadata.h>
#import <XinstaCore/XinstaSettingsDataSource.h>
#import <XinstaAdapter/XinstaIG456Adapter.h>
#import <XinstaUI/XinstaSettingsViewController.h>

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
                                 enabledByDefault:YES],
        [[XinstaFeature alloc] initWithIdentifier:@"demo.toggle"
                                            title:@"Demo Option"
                                      description:@"Demo toggle row"
                                 enabledByDefault:NO],
    ];
    self.registry = [[XinstaFeatureRegistry alloc] initWithFeatures:features
                                                       userDefaults:self.defaults];
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
}

- (void)tearDown {
    [self.defaults removePersistentDomainForName:self.suiteName];
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
