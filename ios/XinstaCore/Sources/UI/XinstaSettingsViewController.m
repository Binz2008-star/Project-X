#import "XinstaSettingsViewController.h"

@interface XinstaSettingsViewController ()
@property (nonatomic, strong) XinstaSettingsDataSource *dataSource;
@property (nonatomic, strong) XinstaIG456Adapter *adapter;
@property (nonatomic, strong) UILabel *statusLabel;
- (void)refreshStatus;
@end

@implementation XinstaSettingsViewController

static NSString *const XinstaSettingsCellIdentifier = @"XinstaSettingsCell";

- (instancetype)initWithDataSource:(XinstaSettingsDataSource *)dataSource
                           adapter:(XinstaIG456Adapter *)adapter {
    self = [super initWithStyle:UITableViewStyleInsetGrouped];
    if (self) {
        _dataSource = dataSource;
        _adapter = adapter;
        self.title = @"X Settings";
    }
    return self;
}

- (instancetype)initWithStyle:(UITableViewStyle)style {
    (void)style;
    [NSException raise:NSInvalidArgumentException
                format:@"Use initWithDataSource:adapter: for XinstaSettingsViewController"];
    return nil;
}

- (instancetype)initWithCoder:(NSCoder *)coder {
    (void)coder;
    [NSException raise:NSInvalidArgumentException
                format:@"Use initWithDataSource:adapter: for XinstaSettingsViewController"];
    return nil;
}

- (instancetype)initWithNibName:(nullable NSString *)nibNameOrNil bundle:(nullable NSBundle *)nibBundleOrNil {
    (void)nibNameOrNil;
    (void)nibBundleOrNil;
    [NSException raise:NSInvalidArgumentException
                format:@"Use initWithDataSource:adapter: for XinstaSettingsViewController"];
    return nil;
}

- (void)viewDidLoad {
    [super viewDidLoad];

    UIView *footer = [[UIView alloc] initWithFrame:CGRectZero];
    UILabel *label = [[UILabel alloc] init];
    label.translatesAutoresizingMaskIntoConstraints = NO;
    label.text = [self.dataSource statusTextForReport:self.adapter.compatibilityReport];
    label.textAlignment = NSTextAlignmentCenter;
    label.textColor = [UIColor secondaryLabelColor];
    label.font = [UIFont systemFontOfSize:13 weight:UIFontWeightRegular];
    label.numberOfLines = 0;
    [footer addSubview:label];
    [NSLayoutConstraint activateConstraints:@[
        [label.leadingAnchor constraintEqualToAnchor:footer.leadingAnchor constant:16.0],
        [label.trailingAnchor constraintEqualToAnchor:footer.trailingAnchor constant:-16.0],
        [label.topAnchor constraintEqualToAnchor:footer.topAnchor constant:8.0],
        [label.bottomAnchor constraintEqualToAnchor:footer.bottomAnchor constant:-8.0],
    ]];

    CGFloat width = CGRectGetWidth(self.tableView.frame);
    if (width <= 0.0) {
        width = CGRectGetWidth(self.view.bounds);
    }
    CGSize fitted = [label sizeThatFits:CGSizeMake(MAX(width - 32.0, 0.0), CGFLOAT_MAX)];
    footer.frame = CGRectMake(0.0, 0.0, width, ceil(fitted.height) + 16.0);
    self.tableView.tableFooterView = footer;
    self.statusLabel = label;
    [self refreshStatus];
}

- (void)viewWillAppear:(BOOL)animated {
    [super viewWillAppear:animated];
    [self refreshStatus];
}

/// Reads adapter status and toggle states again from their owners instead of
/// keeping a cached snapshot in the controller.
- (void)refreshStatus {
    if (self.statusLabel) {
        self.statusLabel.text = [self.dataSource statusTextForReport:self.adapter.compatibilityReport];
    }
    [self.tableView reloadData];
}

#pragma mark - UITableViewDataSource

- (NSInteger)tableView:(UITableView *)tableView numberOfRowsInSection:(NSInteger)section {
    (void)tableView;
    (void)section;
    return (NSInteger)self.dataSource.numberOfRows;
}

- (UITableViewCell *)tableView:(UITableView *)tableView cellForRowAtIndexPath:(NSIndexPath *)indexPath {
    UITableViewCell *cell = [tableView dequeueReusableCellWithIdentifier:XinstaSettingsCellIdentifier];
    if (!cell) {
        cell = [[UITableViewCell alloc] initWithStyle:UITableViewCellStyleSubtitle
                                      reuseIdentifier:XinstaSettingsCellIdentifier];
    }

    XinstaFeature *feature = [self.dataSource featureAtIndex:(NSUInteger)indexPath.row];
    if (!feature) {
        cell.textLabel.text = @"";
        cell.detailTextLabel.text = nil;
        cell.accessoryView = nil;
        return cell;
    }

    cell.textLabel.text = feature.title;
    cell.detailTextLabel.text = feature.featureDescription;

    UISwitch *toggle;
    if ([cell.accessoryView isKindOfClass:[UISwitch class]]) {
        toggle = (UISwitch *)cell.accessoryView;
    } else {
        toggle = [[UISwitch alloc] init];
        [toggle addTarget:self action:@selector(toggleChanged:) forControlEvents:UIControlEventValueChanged];
        cell.accessoryView = toggle;
    }
    toggle.on = [self.dataSource isEnabledAtIndex:(NSUInteger)indexPath.row];
    toggle.tag = (NSInteger)indexPath.row;
    return cell;
}

- (void)toggleChanged:(UISwitch *)sender {
    [self.dataSource setEnabled:sender.on atIndex:(NSUInteger)sender.tag];
    [self.tableView reloadData];
}

@end
