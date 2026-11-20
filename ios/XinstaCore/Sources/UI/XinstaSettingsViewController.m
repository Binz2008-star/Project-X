#import "XinstaSettingsViewController.h"

@interface XinstaSettingsViewController ()
@property (nonatomic, strong) XinstaSettingsDataSource *dataSource;
@property (nonatomic, strong) XinstaIG456Adapter *adapter;
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

- (void)viewDidLoad {
    [super viewDidLoad];
    UILabel *footer = [[UILabel alloc] initWithFrame:CGRectMake(0, 0, self.view.bounds.size.width, 44)];
    footer.text = [self.dataSource statusTextForReport:self.adapter.compatibilityReport];
    footer.textAlignment = NSTextAlignmentCenter;
    footer.textColor = [UIColor secondaryLabelColor];
    footer.font = [UIFont systemFontOfSize:13 weight:UIFontWeightRegular];
    footer.numberOfLines = 0;
    self.tableView.tableFooterView = footer;
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
    cell.textLabel.text = feature.title ?: @"";
    cell.detailTextLabel.text = feature.featureDescription;
    BOOL enabled = [self.dataSource isEnabledAtIndex:(NSUInteger)indexPath.row];
    UISwitch *toggle = [[UISwitch alloc] init];
    toggle.on = enabled;
    toggle.tag = (NSInteger)indexPath.row;
    [toggle addTarget:self action:@selector(toggleChanged:) forControlEvents:UIControlEventValueChanged];
    cell.accessoryView = toggle;
    return cell;
}

- (void)toggleChanged:(UISwitch *)sender {
    [self.dataSource setEnabled:sender.on atIndex:(NSUInteger)sender.tag];
}

@end
