#include <stdio.h>
#import <Foundation/Foundation.h>
#import "XinstaFeature.h"
#import "XinstaFeatureRegistry.h"
#import "XinstaCompatibility.h"
#import "XinstaSettingsDataSource.h"

static NSUInteger gPassed = 0;
static NSUInteger gFailed = 0;

static void Expect(BOOL condition, NSString *description) {
    if (condition) {
        gPassed += 1;
    } else {
        gFailed += 1;
        fprintf(stderr, "FAIL: %s\n", description.UTF8String);
    }
}

static NSUserDefaults *CleanDefaults(void) {
    NSString *suite = [NSString stringWithFormat:@"XinstaCoreTests.%@", [NSUUID UUID].UUIDString];
    return [[NSUserDefaults alloc] initWithSuiteName:suite];
}

static XinstaFeatureRegistry *TestRegistry(NSUserDefaults *defaults) {
    NSArray *features = @[
        [[XinstaFeature alloc] initWithIdentifier:@"info"
                                            title:@"Build Information"
                                      description:@"Info"
                                 enabledByDefault:YES],
        [[XinstaFeature alloc] initWithIdentifier:@"demo.toggle"
                                            title:@"Demo Option"
                                      description:@"Demo"
                                 enabledByDefault:NO],
    ];
    return [[XinstaFeatureRegistry alloc] initWithFeatures:features userDefaults:defaults];
}

static void TestFeatureRegistration(void) {
    NSUserDefaults *defaults = CleanDefaults();
    XinstaFeatureRegistry *registry = TestRegistry(defaults);
    Expect(registry.features.count == 2, @"registry exposes both features");
    Expect([registry isEnabledForIdentifier:@"info"], @"default-enabled feature is on");
    Expect(![registry isEnabledForIdentifier:@"demo.toggle"], @"default-disabled feature is off");

    [registry setEnabled:YES forIdentifier:@"demo.toggle"];
    Expect([registry isEnabledForIdentifier:@"demo.toggle"], @"override enables a feature");

    XinstaFeatureRegistry *reloaded = TestRegistry(defaults);
    Expect([reloaded isEnabledForIdentifier:@"demo.toggle"], @"override survives a registry rebuild");
    Expect(reloaded.effectiveStates.count == 2, @"effective states cover all features");
}

static void TestSettingsBehaviour(void) {
    NSUserDefaults *defaults = CleanDefaults();
    XinstaFeatureRegistry *registry = TestRegistry(defaults);
    XinstaSettingsDataSource *source = [[XinstaSettingsDataSource alloc] initWithRegistry:registry];
    Expect(source.numberOfRows == 2, @"data source row count matches features");
    Expect([[source featureAtIndex:0].identifier isEqualToString:@"info"], @"row maps to feature");
    Expect([source isEnabledAtIndex:0], @"row reports default state");

    [source setEnabled:YES atIndex:1];
    Expect([source isEnabledAtIndex:1], @"toggle updates state");
    Expect(![source isEnabledAtIndex:99], @"out-of-range read is safe");
    [source setEnabled:YES atIndex:99];
    Expect(source.numberOfRows == 2, @"out-of-range write is a no-op");

    XinstaCompatibilityReport *report = [[XinstaCompatibilityReport alloc] initWithSupported:NO
                                                                                      reason:@"Blocked"
                                                                             missingSymbols:@[]];
    Expect([[source statusTextForReport:report] containsString:@"Inactive"], @"status reflects blocked adapter");
}

static void TestCompatibility(void) {
    XinstaSymbolAvailability allAvailable = ^BOOL(NSString *name) { return name.length > 0; };
    XinstaCompatibilityReport *ok = [XinstaCompatibility checkVersion:@"456.0.0"
                                                                build:@"1114925422"
                                                    symbolAvailability:allAvailable];
    Expect(ok.supported, @"matching version and build are supported");

    XinstaCompatibilityReport *badVersion = [XinstaCompatibility checkVersion:@"999.0.0"
                                                                        build:@"1114925422"
                                                            symbolAvailability:allAvailable];
    Expect(!badVersion.supported, @"wrong version is rejected");

    XinstaCompatibilityReport *badBuild = [XinstaCompatibility checkVersion:@"456.0.0"
                                                                      build:@"0"
                                                          symbolAvailability:allAvailable];
    Expect(!badBuild.supported, @"wrong build is rejected");

    XinstaCompatibilityReport *missing = [XinstaCompatibility checkVersion:@"456.0.0"
                                                                     build:@"1114925422"
                                                         symbolAvailability:^BOOL(NSString *name) {
                                                             return ![name isEqualToString:@"IGProfileSheetTableViewController"];
                                                         }];
    Expect(!missing.supported, @"missing symbol is rejected");
    Expect(missing.missingSymbols.count == 1, @"missing symbol is listed");
    Expect([missing.missingSymbols.firstObject isEqualToString:@"IGProfileSheetTableViewController"],
           @"missing symbol name is reported");
}

int main(void) {
    @autoreleasepool {
        TestFeatureRegistration();
        TestSettingsBehaviour();
        TestCompatibility();
        printf("XinstaCore tests: %lu passed, %lu failed\n",
               (unsigned long)gPassed, (unsigned long)gFailed);
    }
    return gFailed == 0 ? 0 : 1;
}
