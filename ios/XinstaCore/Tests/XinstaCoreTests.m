#include <stdio.h>
#import <Foundation/Foundation.h>

#import "XinstaFeature.h"
#import "XinstaFeatureRegistry.h"
#import "XinstaCompatibility.h"
#import "XinstaHostMetadata.h"
#import "XinstaSettingsDataSource.h"
#import "XinstaIG456Adapter.h"
#import "XinstaDiagnostic.h"
#import "XinstaCore.h"

static NSUInteger gPassed = 0;
static NSUInteger gFailed = 0;
static NSMutableArray<NSString *> *gSuiteNames;

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
    [gSuiteNames addObject:suite];
    return [[NSUserDefaults alloc] initWithSuiteName:suite];
}

static void RemoveTestDefaults(void) {
    for (NSString *suite in gSuiteNames) {
        NSUserDefaults *defaults = [[NSUserDefaults alloc] initWithSuiteName:suite];
        [defaults removePersistentDomainForName:suite];
    }
}

static XinstaFeature *Feature(NSString *identifier, NSString *title, BOOL enabled) {
    return [[XinstaFeature alloc] initWithIdentifier:identifier
                                               title:title
                                         description:title
                                    enabledByDefault:enabled
                                   adapterIdentifier:XinstaAdapterIdentifierIG456];
}

static XinstaFeatureRegistry *TestRegistry(NSUserDefaults *defaults) {
    NSArray *features = @[
        Feature(@"info", @"Build Information", YES),
        Feature(@"demo.toggle", @"Demo Option", NO),
    ];
    return [[XinstaFeatureRegistry alloc] initWithFeatures:features
                                               userDefaults:defaults
                                          adapterIdentifier:XinstaAdapterIdentifierIG456];
}

static XinstaHostMetadata *Metadata(NSString *bundleID, NSString *version, NSString *build) {
    return [[XinstaHostMetadata alloc] initWithBundleIdentifier:bundleID
                                                        version:version
                                                          build:build];
}

static XinstaHostMetadata *ValidMetadata(void) {
    return Metadata([XinstaCompatibility supportedBundleIdentifier],
                    [XinstaCompatibility supportedVersion],
                    [XinstaCompatibility supportedBuild]);
}

static XinstaSymbolAvailability AllSymbols(void) {
    return ^BOOL(NSString *name) { return name.length > 0; };
}

static void TestFeatureRegistration(void) {
    NSUserDefaults *defaults = CleanDefaults();
    XinstaFeatureRegistry *registry = TestRegistry(defaults);
    Expect(registry.features.count == 2, @"registry exposes both bound features");
    Expect([registry.adapterIdentifier isEqualToString:XinstaAdapterIdentifierIG456],
           @"registry records its adapter binding");
    Expect([registry.features.firstObject.adapterIdentifier isEqualToString:XinstaAdapterIdentifierIG456],
           @"feature carries the explicit adapter binding");
    Expect([registry isEnabledForIdentifier:@"info"], @"default-enabled feature is on");
    Expect(![registry isEnabledForIdentifier:@"demo.toggle"], @"default-disabled feature is off");

    [registry setEnabled:YES forIdentifier:@"demo.toggle"];
    Expect([registry isEnabledForIdentifier:@"demo.toggle"], @"override enables a feature");

    XinstaFeatureRegistry *reloaded = TestRegistry(defaults);
    Expect([reloaded isEnabledForIdentifier:@"demo.toggle"], @"override survives a registry rebuild");
    Expect(reloaded.effectiveStates.count == 2, @"effective states cover all bound features");
}

static void TestAdapterBindingFilter(void) {
    NSUserDefaults *defaults = CleanDefaults();
    XinstaFeature *bound = Feature(@"info", @"Build Information", YES);
    XinstaFeature *unbound = [[XinstaFeature alloc] initWithIdentifier:@"other"
                                                                 title:@"Other"
                                                           description:@"Other"
                                                      enabledByDefault:YES
                                                     adapterIdentifier:@"com.example.other"];
    XinstaFeatureRegistry *registry = [[XinstaFeatureRegistry alloc]
        initWithFeatures:@[bound, unbound]
             userDefaults:defaults
        adapterIdentifier:XinstaAdapterIdentifierIG456];
    Expect(registry.features.count == 1, @"features bound to another adapter are excluded");
    Expect(![registry isEnabledForIdentifier:@"other"], @"unbound feature state is unavailable");
    [registry setEnabled:YES forIdentifier:@"other"];
    Expect([defaults objectForKey:@"xinsta.core.featureOverrides"] == nil,
           @"unbound feature cannot write an override");
}

static void TestPersistenceHardening(void) {
    NSUserDefaults *defaults = CleanDefaults();
    [defaults setObject:@"not-a-dictionary" forKey:@"xinsta.core.featureOverrides"];
    XinstaFeatureRegistry *registry = TestRegistry(defaults);
    Expect([registry isEnabledForIdentifier:@"info"], @"malformed defaults fall back to feature default");
    Expect(![registry isEnabledForIdentifier:@"demo.toggle"], @"malformed defaults do not enable other features");

    [defaults setObject:@{ @"info": @"YES", @"unknown": @YES } forKey:@"xinsta.core.featureOverrides"];
    Expect([registry isEnabledForIdentifier:@"info"], @"wrong override type falls back to default");
    Expect(registry.effectiveStates.count == 2, @"unknown override key is ignored");

    [registry setEnabled:YES forIdentifier:@"demo.toggle"];
    NSDictionary *stored = [defaults dictionaryForKey:@"xinsta.core.featureOverrides"];
    Expect(stored.count == 1 && stored[@"demo.toggle"] != nil,
           @"unknown keys are dropped when overrides are written");

    [registry setEnabled:YES forIdentifier:@"unknown.feature"];
    Expect([defaults dictionaryForKey:@"xinsta.core.featureOverrides"].count == 1,
           @"unknown feature identifier is rejected");

    XinstaFeature *duplicate = Feature(@"info", @"Duplicate", NO);
    XinstaFeature *primary = Feature(@"info", @"Info", YES);
    NSUserDefaults *duplicateDefaults = CleanDefaults();
    XinstaFeatureRegistry *duplicateRegistry = [[XinstaFeatureRegistry alloc]
        initWithFeatures:@[primary, duplicate]
             userDefaults:duplicateDefaults
        adapterIdentifier:XinstaAdapterIdentifierIG456];
    Expect(duplicateRegistry.effectiveStates.count == 1, @"duplicate feature identifiers collapse to one state");
}

static void TestSettingsBehaviour(void) {
    NSUserDefaults *defaults = CleanDefaults();
    XinstaFeatureRegistry *registry = TestRegistry(defaults);
    XinstaSettingsDataSource *source = [[XinstaSettingsDataSource alloc] initWithRegistry:registry];
    Expect(source.numberOfRows == 2, @"data source row count matches features");
    Expect([[source featureAtIndex:0].identifier isEqualToString:@"info"], @"row maps to feature");
    Expect([source featureAtIndex:99] == nil, @"out-of-range feature is nil");
    Expect([source isEnabledAtIndex:0], @"row reports default state");
    Expect([source.adapterIdentifier isEqualToString:XinstaAdapterIdentifierIG456],
           @"data source exposes the adapter binding");
    Expect(source.currentFeatureStates.count == 2, @"fresh feature states are available");

    [source setEnabled:YES atIndex:1];
    Expect([source isEnabledAtIndex:1], @"toggle updates state");
    Expect(![source isEnabledAtIndex:99], @"out-of-range read is safe");
    [source setEnabled:YES atIndex:99];
    Expect(source.numberOfRows == 2, @"out-of-range write is a no-op");

    [defaults setObject:@{ @"demo.toggle": @NO } forKey:@"xinsta.core.featureOverrides"];
    Expect(![source isEnabledAtIndex:1], @"feature state is read freshly from storage");

    XinstaCompatibilityReport *report = [[XinstaCompatibilityReport alloc] initWithSupported:NO
                                                                                   reasonCode:@"blocked"
                                                                                       reason:@"Blocked"
                                                                              missingSymbols:@[]];
    Expect([[source statusTextForReport:report] containsString:@"Inactive"], @"status reflects blocked adapter");
    Expect([[source statusTextForReport:nil] containsString:@"unavailable"], @"nil report is handled");
}

static void TestCompatibility(void) {
    Expect([[XinstaCompatibility adapterIdentifier] isEqualToString:XinstaAdapterIdentifierIG456],
           @"adapter identifier is stable");
    Expect([[XinstaCompatibility targetClassName] isEqualToString:@"IGProfileSheetTableViewController"],
           @"target class is version-specific");
    Expect([XinstaCompatibility requiredSymbols].count == 4,
           @"required symbols include the target class and three selectors");

    XinstaCompatibilityReport *ok = [XinstaCompatibility checkBundleIdentifier:@"com.burbn.instagram"
                                                                        version:@"456.0.0"
                                                                          build:@"1114925422"
                                                              symbolAvailability:AllSymbols()];
    Expect(ok.supported, @"exact host identity and symbols are supported");
    Expect([ok.reasonCode isEqualToString:XinstaCompatibilityReasonAccepted], @"accepted reason code is stable");

    NSArray *rejections = @[
        [XinstaCompatibility checkBundleIdentifier:nil
                                            version:@"456.0.0"
                                              build:@"1114925422"
                                  symbolAvailability:AllSymbols()],
        [XinstaCompatibility checkBundleIdentifier:@"com.example.other"
                                            version:@"456.0.0"
                                              build:@"1114925422"
                                  symbolAvailability:AllSymbols()],
        [XinstaCompatibility checkBundleIdentifier:@"com.burbn.instagram"
                                            version:@"999.0.0"
                                              build:@"1114925422"
                                  symbolAvailability:AllSymbols()],
        [XinstaCompatibility checkBundleIdentifier:@"com.burbn.instagram"
                                            version:@"456.0.0"
                                              build:@"0"
                                  symbolAvailability:AllSymbols()],
    ];
    NSArray *expectedCodes = @[
        XinstaCompatibilityReasonMissingBundleIdentifier,
        XinstaCompatibilityReasonBundleIdentifierMismatch,
        XinstaCompatibilityReasonVersionMismatch,
        XinstaCompatibilityReasonBuildMismatch,
    ];
    for (NSUInteger i = 0; i < rejections.count; i += 1) {
        XinstaCompatibilityReport *rejection = rejections[i];
        Expect(!rejection.supported, @"unexpected host metadata is rejected");
        Expect([rejection.reasonCode isEqualToString:expectedCodes[i]], @"rejection reason code is stable");
    }

    XinstaCompatibilityReport *nilResolver = [XinstaCompatibility checkBundleIdentifier:@"com.burbn.instagram"
                                                                                 version:@"456.0.0"
                                                                                   build:@"1114925422"
                                                                       symbolAvailability:nil];
    Expect(!nilResolver.supported, @"nil symbol resolver fails closed");
    Expect(nilResolver.missingSymbols.count == 4, @"nil resolver reports every required symbol");
    Expect([nilResolver.reasonCode isEqualToString:XinstaCompatibilityReasonTargetUnavailable],
           @"missing target class has its own stable code");

    XinstaCompatibilityReport *missingClass = [XinstaCompatibility checkBundleIdentifier:@"com.burbn.instagram"
                                                                                   version:@"456.0.0"
                                                                                     build:@"1114925422"
                                                                         symbolAvailability:^BOOL(NSString *name) {
                                                                             return ![name isEqualToString:@"IGProfileSheetTableViewController"];
                                                                         }];
    Expect(!missingClass.supported, @"missing class is rejected");
    Expect(missingClass.missingSymbols.count == 1, @"missing class is listed once");
    Expect([missingClass.reasonCode isEqualToString:XinstaCompatibilityReasonTargetUnavailable],
           @"missing class reason code is stable");

    XinstaCompatibilityReport *missingSelector = [XinstaCompatibility checkBundleIdentifier:@"com.burbn.instagram"
                                                                                      version:@"456.0.0"
                                                                                        build:@"1114925422"
                                                                            symbolAvailability:^BOOL(NSString *name) {
                                                                                return ![name isEqualToString:@"tableView:didSelectRowAtIndexPath:"];
                                                                            }];
    Expect(!missingSelector.supported, @"missing selector is rejected");
    Expect([missingSelector.reasonCode isEqualToString:XinstaCompatibilityReasonSymbolsUnavailable],
           @"symbol failure reason code is stable");
}

static void TestAdapter(void) {
    __block NSUInteger calls = 0;
    XinstaSymbolAvailability counted = ^BOOL(NSString *name) {
        calls += 1;
        return name.length > 0;
    };
    XinstaIG456Adapter *accepted = [[XinstaIG456Adapter alloc] initWithHostMetadata:ValidMetadata()
                                                                 symbolAvailability:counted];
    Expect(!accepted.compatibilityAccepted, @"adapter begins unaccepted");
    Expect(!accepted.targetRuntimeVerified, @"adapter begins without a verified target");
    Expect([[XinstaIG456Adapter adapterIdentifier] isEqualToString:XinstaAdapterIdentifierIG456],
           @"adapter identifier matches the feature binding");
    Expect([accepted evaluateCompatibility], @"injected exact metadata is accepted");
    Expect(accepted.compatibilityAccepted, @"accepted state is exposed");
    Expect(accepted.targetRuntimeVerified, @"accepted evaluation verified the target class");
    NSUInteger callsAfterFirst = calls;
    Expect([accepted evaluateCompatibility], @"second evaluation is idempotent");
    Expect(calls == callsAfterFirst, @"idempotent evaluation does not rerun resolver");
    Expect(accepted.compatibilityReport == accepted.compatibilityReport, @"report getter is stable");

    XinstaIG456Adapter *wrongBundle = [[XinstaIG456Adapter alloc] initWithHostMetadata:Metadata(@"com.example.other", @"456.0.0", @"1114925422")
                                                                     symbolAvailability:AllSymbols()];
    Expect(![wrongBundle evaluateCompatibility], @"wrong bundle is rejected before symbols");
    Expect(!wrongBundle.targetRuntimeVerified, @"wrong bundle never verifies a target");
    Expect([wrongBundle.compatibilityReport.reasonCode isEqualToString:XinstaCompatibilityReasonBundleIdentifierMismatch],
           @"wrong bundle reason code is reported");

    XinstaIG456Adapter *wrongVersion = [[XinstaIG456Adapter alloc] initWithHostMetadata:Metadata(@"com.burbn.instagram", @"1.0", @"1114925422")
                                                                     symbolAvailability:AllSymbols()];
    Expect(![wrongVersion evaluateCompatibility], @"wrong version is rejected");
    XinstaIG456Adapter *wrongBuild = [[XinstaIG456Adapter alloc] initWithHostMetadata:Metadata(@"com.burbn.instagram", @"456.0.0", @"0")
                                                                   symbolAvailability:AllSymbols()];
    Expect(![wrongBuild evaluateCompatibility], @"wrong build is rejected");

    __block NSUInteger failedCalls = 0;
    XinstaSymbolAvailability onceFailing = ^BOOL(NSString *name) {
        (void)name;
        failedCalls += 1;
        return NO;
    };
    XinstaIG456Adapter *retried = [[XinstaIG456Adapter alloc] initWithHostMetadata:ValidMetadata()
                                                                symbolAvailability:onceFailing];
    Expect(![retried evaluateCompatibility], @"failed evaluation is rejected");
    Expect(![retried evaluateCompatibility], @"retry after failure remains rejected");
    Expect(!retried.targetRuntimeVerified, @"failed resolver never verifies a target");
    Expect(failedCalls > 0, @"failed resolver was invoked");
}

static void TestRuntimeSymbolLookup(void) {
    Expect([XinstaIG456Adapter runtimeSymbolAvailable:@"NSString" targetClassName:@"NSString"],
           @"runtime class lookup succeeds for a known class");
    Expect([XinstaIG456Adapter runtimeSymbolAvailable:@"length" targetClassName:@"NSString"],
           @"runtime selector lookup succeeds for a known selector");
    Expect(![XinstaIG456Adapter runtimeSymbolAvailable:@"definitelyMissingSelector" targetClassName:@"NSString"],
           @"unknown selector fails closed");
    Expect(![XinstaIG456Adapter runtimeSymbolAvailable:@"length" targetClassName:@"NoSuchRuntimeClassXYZ"],
           @"unknown class fails closed");
    Expect(![XinstaIG456Adapter runtimeSymbolAvailable:@"" targetClassName:@"NSString"],
           @"empty symbol name fails closed");
}

static void TestInitializationDiagnostic(void) {
    Expect([XinstaDiagnostic statusForAdapter:nil registry:nil] == XinstaInitializationStatusInvalidInput,
           @"nil inputs produce the fixed invalid-input status");
    Expect([[XinstaDiagnostic codeForStatus:XinstaInitializationStatusInvalidInput] isEqualToString:@"invalid_input"],
           @"invalid-input code is stable");

    NSUserDefaults *defaults = CleanDefaults();
    XinstaFeatureRegistry *registry = TestRegistry(defaults);
    XinstaIG456Adapter *unaccepted = [[XinstaIG456Adapter alloc] initWithHostMetadata:ValidMetadata()
                                                                   symbolAvailability:AllSymbols()];
    Expect([XinstaDiagnostic statusForAdapter:unaccepted registry:registry] == XinstaInitializationStatusAdapterNotAccepted,
           @"unaccepted adapter blocks initialization");

    [unaccepted evaluateCompatibility];
    Expect([XinstaDiagnostic statusForAdapter:unaccepted registry:registry] == XinstaInitializationStatusReady,
           @"accepted adapter with bound features is ready");

    XinstaFeatureRegistry *wrongBinding = [[XinstaFeatureRegistry alloc]
        initWithFeatures:@[Feature(@"info", @"Build Information", YES)]
             userDefaults:CleanDefaults()
        adapterIdentifier:@"com.example.other"];
    Expect([XinstaDiagnostic statusForAdapter:unaccepted registry:wrongBinding] == XinstaInitializationStatusBindingMismatch,
           @"adapter/feature binding mismatch is detected");

    XinstaFeatureRegistry *empty = [[XinstaFeatureRegistry alloc]
        initWithFeatures:@[]
             userDefaults:CleanDefaults()
        adapterIdentifier:XinstaAdapterIdentifierIG456];
    Expect([XinstaDiagnostic statusForAdapter:unaccepted registry:empty] == XinstaInitializationStatusNoBoundFeatures,
           @"no bound features blocks initialization");
}

static void TestLoadEntryPoint(void) {
    [XinstaCore evaluateAtLoad];
    XinstaCompatibilityReport *report = [XinstaIG456Adapter sharedAdapter].compatibilityReport;
    Expect(report != nil, @"load entry point populates a report");
    Expect(report.reasonCode.length > 0, @"load entry point records a stable reason code");
}

int main(void) {
    @autoreleasepool {
        gSuiteNames = [NSMutableArray array];
        TestFeatureRegistration();
        TestAdapterBindingFilter();
        TestPersistenceHardening();
        TestSettingsBehaviour();
        TestCompatibility();
        TestAdapter();
        TestRuntimeSymbolLookup();
        TestInitializationDiagnostic();
        TestLoadEntryPoint();
        RemoveTestDefaults();
        printf("XinstaCore tests: %lu passed, %lu failed\n",
               (unsigned long)gPassed, (unsigned long)gFailed);
    }
    return gFailed == 0 ? 0 : 1;
}
