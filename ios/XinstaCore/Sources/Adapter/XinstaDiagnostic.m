#import "XinstaDiagnostic.h"

@implementation XinstaDiagnostic

+ (XinstaInitializationStatus)statusForAdapter:(nullable XinstaIG456Adapter *)adapter
                                       registry:(nullable XinstaFeatureRegistry *)registry {
    @try {
        if (!adapter || !registry) {
            return XinstaInitializationStatusInvalidInput;
        }
        if (!adapter.compatibilityAccepted) {
            return XinstaInitializationStatusAdapterNotAccepted;
        }
        if (!adapter.targetRuntimeVerified) {
            return XinstaInitializationStatusTargetUnavailable;
        }

        NSString *expectedBinding = [XinstaIG456Adapter adapterIdentifier];
        if (![registry.adapterIdentifier isEqualToString:expectedBinding]) {
            return XinstaInitializationStatusBindingMismatch;
        }
        for (XinstaFeature *feature in registry.features) {
            if (![feature.adapterIdentifier isEqualToString:expectedBinding]) {
                return XinstaInitializationStatusBindingMismatch;
            }
        }
        if (registry.features.count == 0) {
            return XinstaInitializationStatusNoBoundFeatures;
        }
        return XinstaInitializationStatusReady;
    } @catch (NSException *exception) {
        (void)exception;
        return XinstaInitializationStatusInvalidInput;
    }
}

+ (NSString *)codeForStatus:(XinstaInitializationStatus)status {
    switch (status) {
        case XinstaInitializationStatusInvalidInput:
            return @"invalid_input";
        case XinstaInitializationStatusAdapterNotAccepted:
            return @"adapter_not_accepted";
        case XinstaInitializationStatusTargetUnavailable:
            return @"target_unavailable";
        case XinstaInitializationStatusBindingMismatch:
            return @"binding_mismatch";
        case XinstaInitializationStatusNoBoundFeatures:
            return @"no_bound_features";
        case XinstaInitializationStatusReady:
            return @"ready";
    }
    return @"invalid_input";
}

@end
