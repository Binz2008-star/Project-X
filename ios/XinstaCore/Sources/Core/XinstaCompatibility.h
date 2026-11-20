#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

typedef BOOL (^XinstaSymbolAvailability)(NSString *symbolName);

extern NSString * const XinstaCompatibilityReasonNotChecked;
extern NSString * const XinstaCompatibilityReasonAccepted;
extern NSString * const XinstaCompatibilityReasonMissingBundleIdentifier;
extern NSString * const XinstaCompatibilityReasonBundleIdentifierMismatch;
extern NSString * const XinstaCompatibilityReasonVersionMismatch;
extern NSString * const XinstaCompatibilityReasonBuildMismatch;
extern NSString * const XinstaCompatibilityReasonSymbolsUnavailable;

/// Stable, non-host-controlled outcome codes suitable for logging.
@interface XinstaCompatibilityReport : NSObject

@property (nonatomic, assign, readonly) BOOL supported;
@property (nonatomic, copy, readonly) NSString *reasonCode;
@property (nonatomic, copy, readonly) NSString *reason;
@property (nonatomic, copy, readonly) NSArray<NSString *> *missingSymbols;

- (instancetype)initWithSupported:(BOOL)supported
                       reasonCode:(NSString *)reasonCode
                           reason:(NSString *)reason
                  missingSymbols:(NSArray<NSString *> *)missingSymbols NS_DESIGNATED_INITIALIZER;
- (instancetype)init NS_UNAVAILABLE;

@end

/// Read-only compatibility gate for the Instagram 456.0.0 adapter.
///
/// This class compares host metadata and confirms that required Objective-C
/// names are visible at runtime. It performs no method modification; passing
/// this gate only records that a future, separately reviewed hook could be
/// considered for this exact host.
@interface XinstaCompatibility : NSObject

+ (NSString *)supportedBundleIdentifier;
+ (NSString *)supportedVersion;
+ (NSString *)supportedBuild;
+ (NSArray<NSString *> *)requiredSymbols;

+ (XinstaCompatibilityReport *)checkBundleIdentifier:(nullable NSString *)bundleIdentifier
                                              version:(nullable NSString *)version
                                                build:(nullable NSString *)build
                                    symbolAvailability:(nullable XinstaSymbolAvailability)availability;

@end

NS_ASSUME_NONNULL_END
