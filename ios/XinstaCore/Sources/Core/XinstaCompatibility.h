#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

typedef BOOL (^XinstaSymbolAvailability)(NSString *symbolName);

@interface XinstaCompatibilityReport : NSObject

@property (nonatomic, assign, readonly) BOOL supported;
@property (nonatomic, copy, readonly) NSString *reason;
@property (nonatomic, copy, readonly) NSArray<NSString *> *missingSymbols;

- (instancetype)initWithSupported:(BOOL)supported
                           reason:(NSString *)reason
                  missingSymbols:(NSArray<NSString *> *)missingSymbols NS_DESIGNATED_INITIALIZER;
- (instancetype)init NS_UNAVAILABLE;

@end

/// Version gate for the Instagram 456.0.0 adapter.
///
/// The symbols below were observed in a read-only scan of the owner-provided
/// reference IPA. They are not a claim that a hook works: runtime availability
/// is checked again before the adapter modifies any method implementation.
@interface XinstaCompatibility : NSObject

+ (NSString *)supportedVersion;
+ (NSString *)supportedBuild;
+ (NSArray<NSString *> *)requiredSymbols;

+ (XinstaCompatibilityReport *)checkVersion:(NSString *)version
                                       build:(NSString *)build
                           symbolAvailability:(XinstaSymbolAvailability)availability;

@end

NS_ASSUME_NONNULL_END
