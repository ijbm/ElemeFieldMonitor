/**
 * ElemeFieldMonitor - 饿了么字段监控悬浮窗 Tweak
 *
 * 功能: Hook NSJSONSerialization 和 NSURLSession，拦截网络请求/响应中的
 *       encryptSceneCode, encryptActCode, rightId, sourceFrom, sceneCode, actCode
 *       并在悬浮窗中实时显示。
 *
 * 目标应用: me.ele.ios.eleme (饿了么/淘宝闪购)
 * 最低系统: iOS 15.0
 * 架构: arm64
 */

#import <UIKit/UIKit.h>
#import <Foundation/Foundation.h>
#import <objc/runtime.h>
#import <sys/socket.h>
#import <netinet/in.h>
#import <arpa/inet.h>
#import <unistd.h>

// ============================================================================
// MARK: - 目标字段定义
// ============================================================================

static NSArray *kTargetKeys(void) {
    static NSArray *keys = nil;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        keys = @[
            @"encryptSceneCode",
            @"encryptActCode",
            @"rightId",
            @"sourceFrom",
            @"sceneCode",
            @"actCode",
            @"pagePath"
        ];
    });
    return keys;
}

// 需要完整记录请求/响应的目标 API
static NSArray *kTargetAPIs(void) {
    static NSArray *apis = nil;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        apis = @[
            @"mtop.alsc.upp.lottery.act.consult",
            @"mtop.alsc.upp.lottery.act.lottery",
            @"mtop.alsc.upp.market.timelimitdraw.consultunit",
            @"mtop.alsc.upp.market.timelimitdraw.draw"
        ];
    });
    return apis;
}

static BOOL isTargetAPI(NSString *api) {
    if (!api || api.length == 0) return NO;
    for (NSString *target in kTargetAPIs()) {
        if ([api containsString:target]) return YES;
    }
    return NO;
}

// 从 URL 中提取 API 名称
static NSString *extractAPIFromURL(NSURL *url) {
    if (!url) return nil;
    NSString *path = url.absoluteString;
    for (NSString *target in kTargetAPIs()) {
        if ([path containsString:target]) return target;
    }
    // 也检查通用 mtop. 模式
    NSRange mtopRange = [path rangeOfString:@"mtop."];
    if (mtopRange.location != NSNotFound) {
        NSString *apiPart = [path substringFromIndex:mtopRange.location];
        NSRange endRange = [apiPart rangeOfString:@"[&/?]" options:NSRegularExpressionSearch];
        if (endRange.location != NSNotFound) {
            return [apiPart substringToIndex:endRange.location];
        }
        return apiPart;
    }
    return nil;
}

// 缓存最近的 URL，用于关联 MTOP 请求
static NSString *g_lastURL = nil;
static NSString *g_lastMethod = nil;
static NSDictionary *g_lastHeaders = nil;
static NSInteger g_lastStatusCode = 0;
static NSString *g_lastResponseAPI = nil;

// captureRequestIfNeeded 函数声明在 FloatWindowManager 接口之后

// ============================================================================
// MARK: - 字段搜索工具
// ============================================================================

@interface FieldHunter : NSObject
/** 递归搜索 JSON 对象中的目标字段 */
+ (void)searchInObject:(id)obj results:(NSMutableDictionary *)results;
/** 搜索 URL query 参数中的目标字段 */
+ (void)searchInURL:(NSURL *)url results:(NSMutableDictionary *)results;
/** 搜索 HTTP body (JSON) 中的目标字段 */
+ (void)searchInBody:(NSData *)body results:(NSMutableDictionary *)results;
+ (void)searchInHeaders:(NSDictionary *)headers results:(NSMutableDictionary *)results;
/** 验证值是否有效 (过滤模板变量等) */
+ (BOOL)isValidValue:(NSString *)str;
@end

@implementation FieldHunter

+ (BOOL)isValidValue:(NSString *)str {
    if (!str || str.length == 0) return NO;
    if ([str isEqualToString:@"(null)"]) return NO;
    // 过滤 Mist 模板变量
    if ([str hasPrefix:@"$:"]) return NO;
    if ([str hasPrefix:@"@query."]) return NO;
    if ([str hasPrefix:@"@path."]) return NO;
    if ([str hasPrefix:@"${"]) return NO;
    // 过滤过于短的值 (单字符如 "new" "all" 对 sceneCode 无意义)
    // 但 rightId/actCode 可能是短数字，所以只过滤空和模板
    return YES;
}

+ (void)searchInObject:(id)obj results:(NSMutableDictionary *)results {
    if (!obj || !results) return;

    if ([obj isKindOfClass:[NSDictionary class]]) {
        NSDictionary *dict = (NSDictionary *)obj;
        for (NSString *key in dict.allKeys) {
            if (![key isKindOfClass:[NSString class]]) continue;
            // 大小写不敏感匹配目标字段
            NSString *lowerKey = [key lowercaseString];
            NSString *matchedTarget = nil;
            for (NSString *target in kTargetKeys()) {
                if ([lowerKey isEqualToString:[target lowercaseString]]) {
                    matchedTarget = target;
                    break;
                }
            }
            if (matchedTarget) {
                id value = dict[key];
                if (value && ![value isKindOfClass:[NSNull class]]) {
                    NSString *strValue = [NSString stringWithFormat:@"%@", value];
                    if ([self isValidValue:strValue]) {
                        // 不覆盖已找到的真实值
                        if (!results[matchedTarget]) {
                            results[matchedTarget] = strValue;
                        }
                    }
                }
            }
        }
        // 递归搜索所有子节点
        for (id value in dict.allValues) {
            [self searchInObject:value results:results];
        }
    } else if ([obj isKindOfClass:[NSArray class]]) {
        for (id item in (NSArray *)obj) {
            [self searchInObject:item results:results];
        }
    }
}

+ (void)searchInURL:(NSURL *)url results:(NSMutableDictionary *)results {
    if (!url) return;
    NSString *query = url.query;
    if (!query || query.length == 0) return;

    NSArray *pairs = [query componentsSeparatedByString:@"&"];
    for (NSString *pair in pairs) {
        NSArray *kv = [pair componentsSeparatedByString:@"="];
        if (kv.count >= 2) {
            NSString *key = [kv[0] stringByRemovingPercentEncoding];
            NSString *value = [[kv subarrayWithRange:NSMakeRange(1, kv.count - 1)]
                componentsJoinedByString:@"="];
            value = [value stringByRemovingPercentEncoding];
            // 大小写不敏感匹配
            NSString *lowerKey = [key lowercaseString];
            NSString *matchedTarget = nil;
            for (NSString *target in kTargetKeys()) {
                if ([lowerKey isEqualToString:[target lowercaseString]]) {
                    matchedTarget = target;
                    break;
                }
            }
            if (matchedTarget && [self isValidValue:value]) {
                if (!results[matchedTarget]) {
                    results[matchedTarget] = value;
                }
            }
        }
    }
}

+ (void)searchInBody:(NSData *)body results:(NSMutableDictionary *)results {
    if (!body || body.length == 0) return;
    
    // 先尝试 JSON 解析
    NSError *err = nil;
    id json = [NSJSONSerialization JSONObjectWithData:body
                                             options:NSJSONReadingAllowFragments
                                               error:&err];
    if (json && !err) {
        [self searchInObject:json results:results];
        return;
    }
    
    // 尝试从 JSONP 响应中提取 JSON (如 kangaroo({...}) 或 callback({...}))
    NSString *bodyStr = [[NSString alloc] initWithData:body encoding:NSUTF8StringEncoding];
    if (bodyStr && bodyStr.length > 0) {
        // JSONP 格式: prefix({...json...})  或  prefix({...json...})
        NSRange parenStart = [bodyStr rangeOfString:@"("];
        if (parenStart.location != NSNotFound) {
            // 从最后一个 ) 往前找
            NSRange parenEnd = [bodyStr rangeOfString:@")" options:NSBackwardsSearch];
            if (parenEnd.location != NSNotFound && parenEnd.location > parenStart.location) {
                NSString *jsonContent = [bodyStr substringWithRange:NSMakeRange(parenStart.location + 1, parenEnd.location - parenStart.location - 1)];
                NSData *jsonData = [jsonContent dataUsingEncoding:NSUTF8StringEncoding];
                if (jsonData) {
                    id jsonpJson = [NSJSONSerialization JSONObjectWithData:jsonData
                                                                   options:NSJSONReadingAllowFragments
                                                                     error:nil];
                    if (jsonpJson) {
                        [self searchInObject:jsonpJson results:results];
                        return;
                    }
                }
            }
        }
        
        // 尝试 form-encoded 解析 (application/x-www-form-urlencoded)
        if ([bodyStr containsString:@"="] && ([bodyStr containsString:@"&"] || [bodyStr componentsSeparatedByString:@"="].count == 2)) {
            NSArray *pairs = [bodyStr componentsSeparatedByString:@"&"];
            for (NSString *pair in pairs) {
                NSArray *kv = [pair componentsSeparatedByString:@"="];
                if (kv.count >= 2) {
                    NSString *key = [kv[0] stringByRemovingPercentEncoding];
                    NSString *value = [[kv subarrayWithRange:NSMakeRange(1, kv.count - 1)]
                        componentsJoinedByString:@"="];
                    value = [value stringByRemovingPercentEncoding];
                    // 大小写不敏感匹配
                    NSString *lowerKey = [key lowercaseString];
                    NSString *matchedTarget = nil;
                    for (NSString *target in kTargetKeys()) {
                        if ([lowerKey isEqualToString:[target lowercaseString]]) {
                            matchedTarget = target;
                            break;
                        }
                    }
                    if (matchedTarget && [self isValidValue:value]) {
                        if (!results[matchedTarget]) {
                            results[matchedTarget] = value;
                        }
                    }
                    // value 可能是嵌套 JSON 字符串 (如 data={"actCode":"xxx",...})
                    // 尝试对 value 做 JSON 解析并递归搜索
                    if ([value hasPrefix:@"{"] || [value hasPrefix:@"["]) {
                        @try {
                            NSData *nestedData = [value dataUsingEncoding:NSUTF8StringEncoding];
                            id nestedJson = [NSJSONSerialization JSONObjectWithData:nestedData
                                                                          options:NSJSONReadingAllowFragments
                                                                            error:nil];
                            if (nestedJson) {
                                [self searchInObject:nestedJson results:results];
                            }
                        } @catch (NSException *e) {}
                    }
                }
            }
        }
        // 也尝试在纯文本中搜索字段名 (如 "encryptSceneCode":"xxx" 或 encryptSceneCode=xxx)
        for (NSString *target in kTargetKeys()) {
            if (results[target]) continue; // 已找到就跳过
            // 搜索 "key":"value" 模式 - 用简单字符串搜索避免转义问题
            NSString *quote = [NSString stringWithFormat:@"\"%@\":\"", target];
            NSRange qRange = [bodyStr rangeOfString:quote options:NSCaseInsensitiveSearch];
            if (qRange.location != NSNotFound) {
                NSUInteger valStart = qRange.location + qRange.length;
                NSRange endQuote = [bodyStr rangeOfString:@"\"" options:0 range:NSMakeRange(valStart, bodyStr.length - valStart)];
                if (endQuote.location != NSNotFound) {
                    NSString *val = [bodyStr substringWithRange:NSMakeRange(valStart, endQuote.location - valStart)];
                    if ([self isValidValue:val]) {
                        results[target] = val;
                        continue;
                    }
                }
            }
            // 搜索 key=value 模式 (form-encoded 或 URL 参数)
            NSString *eq = [NSString stringWithFormat:@"%@=", target];
            NSRange eqRange = [bodyStr rangeOfString:eq options:NSCaseInsensitiveSearch];
            if (eqRange.location != NSNotFound) {
                NSUInteger valStart = eqRange.location + eqRange.length;
                // 找到值结束位置 (& 或换行 或 结尾)
                NSUInteger valEnd = bodyStr.length;
                NSRange ampRange = [bodyStr rangeOfString:@"&" options:0 range:NSMakeRange(valStart, bodyStr.length - valStart)];
                if (ampRange.location != NSNotFound) valEnd = ampRange.location;
                NSRange nlRange = [bodyStr rangeOfString:@"\n" options:0 range:NSMakeRange(valStart, bodyStr.length - valStart)];
                if (nlRange.location != NSNotFound && nlRange.location < valEnd) valEnd = nlRange.location;
                NSString *val = [bodyStr substringWithRange:NSMakeRange(valStart, valEnd - valStart)];
                val = [val stringByRemovingPercentEncoding];
                if ([self isValidValue:val]) {
                    results[target] = val;
                }
            }
        }
    }
}

+ (void)searchInHeaders:(NSDictionary *)headers results:(NSMutableDictionary *)results {
    if (!headers || headers.count == 0) return;
    for (NSString *hKey in headers.allKeys) {
        if (![hKey isKindOfClass:[NSString class]]) continue;
        NSString *lowerKey = [hKey lowercaseString];
        NSString *matchedTarget = nil;
        for (NSString *target in kTargetKeys()) {
            if ([lowerKey isEqualToString:[target lowercaseString]]) {
                matchedTarget = target;
                break;
            }
        }
        if (matchedTarget) {
            NSString *value = [NSString stringWithFormat:@"%@", headers[hKey]];
            if ([self isValidValue:value]) {
                if (!results[matchedTarget]) {
                    results[matchedTarget] = value;
                }
            }
        }
    }
}

@end

// ============================================================================
// MARK: - 悬浮窗管理器
// ============================================================================

@interface FloatWindowManager : NSObject

@property (nonatomic, strong) UIWindow *window;
@property (nonatomic, strong) UIView *containerView;
@property (nonatomic, strong) UIView *headerView;
@property (nonatomic, strong) UIView *footerView;
@property (nonatomic, strong) UIView *tabBarView;
@property (nonatomic, strong) UIScrollView *fieldsScrollView;
@property (nonatomic, strong) UIScrollView *harScrollView;
@property (nonatomic, strong) UIScrollView *mcpScrollView;
@property (nonatomic, strong) UIButton *tabFieldsBtn;
@property (nonatomic, strong) UIButton *tabHarBtn;
@property (nonatomic, strong) UIButton *tabMcpBtn;
@property (nonatomic, strong) UIView *tabFieldsIndicator;
@property (nonatomic, strong) UIView *tabHarIndicator;
@property (nonatomic, strong) UIView *tabMcpIndicator;
@property (nonatomic, assign) NSInteger activeTab; // 0=fields, 1=har, 2=mcp
@property (nonatomic, strong) UIView *detailOverlayView;

@property (nonatomic, strong) UILabel *titleLabel;
@property (nonatomic, strong) UILabel *statusLabel;
@property (nonatomic, strong) UILabel *apiLabel;
@property (nonatomic, strong) UIButton *closeButton;

@property (nonatomic, strong) NSMutableDictionary<NSString *, UILabel *> *fieldLabels;
@property (nonatomic, strong) NSMutableDictionary<NSString *, NSString *> *fieldValues;
@property (nonatomic, strong) NSMutableDictionary<NSString *, NSString *> *fieldSources;

@property (nonatomic, assign) NSInteger captureCount;
@property (nonatomic, strong) NSString *lastAPI;
@property (nonatomic, strong) NSString *lastSource;
@property (nonatomic, strong) NSDate *lastUpdate;

@property (nonatomic, strong) UIButton *exportBtn;
@property (nonatomic, strong) UIButton *clearButton;
@property (nonatomic, strong) UIButton *collapseBtn;
@property (nonatomic, strong) UIButton *harExportBtn;
@property (nonatomic, strong) UIButton *cookieCopyBtn;
@property (nonatomic, strong) UILabel *urlLabel;
@property (nonatomic, strong) UILabel *cookieLabel;
@property (nonatomic, strong) NSString *lastURL;
@property (nonatomic, strong) NSString *lastCookie;
@property (nonatomic, assign) BOOL collapsed;
@property (nonatomic, strong) NSMutableArray *pendingRequests; // 每个 pending 请求 dict, 含 _api key
@property (nonatomic, strong) NSMutableArray *harEntries;
@property (nonatomic, strong) UITextField *harSearchField;
@property (nonatomic, strong) NSString *harSearchQuery;

+ (instancetype)sharedInstance;
- (void)show;
- (void)hide;
- (void)toggle;
- (void)toggleCollapse;
- (void)updateWithDictionary:(NSDictionary *)dict source:(NSString *)source api:(NSString *)api;
- (void)updateURL:(NSString *)url;
- (void)updateCookie:(NSString *)cookie;
- (void)copyAllToClipboard;
- (void)copyCookieToClipboard;
- (void)exportHAR;
- (void)recordAPIRequest:(NSString *)api url:(NSString *)url method:(NSString *)method headers:(NSDictionary *)headers body:(NSString *)body;
- (void)recordAPIResponse:(NSString *)api response:(NSString *)response statusCode:(NSInteger)code;
- (void)switchTab:(NSInteger)tabIndex;
- (void)refreshHarList;
- (void)tabFieldsTapped;
- (void)tabHarTapped;
- (void)tabMcpTapped;
- (void)clearHar;
- (void)showHarDetail:(NSDictionary *)entry;
- (void)dismissHarDetail;
- (void)handleHarCardTap:(UITapGestureRecognizer *)gesture;
- (void)copyHarRequest:(UIButton *)btn;
- (void)copyHarResponse:(UIButton *)btn;
- (void)harSearchChanged:(UITextField *)field;

@end

// 从请求中提取完整信息并记录（需要在 FloatWindowManager 接口声明之后）
static void captureRequestIfNeeded(NSURLRequest *request) {
    if (!request) return;
    NSURL *url = request.URL;
    NSString *api = extractAPIFromURL(url);
    
    // 也从 body 提取 API
    if (!api) {
        NSData *body = request.HTTPBody;
        if (body && body.length > 0) {
            @try {
                id bodyJson = [NSJSONSerialization JSONObjectWithData:body options:NSJSONReadingAllowFragments error:nil];
                if ([bodyJson isKindOfClass:[NSDictionary class]]) {
                    api = bodyJson[@"api"] ?: bodyJson[@"apiName"];
                }
            } @catch (NSException *e) {}
        }
    }
    
    // 没有 MTOP API 名时，使用 URL path 作为标识符，确保所有请求都被记录
    if (!api || api.length == 0) {
        if (url) {
            NSString *path = url.path ?: @"";
            NSString *host = url.host ?: @"";
            if (path.length > 0) {
                api = [NSString stringWithFormat:@"%@%@", host, path];
            } else {
                api = host.length > 0 ? host : url.absoluteString;
            }
        } else {
            return;
        }
    }
    
    NSString *bodyStr = @"-";
    NSData *body = request.HTTPBody;
    if (body) {
        bodyStr = [[NSString alloc] initWithData:body encoding:NSUTF8StringEncoding] ?: @"-";
    }
    
    [[FloatWindowManager sharedInstance] recordAPIRequest:api
                                                      url:url.absoluteString
                                                   method:request.HTTPMethod ?: @"GET"
                                                  headers:request.allHTTPHeaderFields ?: @{}
                                                     body:bodyStr];
    NSLog(@"[ElemeFieldMonitor] Request captured: %@", api);
}

@implementation FloatWindowManager

+ (instancetype)sharedInstance {
    static FloatWindowManager *instance = nil;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        instance = [[FloatWindowManager alloc] init];
    });
    return instance;
}

- (instancetype)init {
    self = [super init];
    if (self) {
        _fieldLabels = [NSMutableDictionary dictionary];
        _fieldValues = [NSMutableDictionary dictionary];
        _fieldSources = [NSMutableDictionary dictionary];
        _captureCount = 0;
        _lastSource = @"-";
        _lastAPI = @"-";
        _lastURL = @"-";
        _lastCookie = @"-";
        _pendingRequests = [NSMutableArray array];
        _harEntries = [NSMutableArray array];
        // 延迟创建窗口，确保 UIApplication 已就绪
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(0.5 * NSEC_PER_SEC)),
                       dispatch_get_main_queue(), ^{
            [self setupWindow];
        });
    }
    return self;
}

- (void)setupWindow {
    // 获取活跃的 UIWindowScene
    UIWindowScene *scene = nil;
    for (UIScene *s in [UIApplication sharedApplication].connectedScenes.allObjects) {
        if (s.activationState == UISceneActivationStateForegroundActive &&
            [s isKindOfClass:[UIWindowScene class]]) {
            scene = (UIWindowScene *)s;
            break;
        }
    }
    if (!scene) {
        // fallback: 尝试获取任意 windowScene
        for (UIScene *s in [UIApplication sharedApplication].connectedScenes.allObjects) {
            if ([s isKindOfClass:[UIWindowScene class]]) {
                scene = (UIWindowScene *)s;
                break;
            }
        }
    }
    if (!scene) {
        NSLog(@"[ElemeFieldMonitor] No UIWindowScene found, retrying...");
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(1.0 * NSEC_PER_SEC)),
                       dispatch_get_main_queue(), ^{
            [self setupWindow];
        });
        return;
    }

    CGFloat windowW = 360;
    CGFloat windowH = 460;
    CGFloat startX = 10;
    CGFloat startY = 100;
    CGFloat sidePad = 10;

    self.window = [[UIWindow alloc] initWithWindowScene:scene];
    self.window.frame = CGRectMake(startX, startY, windowW, windowH);
    self.window.windowLevel = UIWindowLevelAlert + 1000;
    self.window.backgroundColor = [UIColor clearColor];
    self.window.hidden = NO;
    self.window.userInteractionEnabled = YES;

    // 容器视图
    self.containerView = [[UIView alloc] initWithFrame:CGRectMake(0, 0, windowW, windowH)];
    self.containerView.backgroundColor = [UIColor colorWithRed:0.06 green:0.06 blue:0.08 alpha:0.96];
    self.containerView.layer.cornerRadius = 16;
    self.containerView.layer.masksToBounds = YES;
    self.containerView.layer.borderWidth = 1;
    self.containerView.layer.borderColor = [UIColor colorWithRed:0.15 green:0.15 blue:0.18 alpha:0.8].CGColor;
    [self.window addSubview:self.containerView];

    // 色板
    UIColor *titleColor = [UIColor colorWithRed:0.25 green:0.60 blue:1.0 alpha:1.0];
    UIColor *statusColor = [UIColor colorWithRed:0.55 green:0.55 blue:0.60 alpha:1.0];
    UIColor *apiColor = [UIColor colorWithRed:0.40 green:0.78 blue:0.47 alpha:1.0];
    UIColor *urlColor = [UIColor colorWithRed:0.55 green:0.65 blue:0.90 alpha:1.0];
    UIColor *cookieColor = [UIColor colorWithRed:0.90 green:0.70 blue:0.35 alpha:1.0];
    UIColor *cardBg = [UIColor colorWithRed:0.10 green:0.10 blue:0.13 alpha:0.85];
    UIColor *keyColor = [UIColor colorWithRed:0.50 green:0.58 blue:0.65 alpha:1.0];
    UIColor *notFoundColor = [UIColor colorWithRed:0.35 green:0.35 blue:0.38 alpha:1.0];
    UIColor *tabActiveColor = [UIColor colorWithRed:0.25 green:0.60 blue:1.0 alpha:1.0];
    UIColor *tabInactiveColor = [UIColor colorWithRed:0.45 green:0.45 blue:0.50 alpha:1.0];
    UIColor *dividerColor = [UIColor colorWithRed:0.18 green:0.18 blue:0.22 alpha:1.0];

    // ---- Header (56px) ----
    CGFloat headerH = 56;
    self.headerView = [[UIView alloc] initWithFrame:CGRectMake(0, 0, windowW, headerH)];
    self.headerView.backgroundColor = [UIColor colorWithRed:0.09 green:0.09 blue:0.12 alpha:1.0];
    [self.containerView addSubview:self.headerView];

    UIView *headerDivider = [[UIView alloc] initWithFrame:CGRectMake(0, headerH - 1, windowW, 1)];
    headerDivider.backgroundColor = dividerColor;
    [self.headerView addSubview:headerDivider];

    self.titleLabel = [[UILabel alloc] initWithFrame:CGRectMake(14, 4, 230, 20)];
    self.titleLabel.text = @"Eleme Field Monitor";
    self.titleLabel.textColor = titleColor;
    self.titleLabel.font = [UIFont boldSystemFontOfSize:13];
    [self.headerView addSubview:self.titleLabel];

    self.collapseBtn = [UIButton buttonWithType:UIButtonTypeSystem];
    self.collapseBtn.frame = CGRectMake(windowW - 60, 3, 24, 20);
    [self.collapseBtn setTitle:@"▲" forState:UIControlStateNormal];
    [self.collapseBtn setTitleColor:[UIColor colorWithRed:0.55 green:0.65 blue:0.80 alpha:1.0] forState:UIControlStateNormal];
    self.collapseBtn.titleLabel.font = [UIFont boldSystemFontOfSize:12];
    [self.collapseBtn addTarget:self action:@selector(toggleCollapse) forControlEvents:UIControlEventTouchUpInside];
    [self.headerView addSubview:self.collapseBtn];

    self.closeButton = [UIButton buttonWithType:UIButtonTypeSystem];
    self.closeButton.frame = CGRectMake(windowW - 34, 3, 24, 20);
    [self.closeButton setTitle:@"✕" forState:UIControlStateNormal];
    [self.closeButton setTitleColor:[UIColor colorWithRed:0.9 green:0.3 blue:0.3 alpha:1.0] forState:UIControlStateNormal];
    self.closeButton.titleLabel.font = [UIFont boldSystemFontOfSize:14];
    [self.closeButton addTarget:self action:@selector(hide) forControlEvents:UIControlEventTouchUpInside];
    [self.headerView addSubview:self.closeButton];

    self.statusLabel = [[UILabel alloc] initWithFrame:CGRectMake(14, 24, windowW - 28, 14)];
    self.statusLabel.text = @"Count: 0 | HAR: 0 | --:--:--";
    self.statusLabel.textColor = statusColor;
    self.statusLabel.font = [UIFont systemFontOfSize:10];
    [self.headerView addSubview:self.statusLabel];

    self.apiLabel = [[UILabel alloc] initWithFrame:CGRectMake(14, 39, windowW - 28, 14)];
    self.apiLabel.text = @"API: -";
    self.apiLabel.textColor = apiColor;
    self.apiLabel.font = [UIFont fontWithName:@"Menlo" size:9];
    self.apiLabel.adjustsFontSizeToFitWidth = YES;
    self.apiLabel.minimumScaleFactor = 0.55;
    [self.headerView addSubview:self.apiLabel];

    // ---- TabBar (32px) ----
    CGFloat tabH = 32;
    CGFloat tabY = headerH;
    self.tabBarView = [[UIView alloc] initWithFrame:CGRectMake(0, tabY, windowW, tabH)];
    self.tabBarView.backgroundColor = [UIColor colorWithRed:0.08 green:0.08 blue:0.10 alpha:1.0];
    [self.containerView addSubview:self.tabBarView];

    UIView *tabDivider = [[UIView alloc] initWithFrame:CGRectMake(0, tabH - 1, windowW, 1)];
    tabDivider.backgroundColor = dividerColor;
    [self.tabBarView addSubview:tabDivider];

    CGFloat tabW = windowW / 3;
    self.tabFieldsBtn = [UIButton buttonWithType:UIButtonTypeSystem];
    self.tabFieldsBtn.frame = CGRectMake(0, 0, tabW, tabH);
    [self.tabFieldsBtn setTitle:@"Fields" forState:UIControlStateNormal];
    [self.tabFieldsBtn setTitleColor:tabActiveColor forState:UIControlStateNormal];
    self.tabFieldsBtn.titleLabel.font = [UIFont boldSystemFontOfSize:12];
    [self.tabFieldsBtn addTarget:self action:@selector(tabFieldsTapped) forControlEvents:UIControlEventTouchUpInside];
    [self.tabBarView addSubview:self.tabFieldsBtn];

    self.tabHarBtn = [UIButton buttonWithType:UIButtonTypeSystem];
    self.tabHarBtn.frame = CGRectMake(tabW, 0, tabW, tabH);
    [self.tabHarBtn setTitle:@"HAR" forState:UIControlStateNormal];
    [self.tabHarBtn setTitleColor:tabInactiveColor forState:UIControlStateNormal];
    self.tabHarBtn.titleLabel.font = [UIFont boldSystemFontOfSize:12];
    [self.tabHarBtn addTarget:self action:@selector(tabHarTapped) forControlEvents:UIControlEventTouchUpInside];
    [self.tabBarView addSubview:self.tabHarBtn];

    self.tabMcpBtn = [UIButton buttonWithType:UIButtonTypeSystem];
    self.tabMcpBtn.frame = CGRectMake(tabW * 2, 0, tabW, tabH);
    [self.tabMcpBtn setTitle:@"MCP" forState:UIControlStateNormal];
    [self.tabMcpBtn setTitleColor:tabInactiveColor forState:UIControlStateNormal];
    self.tabMcpBtn.titleLabel.font = [UIFont boldSystemFontOfSize:12];
    [self.tabMcpBtn addTarget:self action:@selector(tabMcpTapped) forControlEvents:UIControlEventTouchUpInside];
    [self.tabBarView addSubview:self.tabMcpBtn];

    // Tab indicators (底部色条)
    self.tabFieldsIndicator = [[UIView alloc] initWithFrame:CGRectMake(tabW / 2 - 20, tabH - 3, 40, 3)];
    self.tabFieldsIndicator.backgroundColor = tabActiveColor;
    self.tabFieldsIndicator.layer.cornerRadius = 1.5;
    [self.tabBarView addSubview:self.tabFieldsIndicator];

    self.tabHarIndicator = [[UIView alloc] initWithFrame:CGRectMake(tabW + tabW / 2 - 20, tabH - 3, 40, 3)];
    self.tabHarIndicator.backgroundColor = tabActiveColor;
    self.tabHarIndicator.layer.cornerRadius = 1.5;
    self.tabHarIndicator.alpha = 0;
    [self.tabBarView addSubview:self.tabHarIndicator];

    self.tabMcpIndicator = [[UIView alloc] initWithFrame:CGRectMake(tabW * 2 + tabW / 2 - 20, tabH - 3, 40, 3)];
    self.tabMcpIndicator.backgroundColor = tabActiveColor;
    self.tabMcpIndicator.layer.cornerRadius = 1.5;
    self.tabMcpIndicator.alpha = 0;
    [self.tabBarView addSubview:self.tabMcpIndicator];

    // ---- Content area ----
    CGFloat footerH = 44;
    CGFloat contentY = headerH + tabH;
    CGFloat contentH = windowH - headerH - tabH - footerH;

    // === Fields ScrollView ===
    self.fieldsScrollView = [[UIScrollView alloc] initWithFrame:CGRectMake(0, contentY, windowW, contentH)];
    self.fieldsScrollView.backgroundColor = [UIColor clearColor];
    self.fieldsScrollView.showsVerticalScrollIndicator = YES;
    self.fieldsScrollView.alwaysBounceVertical = YES;
    [self.containerView addSubview:self.fieldsScrollView];

    // URL & Cookie info cards at top of Fields tab
    CGFloat cy = 8;
    CGFloat infoCardH = 28;

    // URL card
    UIView *urlCard = [[UIView alloc] initWithFrame:CGRectMake(sidePad, cy, windowW - sidePad * 2, infoCardH)];
    urlCard.backgroundColor = cardBg;
    urlCard.layer.cornerRadius = 5;
    urlCard.layer.masksToBounds = YES;
    [self.fieldsScrollView addSubview:urlCard];

    UIView *urlBar = [[UIView alloc] initWithFrame:CGRectMake(0, 0, 2, infoCardH)];
    urlBar.backgroundColor = [urlColor colorWithAlphaComponent:0.5];
    [urlCard addSubview:urlBar];

    UILabel *urlKey = [[UILabel alloc] initWithFrame:CGRectMake(8, 0, 40, infoCardH)];
    urlKey.text = @"URL";
    urlKey.textColor = [UIColor colorWithRed:0.45 green:0.55 blue:0.70 alpha:1.0];
    urlKey.font = [UIFont boldSystemFontOfSize:9];
    urlKey.textAlignment = NSTextAlignmentLeft;
    [urlCard addSubview:urlKey];

    self.urlLabel = [[UILabel alloc] initWithFrame:CGRectMake(50, 0, urlCard.bounds.size.width - 56, infoCardH)];
    self.urlLabel.text = @"-";
    self.urlLabel.textColor = urlColor;
    self.urlLabel.font = [UIFont fontWithName:@"Menlo" size:8];
    self.urlLabel.adjustsFontSizeToFitWidth = YES;
    self.urlLabel.minimumScaleFactor = 0.4;
    self.urlLabel.numberOfLines = 1;
    [urlCard addSubview:self.urlLabel];

    cy += infoCardH + 3;

    // Cookie card
    UIView *cookieCard = [[UIView alloc] initWithFrame:CGRectMake(sidePad, cy, windowW - sidePad * 2, infoCardH)];
    cookieCard.backgroundColor = cardBg;
    cookieCard.layer.cornerRadius = 5;
    cookieCard.layer.masksToBounds = YES;
    [self.fieldsScrollView addSubview:cookieCard];

    UIView *cookieBar = [[UIView alloc] initWithFrame:CGRectMake(0, 0, 2, infoCardH)];
    cookieBar.backgroundColor = [cookieColor colorWithAlphaComponent:0.5];
    [cookieCard addSubview:cookieBar];

    UILabel *cookieKey = [[UILabel alloc] initWithFrame:CGRectMake(8, 0, 44, infoCardH)];
    cookieKey.text = @"Cookie";
    cookieKey.textColor = [UIColor colorWithRed:0.65 green:0.50 blue:0.25 alpha:1.0];
    cookieKey.font = [UIFont boldSystemFontOfSize:9];
    cookieKey.textAlignment = NSTextAlignmentLeft;
    [cookieCard addSubview:cookieKey];

    self.cookieLabel = [[UILabel alloc] initWithFrame:CGRectMake(54, 0, cookieCard.bounds.size.width - 60, infoCardH)];
    self.cookieLabel.text = @"-";
    self.cookieLabel.textColor = cookieColor;
    self.cookieLabel.font = [UIFont fontWithName:@"Menlo" size:8];
    self.cookieLabel.adjustsFontSizeToFitWidth = YES;
    self.cookieLabel.minimumScaleFactor = 0.4;
    self.cookieLabel.numberOfLines = 1;
    [cookieCard addSubview:self.cookieLabel];

    cy += infoCardH + 8;

    // 分组定义
    NSArray *groupDefs = @[
        @{@"title": @"加密字段", @"r": @0.09, @"g": @0.56, @"b": @1.0,
          @"fields": @[@"encryptSceneCode", @"encryptActCode"]},
        @{@"title": @"活动标识", @"r": @0.32, @"g": @0.77, @"b": @0.10,
          @"fields": @[@"rightId", @"actCode", @"sceneCode"]},
        @{@"title": @"来源", @"r": @0.98, @"g": @0.55, @"b": @0.09,
          @"fields": @[@"sourceFrom"]},
        @{@"title": @"页面", @"r": @0.55, @"g": @0.35, @"b": @0.75,
          @"fields": @[@"pagePath"]},
    ];

    CGFloat cardH = 36;
    CGFloat cardSpacing = 3;
    CGFloat groupTopMargin = 8;
    CGFloat groupHeaderH = 20;

    for (NSInteger gi = 0; gi < groupDefs.count; gi++) {
        NSDictionary *gd = groupDefs[gi];
        NSString *gTitle = gd[@"title"];
        CGFloat gr = [gd[@"r"] floatValue];
        CGFloat gg = [gd[@"g"] floatValue];
        CGFloat gb = [gd[@"b"] floatValue];
        NSArray *gFields = gd[@"fields"];
        UIColor *accent = [UIColor colorWithRed:gr green:gg blue:gb alpha:1.0];

        if (gi > 0) cy += groupTopMargin;

        // 分组标题栏
        UIView *groupHeader = [[UIView alloc] initWithFrame:CGRectMake(sidePad, cy, windowW - sidePad * 2, groupHeaderH)];
        groupHeader.backgroundColor = [UIColor colorWithRed:0.08 green:0.08 blue:0.10 alpha:0.6];
        groupHeader.layer.cornerRadius = 4;
        groupHeader.layer.masksToBounds = YES;
        [self.fieldsScrollView addSubview:groupHeader];

        UIView *accentBar = [[UIView alloc] initWithFrame:CGRectMake(0, 0, 3, groupHeaderH)];
        accentBar.backgroundColor = accent;
        [groupHeader addSubview:accentBar];

        UILabel *gLabel = [[UILabel alloc] initWithFrame:CGRectMake(10, 0, groupHeader.bounds.size.width - 30, groupHeaderH)];
        gLabel.text = gTitle;
        gLabel.textColor = accent;
        gLabel.font = [UIFont boldSystemFontOfSize:10];
        gLabel.textAlignment = NSTextAlignmentLeft;
        [groupHeader addSubview:gLabel];

        UILabel *countLabel = [[UILabel alloc] initWithFrame:CGRectMake(groupHeader.bounds.size.width - 24, 0, 20, groupHeaderH)];
        countLabel.text = [NSString stringWithFormat:@"%ld", (long)gFields.count];
        countLabel.textColor = [UIColor colorWithRed:0.4 green:0.4 blue:0.45 alpha:1.0];
        countLabel.font = [UIFont systemFontOfSize:9];
        countLabel.textAlignment = NSTextAlignmentRight;
        [groupHeader addSubview:countLabel];

        cy += groupHeaderH + 3;

        for (NSString *fieldName in gFields) {
            // pagePath 值很长，用更高的卡片和多行显示
            BOOL isLongField = [fieldName isEqualToString:@"pagePath"];
            CGFloat fieldCardH = isLongField ? 60 : cardH;
            
            UIView *card = [[UIView alloc] initWithFrame:CGRectMake(sidePad, cy, windowW - sidePad * 2, fieldCardH)];
            card.backgroundColor = cardBg;
            card.layer.cornerRadius = 5;
            card.layer.masksToBounds = YES;
            [self.fieldsScrollView addSubview:card];

            UIView *cardBar = [[UIView alloc] initWithFrame:CGRectMake(0, 0, 2, fieldCardH)];
            cardBar.backgroundColor = [accent colorWithAlphaComponent:0.4];
            [card addSubview:cardBar];

            CGFloat keyW = 120;
            UILabel *keyLabel = [[UILabel alloc] initWithFrame:CGRectMake(8, 0, keyW, fieldCardH)];
            keyLabel.text = fieldName;
            keyLabel.textColor = keyColor;
            keyLabel.font = [UIFont fontWithName:@"Menlo" size:10];
            keyLabel.textAlignment = NSTextAlignmentLeft;
            keyLabel.adjustsFontSizeToFitWidth = YES;
            keyLabel.minimumScaleFactor = 0.6;
            [card addSubview:keyLabel];

            UIView *vDivider = [[UIView alloc] initWithFrame:CGRectMake(keyW + 6, 5, 1, fieldCardH - 10)];
            vDivider.backgroundColor = [UIColor colorWithRed:0.2 green:0.2 blue:0.24 alpha:0.6];
            [card addSubview:vDivider];

            UILabel *valueLabel = [[UILabel alloc] initWithFrame:CGRectMake(keyW + 12, 0, card.bounds.size.width - keyW - 18, fieldCardH)];
            valueLabel.text = @"(waiting...)";
            valueLabel.textColor = notFoundColor;
            valueLabel.font = [UIFont fontWithName:@"Menlo" size:10];
            valueLabel.adjustsFontSizeToFitWidth = YES;
            valueLabel.minimumScaleFactor = 0.4;
            valueLabel.numberOfLines = isLongField ? 3 : 1;
            valueLabel.textAlignment = NSTextAlignmentLeft;
            [card addSubview:valueLabel];

            self.fieldLabels[fieldName] = valueLabel;

            UILongPressGestureRecognizer *longPress = [[UILongPressGestureRecognizer alloc]
                initWithTarget:self action:@selector(handleLongPress:)];
            longPress.minimumPressDuration = 0.5;
            [card addGestureRecognizer:longPress];

            cy += fieldCardH + cardSpacing;
        }
    }

    self.fieldsScrollView.contentSize = CGSizeMake(windowW, cy + 8);

    // === HAR Search Bar (28px) ===
    CGFloat searchH = 28;
    self.harSearchField = [[UITextField alloc] initWithFrame:CGRectMake(sidePad, contentY, windowW - sidePad * 2, searchH)];
    self.harSearchField.placeholder = @"Search API name or URL...";
    self.harSearchField.font = [UIFont fontWithName:@"Menlo" size:11];
    self.harSearchField.textColor = [UIColor colorWithRed:0.85 green:0.85 blue:0.90 alpha:1.0];
    self.harSearchField.backgroundColor = [UIColor colorWithRed:0.12 green:0.12 blue:0.15 alpha:0.9];
    self.harSearchField.layer.cornerRadius = 6;
    self.harSearchField.layer.masksToBounds = YES;
    self.harSearchField.leftView = [[UIView alloc] initWithFrame:CGRectMake(0, 0, 6, searchH)];
    self.harSearchField.leftViewMode = UITextFieldViewModeAlways;
    self.harSearchField.rightView = [[UIView alloc] initWithFrame:CGRectMake(0, 0, 6, searchH)];
    self.harSearchField.rightViewMode = UITextFieldViewModeAlways;
    self.harSearchField.attributedPlaceholder = [[NSAttributedString alloc] initWithString:@"Search API name or URL..." attributes:@{NSForegroundColorAttributeName: [UIColor colorWithRed:0.40 green:0.40 blue:0.45 alpha:1.0], NSFontAttributeName: [UIFont fontWithName:@"Menlo" size:11]}];
    self.harSearchField.hidden = YES;
    self.harSearchField.tag = 998;
    [self.harSearchField addTarget:self action:@selector(harSearchChanged:) forControlEvents:UIControlEventEditingChanged];
    [self.containerView addSubview:self.harSearchField];

    // === HAR ScrollView ===
    CGFloat harScrollY = contentY + searchH;
    CGFloat harScrollH = contentH - searchH;
    self.harScrollView = [[UIScrollView alloc] initWithFrame:CGRectMake(0, harScrollY, windowW, harScrollH)];
    self.harScrollView.backgroundColor = [UIColor clearColor];
    self.harScrollView.showsVerticalScrollIndicator = YES;
    self.harScrollView.alwaysBounceVertical = YES;
    self.harScrollView.hidden = YES;
    [self.containerView addSubview:self.harScrollView];

    // HAR 空状态
    UILabel *harEmpty = [[UILabel alloc] initWithFrame:CGRectMake(0, harScrollH / 2 - 30, windowW, 30)];
    harEmpty.text = @"No HAR entries yet";
    harEmpty.textColor = [UIColor colorWithRed:0.35 green:0.35 blue:0.40 alpha:1.0];
    harEmpty.font = [UIFont systemFontOfSize:13];
    harEmpty.textAlignment = NSTextAlignmentCenter;
    harEmpty.tag = 999;
    [self.harScrollView addSubview:harEmpty];

    self.harScrollView.contentSize = CGSizeMake(windowW, harScrollH);

    // === MCP ScrollView ===
    self.mcpScrollView = [[UIScrollView alloc] initWithFrame:CGRectMake(0, contentY, windowW, contentH)];
    self.mcpScrollView.backgroundColor = [UIColor clearColor];
    self.mcpScrollView.showsVerticalScrollIndicator = YES;
    self.mcpScrollView.alwaysBounceVertical = YES;
    self.mcpScrollView.hidden = YES;
    [self.containerView addSubview:self.mcpScrollView];

    CGFloat mcpCy = 12;
    CGFloat mcpPad = 12;
    CGFloat mcpCardW = windowW - mcpPad * 2;

    // MCP 标题
    UILabel *mcpTitle = [[UILabel alloc] initWithFrame:CGRectMake(mcpPad, mcpCy, mcpCardW, 20)];
    mcpTitle.text = @"MCP HTTP Server";
    mcpTitle.textColor = [UIColor colorWithRed:0.40 green:0.78 blue:0.47 alpha:1.0];
    mcpTitle.font = [UIFont boldSystemFontOfSize:14];
    [self.mcpScrollView addSubview:mcpTitle];
    mcpCy += 26;

    // 状态
    UILabel *mcpStatus = [[UILabel alloc] initWithFrame:CGRectMake(mcpPad, mcpCy, mcpCardW, 16)];
    mcpStatus.text = @"Status: Running on port 9876";
    mcpStatus.textColor = [UIColor colorWithRed:0.32 green:0.77 blue:0.10 alpha:1.0];
    mcpStatus.font = [UIFont fontWithName:@"Menlo" size:11];
    mcpStatus.tag = 5001;
    [self.mcpScrollView addSubview:mcpStatus];
    mcpCy += 22;

    // 获取设备 IP 地址 (用 gethostname + 简单提示)
    char hostname[256];
    gethostname(hostname, sizeof(hostname));
    NSString *hostStr = [NSString stringWithUTF8String:hostname];

    // IP 地址卡片
    UIView *ipCard = [[UIView alloc] initWithFrame:CGRectMake(mcpPad, mcpCy, mcpCardW, 50)];
    ipCard.backgroundColor = [UIColor colorWithRed:0.10 green:0.10 blue:0.13 alpha:0.85];
    ipCard.layer.cornerRadius = 6;
    ipCard.layer.masksToBounds = YES;
    [self.mcpScrollView addSubview:ipCard];

    UILabel *ipTitle = [[UILabel alloc] initWithFrame:CGRectMake(8, 4, mcpCardW - 16, 14)];
    ipTitle.text = @"Access URL";
    ipTitle.textColor = [UIColor colorWithRed:0.55 green:0.65 blue:0.90 alpha:1.0];
    ipTitle.font = [UIFont fontWithName:@"Menlo" size:9];
    [ipCard addSubview:ipTitle];

    UILabel *ipLabel = [[UILabel alloc] initWithFrame:CGRectMake(8, 20, mcpCardW - 16, 22)];
    ipLabel.text = [NSString stringWithFormat:@"http://<设备IP>:9876  (%@)", hostStr];
    ipLabel.textColor = [UIColor colorWithRed:0.85 green:0.85 blue:0.90 alpha:1.0];
    ipLabel.font = [UIFont fontWithName:@"Menlo" size:10];
    ipLabel.adjustsFontSizeToFitWidth = YES;
    ipLabel.minimumScaleFactor = 0.6;
    ipLabel.tag = 5002;
    [ipCard addSubview:ipLabel];
    mcpCy += 58;

    // 端点列表标题
    UILabel *epTitle = [[UILabel alloc] initWithFrame:CGRectMake(mcpPad, mcpCy, mcpCardW, 18)];
    epTitle.text = @"API Endpoints";
    epTitle.textColor = [UIColor colorWithRed:0.40 green:0.78 blue:0.47 alpha:1.0];
    epTitle.font = [UIFont boldSystemFontOfSize:12];
    [self.mcpScrollView addSubview:epTitle];
    mcpCy += 22;

    // 端点列表
    NSArray *endpoints = @[
        @[@"GET /", @"Web UI Dashboard"],
        @[@"GET /status", @"Status + field values"],
        @[@"GET /fields", @"All captured fields"],
        @[@"GET /har", @"All HAR entries"],
        @[@"GET /har/search?q=", @"Search HAR"],
        @[@"GET /har/{index}", @"Single HAR entry"],
        @[@"GET /clear", @"Clear all data"]
    ];

    for (NSArray *ep in endpoints) {
        UIView *epCard = [[UIView alloc] initWithFrame:CGRectMake(mcpPad, mcpCy, mcpCardW, 28)];
        epCard.backgroundColor = [UIColor colorWithRed:0.10 green:0.10 blue:0.13 alpha:0.6];
        epCard.layer.cornerRadius = 4;
        epCard.layer.masksToBounds = YES;
        [self.mcpScrollView addSubview:epCard];

        UILabel *epPath = [[UILabel alloc] initWithFrame:CGRectMake(8, 2, mcpCardW - 16, 14)];
        epPath.text = ep[0];
        epPath.textColor = [UIColor colorWithRed:0.55 green:0.65 blue:0.90 alpha:1.0];
        epPath.font = [UIFont fontWithName:@"Menlo" size:10];
        [epCard addSubview:epPath];

        UILabel *epDesc = [[UILabel alloc] initWithFrame:CGRectMake(8, 15, mcpCardW - 16, 12)];
        epDesc.text = ep[1];
        epDesc.textColor = [UIColor colorWithRed:0.50 green:0.58 blue:0.65 alpha:1.0];
        epDesc.font = [UIFont systemFontOfSize:9];
        [epCard addSubview:epDesc];

        mcpCy += 32;
    }

    // 使用说明
    mcpCy += 6;
    UILabel *usageTitle = [[UILabel alloc] initWithFrame:CGRectMake(mcpPad, mcpCy, mcpCardW, 18)];
    usageTitle.text = @"Usage";
    usageTitle.textColor = [UIColor colorWithRed:0.40 green:0.78 blue:0.47 alpha:1.0];
    usageTitle.font = [UIFont boldSystemFontOfSize:12];
    [self.mcpScrollView addSubview:usageTitle];
    mcpCy += 22;

    UILabel *usageText = [[UILabel alloc] initWithFrame:CGRectMake(mcpPad, mcpCy, mcpCardW, 80)];
    usageText.text = @"1. 电脑和设备在同一 WiFi\n2. 浏览器打开上面的 URL\n3. 可查看 HAR/Fields 实时数据\n4. 也可用 curl 调用 API";
    usageText.textColor = [UIColor colorWithRed:0.65 green:0.65 blue:0.70 alpha:1.0];
    usageText.font = [UIFont fontWithName:@"Menlo" size:10];
    usageText.numberOfLines = 0;
    [self.mcpScrollView addSubview:usageText];
    mcpCy += 86;

    self.mcpScrollView.contentSize = CGSizeMake(windowW, mcpCy + 8);

    // ---- Footer (44px) ----
    CGFloat footerY = windowH - footerH;
    self.footerView = [[UIView alloc] initWithFrame:CGRectMake(0, footerY, windowW, footerH)];
    self.footerView.backgroundColor = [UIColor colorWithRed:0.09 green:0.09 blue:0.12 alpha:1.0];
    [self.containerView addSubview:self.footerView];

    UIView *footerDivider = [[UIView alloc] initWithFrame:CGRectMake(0, 0, windowW, 1)];
    footerDivider.backgroundColor = dividerColor;
    [self.footerView addSubview:footerDivider];

    // Fields tab footer buttons (3 buttons)
    CGFloat btnH = 30;
    CGFloat btnSpacing = 6;
    CGFloat btnY = (footerH - btnH) / 2;

    // Fields footer: Copy | Cookie | Clear
    CGFloat fieldsBtnW = (windowW - btnSpacing * 4) / 3;

    self.exportBtn = [UIButton buttonWithType:UIButtonTypeSystem];
    self.exportBtn.frame = CGRectMake(btnSpacing, btnY, fieldsBtnW, btnH);
    [self.exportBtn setTitle:@"Copy" forState:UIControlStateNormal];
    [self.exportBtn setTitleColor:[UIColor whiteColor] forState:UIControlStateNormal];
    self.exportBtn.titleLabel.font = [UIFont systemFontOfSize:10];
    self.exportBtn.backgroundColor = [UIColor colorWithRed:0.12 green:0.40 blue:0.78 alpha:0.85];
    self.exportBtn.layer.cornerRadius = 6;
    [self.exportBtn addTarget:self action:@selector(copyAllToClipboard) forControlEvents:UIControlEventTouchUpInside];
    [self.footerView addSubview:self.exportBtn];

    self.cookieCopyBtn = [UIButton buttonWithType:UIButtonTypeSystem];
    self.cookieCopyBtn.frame = CGRectMake(btnSpacing * 2 + fieldsBtnW, btnY, fieldsBtnW, btnH);
    [self.cookieCopyBtn setTitle:@"Cookie" forState:UIControlStateNormal];
    [self.cookieCopyBtn setTitleColor:[UIColor whiteColor] forState:UIControlStateNormal];
    self.cookieCopyBtn.titleLabel.font = [UIFont systemFontOfSize:10];
    self.cookieCopyBtn.backgroundColor = [UIColor colorWithRed:0.65 green:0.45 blue:0.15 alpha:0.85];
    self.cookieCopyBtn.layer.cornerRadius = 6;
    [self.cookieCopyBtn addTarget:self action:@selector(copyCookieToClipboard) forControlEvents:UIControlEventTouchUpInside];
    [self.footerView addSubview:self.cookieCopyBtn];

    self.clearButton = [UIButton buttonWithType:UIButtonTypeSystem];
    self.clearButton.frame = CGRectMake(btnSpacing * 3 + fieldsBtnW * 2, btnY, fieldsBtnW, btnH);
    [self.clearButton setTitle:@"Clear" forState:UIControlStateNormal];
    [self.clearButton setTitleColor:[UIColor whiteColor] forState:UIControlStateNormal];
    self.clearButton.titleLabel.font = [UIFont systemFontOfSize:10];
    self.clearButton.backgroundColor = [UIColor colorWithRed:0.55 green:0.18 blue:0.18 alpha:0.85];
    self.clearButton.layer.cornerRadius = 6;
    [self.clearButton addTarget:self action:@selector(clearAll) forControlEvents:UIControlEventTouchUpInside];
    [self.footerView addSubview:self.clearButton];

    // HAR footer buttons (hidden by default)
    CGFloat harBtnW = (windowW - btnSpacing * 3) / 2;

    self.harExportBtn = [UIButton buttonWithType:UIButtonTypeSystem];
    self.harExportBtn.frame = CGRectMake(btnSpacing, btnY, harBtnW, btnH);
    [self.harExportBtn setTitle:@"Export HAR" forState:UIControlStateNormal];
    [self.harExportBtn setTitleColor:[UIColor whiteColor] forState:UIControlStateNormal];
    self.harExportBtn.titleLabel.font = [UIFont systemFontOfSize:10];
    self.harExportBtn.backgroundColor = [UIColor colorWithRed:0.12 green:0.40 blue:0.78 alpha:0.85];
    self.harExportBtn.layer.cornerRadius = 6;
    [self.harExportBtn addTarget:self action:@selector(exportHAR) forControlEvents:UIControlEventTouchUpInside];
    self.harExportBtn.hidden = YES;
    [self.footerView addSubview:self.harExportBtn];

    UIButton *harClearBtn = [UIButton buttonWithType:UIButtonTypeSystem];
    harClearBtn.frame = CGRectMake(btnSpacing * 2 + harBtnW, btnY, harBtnW, btnH);
    [harClearBtn setTitle:@"Clear HAR" forState:UIControlStateNormal];
    [harClearBtn setTitleColor:[UIColor whiteColor] forState:UIControlStateNormal];
    harClearBtn.titleLabel.font = [UIFont systemFontOfSize:10];
    harClearBtn.backgroundColor = [UIColor colorWithRed:0.55 green:0.18 blue:0.18 alpha:0.85];
    harClearBtn.layer.cornerRadius = 6;
    [harClearBtn addTarget:self action:@selector(clearHar) forControlEvents:UIControlEventTouchUpInside];
    harClearBtn.tag = 888;
    harClearBtn.hidden = YES;
    [self.footerView addSubview:harClearBtn];

    // 手势
    UIPanGestureRecognizer *pan = [[UIPanGestureRecognizer alloc]
        initWithTarget:self action:@selector(handlePan:)];
    [self.headerView addGestureRecognizer:pan];

    UITapGestureRecognizer *doubleTap = [[UITapGestureRecognizer alloc]
        initWithTarget:self action:@selector(handleDoubleTap:)];
    doubleTap.numberOfTapsRequired = 2;
    [self.headerView addGestureRecognizer:doubleTap];

    self.activeTab = 0;
    NSLog(@"[ElemeFieldMonitor] Float window ready!");
}

#pragma mark - 手势处理

- (void)handlePan:(UIPanGestureRecognizer *)gesture {
    CGPoint translation = [gesture translationInView:self.window.superview ?: self.window];
    CGPoint newCenter = CGPointMake(self.window.center.x + translation.x,
                                     self.window.center.y + translation.y);
    // 限制在屏幕范围内
    CGFloat halfW = self.window.bounds.size.width / 2;
    CGFloat halfH = self.window.bounds.size.height / 2;
    CGFloat screenW = [UIScreen mainScreen].bounds.size.width;
    CGFloat screenH = [UIScreen mainScreen].bounds.size.height;
    newCenter.x = MAX(halfW, MIN(screenW - halfW, newCenter.x));
    newCenter.y = MAX(halfH, MIN(screenH - halfH, newCenter.y));
    self.window.center = newCenter;
    [gesture setTranslation:CGPointZero inView:self.window];
}

- (void)handleDoubleTap:(UITapGestureRecognizer *)gesture {
    [self toggleCollapse];
}

- (void)handleLongPress:(UILongPressGestureRecognizer *)gesture {
    if (gesture.state != UIGestureRecognizerStateBegan) return;
    UIView *container = gesture.view;
    // 查找最右侧的 UILabel 作为 value label
    UILabel *valueLabel = nil;
    CGFloat maxX = -1;
    for (UIView *sub in container.subviews) {
        if ([sub isKindOfClass:[UILabel class]]) {
            UILabel *lbl = (UILabel *)sub;
            if (lbl.frame.origin.x > maxX) {
                maxX = lbl.frame.origin.x;
                valueLabel = lbl;
            }
        }
    }
    if (valueLabel && valueLabel.text.length > 0 && ![valueLabel.text isEqualToString:@"(waiting...)"]) {
        UIPasteboard.generalPasteboard.string = valueLabel.text;
        [self showToast:[NSString stringWithFormat:@"Copied: %@", valueLabel.text]];
    }
}

#pragma mark - 显示控制

- (void)show {
    dispatch_async(dispatch_get_main_queue(), ^{
        self.window.hidden = NO;
    });
}

- (void)hide {
    dispatch_async(dispatch_get_main_queue(), ^{
        self.window.hidden = YES;
    });
}

- (void)toggle {
    if (self.window.isHidden) {
        [self show];
    } else {
        [self hide];
    }
}

- (void)toggleCollapse {
    dispatch_async(dispatch_get_main_queue(), ^{
        self.collapsed = !self.collapsed;
        CGFloat fullH = 460;
        CGFloat headerH = 56;
        CGFloat targetH = self.collapsed ? headerH : fullH;
        CGFloat currentW = self.window.frame.size.width;
        CGFloat currentX = self.window.frame.origin.x;
        CGFloat currentY = self.window.frame.origin.y;

        [UIView animateWithDuration:0.25
                               delay:0
             usingSpringWithDamping:0.8
              initialSpringVelocity:0.3
                            options:UIViewAnimationOptionCurveEaseInOut
                         animations:^{
            self.window.frame = CGRectMake(currentX, currentY, currentW, targetH);
            self.containerView.frame = CGRectMake(0, 0, currentW, targetH);
            self.fieldsScrollView.hidden = self.collapsed ? YES : (self.activeTab != 0);
            self.harScrollView.hidden = self.collapsed ? YES : (self.activeTab != 1);
            self.tabBarView.hidden = self.collapsed;
            self.footerView.hidden = self.collapsed;
            [self.collapseBtn setTitle:self.collapsed ? @"▼" : @"▲" forState:UIControlStateNormal];
        } completion:nil];
    });
}

- (void)updateURL:(NSString *)url {
    if (!url || url.length == 0) return;
    dispatch_async(dispatch_get_main_queue(), ^{
        self.lastURL = url;
        NSString *display = url;
        if (display.length > 60) {
            display = [NSString stringWithFormat:@"%@...", [display substringToIndex:60]];
        }
        self.urlLabel.text = display;
    });
}

- (void)updateCookie:(NSString *)cookie {
    if (!cookie || cookie.length == 0) return;
    dispatch_async(dispatch_get_main_queue(), ^{
        self.lastCookie = cookie;
        NSString *display = cookie;
        if (display.length > 50) {
            display = [NSString stringWithFormat:@"%@...", [display substringToIndex:50]];
        }
        self.cookieLabel.text = display;
    });
}

#pragma mark - 数据更新

- (void)updateWithDictionary:(NSDictionary *)dict source:(NSString *)source api:(NSString *)api {
    if (!dict || dict.count == 0) return;

    dispatch_async(dispatch_get_main_queue(), ^{
        BOOL hasNewData = NO;

        for (NSString *key in kTargetKeys()) {
            NSString *newValue = dict[key];
            if (newValue) {
                NSString *oldValue = self.fieldValues[key];
                if (![oldValue isEqualToString:newValue]) {
                    hasNewData = YES;
                }
                self.fieldValues[key] = newValue;
                self.fieldSources[key] = source;

                UILabel *label = self.fieldLabels[key];
                if (label) {
                    // 显示值
                    label.text = newValue;
                    label.textColor = [UIColor colorWithRed:0.95 green:0.85 blue:0.55 alpha:1.0];

                    // 闪烁动画提示新数据
                    [UIView animateWithDuration:0.3 animations:^{
                        label.superview.backgroundColor = [UIColor colorWithRed:0.12 green:0.28 blue:0.12 alpha:0.9];
                    } completion:^(BOOL finished) {
                        [UIView animateWithDuration:0.5 delay:0.3 options:UIViewAnimationOptionCurveEaseOut animations:^{
                            label.superview.backgroundColor = [UIColor colorWithRed:0.10 green:0.10 blue:0.13 alpha:0.85];
                        } completion:nil];
                    }];
                }

                NSLog(@"[ElemeFieldMonitor] %@ = %@ (source: %@)", key, newValue, source);
            }
        }

        // 只有当包含重要字段时才更新显示和历史
        // sceneCode/sourceFrom 太常见，不能作为唯一触发条件
        NSArray *importantKeys = @[@"encryptSceneCode", @"encryptActCode", @"rightId", @"actCode"];
        BOOL hasImportant = NO;
        for (NSString *ik in importantKeys) {
            if (dict[ik]) { hasImportant = YES; break; }
        }
        
        if (hasNewData || (api && hasImportant)) {
            self.captureCount += 1;
            self.lastUpdate = [NSDate date];
            if (api) self.lastAPI = api;
            if (source) self.lastSource = source;
            [self updateStatusBar];
        }
    });
}


- (void)updateStatusBar {
    NSDateFormatter *fmt = [[NSDateFormatter alloc] init];
    fmt.dateFormat = @"HH:mm:ss";
    NSString *timeStr = self.lastUpdate ? [fmt stringFromDate:self.lastUpdate] : @"--:--:--";

    self.statusLabel.text = [NSString stringWithFormat:@"Count: %ld | HAR: %ld | %@",
                              (long)self.captureCount, (long)self.harEntries.count, timeStr];

    // 截断 API 名称
    NSString *apiDisplay = self.lastAPI ?: @"-";
    if (apiDisplay.length > 50) {
        apiDisplay = [NSString stringWithFormat:@"%@...", [apiDisplay substringToIndex:50]];
    }
    self.apiLabel.text = [NSString stringWithFormat:@"API: %@", apiDisplay];
}

#pragma mark - 操作

- (void)copyAllToClipboard {
    NSMutableDictionary *json = [NSMutableDictionary dictionary];
    for (NSString *key in kTargetKeys()) {
        NSString *value = self.fieldValues[key];
        if (value) {
            json[key] = value;
        }
    }
    json[@"_captureCount"] = @(self.captureCount);
    json[@"_lastSource"] = self.lastSource;
    json[@"_lastAPI"] = self.lastAPI;
    json[@"_lastURL"] = self.lastURL;
    json[@"_lastCookie"] = self.lastCookie;
    json[@"_lastUpdate"] = self.lastUpdate ? [self.lastUpdate description] : @"-";

    NSData *data = [NSJSONSerialization dataWithJSONObject:json options:NSJSONWritingPrettyPrinted error:nil];
    NSString *jsonStr = [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];
    UIPasteboard.generalPasteboard.string = jsonStr;

    [self showToast:@"Current snapshot copied!"];
}

- (void)copyCookieToClipboard {
    NSString *cookie = self.lastCookie ?: @"-";
    if ([cookie isEqualToString:@"-"] || cookie.length == 0) {
        [self showToast:@"No cookie captured!"];
        return;
    }
    UIPasteboard.generalPasteboard.string = cookie;
    [self showToast:@"Cookie copied!"];
}

- (void)exportHAR {
    if (self.harEntries.count == 0) {
        [self showToast:@"No HAR entries!"];
        return;
    }
    // 将 pendingRequests 中未配对的请求也作为条目输出
    NSMutableArray *allEntries = [NSMutableArray array];
    // 先添加已配对的 entries，移除 _api 非标准字段
    for (NSDictionary *e in self.harEntries) {
        NSMutableDictionary *cleanEntry = [e mutableCopy];
        [cleanEntry removeObjectForKey:@"_api"];
        [allEntries addObject:cleanEntry];
    }
    for (NSDictionary *req in self.pendingRequests) {
        NSString *api = req[@"_api"] ?: @"unknown";
        NSMutableDictionary *entry = [NSMutableDictionary dictionary];
        entry[@"startedDateTime"] = req[@"_timestamp"] ?: @"1970-01-01T00:00:00.000Z";
        entry[@"time"] = @0;
        // request
        NSMutableDictionary *harReq = [NSMutableDictionary dictionary];
        harReq[@"method"] = req[@"method"] ?: @"GET";
        harReq[@"url"] = req[@"url"] ?: @"-";
        harReq[@"httpVersion"] = @"HTTP/1.1";
        // headers array
        NSMutableArray *hdrArr = [NSMutableArray array];
        NSDictionary *hdrs = req[@"headers"];
        for (NSString *hk in hdrs) {
            [hdrArr addObject:@{@"name": hk, @"value": [NSString stringWithFormat:@"%@", hdrs[hk]]}];
        }
        harReq[@"headers"] = hdrArr;
        harReq[@"queryString"] = @[];
        harReq[@"headersSize"] = @(-1);
        NSString *bodyStr = req[@"body"] ?: @"";
        harReq[@"bodySize"] = @(bodyStr.length);
        if (bodyStr.length > 0 && ![bodyStr isEqualToString:@"-"]) {
            harReq[@"postData"] = @{@"mimeType": @"application/json", @"text": bodyStr};
        }
        entry[@"request"] = harReq;
        // empty response
        entry[@"response"] = @{
            @"status": @0,
            @"statusText": @"(no response captured)",
            @"httpVersion": @"HTTP/1.1",
            @"headers": @[],
            @"cookies": @[],
            @"content": @{@"mimeType": @"", @"text": @"", @"size": @0},
            @"redirectURL": @"",
            @"headersSize": @(-1),
            @"bodySize": @0
        };
        entry[@"cache"] = @{};
        entry[@"timings"] = @{@"send": @(-1), @"wait": @(-1), @"receive": @(-1)};
        [allEntries addObject:entry];
    }

    NSDictionary *har = @{
        @"log": @{
            @"version": @"1.2",
            @"creator": @{@"name": @"ElemeFieldMonitor", @"version": @"1.0"},
            @"entries": allEntries
        }
    };
    NSData *data = [NSJSONSerialization dataWithJSONObject:har options:0 error:nil];

    // 写入临时 .har 文件
    NSString *tempDir = NSTemporaryDirectory();
    NSDateFormatter *fileFmt = [[NSDateFormatter alloc] init];
    fileFmt.dateFormat = @"yyyyMMdd_HHmmss";
    fileFmt.timeZone = [NSTimeZone localTimeZone];
    fileFmt.locale = [[NSLocale alloc] initWithLocaleIdentifier:@"en_US_POSIX"];
    NSString *fileName = [NSString stringWithFormat:@"eleme_%@.har", [fileFmt stringFromDate:[NSDate date]]];
    NSString *filePath = [tempDir stringByAppendingPathComponent:fileName];
    [data writeToFile:filePath atomically:YES];

    // 通过 UIActivityViewController 分享文件
    dispatch_async(dispatch_get_main_queue(), ^{
        NSURL *fileURL = [NSURL fileURLWithPath:filePath];
        UIActivityViewController *activityVC = [[UIActivityViewController alloc] initWithActivityItems:@[fileURL] applicationActivities:nil];
        activityVC.completionWithItemsHandler = ^(NSString *activityType, BOOL completed, NSArray *returnedItems, NSError *activityError) {
            // 清理临时文件
            [[NSFileManager defaultManager] removeItemAtPath:filePath error:nil];
            if (completed) {
                [self showToast:[NSString stringWithFormat:@"HAR exported: %ld entries", (long)allEntries.count]];
            }
        };

        // 找到合适的 ViewController 来 present
        UIWindowScene *scene = nil;
        for (UIScene *s in [UIApplication sharedApplication].connectedScenes.allObjects) {
            if (s.activationState == UISceneActivationStateForegroundActive && [s isKindOfClass:[UIWindowScene class]]) {
                scene = (UIWindowScene *)s;
                break;
            }
        }
        UIViewController *rootVC = nil;
        if (scene) {
            for (UIWindow *w in scene.windows) {
                if (w != self.window && w.rootViewController) {
                    rootVC = w.rootViewController;
                    break;
                }
            }
        }
        if (rootVC) {
            [rootVC presentViewController:activityVC animated:YES completion:nil];
        } else {
            // fallback: 用 self.window 的 rootViewController
            if (self.window.rootViewController) {
                [self.window.rootViewController presentViewController:activityVC animated:YES completion:nil];
            } else {
                // 最后 fallback: 复制到剪贴板
                UIPasteboard.generalPasteboard.string = [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];
                [[NSFileManager defaultManager] removeItemAtPath:filePath error:nil];
                [self showToast:@"HAR copied to clipboard (no VC)"];
            }
        }
    });
}

- (void)recordAPIRequest:(NSString *)api url:(NSString *)url method:(NSString *)method headers:(NSDictionary *)headers body:(NSString *)body {
    if (!api || api.length == 0) {
        // 没有API名时用URL作为标识
        api = url ?: @"unknown";
    }
    dispatch_async(dispatch_get_main_queue(), ^{
        NSMutableDictionary *req = [NSMutableDictionary dictionary];
        req[@"_api"] = api;
        req[@"url"] = url ?: @"-";
        req[@"method"] = method ?: @"GET";
        req[@"headers"] = headers ?: @{};
        req[@"body"] = body ?: @"-";
        // ISO 8601 格式: 2026-08-11T08:22:11.000Z
        NSDateFormatter *isoFmt = [[NSDateFormatter alloc] init];
        isoFmt.dateFormat = @"yyyy-MM-dd'T'HH:mm:ss.SSS'Z'";
        isoFmt.timeZone = [NSTimeZone timeZoneWithAbbreviation:@"UTC"];
        isoFmt.locale = [[NSLocale alloc] initWithLocaleIdentifier:@"en_US_POSIX"];
        req[@"_timestamp"] = [isoFmt stringFromDate:[NSDate date]];
        // 追加到 pendingRequests 数组，等待响应配对 (FIFO)
        [self.pendingRequests addObject:req];
        NSLog(@"[ElemeFieldMonitor] API request pending (#%lu): %@", (unsigned long)self.pendingRequests.count, api);
    });
}

- (void)recordAPIResponse:(NSString *)api response:(NSString *)response statusCode:(NSInteger)code {
    if (!api || api.length == 0) {
        api = @"unknown";
    }
    // 如果 code 为 0 但有响应内容，说明是 delegate-based 请求，
    // 响应数据通过 JSON hook 捕获但没有 HTTP 状态码，默认设为 200
    NSInteger effectiveCode = code;
    if (effectiveCode == 0 && response && response.length > 0 && ![response isEqualToString:@"-"]) {
        effectiveCode = 200;
    }
    dispatch_async(dispatch_get_main_queue(), ^{
        // FIFO 查找匹配的 pending request
        NSDictionary *pendingReq = nil;
        NSInteger pendingIdx = -1;
        for (NSInteger i = 0; i < (NSInteger)self.pendingRequests.count; i++) {
            NSDictionary *pr = self.pendingRequests[i];
            if ([pr[@"_api"] isEqualToString:api]) {
                pendingReq = pr;
                pendingIdx = i;
                break;
            }
        }
        
        // 如果没有匹配的 pending request，检查是否已有同 API 的 HAR 条目（避免重复）
        if (!pendingReq) {
            // 检查是否已有该 API 的条目（URLSession hook 可能已记录）
            BOOL foundExisting = NO;
            for (NSInteger i = (NSInteger)self.harEntries.count - 1; i >= 0; i--) {
                NSDictionary *existing = self.harEntries[i];
                if ([existing[@"_api"] isEqualToString:api]) {
                    // 已有条目，如果已有非零 status 则跳过，否则更新 status
                    NSDictionary *existingResp = existing[@"response"];
                    NSInteger existingStatus = [existingResp[@"status"] integerValue];
                    if (existingStatus > 0) {
                        // 已有正确 status，跳过不创建重复
                        NSLog(@"[ElemeFieldMonitor] Response duplicate skipped: %@ (existing status: %ld)", api, (long)existingStatus);
                        return;
                    } else if (effectiveCode > 0) {
                        // 更新现有条目的 status 和 response
                        NSMutableDictionary *mutableEntry = [existing mutableCopy];
                        NSMutableDictionary *mutableResp = [existingResp mutableCopy];
                        mutableResp[@"status"] = @(effectiveCode);
                        mutableResp[@"statusText"] = @"OK";
                        // 也更新响应内容（之前可能是空的）
                        if (response && response.length > 0) {
                            mutableResp[@"content"] = @{@"mimeType": @"application/json", @"text": response, @"size": @(response.length)};
                            mutableResp[@"bodySize"] = @(response.length);
                        }
                        mutableEntry[@"response"] = mutableResp;
                        [self.harEntries replaceObjectAtIndex:i withObject:mutableEntry];
                        NSLog(@"[ElemeFieldMonitor] Updated existing entry status: %@ -> %ld", api, (long)effectiveCode);
                        foundExisting = YES;
                    }
                    break;
                }
            }
            if (foundExisting) return;
            
            // 确实没有匹配，创建 response-only 条目，使用当前时间戳
            NSLog(@"[ElemeFieldMonitor] Response without pending request: %@ (creating response-only entry)", api);
            NSDateFormatter *nowFmt = [[NSDateFormatter alloc] init];
            nowFmt.dateFormat = @"yyyy-MM-dd'T'HH:mm:ss.SSS'Z'";
            nowFmt.timeZone = [NSTimeZone timeZoneWithAbbreviation:@"UTC"];
            nowFmt.locale = [[NSLocale alloc] initWithLocaleIdentifier:@"en_US_POSIX"];
            pendingReq = @{
                @"_api": api,
                @"url": g_lastURL ?: @"-",
                @"method": g_lastMethod ?: @"?",
                @"headers": g_lastHeaders ?: @{},
                @"body": @"",
                @"_timestamp": [nowFmt stringFromDate:[NSDate date]]
            };
        }
        
        NSMutableDictionary *entry = [NSMutableDictionary dictionary];
        entry[@"_api"] = api; // 仅供 UI 显示，导出时移除
        entry[@"startedDateTime"] = pendingReq[@"_timestamp"] ?: @"1970-01-01T00:00:00.000Z";
        entry[@"time"] = @0;
        
        // build request part
        NSMutableDictionary *harReq = [NSMutableDictionary dictionary];
        harReq[@"method"] = pendingReq[@"method"] ?: @"GET";
        harReq[@"url"] = pendingReq[@"url"] ?: @"-";
        harReq[@"httpVersion"] = @"HTTP/1.1";
        NSMutableArray *hdrArr = [NSMutableArray array];
        NSDictionary *hdrs = pendingReq[@"headers"];
        for (NSString *hk in hdrs) {
            [hdrArr addObject:@{@"name": hk, @"value": [NSString stringWithFormat:@"%@", hdrs[hk]]}];
        }
        harReq[@"headers"] = hdrArr;
        harReq[@"queryString"] = @[];
        harReq[@"headersSize"] = @(-1);
        NSString *bodyStr = pendingReq[@"body"] ?: @"";
        harReq[@"bodySize"] = @(bodyStr.length);
        if (bodyStr.length > 0 && ![bodyStr isEqualToString:@"-"]) {
            harReq[@"postData"] = @{@"mimeType": @"application/json", @"text": bodyStr};
        }
        entry[@"request"] = harReq;
        
        // build response part
        NSString *respStr = response ?: @"";
        NSInteger respSize = respStr.length;
        entry[@"response"] = @{
            @"status": @(effectiveCode),
            @"statusText": effectiveCode > 0 ? @"OK" : @"(unknown)",
            @"httpVersion": @"HTTP/1.1",
            @"headers": @[],
            @"cookies": @[],
            @"content": @{@"mimeType": @"application/json", @"text": respStr, @"size": @(respSize)},
            @"redirectURL": @"",
            @"headersSize": @(-1),
            @"bodySize": @(respSize)
        };
        entry[@"cache"] = @{};
        entry[@"timings"] = @{@"send": @(-1), @"wait": @(-1), @"receive": @(-1)};
        
        [self.harEntries addObject:entry];
        // 移除已配对的 pending request
        if (pendingIdx >= 0) {
            [self.pendingRequests removeObjectAtIndex:pendingIdx];
        }
        NSLog(@"[ElemeFieldMonitor] HAR entry #%ld: %@ (pending remaining: %lu)", (long)self.harEntries.count, api, (unsigned long)self.pendingRequests.count);
        // 如果当前在 HAR tab，刷新列表
        if (self.activeTab == 1) {
            [self refreshHarList];
        }
    });
}

- (void)clearAll {
    for (NSString *key in kTargetKeys()) {
        self.fieldValues[key] = nil;
        self.fieldSources[key] = nil;
        UILabel *label = self.fieldLabels[key];
        if (label) {
            label.text = @"(waiting...)";
            label.textColor = [UIColor colorWithRed:0.35 green:0.35 blue:0.38 alpha:1.0];
        }
    }
    self.captureCount = 0;
    self.lastAPI = @"-";
    self.lastSource = @"-";
    self.lastURL = @"-";
    self.lastCookie = @"-";
    self.lastUpdate = nil;
    [self.pendingRequests removeAllObjects];
    [self.harEntries removeAllObjects];
    self.urlLabel.text = @"URL: -";
    self.cookieLabel.text = @"Cookie: -";
    [self updateStatusBar];
    [self refreshHarList];
    [self showToast:@"Cleared!"];
}

- (void)tabFieldsTapped {
    [self switchTab:0];
}

- (void)tabHarTapped {
    [self switchTab:1];
}

- (void)tabMcpTapped {
    [self switchTab:2];
}

- (void)switchTab:(NSInteger)tabIndex {
    dispatch_async(dispatch_get_main_queue(), ^{
        self.activeTab = tabIndex;
        UIColor *activeColor = [UIColor colorWithRed:0.25 green:0.60 blue:1.0 alpha:1.0];
        UIColor *inactiveColor = [UIColor colorWithRed:0.45 green:0.45 blue:0.50 alpha:1.0];

        // Reset all tabs
        self.fieldsScrollView.hidden = YES;
        self.harScrollView.hidden = YES;
        self.mcpScrollView.hidden = YES;
        self.harSearchField.hidden = YES;
        [self.harSearchField resignFirstResponder];
        [self.tabFieldsBtn setTitleColor:inactiveColor forState:UIControlStateNormal];
        [self.tabHarBtn setTitleColor:inactiveColor forState:UIControlStateNormal];
        [self.tabMcpBtn setTitleColor:inactiveColor forState:UIControlStateNormal];

        // Footer: hide all by default
        self.exportBtn.hidden = YES;
        self.cookieCopyBtn.hidden = YES;
        self.clearButton.hidden = YES;
        self.harExportBtn.hidden = YES;
        UIView *harClear = [self.footerView viewWithTag:888];
        harClear.hidden = YES;

        if (tabIndex == 0) {
            // Fields tab
            self.fieldsScrollView.hidden = NO;
            [self.tabFieldsBtn setTitleColor:activeColor forState:UIControlStateNormal];
            [UIView animateWithDuration:0.2 animations:^{
                self.tabFieldsIndicator.alpha = 1.0;
                self.tabHarIndicator.alpha = 0.0;
                self.tabMcpIndicator.alpha = 0.0;
            }];
            self.exportBtn.hidden = NO;
            self.cookieCopyBtn.hidden = NO;
            self.clearButton.hidden = NO;
        } else if (tabIndex == 1) {
            // HAR tab
            self.harScrollView.hidden = NO;
            [self.tabHarBtn setTitleColor:activeColor forState:UIControlStateNormal];
            [UIView animateWithDuration:0.2 animations:^{
                self.tabFieldsIndicator.alpha = 0.0;
                self.tabHarIndicator.alpha = 1.0;
                self.tabMcpIndicator.alpha = 0.0;
            }];
            self.harExportBtn.hidden = NO;
            harClear.hidden = NO;
            self.harSearchField.hidden = NO;
            [self refreshHarList];
        } else {
            // MCP tab
            self.mcpScrollView.hidden = NO;
            [self.tabMcpBtn setTitleColor:activeColor forState:UIControlStateNormal];
            [UIView animateWithDuration:0.2 animations:^{
                self.tabFieldsIndicator.alpha = 0.0;
                self.tabHarIndicator.alpha = 0.0;
                self.tabMcpIndicator.alpha = 1.0;
            }];
        }
    });
}

- (void)harSearchChanged:(UITextField *)field {
    self.harSearchQuery = field.text ?: @"";
    if (self.harSearchQuery.length == 0) {
        self.harSearchQuery = nil;
    }
    [self refreshHarList];
}

- (void)refreshHarList {
    dispatch_async(dispatch_get_main_queue(), ^{
        // 清除旧内容（保留 tag=999 空状态标签）
        NSMutableArray *toRemove = [NSMutableArray array];
        for (UIView *sub in self.harScrollView.subviews) {
            if (sub.tag != 999) {
                [toRemove addObject:sub];
            }
        }
        for (UIView *sub in toRemove) {
            [sub removeFromSuperview];
        }

        // 隐藏空状态
        UILabel *emptyLabel = (UILabel *)[self.harScrollView viewWithTag:999];
        BOOL hasEntries = (self.harEntries.count > 0) || (self.pendingRequests.count > 0);

        if (!hasEntries) {
            emptyLabel.hidden = NO;
            self.harScrollView.contentSize = CGSizeMake(self.harScrollView.bounds.size.width, self.harScrollView.bounds.size.height);
            return;
        }
        emptyLabel.hidden = YES;

        CGFloat cy = 8;
        CGFloat sidePad = 10;
        CGFloat cardW = self.harScrollView.bounds.size.width - sidePad * 2;
        CGFloat cardSpacing = 4;

        // 搜索过滤
        NSString *searchQuery = self.harSearchQuery;
        BOOL hasSearch = (searchQuery && searchQuery.length > 0);
        NSInteger displayIndex = 0;

        // 已配对的 HAR entries
        for (NSInteger i = 0; i < (NSInteger)self.harEntries.count; i++) {
            NSDictionary *entry = self.harEntries[i];
            NSString *apiName = entry[@"_api"] ?: [NSString stringWithFormat:@"Entry %ld", (long)(i + 1)];
            NSDictionary *req = entry[@"request"];
            NSDictionary *resp = entry[@"response"];
            NSString *method = req[@"method"] ?: @"?";
            NSString *url = req[@"url"] ?: @"-";
            NSInteger statusCode = [resp[@"status"] integerValue];
            NSString *bodyStr = @"";
            if (req[@"postData"][@"text"]) {
                bodyStr = req[@"postData"][@"text"];
            }
            NSString *respStr = @"";
            if (resp[@"content"][@"text"]) {
                respStr = resp[@"content"][@"text"];
            }

            // 搜索过滤
            if (hasSearch) {
                NSRange apiRange = [apiName rangeOfString:searchQuery options:NSCaseInsensitiveSearch];
                NSRange urlRange = [url rangeOfString:searchQuery options:NSCaseInsensitiveSearch];
                if (apiRange.location == NSNotFound && urlRange.location == NSNotFound) {
                    continue; // 不匹配，跳过
                }
            }
            NSInteger i = displayIndex;
            displayIndex++;

            // 截断显示
            NSString *urlShort = url;
            if (urlShort.length > 50) {
                urlShort = [NSString stringWithFormat:@"%@...", [urlShort substringToIndex:50]];
            }

            // 计算卡片高度: API名(18) + URL(16) + Method/Status(16) + Body预览(28) + Response预览(28) + padding
            CGFloat cardH = 18 + 16 + 16 + 28 + 28 + 12;

            UIView *card = [[UIView alloc] initWithFrame:CGRectMake(sidePad, cy, cardW, cardH)];
            card.backgroundColor = [UIColor colorWithRed:0.10 green:0.10 blue:0.13 alpha:0.85];
            card.layer.cornerRadius = 6;
            card.layer.masksToBounds = YES;
            [self.harScrollView addSubview:card];

            // 左侧色条 (根据状态码变色)
            UIColor *statusColor = (statusCode >= 200 && statusCode < 300) ?
                [UIColor colorWithRed:0.32 green:0.77 blue:0.10 alpha:1.0] :
                [UIColor colorWithRed:0.55 green:0.18 blue:0.18 alpha:1.0];
            UIView *bar = [[UIView alloc] initWithFrame:CGRectMake(0, 0, 3, cardH)];
            bar.backgroundColor = statusColor;
            [card addSubview:bar];

            // 序号 + API名
            UILabel *apiLabel = [[UILabel alloc] initWithFrame:CGRectMake(8, 4, cardW - 16, 18)];
            apiLabel.text = [NSString stringWithFormat:@"%ld. %@", (long)(i + 1), apiName];
            apiLabel.textColor = [UIColor colorWithRed:0.40 green:0.78 blue:0.47 alpha:1.0];
            apiLabel.font = [UIFont fontWithName:@"Menlo" size:10];
            apiLabel.adjustsFontSizeToFitWidth = YES;
            apiLabel.minimumScaleFactor = 0.5;
            [card addSubview:apiLabel];

            // URL
            UILabel *urlLabel = [[UILabel alloc] initWithFrame:CGRectMake(8, 22, cardW - 16, 14)];
            urlLabel.text = urlShort;
            urlLabel.textColor = [UIColor colorWithRed:0.55 green:0.65 blue:0.90 alpha:1.0];
            urlLabel.font = [UIFont fontWithName:@"Menlo" size:8];
            urlLabel.adjustsFontSizeToFitWidth = YES;
            urlLabel.minimumScaleFactor = 0.4;
            [card addSubview:urlLabel];

            // Method + Status
            UILabel *msLabel = [[UILabel alloc] initWithFrame:CGRectMake(8, 37, cardW - 16, 14)];
            msLabel.text = [NSString stringWithFormat:@"%@ | Status: %ld", method, (long)statusCode];
            msLabel.textColor = [UIColor colorWithRed:0.50 green:0.58 blue:0.65 alpha:1.0];
            msLabel.font = [UIFont fontWithName:@"Menlo" size:9];
            [card addSubview:msLabel];

            // Body preview
            NSString *bodyPreview = bodyStr;
            if (bodyPreview.length > 80) {
                bodyPreview = [NSString stringWithFormat:@"%@...", [bodyPreview substringToIndex:80]];
            }
            UILabel *bodyLabel = [[UILabel alloc] initWithFrame:CGRectMake(8, 52, cardW - 16, 24)];
            bodyLabel.text = [NSString stringWithFormat:@"Req: %@", bodyPreview];
            bodyLabel.textColor = [UIColor colorWithRed:0.85 green:0.75 blue:0.45 alpha:1.0];
            bodyLabel.font = [UIFont fontWithName:@"Menlo" size:8];
            bodyLabel.adjustsFontSizeToFitWidth = YES;
            bodyLabel.minimumScaleFactor = 0.4;
            bodyLabel.numberOfLines = 2;
            [card addSubview:bodyLabel];

            // Response preview
            NSString *respPreview = respStr;
            if (respPreview.length > 80) {
                respPreview = [NSString stringWithFormat:@"%@...", [respPreview substringToIndex:80]];
            }
            UILabel *respLabel = [[UILabel alloc] initWithFrame:CGRectMake(8, 78, cardW - 16, 24)];
            respLabel.text = [NSString stringWithFormat:@"Res: %@", respPreview];
            respLabel.textColor = [UIColor colorWithRed:0.65 green:0.80 blue:0.55 alpha:1.0];
            respLabel.font = [UIFont fontWithName:@"Menlo" size:8];
            respLabel.adjustsFontSizeToFitWidth = YES;
            respLabel.minimumScaleFactor = 0.4;
            respLabel.numberOfLines = 2;
            [card addSubview:respLabel];

            // 点击查看详情
            card.tag = 1000 + i;
            UITapGestureRecognizer *tap = [[UITapGestureRecognizer alloc]
                initWithTarget:self action:@selector(handleHarCardTap:)];
            [card addGestureRecognizer:tap];

            cy += cardH + cardSpacing;
        }

        // Pending requests (未配对)
        NSInteger pendingIdx = displayIndex;
        for (NSDictionary *req in self.pendingRequests) {
            NSString *apiName = req[@"_api"] ?: @"unknown";
            NSString *method = req[@"method"] ?: @"?";
            NSString *url = req[@"url"] ?: @"-";
            NSString *bodyStr = req[@"body"] ?: @"";

            // 搜索过滤
            if (hasSearch) {
                NSRange apiRange = [apiName rangeOfString:searchQuery options:NSCaseInsensitiveSearch];
                NSRange urlRange = [url rangeOfString:searchQuery options:NSCaseInsensitiveSearch];
                if (apiRange.location == NSNotFound && urlRange.location == NSNotFound) {
                    continue;
                }
            }

            NSString *urlShort = url;
            if (urlShort.length > 50) {
                urlShort = [NSString stringWithFormat:@"%@...", [urlShort substringToIndex:50]];
            }

            CGFloat cardH = 18 + 16 + 16 + 28 + 12;

            UIView *card = [[UIView alloc] initWithFrame:CGRectMake(sidePad, cy, cardW, cardH)];
            card.backgroundColor = [UIColor colorWithRed:0.10 green:0.10 blue:0.13 alpha:0.85];
            card.layer.cornerRadius = 6;
            card.layer.masksToBounds = YES;
            [self.harScrollView addSubview:card];

            // 橙色色条表示 pending
            UIView *bar = [[UIView alloc] initWithFrame:CGRectMake(0, 0, 3, cardH)];
            bar.backgroundColor = [UIColor colorWithRed:0.90 green:0.60 blue:0.10 alpha:1.0];
            [card addSubview:bar];

            UILabel *apiLabel = [[UILabel alloc] initWithFrame:CGRectMake(8, 4, cardW - 16, 18)];
            apiLabel.text = [NSString stringWithFormat:@"%ld. %@ (pending)", (long)(pendingIdx + 1), apiName];
            apiLabel.textColor = [UIColor colorWithRed:0.90 green:0.60 blue:0.10 alpha:1.0];
            apiLabel.font = [UIFont fontWithName:@"Menlo" size:10];
            apiLabel.adjustsFontSizeToFitWidth = YES;
            apiLabel.minimumScaleFactor = 0.5;
            [card addSubview:apiLabel];

            UILabel *urlLabel = [[UILabel alloc] initWithFrame:CGRectMake(8, 22, cardW - 16, 14)];
            urlLabel.text = urlShort;
            urlLabel.textColor = [UIColor colorWithRed:0.55 green:0.65 blue:0.90 alpha:1.0];
            urlLabel.font = [UIFont fontWithName:@"Menlo" size:8];
            urlLabel.adjustsFontSizeToFitWidth = YES;
            urlLabel.minimumScaleFactor = 0.4;
            [card addSubview:urlLabel];

            UILabel *msLabel = [[UILabel alloc] initWithFrame:CGRectMake(8, 37, cardW - 16, 14)];
            msLabel.text = [NSString stringWithFormat:@"%@ | Waiting response...", method];
            msLabel.textColor = [UIColor colorWithRed:0.50 green:0.58 blue:0.65 alpha:1.0];
            msLabel.font = [UIFont fontWithName:@"Menlo" size:9];
            [card addSubview:msLabel];

            NSString *bodyPreview = bodyStr;
            if (bodyPreview.length > 80) {
                bodyPreview = [NSString stringWithFormat:@"%@...", [bodyPreview substringToIndex:80]];
            }
            UILabel *bodyLabel = [[UILabel alloc] initWithFrame:CGRectMake(8, 52, cardW - 16, 24)];
            bodyLabel.text = [NSString stringWithFormat:@"Req: %@", bodyPreview];
            bodyLabel.textColor = [UIColor colorWithRed:0.85 green:0.75 blue:0.45 alpha:1.0];
            bodyLabel.font = [UIFont fontWithName:@"Menlo" size:8];
            bodyLabel.adjustsFontSizeToFitWidth = YES;
            bodyLabel.minimumScaleFactor = 0.4;
            bodyLabel.numberOfLines = 2;
            [card addSubview:bodyLabel];

            cy += cardH + cardSpacing;
            pendingIdx++;
        }

        self.harScrollView.contentSize = CGSizeMake(self.harScrollView.bounds.size.width, cy + 8);
    });
}

- (void)handleHarCardTap:(UITapGestureRecognizer *)gesture {
    UIView *card = gesture.view;
    NSInteger tag = card.tag;
    if (tag < 1000) return;
    NSInteger idx = tag - 1000;
    if (idx >= 0 && idx < (NSInteger)self.harEntries.count) {
        NSDictionary *entry = self.harEntries[idx];
        [self showHarDetail:entry];
    }
}

- (void)showHarDetail:(NSDictionary *)entry {
    dispatch_async(dispatch_get_main_queue(), ^{
        if (self.detailOverlayView) {
            [self.detailOverlayView removeFromSuperview];
        }

        CGFloat windowW = self.window.bounds.size.width;
        CGFloat windowH = self.window.bounds.size.height;

        // 半透明遮罩
        self.detailOverlayView = [[UIView alloc] initWithFrame:CGRectMake(0, 0, windowW, windowH)];
        self.detailOverlayView.backgroundColor = [UIColor colorWithRed:0 green:0 blue:0 alpha:0.5];
        self.detailOverlayView.tag = 7777;
        [self.containerView addSubview:self.detailOverlayView];

        // 点击遮罩关闭
        UITapGestureRecognizer *maskTap = [[UITapGestureRecognizer alloc]
            initWithTarget:self action:@selector(dismissHarDetail)];
        [self.detailOverlayView addGestureRecognizer:maskTap];

        // 详情面板
        CGFloat panelMargin = 8;
        CGFloat panelW = windowW - panelMargin * 2;
        CGFloat panelH = windowH - panelMargin * 2;
        UIView *panel = [[UIView alloc] initWithFrame:CGRectMake(panelMargin, panelMargin, panelW, panelH)];
        panel.backgroundColor = [UIColor colorWithRed:0.08 green:0.08 blue:0.10 alpha:0.98];
        panel.layer.cornerRadius = 12;
        panel.layer.masksToBounds = YES;
        panel.layer.borderWidth = 1;
        panel.layer.borderColor = [UIColor colorWithRed:0.18 green:0.18 blue:0.22 alpha:0.8].CGColor;
        [self.detailOverlayView addSubview:panel];

        // 关闭按钮
        UIButton *closeBtn = [UIButton buttonWithType:UIButtonTypeSystem];
        closeBtn.frame = CGRectMake(panelW - 32, 6, 26, 24);
        [closeBtn setTitle:@"✕" forState:UIControlStateNormal];
        [closeBtn setTitleColor:[UIColor colorWithRed:0.9 green:0.3 blue:0.3 alpha:1.0] forState:UIControlStateNormal];
        closeBtn.titleLabel.font = [UIFont boldSystemFontOfSize:14];
        [closeBtn addTarget:self action:@selector(dismissHarDetail) forControlEvents:UIControlEventTouchUpInside];
        [panel addSubview:closeBtn];

        // 标题
        NSString *apiName = entry[@"_api"] ?: @"Entry";
        UILabel *title = [[UILabel alloc] initWithFrame:CGRectMake(12, 8, panelW - 50, 20)];
        title.text = apiName;
        title.textColor = [UIColor colorWithRed:0.40 green:0.78 blue:0.47 alpha:1.0];
        title.font = [UIFont fontWithName:@"Menlo" size:11];
        title.adjustsFontSizeToFitWidth = YES;
        title.minimumScaleFactor = 0.5;
        [panel addSubview:title];

        // 分割线
        UIView *divider = [[UIView alloc] initWithFrame:CGRectMake(0, 30, panelW, 1)];
        divider.backgroundColor = [UIColor colorWithRed:0.18 green:0.18 blue:0.22 alpha:1.0];
        [panel addSubview:divider];

        // ScrollView for detail content
        UIScrollView *detailScroll = [[UIScrollView alloc] initWithFrame:CGRectMake(0, 31, panelW, panelH - 31 - 40)];
        detailScroll.showsVerticalScrollIndicator = YES;
        [panel addSubview:detailScroll];

        NSDictionary *req = entry[@"request"];
        NSDictionary *resp = entry[@"response"];

        CGFloat cy = 8;
        CGFloat pad = 12;
        CGFloat lblW = panelW - pad * 2;

        // --- Request section ---
        UILabel *reqHeader = [[UILabel alloc] initWithFrame:CGRectMake(pad, cy, lblW, 18)];
        reqHeader.text = @"▼ Request";
        reqHeader.textColor = [UIColor colorWithRed:0.25 green:0.60 blue:1.0 alpha:1.0];
        reqHeader.font = [UIFont boldSystemFontOfSize:11];
        [detailScroll addSubview:reqHeader];
        cy += 20;

        // Method
        UILabel *methodLabel = [[UILabel alloc] initWithFrame:CGRectMake(pad, cy, lblW, 16)];
        methodLabel.text = [NSString stringWithFormat:@"Method: %@", req[@"method"] ?: @"?"];
        methodLabel.textColor = [UIColor colorWithRed:0.50 green:0.58 blue:0.65 alpha:1.0];
        methodLabel.font = [UIFont fontWithName:@"Menlo" size:10];
        [detailScroll addSubview:methodLabel];
        cy += 16;

        // URL
        UILabel *urlLabel = [[UILabel alloc] initWithFrame:CGRectMake(pad, cy, lblW, 16)];
        urlLabel.text = [NSString stringWithFormat:@"URL: %@", req[@"url"] ?: @"-"];
        urlLabel.textColor = [UIColor colorWithRed:0.55 green:0.65 blue:0.90 alpha:1.0];
        urlLabel.font = [UIFont fontWithName:@"Menlo" size:9];
        urlLabel.adjustsFontSizeToFitWidth = YES;
        urlLabel.minimumScaleFactor = 0.4;
        urlLabel.numberOfLines = 2;
        [detailScroll addSubview:urlLabel];
        cy += 22;

        // Headers
        UILabel *hdrTitle = [[UILabel alloc] initWithFrame:CGRectMake(pad, cy, lblW, 16)];
        hdrTitle.text = @"Headers:";
        hdrTitle.textColor = [UIColor colorWithRed:0.50 green:0.58 blue:0.65 alpha:1.0];
        hdrTitle.font = [UIFont boldSystemFontOfSize:9];
        [detailScroll addSubview:hdrTitle];
        cy += 16;

        NSArray *headers = req[@"headers"] ?: @[];
        for (NSDictionary *hdr in headers) {
            NSString *hdrText = [NSString stringWithFormat:@"%@: %@", hdr[@"name"] ?: @"?", hdr[@"value"] ?: @"?"];
            UILabel *hdrLabel = [[UILabel alloc] initWithFrame:CGRectMake(pad + 8, cy, lblW - 8, 14)];
            hdrLabel.text = hdrText;
            hdrLabel.textColor = [UIColor colorWithRed:0.60 green:0.60 blue:0.65 alpha:1.0];
            hdrLabel.font = [UIFont fontWithName:@"Menlo" size:8];
            hdrLabel.adjustsFontSizeToFitWidth = YES;
            hdrLabel.minimumScaleFactor = 0.4;
            hdrLabel.numberOfLines = 2;
            [detailScroll addSubview:hdrLabel];
            cy += 16;
        }

        // Request Body
        NSString *bodyStr = @"";
        if (req[@"postData"][@"text"]) {
            bodyStr = req[@"postData"][@"text"];
        }
        UILabel *bodyTitle = [[UILabel alloc] initWithFrame:CGRectMake(pad, cy, lblW, 16)];
        bodyTitle.text = @"Request Body:";
        bodyTitle.textColor = [UIColor colorWithRed:0.50 green:0.58 blue:0.65 alpha:1.0];
        bodyTitle.font = [UIFont boldSystemFontOfSize:9];
        [detailScroll addSubview:bodyTitle];
        cy += 16;

        // 尝试格式化 JSON
        NSString *formattedBody = bodyStr;
        if (bodyStr.length > 0) {
            @try {
                NSData *bd = [bodyStr dataUsingEncoding:NSUTF8StringEncoding];
                id jsonObj = [NSJSONSerialization JSONObjectWithData:bd options:NSJSONReadingAllowFragments error:nil];
                if (jsonObj) {
                    NSData *pretty = [NSJSONSerialization dataWithJSONObject:jsonObj options:NSJSONWritingPrettyPrinted error:nil];
                    NSString *prettyStr = [[NSString alloc] initWithData:pretty encoding:NSUTF8StringEncoding];
                    if (prettyStr) formattedBody = prettyStr;
                }
            } @catch (NSException *e) {}
        }

        // 计算 body 高度
        UIFont *bodyFont = [UIFont fontWithName:@"Menlo" size:8];
        CGSize bodySize = [formattedBody boundingRectWithSize:CGSizeMake(lblW, CGFLOAT_MAX)
                                                       options:NSStringDrawingUsesLineFragmentOrigin
                                                    attributes:@{NSFontAttributeName: bodyFont}
                                                       context:nil].size;
        CGFloat bodyHeight = MAX(bodySize.height + 8, 30);
        UILabel *bodyContent = [[UILabel alloc] initWithFrame:CGRectMake(pad + 8, cy, lblW - 8, bodyHeight)];
        bodyContent.text = formattedBody;
        bodyContent.textColor = [UIColor colorWithRed:0.85 green:0.75 blue:0.45 alpha:1.0];
        bodyContent.font = bodyFont;
        bodyContent.numberOfLines = 0;
        bodyContent.lineBreakMode = NSLineBreakByCharWrapping;
        [detailScroll addSubview:bodyContent];
        cy += bodyHeight + 8;

        // --- Response section ---
        UILabel *respHeader = [[UILabel alloc] initWithFrame:CGRectMake(pad, cy, lblW, 18)];
        respHeader.text = @"▼ Response";
        respHeader.textColor = [UIColor colorWithRed:0.32 green:0.77 blue:0.10 alpha:1.0];
        respHeader.font = [UIFont boldSystemFontOfSize:11];
        [detailScroll addSubview:respHeader];
        cy += 20;

        // Status
        NSInteger statusCode = [resp[@"status"] integerValue];
        UILabel *statusLabel = [[UILabel alloc] initWithFrame:CGRectMake(pad, cy, lblW, 16)];
        statusLabel.text = [NSString stringWithFormat:@"Status: %ld", (long)statusCode];
        statusLabel.textColor = [UIColor colorWithRed:0.50 green:0.58 blue:0.65 alpha:1.0];
        statusLabel.font = [UIFont fontWithName:@"Menlo" size:10];
        [detailScroll addSubview:statusLabel];
        cy += 18;

        // Response Body
        NSString *respStr = @"";
        if (resp[@"content"][@"text"]) {
            respStr = resp[@"content"][@"text"];
        }
        UILabel *respBodyTitle = [[UILabel alloc] initWithFrame:CGRectMake(pad, cy, lblW, 16)];
        respBodyTitle.text = @"Response Body:";
        respBodyTitle.textColor = [UIColor colorWithRed:0.50 green:0.58 blue:0.65 alpha:1.0];
        respBodyTitle.font = [UIFont boldSystemFontOfSize:9];
        [detailScroll addSubview:respBodyTitle];
        cy += 16;

        // 格式化 response JSON
        NSString *formattedResp = respStr;
        if (respStr.length > 0) {
            @try {
                NSData *rd = [respStr dataUsingEncoding:NSUTF8StringEncoding];
                id jsonResp = [NSJSONSerialization JSONObjectWithData:rd options:NSJSONReadingAllowFragments error:nil];
                if (jsonResp) {
                    NSData *prettyResp = [NSJSONSerialization dataWithJSONObject:jsonResp options:NSJSONWritingPrettyPrinted error:nil];
                    NSString *prettyRespStr = [[NSString alloc] initWithData:prettyResp encoding:NSUTF8StringEncoding];
                    if (prettyRespStr) formattedResp = prettyRespStr;
                }
            } @catch (NSException *e) {}
        }

        CGSize respSize = [formattedResp boundingRectWithSize:CGSizeMake(lblW, CGFLOAT_MAX)
                                                      options:NSStringDrawingUsesLineFragmentOrigin
                                                   attributes:@{NSFontAttributeName: bodyFont}
                                                      context:nil].size;
        CGFloat respHeight = MAX(respSize.height + 8, 30);
        UILabel *respContent = [[UILabel alloc] initWithFrame:CGRectMake(pad + 8, cy, lblW - 8, respHeight)];
        respContent.text = formattedResp;
        respContent.textColor = [UIColor colorWithRed:0.65 green:0.80 blue:0.55 alpha:1.0];
        respContent.font = bodyFont;
        respContent.numberOfLines = 0;
        respContent.lineBreakMode = NSLineBreakByCharWrapping;
        [detailScroll addSubview:respContent];
        cy += respHeight + 8;

        detailScroll.contentSize = CGSizeMake(panelW, cy + 8);

        // 底部操作栏
        UIView *detailFooter = [[UIView alloc] initWithFrame:CGRectMake(0, panelH - 40, panelW, 40)];
        detailFooter.backgroundColor = [UIColor colorWithRed:0.09 green:0.09 blue:0.12 alpha:1.0];
        [panel addSubview:detailFooter];

        UIView *fDivider = [[UIView alloc] initWithFrame:CGRectMake(0, 0, panelW, 1)];
        fDivider.backgroundColor = [UIColor colorWithRed:0.18 green:0.18 blue:0.22 alpha:1.0];
        [detailFooter addSubview:fDivider];

        CGFloat dBtnH = 28;
        CGFloat dBtnSpacing = 8;
        CGFloat dBtnW = (panelW - dBtnSpacing * 3) / 2;
        CGFloat dBtnY = (40 - dBtnH) / 2;

        // Copy Request
        UIButton *copyReqBtn = [UIButton buttonWithType:UIButtonTypeSystem];
        copyReqBtn.frame = CGRectMake(dBtnSpacing, dBtnY, dBtnW, dBtnH);
        [copyReqBtn setTitle:@"Copy Request" forState:UIControlStateNormal];
        [copyReqBtn setTitleColor:[UIColor whiteColor] forState:UIControlStateNormal];
        copyReqBtn.titleLabel.font = [UIFont systemFontOfSize:10];
        copyReqBtn.backgroundColor = [UIColor colorWithRed:0.12 green:0.40 blue:0.78 alpha:0.85];
        copyReqBtn.layer.cornerRadius = 6;
        [copyReqBtn addTarget:self action:@selector(copyHarRequest:) forControlEvents:UIControlEventTouchUpInside];
        copyReqBtn.tag = 7001;
        [copyReqBtn setValue:bodyStr forKey:@"bodyText"];
        [detailFooter addSubview:copyReqBtn];

        // Copy Response
        UIButton *copyRespBtn = [UIButton buttonWithType:UIButtonTypeSystem];
        copyRespBtn.frame = CGRectMake(dBtnSpacing * 2 + dBtnW, dBtnY, dBtnW, dBtnH);
        [copyRespBtn setTitle:@"Copy Response" forState:UIControlStateNormal];
        [copyRespBtn setTitleColor:[UIColor whiteColor] forState:UIControlStateNormal];
        copyRespBtn.titleLabel.font = [UIFont systemFontOfSize:10];
        copyRespBtn.backgroundColor = [UIColor colorWithRed:0.20 green:0.52 blue:0.30 alpha:0.85];
        copyRespBtn.layer.cornerRadius = 6;
        [copyRespBtn addTarget:self action:@selector(copyHarResponse:) forControlEvents:UIControlEventTouchUpInside];
        copyRespBtn.tag = 7002;
        [copyRespBtn setValue:respStr forKey:@"respText"];
        [detailFooter addSubview:copyRespBtn];

        // 动画弹出
        panel.transform = CGAffineTransformMakeScale(0.9, 0.9);
        panel.alpha = 0;
        [UIView animateWithDuration:0.2 animations:^{
            panel.transform = CGAffineTransformIdentity;
            panel.alpha = 1.0;
        }];
    });
}

- (void)copyHarRequest:(UIButton *)btn {
    NSString *body = [btn valueForKey:@"bodyText"];
    if (body && body.length > 0) {
        UIPasteboard.generalPasteboard.string = body;
        [self showToast:@"Request body copied!"];
    }
}

- (void)copyHarResponse:(UIButton *)btn {
    NSString *resp = [btn valueForKey:@"respText"];
    if (resp && resp.length > 0) {
        UIPasteboard.generalPasteboard.string = resp;
        [self showToast:@"Response body copied!"];
    }
}

- (void)dismissHarDetail {
    dispatch_async(dispatch_get_main_queue(), ^{
        if (self.detailOverlayView) {
            [UIView animateWithDuration:0.15 animations:^{
                self.detailOverlayView.alpha = 0;
            } completion:^(BOOL finished) {
                [self.detailOverlayView removeFromSuperview];
                self.detailOverlayView = nil;
            }];
        }
    });
}

- (void)clearHar {
    dispatch_async(dispatch_get_main_queue(), ^{
        [self.pendingRequests removeAllObjects];
        [self.harEntries removeAllObjects];
        [self updateStatusBar];
        [self refreshHarList];
        [self showToast:@"HAR cleared!"];
    });
}

- (void)showToast:(NSString *)msg {
    UILabel *toast = [[UILabel alloc] init];
    toast.text = msg;
    toast.textColor = [UIColor whiteColor];
    toast.font = [UIFont systemFontOfSize:13];
    toast.backgroundColor = [UIColor colorWithRed:0.1 green:0.1 blue:0.12 alpha:0.95];
    toast.textAlignment = NSTextAlignmentCenter;
    toast.layer.cornerRadius = 8;
    toast.layer.masksToBounds = YES;

    [toast sizeToFit];
    CGFloat pad = 16;
    toast.frame = CGRectMake(0, 0, toast.bounds.size.width + pad * 2, toast.bounds.size.height + pad);
    toast.center = self.containerView.center;

    [self.containerView addSubview:toast];
    toast.alpha = 0.0;

    [UIView animateWithDuration:0.2 animations:^{
        toast.alpha = 1.0;
    } completion:^(BOOL finished) {
        [UIView animateWithDuration:0.3 delay:1.2 options:0 animations:^{
            toast.alpha = 0.0;
        } completion:^(BOOL finished) {
            [toast removeFromSuperview];
        }];
    }];
}

@end

// ============================================================================
// MARK: - Hooks
// ============================================================================

// --- Hook 1: NSJSONSerialization (拦截所有 JSON 解析) ---
%hook NSJSONSerialization

+ (id)JSONObjectWithData:(NSData *)data options:(NSJSONReadingOptions)opt error:(NSError **)error {
    id result = %orig;

    if (result && data && data.length > 0) {
        @try {
            NSMutableDictionary *results = [NSMutableDictionary dictionary];
            [FieldHunter searchInObject:result results:results];
            
            // 提取 API 名称（不受 results 门控）
            NSString *api = nil;
            if ([result isKindOfClass:[NSDictionary class]]) {
                api = result[@"api"] ?: result[@"apiName"];
                if (!api) {
                    // 搜索嵌套的 api 字段
                    NSDictionary *dict = (NSDictionary *)result;
                    if (dict[@"data"] && [dict[@"data"] isKindOfClass:[NSDictionary class]]) {
                        api = dict[@"data"][@"api"];
                    }
                }
            }
            
            // 更新 UI 字段（仅当找到目标字段时）
            if (results.count > 0) {
                [[FloatWindowManager sharedInstance] updateWithDictionary:results
                                                                    source:@"JSONResponse"
                                                                       api:api];
            }
            
            // 如果有 API 名称，区分请求信封和响应（不受 results 门控，不限目标 API）
            {
                NSString *rawStr = [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding] ?: @"-";
                NSDictionary *dict = (NSDictionary *)result;
                BOOL isRequestEnvelope = (dict[@"param"] != nil && dict[@"data"] == nil && dict[@"ret"] == nil);
                BOOL isResponse = (dict[@"data"] != nil || dict[@"ret"] != nil);
                
                // 没有 API 名时用 URL 作为标识
                if (!api || api.length == 0) {
                    if (g_lastURL) {
                        api = g_lastURL;
                    } else {
                        api = @"unknown";
                    }
                }
                
                if (isRequestEnvelope) {
                    // MTOP 请求信封（被 JSON 解析捕获）
                    NSString *reqURL = g_lastURL ?: @"-";
                    NSString *reqMethod = g_lastMethod ?: @"POST";
                    NSDictionary *reqHeaders = g_lastHeaders ?: @{};
                    [[FloatWindowManager sharedInstance] recordAPIRequest:api
                                                                      url:reqURL
                                                                   method:reqMethod
                                                                  headers:reqHeaders
                                                                     body:rawStr];
                    NSLog(@"[ElemeFieldMonitor] Request (envelope) captured: %@", api);
                } else if (isResponse) {
                    // MTOP 响应（使用 g_lastStatusCode 供 JSON hook 获取状态码）
                    [[FloatWindowManager sharedInstance] recordAPIResponse:api
                                                                   response:rawStr
                                                                  statusCode:g_lastStatusCode];
                    NSLog(@"[ElemeFieldMonitor] Response (JSON) captured: %@ (status: %ld)", api, (long)g_lastStatusCode);
                } else {
                    // 未知类型，默认当响应
                    [[FloatWindowManager sharedInstance] recordAPIResponse:api
                                                                   response:rawStr
                                                                  statusCode:g_lastStatusCode];
                    NSLog(@"[ElemeFieldMonitor] Response (JSON unknown) captured: %@ (status: %ld)", api, (long)g_lastStatusCode);
                }
            }
        } @catch (NSException *e) {
            // 忽略异常
        }
    }
    return result;
}

+ (id)JSONObjectWithStream:(NSInputStream *)stream options:(NSJSONReadingOptions)opt error:(NSError **)error {
    id result = %orig;
    if (result) {
        @try {
            NSMutableDictionary *results = [NSMutableDictionary dictionary];
            [FieldHunter searchInObject:result results:results];
            if (results.count > 0) {
                [[FloatWindowManager sharedInstance] updateWithDictionary:results
                                                                    source:@"JSONStream"
                                                                       api:nil];
            }
        } @catch (NSException *e) {}
    }
    return result;
}

// Hook dataWithJSONObject:options:error: (捕获请求序列化)
+ (NSData *)dataWithJSONObject:(id)obj options:(NSJSONWritingOptions)opt error:(NSError **)error {
    NSData *result = %orig;
    if (result && result.length > 0 && [obj isKindOfClass:[NSDictionary class]]) {
        @try {
            NSString *api = obj[@"api"] ?: obj[@"apiName"];
            if (api && api.length > 0) {
                // 这是 API 请求序列化
                NSString *bodyStr = [[NSString alloc] initWithData:result encoding:NSUTF8StringEncoding] ?: @"-";
                NSString *reqURL = g_lastURL ?: @"-";
                NSString *reqMethod = g_lastMethod ?: @"POST";
                NSDictionary *reqHeaders = g_lastHeaders ?: @{};
                [[FloatWindowManager sharedInstance] recordAPIRequest:api
                                                                  url:reqURL
                                                               method:reqMethod
                                                              headers:reqHeaders
                                                                 body:bodyStr];
                NSLog(@"[ElemeFieldMonitor] API request (serialize) captured: %@", api);
            }
        } @catch (NSException *e) {}
    }
    return result;
}

%end

// --- Hook 2: NSURLSession (拦截网络请求和响应) ---
%hook NSURLSession

- (NSURLSessionDataTask *)dataTaskWithRequest:(NSURLRequest *)request
                            completionHandler:(void (^)(NSData *, NSURLResponse *, NSError *))completionHandler {

    // ---- 拦截请求 ----
    NSString *requestAPI = nil;
    NSMutableDictionary *reqResults = [NSMutableDictionary dictionary];

    // 解析 URL query 参数
    NSURL *url = request.URL;
    if (url) {
        [FieldHunter searchInURL:url results:reqResults];
        // 提取可能的 API 名称 (MTOP URL 通常包含 mtop.)
        NSString *path = url.absoluteString;
        NSRange mtopRange = [path rangeOfString:@"mtop."];
        if (mtopRange.location != NSNotFound) {
            NSString *apiPart = [path substringFromIndex:mtopRange.location];
            // 截取到下一个 & 或 / 或 ?
            NSRange endRange = [apiPart rangeOfString:@"[&/?]"
                                              options:NSRegularExpressionSearch];
            if (endRange.location != NSNotFound) {
                requestAPI = [apiPart substringToIndex:endRange.location];
            } else {
                requestAPI = apiPart;
            }
        }
    }

    // 解析请求 body
    NSData *body = request.HTTPBody;
    if (body) {
        [FieldHunter searchInBody:body results:reqResults];
        // 也尝试从 body 提取 API 名称
        if (!requestAPI) {
            @try {
                id bodyJson = [NSJSONSerialization JSONObjectWithData:body
                                                              options:NSJSONReadingAllowFragments
                                                                error:nil];
                if ([bodyJson isKindOfClass:[NSDictionary class]]) {
                    requestAPI = bodyJson[@"api"] ?: bodyJson[@"apiName"];
                }
            } @catch (NSException *e) {}
        }
    }

    // 搜索 HTTP headers 中的目标字段
    NSDictionary *headers = request.allHTTPHeaderFields;
    if (headers) {
        [FieldHunter searchInHeaders:headers results:reqResults];
    }

    if (reqResults.count > 0) {
        [[FloatWindowManager sharedInstance] updateWithDictionary:reqResults
                                                            source:@"Request"
                                                               api:requestAPI];
    }

    // 更新 URL 显示
    if (url) {
        [[FloatWindowManager sharedInstance] updateURL:url.absoluteString];
    }

    // 捕获请求 Cookie
    NSString *cookieHeader = headers[@"Cookie"] ?: headers[@"cookie"];
    if (cookieHeader && cookieHeader.length > 0) {
        [[FloatWindowManager sharedInstance] updateCookie:cookieHeader];
    }

    // 记录完整请求信息（所有请求，不限目标 API）
    {
        // 没有 API 名时用 URL path 作为标识
        if (!requestAPI || requestAPI.length == 0) {
            if (url) {
                NSString *path = url.path ?: @"";
                NSString *host = url.host ?: @"";
                if (path.length > 0) {
                    requestAPI = [NSString stringWithFormat:@"%@%@", host, path];
                } else {
                    requestAPI = host.length > 0 ? host : url.absoluteString;
                }
            } else {
                requestAPI = @"unknown";
            }
        }
        NSString *bodyStr = @"-";
        if (body) {
            bodyStr = [[NSString alloc] initWithData:body encoding:NSUTF8StringEncoding] ?: @"-";
        }
        [[FloatWindowManager sharedInstance] recordAPIRequest:requestAPI
                                                           url:url.absoluteString
                                                        method:request.HTTPMethod ?: @"GET"
                                                       headers:headers ?: @{}
                                                          body:bodyStr];
        NSLog(@"[ElemeFieldMonitor] API request captured: %@", requestAPI);
    }

    // ---- 包装 completionHandler 拦截响应 ----
    void (^wrappedHandler)(NSData *, NSURLResponse *, NSError *) = ^(NSData *data, NSURLResponse *response, NSError *error) {
        // 捕获响应中的 Set-Cookie
        if ([response isKindOfClass:[NSHTTPURLResponse class]]) {
            NSHTTPURLResponse *httpResp = (NSHTTPURLResponse *)response;
            NSDictionary *respHeaders = httpResp.allHeaderFields;
            NSString *setCookie = respHeaders[@"Set-Cookie"] ?: respHeaders[@"set-cookie"];
            if (setCookie && setCookie.length > 0) {
                [[FloatWindowManager sharedInstance] updateCookie:setCookie];
            }
        }
        if (data && data.length > 0) {
            @try {
                // 先提取状态码，设置 g_lastStatusCode 供 JSON hook 使用
                NSInteger statusCode = 0;
                if ([response isKindOfClass:[NSHTTPURLResponse class]]) {
                    statusCode = ((NSHTTPURLResponse *)response).statusCode;
                }
                g_lastStatusCode = statusCode;
                
                NSMutableDictionary *respResults = [NSMutableDictionary dictionary];
                [FieldHunter searchInBody:data results:respResults];
                // 尝试从响应中提取 API 名称
                NSString *respAPI = nil;
                if (respResults.count > 0) {
                    @try {
                        id respJson = [NSJSONSerialization JSONObjectWithData:data
                                                                      options:NSJSONReadingAllowFragments
                                                                        error:nil];
                        if ([respJson isKindOfClass:[NSDictionary class]]) {
                            respAPI = respJson[@"api"] ?: respJson[@"apiName"];
                        }
                    } @catch (NSException *e) {}
                    [[FloatWindowManager sharedInstance] updateWithDictionary:respResults
                                                                        source:@"Response"
                                                                           api:respAPI ?: requestAPI];
                }
                
                // 记录所有响应（不限目标 API）
                NSString *effectiveAPI = respAPI ?: requestAPI;
                if (!effectiveAPI || effectiveAPI.length == 0) {
                    // 没有 API 名时用 URL path 作为标识
                    NSURL *respUrl = request.URL;
                    if (respUrl) {
                        NSString *path = respUrl.path ?: @"";
                        NSString *host = respUrl.host ?: @"";
                        if (path.length > 0) {
                            effectiveAPI = [NSString stringWithFormat:@"%@%@", host, path];
                        } else {
                            effectiveAPI = host.length > 0 ? host : respUrl.absoluteString;
                        }
                    } else {
                        effectiveAPI = @"unknown";
                    }
                }
                // 尝试将响应转为字符串，二进制数据用描述代替
                NSString *respStr = [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];
                if (!respStr) {
                    // 非文本响应（图片、二进制等）
                    NSString *mimeType = @"";
                    if ([response isKindOfClass:[NSHTTPURLResponse class]]) {
                        mimeType = ((NSHTTPURLResponse *)response).MIMEString ?: @"";
                    }
                    respStr = [NSString stringWithFormat:@"(binary data, %lu bytes, %@)", (unsigned long)data.length, mimeType];
                }
                g_lastResponseAPI = [effectiveAPI copy];
                [[FloatWindowManager sharedInstance] recordAPIResponse:effectiveAPI
                                                               response:respStr
                                                              statusCode:statusCode];
                NSLog(@"[ElemeFieldMonitor] Response captured: %@ (status: %ld, %lu bytes)", effectiveAPI, (long)statusCode, (unsigned long)data.length);
            } @catch (NSException *e) {}
        }
        if (completionHandler) completionHandler(data, response, error);
    };

    return %orig(request, wrappedHandler);
}

- (NSURLSessionDataTask *)dataTaskWithRequest:(NSURLRequest *)request {
    captureRequestIfNeeded(request);
    return %orig;
}

%end

// --- Hook 3: NSMutableURLRequest (拦截请求 body 和 URL 设置) ---
%hook NSMutableURLRequest

- (void)setHTTPBody:(NSData *)body {
    %orig;

    if (body && body.length > 0) {
        @try {
            // 提取 API（不受 results 门控）
            NSString *api = nil;
            id bodyJson = [NSJSONSerialization JSONObjectWithData:body
                                                          options:NSJSONReadingAllowFragments
                                                            error:nil];
            if ([bodyJson isKindOfClass:[NSDictionary class]]) {
                api = bodyJson[@"api"] ?: bodyJson[@"apiName"];
            }
            
            // 搜索目标字段并更新 UI（仅当找到目标字段时）
            NSMutableDictionary *results = [NSMutableDictionary dictionary];
            [FieldHunter searchInBody:body results:results];
            if (results.count > 0) {
                [[FloatWindowManager sharedInstance] updateWithDictionary:results
                                                                    source:@"RequestBody"
                                                                       api:api];
            }
            
            // 记录完整请求（不限目标 API，不受 results 门控）
            // 如果 body 中没有 API，也检查 URL
            if (!api || api.length == 0) {
                NSURL *selfURL = [self URL];
                api = extractAPIFromURL(selfURL);
            }
            // 仍然没有 API 名时用 URL path 作为标识
            if (!api || api.length == 0) {
                NSURL *selfURL = [self URL];
                if (selfURL) {
                    NSString *path = selfURL.path ?: @"";
                    NSString *host = selfURL.host ?: @"";
                    if (path.length > 0) {
                        api = [NSString stringWithFormat:@"%@%@", host, path];
                    } else {
                        api = host.length > 0 ? host : selfURL.absoluteString;
                    }
                } else {
                    api = @"unknown";
                }
            }
            {
                NSString *bodyStr = [[NSString alloc] initWithData:body encoding:NSUTF8StringEncoding] ?: @"-";
                NSString *reqURL = @"-";
                NSString *reqMethod = @"POST";
                NSDictionary *reqHeaders = @{};
                @try {
                    NSURL *selfURL = [self URL];
                    if (selfURL) reqURL = selfURL.absoluteString;
                    reqMethod = [self HTTPMethod] ?: @"POST";
                    reqHeaders = [self allHTTPHeaderFields] ?: @{};
                } @catch (NSException *e) {}
                [[FloatWindowManager sharedInstance] recordAPIRequest:api
                                                                  url:reqURL
                                                               method:reqMethod
                                                              headers:reqHeaders
                                                                 body:bodyStr];
                NSLog(@"[ElemeFieldMonitor] Request (body) captured: %@", api);
            }
        } @catch (NSException *e) {}
    }
}

- (void)setURL:(NSURL *)url {
    %orig;
    if (url) {
        // 缓存最近的 URL 信息，供 MTOP 请求信封关联
        g_lastURL = url.absoluteString;
        @try {
            g_lastMethod = [self HTTPMethod] ?: @"POST";
            g_lastHeaders = [self allHTTPHeaderFields] ?: @{};
        } @catch (NSException *e) {}
        
        NSString *urlAPI = extractAPIFromURL(url);
        if (urlAPI && urlAPI.length > 0) {
            NSLog(@"[ElemeFieldMonitor] API URL detected in setURL: %@", urlAPI);
        }
    }
}

%end

// --- Hook 3d: NSURLConnection (同步请求) ---
%hook NSURLConnection

+ (NSData *)sendSynchronousRequest:(NSURLRequest *)request returningResponse:(NSURLResponse **)response error:(NSError **)error {
    captureRequestIfNeeded(request);
    NSData *data = %orig;
    // 记录所有响应
    if (data && data.length > 0) {
        NSURL *url = request.URL;
        NSString *api = extractAPIFromURL(url);
        if (!api) {
            @try {
                id bodyJson = [NSJSONSerialization JSONObjectWithData:data options:NSJSONReadingAllowFragments error:nil];
                if ([bodyJson isKindOfClass:[NSDictionary class]]) {
                    api = bodyJson[@"api"] ?: bodyJson[@"apiName"];
                }
            } @catch (NSException *e) {}
        }
        // 没有 API 名时用 URL path 作为标识
        if (!api || api.length == 0) {
            if (url) {
                NSString *path = url.path ?: @"";
                NSString *host = url.host ?: @"";
                if (path.length > 0) {
                    api = [NSString stringWithFormat:@"%@%@", host, path];
                } else {
                    api = host.length > 0 ? host : url.absoluteString;
                }
            } else {
                api = @"unknown";
            }
        }
        NSString *respStr = [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];
        if (!respStr) {
            NSString *mimeType = @"";
            if (response && [*response isKindOfClass:[NSHTTPURLResponse class]]) {
                mimeType = ((NSHTTPURLResponse *)*response).MIMEString ?: @"";
            }
            respStr = [NSString stringWithFormat:@"(binary data, %lu bytes, %@)", (unsigned long)data.length, mimeType];
        }
        NSInteger statusCode = 0;
        if (response && [*response isKindOfClass:[NSHTTPURLResponse class]]) {
            statusCode = ((NSHTTPURLResponse *)*response).statusCode;
        }
        [[FloatWindowManager sharedInstance] recordAPIResponse:api
                                                       response:respStr
                                                      statusCode:statusCode];
        NSLog(@"[ElemeFieldMonitor] Response (sync) captured: %@ (status: %ld)", api, (long)statusCode);
    }
    return data;
}

+ (void)sendAsynchronousRequest:(NSURLRequest *)request queue:(NSOperationQueue *)queue completionHandler:(void (^)(NSURLResponse *, NSData *, NSError *))handler {
    captureRequestIfNeeded(request);
    void (^wrappedHandler)(NSURLResponse *, NSData *, NSError *) = ^(NSURLResponse *response, NSData *data, NSError *error) {
        if (data && data.length > 0) {
            NSURL *url = request.URL;
            NSString *api = extractAPIFromURL(url);
            if (!api) {
                @try {
                    id bodyJson = [NSJSONSerialization JSONObjectWithData:data options:NSJSONReadingAllowFragments error:nil];
                    if ([bodyJson isKindOfClass:[NSDictionary class]]) {
                        api = bodyJson[@"api"] ?: bodyJson[@"apiName"];
                    }
                } @catch (NSException *e) {}
            }
            // 没有 API 名时用 URL path 作为标识
            if (!api || api.length == 0) {
                if (url) {
                    NSString *path = url.path ?: @"";
                    NSString *host = url.host ?: @"";
                    if (path.length > 0) {
                        api = [NSString stringWithFormat:@"%@%@", host, path];
                    } else {
                        api = host.length > 0 ? host : url.absoluteString;
                    }
                } else {
                    api = @"unknown";
                }
            }
            NSString *respStr = [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];
            if (!respStr) {
                NSString *mimeType = @"";
                if ([response isKindOfClass:[NSHTTPURLResponse class]]) {
                    mimeType = ((NSHTTPURLResponse *)response).MIMEString ?: @"";
                }
                respStr = [NSString stringWithFormat:@"(binary data, %lu bytes, %@)", (unsigned long)data.length, mimeType];
            }
            NSInteger statusCode = 0;
            if ([response isKindOfClass:[NSHTTPURLResponse class]]) {
                statusCode = ((NSHTTPURLResponse *)response).statusCode;
            }
            [[FloatWindowManager sharedInstance] recordAPIResponse:api
                                                           response:respStr
                                                          statusCode:statusCode];
            NSLog(@"[ElemeFieldMonitor] Response (async) captured: %@ (status: %ld)", api, (long)statusCode);
        }
        if (handler) handler(response, data, error);
    };
    %orig(request, queue, wrappedHandler);
}

%end

// --- Hook 5: NSHTTPCookieStorage (拦截 Cookie 读取) ---
%hook NSHTTPCookieStorage

- (NSArray *)cookiesForURL:(NSURL *)URL {
    NSArray *cookies = %orig;
    if (cookies && cookies.count > 0 && URL) {
        NSMutableString *cookieStr = [NSMutableString string];
        for (NSHTTPCookie *cookie in cookies) {
            if (cookieStr.length > 0) [cookieStr appendString:@"; "];
            [cookieStr appendFormat:@"%@=%@", cookie.name, cookie.value];
        }
        if (cookieStr.length > 0) {
            [[FloatWindowManager sharedInstance] updateCookie:cookieStr];
        }
    }
    return cookies;
}

%end
// --- Hook 4: NSMutableDictionary setObject:forKey: (拦截字典写入) ---
// 仅 hook NSMutableDictionary 而非 NSDictionary，避免性能问题
%hook NSMutableDictionary

- (void)setObject:(id)anObject forKey:(id<NSCopying>)aKey {
    %orig;

    if ([(id)aKey isKindOfClass:[NSString class]]) {
        NSString *lowerKey = [(NSString *)aKey lowercaseString];
        NSString *matchedTarget = nil;
        for (NSString *target in kTargetKeys()) {
            if ([lowerKey isEqualToString:[target lowercaseString]]) {
                matchedTarget = target;
                break;
            }
        }
        if (matchedTarget) {
            NSString *value = [NSString stringWithFormat:@"%@", anObject];
            if (value.length > 0 && ![value isEqualToString:@"(null)"] && 
                ![anObject isKindOfClass:[NSNull class]]) {
                NSMutableDictionary *results = [NSMutableDictionary dictionary];
                results[matchedTarget] = value;
                [[FloatWindowManager sharedInstance] updateWithDictionary:results
                                                                source:@"DictSet"
                                                                   api:nil];
            }
        }
    }
}

%end

// ============================================================================
// MARK: - HTTP Server (MCP-style endpoint for computer queries)
// ============================================================================

@interface MCPHTTPServer : NSObject <NSURLSessionDelegate>
@property (nonatomic, strong) NSURLSession *serverSession;
+ (instancetype)sharedInstance;
- (void)start;
@end

@implementation MCPHTTPServer

+ (instancetype)sharedInstance {
    static MCPHTTPServer *instance = nil;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        instance = [[MCPHTTPServer alloc] init];
    });
    return instance;
}

- (NSString *)buildJSONResponseForPath:(NSString *)path query:(NSString *)query {
    FloatWindowManager *mgr = [FloatWindowManager sharedInstance];

    if ([path isEqualToString:@"/status"]) {
        // 返回 tweak 状态
        NSDictionary *status = @{
            @"captureCount": @(mgr.captureCount),
            @"harCount": @(mgr.harEntries.count),
            @"pendingCount": @(mgr.pendingRequests.count),
            @"lastAPI": mgr.lastAPI ?: @"-",
            @"lastURL": mgr.lastURL ?: @"-",
            @"lastCookie": mgr.lastCookie ?: @"-",
            @"lastSource": mgr.lastSource ?: @"-",
            @"lastUpdate": mgr.lastUpdate ? [mgr.lastUpdate description] : @"-"
        };
        NSDictionary *fields = mgr.fieldValues;
        NSMutableDictionary *fieldData = [NSMutableDictionary dictionary];
        for (NSString *key in fields) {
            fieldData[key] = @{
                @"value": fields[key] ?: @"-",
                @"source": mgr.fieldSources[key] ?: @"-"
            };
        }
        return [self dictToJSON:@{@"status": status, @"fields": fieldData}];
    }

    if ([path isEqualToString:@"/har"]) {
        // 返回所有 HAR 条目
        NSMutableArray *cleanEntries = [NSMutableArray array];
        for (NSDictionary *e in mgr.harEntries) {
            NSMutableDictionary *clean = [e mutableCopy];
            [clean removeObjectForKey:@"_api"];
            [cleanEntries addObject:clean];
        }
        return [self dictToJSON:@{
            @"total": @(cleanEntries.count),
            @"entries": cleanEntries
        }];
    }

    if ([path isEqualToString:@"/har/search"]) {
        // 搜索 HAR 条目 ?q=keyword
        NSString *keyword = @"";
        if (query) {
            NSDictionary *params = [self parseQueryString:query];
            keyword = params[@"q"] ?: @"";
        }
        NSMutableArray *results = [NSMutableArray array];
        for (NSDictionary *e in mgr.harEntries) {
            NSString *api = e[@"_api"] ?: @"";
            NSDictionary *req = e[@"request"];
            NSString *url = req[@"url"] ?: @"";
            if (keyword.length == 0 ||
                [api rangeOfString:keyword options:NSCaseInsensitiveSearch].location != NSNotFound ||
                [url rangeOfString:keyword options:NSCaseInsensitiveSearch].location != NSNotFound) {
                NSMutableDictionary *clean = [e mutableCopy];
                [clean removeObjectForKey:@"_api"];
                [results addObject:clean];
            }
        }
        return [self dictToJSON:@{
            @"query": keyword,
            @"total": @(results.count),
            @"entries": results
        }];
    }

    if ([path hasPrefix:@"/har/"]) {
        // 获取单条 HAR ?index=N
        NSString *idxStr = [path substringFromIndex:5];
        NSInteger idx = [idxStr integerValue];
        if (idx >= 0 && idx < (NSInteger)mgr.harEntries.count) {
            NSMutableDictionary *clean = [mgr.harEntries[idx] mutableCopy];
            [clean removeObjectForKey:@"_api"];
            return [self dictToJSON:clean];
        }
        return [self dictToJSON:@{@"error": @"Index out of range"}];
    }

    if ([path isEqualToString:@"/fields"]) {
        // 返回所有字段值
        NSMutableDictionary *fieldData = [NSMutableDictionary dictionary];
        for (NSString *key in mgr.fieldValues) {
            fieldData[key] = @{
                @"value": mgr.fieldValues[key] ?: @"-",
                @"source": mgr.fieldSources[key] ?: @"-"
            };
        }
        return [self dictToJSON:fieldData];
    }

    if ([path isEqualToString:@"/clear"]) {
        // 清除所有数据
        [mgr clearAll];
        [mgr clearHar];
        return [self dictToJSON:@{@"result": @"ok", @"message": @"All data cleared"}];
    }

    // 默认: 返回 HTML 网页界面
    return [self buildHTMLPage];
}

- (NSString *)buildHTMLPage {
    return @"<!DOCTYPE html><html><head><meta charset='utf-8'><meta name='viewport' content='width=device-width,initial-scale=1'><title>ElemeFieldMonitor</title><style>"
    "*{margin:0;padding:0;box-sizing:border-box}body{font-family:Menlo,Monaco,monospace;background:#0d0d0f;color:#ccc;font-size:13px}"
    ".header{background:#12121a;padding:12px 16px;border-bottom:1px solid #222;display:flex;justify-content:space-between;align-items:center;position:sticky;top:0;z-index:100}"
    ".header h1{font-size:15px;color:#5fa83a}.header .stats{font-size:11px;color:#888}"
    ".tabs{display:flex;gap:0;border-bottom:1px solid #222}.tab{padding:8px 20px;cursor:pointer;border-bottom:2px solid transparent;color:#666}"
    ".tab.active{color:#5fa83a;border-bottom-color:#5fa83a}"
    ".content{padding:12px}.search-box{width:100%;padding:8px 12px;background:#1a1a22;border:1px solid #333;border-radius:6px;color:#ccc;font-family:Menlo;font-size:12px;margin-bottom:10px}"
    ".card{background:#111118;border-radius:6px;margin-bottom:6px;overflow:hidden;cursor:pointer;border-left:3px solid #333}"
    ".card.ok{border-left-color:#4fc726}.card.err{border-left-color:#c43}.card.pending{border-left-color:#e6990a}"
    ".card-header{padding:6px 10px}.card-api{color:#5fa83a;font-size:11px}.card-url{color:#8aa5e0;font-size:10px;word-break:break-all}"
    ".card-meta{color:#8090a0;font-size:10px}.card-body{color:#d9b873;font-size:10px;word-break:break-all;max-height:40px;overflow:hidden}"
    ".card-resp{color:#a6cc8c;font-size:10px;word-break:break-all;max-height:40px;overflow:hidden}"
    ".field-row{display:flex;justify-content:space-between;padding:6px 10px;background:#111118;border-radius:4px;margin-bottom:4px}"
    ".field-name{color:#8aa5e0}.field-value{color:#d9b873;word-break:break-all;text-align:right;max-width:60%}"
    ".field-source{color:#666;font-size:10px}"
    ".detail-overlay{position:fixed;top:0;left:0;width:100%;height:100%;background:rgba(0,0,0,0.7);display:none;z-index:200;overflow:auto}"
    ".detail-overlay.show{display:block}.detail-box{background:#0d0d0f;margin:20px auto;max-width:800px;border-radius:8px;padding:16px}"
    ".detail-box h2{color:#5fa83a;margin-bottom:8px}.detail-section{margin-bottom:12px}.detail-section h3{color:#8aa5e0;font-size:12px;margin-bottom:4px}"
    ".detail-section pre{background:#111118;padding:8px;border-radius:4px;overflow:auto;font-size:11px;max-height:300px;white-space:pre-wrap;word-break:break-all}"
    ".detail-close{float:right;cursor:pointer;color:#c44;font-size:16px}.btn{padding:4px 12px;background:#222;border:1px solid #333;border-radius:4px;color:#aaa;cursor:pointer;font-size:11px}.btn:hover{background:#333}"
    "</style></head><body>"
    "<div class='header'><h1>ElemeFieldMonitor</h1><div class='stats' id='stats'>Loading...</div>"
    "<div><button class='btn' onclick='clearData()'>Clear</button> <button class='btn' onclick='refresh()'>Refresh</button></div></div>"
    "<div class='tabs'><div class='tab active' id='tab-har' onclick='switchTab(\"har\")'>HAR</div><div class='tab' id='tab-fields' onclick='switchTab(\"fields\")'>Fields</div></div>"
    "<div class='content' id='content'></div>"
    "<div class='detail-overlay' id='overlay' onclick='closeDetail(event)'>"
    "<div class='detail-box' id='detailBox'></div></div>"
    "<script>"
    "var currentTab='har',searchQuery='',harData=[];"
    "function fetchJSON(url,cb){var x=new XMLHttpRequest();x.open('GET',url);x.onload=function(){try{cb(JSON.parse(x.responseText))}catch(e){cb(null)}};x.send();}"
    "function refresh(){fetchJSON('/status',function(d){if(!d)return;var s=d.status;document.getElementById('stats').textContent='Count:'+s.captureCount+' | HAR:'+s.harCount+' | Pending:'+s.pendingCount+' | API:'+s.lastAPI;if(currentTab==='har')loadHar();else loadFields();});}"
    "function loadHar(){fetchJSON('/har',function(d){if(!d)return;harData=d.entries;renderHar();});}"
    "function renderHar(){var q=searchQuery.toLowerCase();var html='<input class=\"search-box\" placeholder=\"Search API or URL...\" value=\"'+searchQuery+'\" oninput=\"searchQuery=this.value;renderHar()\">';var filtered=q?harData.filter(function(e){var api=e._api||'';var url=(e.request||{}).url||'';return api.toLowerCase().indexOf(q)>=0||url.toLowerCase().indexOf(q)>=0;}):harData;html+='<div style=\"color:#666;margin-bottom:6px\">'+filtered.length+' entries</div>';filtered.forEach(function(e,i){var api=e._api||('Entry '+i);var req=e.request||{};var resp=e.response||{};var status=resp.status||0;var cls=status>=200&&status<300?'ok':(status>0?'err':'pending');var url=(req.url||'-').substring(0,80);var body=((req.postData||{}).text||'').substring(0,100);var respText=((resp.content||{}).text||'').substring(0,100);html+='<div class=\"card '+cls+'\" onclick=\"showDetail('+i+')\"><div class=\"card-header\"><div class=\"card-api\">'+(i+1)+'. '+api+'</div><div class=\"card-url\">'+url+'</div><div class=\"card-meta\">'+(req.method||'?')+' | Status: '+status+'</div><div class=\"card-body\">Req: '+body+'</div><div class=\"card-resp\">Res: '+respText+'</div></div></div>';});document.getElementById('content').innerHTML=html;}"
    "function showDetail(i){var e=harData[i];if(!e)return;var req=e.request||{};var resp=e.response||{};var html='<div class=\"detail-box\"><span class=\"detail-close\" onclick=\"closeDetail()\">✕</span><h2>'+(e._api||'Entry '+i)+'</h2>';html+='<div class=\"detail-section\"><h3>Request</h3><pre>Method: '+(req.method||'?')+'\nURL: '+(req.url||'-')+'\n\nHeaders:\n'+JSON.stringify(req.headers||{},null,2)+'\n\nBody:\n'+((req.postData||{}).text||'-')+'</pre></div>';html+='<div class=\"detail-section\"><h3>Response</h3><pre>Status: '+(resp.status||0)+'\n\n'+((resp.content||{}).text||'-')+'</pre></div>';html+='</div>';document.getElementById('detailBox').innerHTML=html;document.getElementById('overlay').classList.add('show');}"
    "function closeDetail(ev){if(ev&&ev.target.id!=='overlay'&&ev.target.className!=='detail-close')return;document.getElementById('overlay').classList.remove('show');}"
    "function loadFields(statusData){fetchJSON('/fields',function(d){if(!d)return;var html='';var keys=Object.keys(d).sort();keys.forEach(function(k){var v=d[k];html+='<div class=\"field-row\"><div><div class=\"field-name\">'+k+'</div><div class=\"field-source\">'+(v.source||'-')+'</div></div><div class=\"field-value\">'+(v.value||'-')+'</div></div>';});if(!html)html='<div style=\"color:#666;text-align:center;padding:20px\">No fields captured yet</div>';document.getElementById('content').innerHTML=html;});}"
    "function switchTab(t){currentTab=t;document.getElementById('tab-har').classList.toggle('active',t==='har');document.getElementById('tab-fields').classList.toggle('active',t==='fields');if(t==='har')loadHar();else{fetchJSON('/status',function(d){if(!d)return;loadFields(d);});}}"
    "function clearData(){if(!confirm('Clear all data?'))return;fetchJSON('/clear',function(d){alert(d&&d.message||'Done');refresh();});}"
    "refresh();setInterval(refresh,5000);"
    "</script></body></html>";
}

- (NSDictionary *)parseQueryString:(NSString *)query {
    NSMutableDictionary *params = [NSMutableDictionary dictionary];
    NSArray *pairs = [query componentsSeparatedByString:@"&"];
    for (NSString *pair in pairs) {
        NSArray *kv = [pair componentsSeparatedByString:@"="];
        if (kv.count == 2) {
            NSString *key = [kv[0] stringByRemovingPercentEncoding] ?: kv[0];
            NSString *val = [kv[1] stringByRemovingPercentEncoding] ?: kv[1];
            params[key] = val;
        }
    }
    return params;
}

- (NSString *)dictToJSON:(NSDictionary *)dict {
    NSError *err = nil;
    NSData *data = [NSJSONSerialization dataWithJSONObject:dict options:NSJSONWritingPrettyPrinted error:&err];
    if (err || !data) return @"{\"error\":\"JSON encoding failed\"}";
    return [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding] ?: @"{\"error\":\"encoding failed\"}";
}

- (void)start {
    // 使用 GCDHTTPServer 风格: 直接用 socket 监听
    // 由于 tweak 环境没有 GCDHTTPServer，使用轻量 socket 实现
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_BACKGROUND, 0), ^{
        int serverFd = socket(AF_INET, SOCK_STREAM, 0);
        if (serverFd < 0) {
            NSLog(@"[ElemeFieldMonitor] MCP HTTP Server: socket() failed");
            return;
        }

        int reuse = 1;
        setsockopt(serverFd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));

        struct sockaddr_in addr;
        memset(&addr, 0, sizeof(addr));
        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = INADDR_ANY;
        addr.sin_port = htons(9876);

        if (bind(serverFd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
            NSLog(@"[ElemeFieldMonitor] MCP HTTP Server: bind() failed on port 9876");
            close(serverFd);
            return;
        }

        if (listen(serverFd, 5) < 0) {
            NSLog(@"[ElemeFieldMonitor] MCP HTTP Server: listen() failed");
            close(serverFd);
            return;
        }

        NSLog(@"[ElemeFieldMonitor] MCP HTTP Server listening on port 9876");

        while (YES) {
            struct sockaddr_in clientAddr;
            socklen_t clientLen = sizeof(clientAddr);
            int clientFd = accept(serverFd, (struct sockaddr *)&clientAddr, &clientLen);
            if (clientFd < 0) continue;

            // 读取请求 (简单读取一行)
            char buf[4096];
            ssize_t n = read(clientFd, buf, sizeof(buf) - 1);
            if (n <= 0) {
                close(clientFd);
                continue;
            }
            buf[n] = '\0';

            // 解析 HTTP 请求行: GET /path?query HTTP/1.1
            NSString *requestStr = [NSString stringWithUTF8String:buf];
            NSString *path = @"/";
            NSString *query = @"";
            NSRange firstLineEnd = [requestStr rangeOfString:@"\r\n"];
            if (firstLineEnd.location != NSNotFound) {
                NSString *firstLine = [requestStr substringToIndex:firstLineEnd.location];
                NSArray *parts = [firstLine componentsSeparatedByString:@" "];
                if (parts.count >= 2) {
                    NSString *fullPath = parts[1];
                    NSRange qRange = [fullPath rangeOfString:@"?"];
                    if (qRange.location != NSNotFound) {
                        path = [fullPath substringToIndex:qRange.location];
                        query = [fullPath substringFromIndex:qRange.location + 1];
                    } else {
                        path = fullPath;
                    }
                }
            }

            // 构建响应
            BOOL isHTML = [path isEqualToString:@"/"];
            NSString *body = isHTML ? [self buildHTMLPage] : [self buildJSONResponseForPath:path query:query];
            NSData *respData = [body dataUsingEncoding:NSUTF8StringEncoding];
            NSString *contentType = isHTML ? @"text/html; charset=utf-8" : @"application/json; charset=utf-8";

            NSString *header = [NSString stringWithFormat:
                @"HTTP/1.1 200 OK\r\n"
                @"Content-Type: %@\r\n"
                @"Content-Length: %lu\r\n"
                @"Access-Control-Allow-Origin: *\r\n"
                @"Connection: close\r\n"
                @"\r\n", contentType, (unsigned long)respData.length];

            NSData *headerData = [header dataUsingEncoding:NSUTF8StringEncoding];
            write(clientFd, headerData.bytes, headerData.length);
            write(clientFd, respData.bytes, respData.length);
            close(clientFd);
        }
    });
}

@end

// ============================================================================
// MARK: - 构造函数
// ============================================================================

%ctor {
    NSLog(@"[ElemeFieldMonitor] ============================================");
    NSLog(@"[ElemeFieldMonitor] Tweak loaded into me.ele.ios.eleme");
    NSLog(@"[ElemeFieldMonitor] Monitoring: encryptSceneCode, encryptActCode, rightId, sourceFrom, sceneCode, actCode + Cookie + API Records");
    NSLog(@"[ElemeFieldMonitor] ============================================");

    // 初始化悬浮窗管理器 (触发 dispatch_once 创建实例)
    [FloatWindowManager sharedInstance];

    // 启动 MCP HTTP Server (端口 9876)
    [[MCPHTTPServer sharedInstance] start];

    // 延迟显示悬浮窗，确保 UI 已就绪
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(2.5 * NSEC_PER_SEC)),
                   dispatch_get_main_queue(), ^{
        [[FloatWindowManager sharedInstance] show];
        NSLog(@"[ElemeFieldMonitor] Float window shown!");
    });
}
