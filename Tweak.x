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
            @"actCode"
        ];
    });
    return keys;
}

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
@end

@implementation FieldHunter

+ (void)searchInObject:(id)obj results:(NSMutableDictionary *)results {
    if (!obj || !results) return;

    if ([obj isKindOfClass:[NSDictionary class]]) {
        NSDictionary *dict = (NSDictionary *)obj;
        for (NSString *key in kTargetKeys()) {
            // 支持嵌套 key (如 svip.encryptSceneCode)
            id value = dict[key];
            if (value && ![value isKindOfClass:[NSNull class]]) {
                NSString *strValue = [NSString stringWithFormat:@"%@", value];
                if (strValue.length > 0 && ![strValue isEqualToString:@"(null)"]) {
                    results[key] = strValue;
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
            if ([kTargetKeys() containsObject:key] && value.length > 0) {
                results[key] = value;
            }
        }
    }
}

+ (void)searchInBody:(NSData *)body results:(NSMutableDictionary *)results {
    if (!body || body.length == 0) return;
    NSError *err = nil;
    id json = [NSJSONSerialization JSONObjectWithData:body
                                             options:NSJSONReadingAllowFragments
                                               error:&err];
    if (json && !err) {
        [self searchInObject:json results:results];
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
@property (nonatomic, strong) UIScrollView *scrollView;

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
@property (nonatomic, strong) UILabel *urlLabel;
@property (nonatomic, strong) NSString *lastURL;
@property (nonatomic, assign) BOOL collapsed;

+ (instancetype)sharedInstance;
- (void)show;
- (void)hide;
- (void)toggle;
- (void)toggleCollapse;
- (void)updateWithDictionary:(NSDictionary *)dict source:(NSString *)source api:(NSString *)api;
- (void)updateURL:(NSString *)url;
- (void)copyAllToClipboard;

@end

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
    CGFloat windowH = 380;
    CGFloat startX = 10;
    CGFloat startY = 120;

    self.window = [[UIWindow alloc] initWithWindowScene:scene];
    self.window.frame = CGRectMake(startX, startY, windowW, windowH);
    self.window.windowLevel = UIWindowLevelAlert + 1000;
    self.window.backgroundColor = [UIColor clearColor];
    self.window.hidden = NO;
    self.window.userInteractionEnabled = YES;

    // 容器视图
    self.containerView = [[UIView alloc] initWithFrame:CGRectMake(0, 0, windowW, windowH)];
    self.containerView.backgroundColor = [UIColor colorWithRed:0.08 green:0.08 blue:0.10 alpha:0.95];
    self.containerView.layer.cornerRadius = 14;
    self.containerView.layer.masksToBounds = YES;
    self.containerView.layer.borderWidth = 1.5;
    self.containerView.layer.borderColor = [UIColor colorWithRed:0.2 green:0.5 blue:0.9 alpha:0.7].CGColor;
    [self.window addSubview:self.containerView];

    // ---- Header ----
    CGFloat headerH = 88;
    self.headerView = [[UIView alloc] initWithFrame:CGRectMake(0, 0, windowW, headerH)];
    self.headerView.backgroundColor = [UIColor colorWithRed:0.12 green:0.12 blue:0.16 alpha:1.0];
    [self.containerView addSubview:self.headerView];

    // Title
    self.titleLabel = [[UILabel alloc] initWithFrame:CGRectMake(12, 6, 260, 22)];
    self.titleLabel.text = @"🔑 Eleme Field Monitor";
    self.titleLabel.textColor = [UIColor colorWithRed:0.3 green:0.6 blue:1.0 alpha:1.0];
    self.titleLabel.font = [UIFont boldSystemFontOfSize:15];
    [self.headerView addSubview:self.titleLabel];

    // Collapse button
    self.collapseBtn = [UIButton buttonWithType:UIButtonTypeSystem];
    self.collapseBtn.frame = CGRectMake(windowW - 66, 6, 28, 22);
    [self.collapseBtn setTitle:@"▲" forState:UIControlStateNormal];
    [self.collapseBtn setTitleColor:[UIColor colorWithRed:0.6 green:0.8 blue:1.0 alpha:1.0]
                          forState:UIControlStateNormal];
    self.collapseBtn.titleLabel.font = [UIFont boldSystemFontOfSize:14];
    [self.collapseBtn addTarget:self action:@selector(toggleCollapse) forControlEvents:UIControlEventTouchUpInside];
    [self.headerView addSubview:self.collapseBtn];

    // Close button
    self.closeButton = [UIButton buttonWithType:UIButtonTypeSystem];
    self.closeButton.frame = CGRectMake(windowW - 36, 6, 28, 22);
    [self.closeButton setTitle:@"✕" forState:UIControlStateNormal];
    [self.closeButton setTitleColor:[UIColor colorWithRed:1.0 green:0.3 blue:0.3 alpha:1.0]
                          forState:UIControlStateNormal];
    self.closeButton.titleLabel.font = [UIFont boldSystemFontOfSize:16];
    [self.closeButton addTarget:self action:@selector(hide) forControlEvents:UIControlEventTouchUpInside];
    [self.headerView addSubview:self.closeButton];

    // Status line
    self.statusLabel = [[UILabel alloc] initWithFrame:CGRectMake(12, 30, windowW - 24, 16)];
    self.statusLabel.text = @"Count: 0 | Source: - | --:--:--";
    self.statusLabel.textColor = [UIColor colorWithRed:0.6 green:0.6 blue:0.65 alpha:1.0];
    self.statusLabel.font = [UIFont systemFontOfSize:11];
    [self.headerView addSubview:self.statusLabel];

    // API line
    self.apiLabel = [[UILabel alloc] initWithFrame:CGRectMake(12, 48, windowW - 24, 16)];
    self.apiLabel.text = @"API: -";
    self.apiLabel.textColor = [UIColor colorWithRed:0.5 green:0.75 blue:0.55 alpha:1.0];
    self.apiLabel.font = [UIFont fontWithName:@"Menlo" size:10];
    self.apiLabel.adjustsFontSizeToFitWidth = YES;
    self.apiLabel.minimumScaleFactor = 0.6;
    [self.headerView addSubview:self.apiLabel];

    // URL line
    self.urlLabel = [[UILabel alloc] initWithFrame:CGRectMake(12, 66, windowW - 24, 16)];
    self.urlLabel.text = @"URL: -";
    self.urlLabel.textColor = [UIColor colorWithRed:0.7 green:0.6 blue:0.9 alpha:1.0];
    self.urlLabel.font = [UIFont fontWithName:@"Menlo" size:9];
    self.urlLabel.adjustsFontSizeToFitWidth = YES;
    self.urlLabel.minimumScaleFactor = 0.5;
    self.urlLabel.numberOfLines = 1;
    [self.headerView addSubview:self.urlLabel];

    // ---- ScrollView for fields ----
    CGFloat scrollY = headerH;
    CGFloat scrollH = windowH - headerH - 40;
    self.scrollView = [[UIScrollView alloc] initWithFrame:CGRectMake(0, scrollY, windowW, scrollH)];
    self.scrollView.backgroundColor = [UIColor clearColor];
    self.scrollView.showsVerticalScrollIndicator = YES;
    self.scrollView.alwaysBounceVertical = YES;
    [self.containerView addSubview:self.scrollView];

    // 创建字段标签
    NSArray *fields = kTargetKeys();
    CGFloat labelY = 8;
    CGFloat labelH = 48;
    CGFloat labelSpacing = 4;
    UIColor *keyColor = [UIColor colorWithRed:0.4 green:0.7 blue:1.0 alpha:1.0];
    UIColor *valueColor = [UIColor colorWithRed:0.95 green:0.85 blue:0.55 alpha:1.0];
    UIColor *notFoundColor = [UIColor colorWithRed:0.4 green:0.4 blue:0.4 alpha:1.0];

    for (NSString *fieldName in fields) {
        // 容器
        UIView *fieldContainer = [[UIView alloc] initWithFrame:CGRectMake(8, labelY, windowW - 16, labelH)];
        fieldContainer.backgroundColor = [UIColor colorWithRed:0.1 green:0.1 blue:0.12 alpha:0.8];
        fieldContainer.layer.cornerRadius = 6;
        fieldContainer.layer.masksToBounds = YES;
        [self.scrollView addSubview:fieldContainer];

        // Key label
        UILabel *keyLabel = [[UILabel alloc] initWithFrame:CGRectMake(8, 2, fieldContainer.bounds.size.width - 16, 16)];
        keyLabel.text = fieldName;
        keyLabel.textColor = keyColor;
        keyLabel.font = [UIFont fontWithName:@"Menlo" size:11];
        [fieldContainer addSubview:keyLabel];

        // Value label
        UILabel *valueLabel = [[UILabel alloc] initWithFrame:CGRectMake(8, 20, fieldContainer.bounds.size.width - 16, 24)];
        valueLabel.text = @"(waiting...)";
        valueLabel.textColor = notFoundColor;
        valueLabel.font = [UIFont fontWithName:@"Menlo" size:10];
        valueLabel.adjustsFontSizeToFitWidth = YES;
        valueLabel.minimumScaleFactor = 0.5;
        valueLabel.numberOfLines = 2;
        [fieldContainer addSubview:valueLabel];

        self.fieldLabels[fieldName] = valueLabel;

        // 长按复制单个字段
        UILongPressGestureRecognizer *longPress = [[UILongPressGestureRecognizer alloc]
            initWithTarget:self action:@selector(handleLongPress:)];
        longPress.minimumPressDuration = 0.5;
        [fieldContainer addGestureRecognizer:longPress];

        labelY += labelH + labelSpacing;
    }

    self.scrollView.contentSize = CGSizeMake(windowW, labelY + 8);

    // ---- Footer ----
    CGFloat footerY = windowH - 40;
    self.footerView = [[UIView alloc] initWithFrame:CGRectMake(0, footerY, windowW, 40)];
    self.footerView.backgroundColor = [UIColor colorWithRed:0.12 green:0.12 blue:0.16 alpha:1.0];
    [self.containerView addSubview:self.footerView];

    // Copy All button
    self.exportBtn = [UIButton buttonWithType:UIButtonTypeSystem];
    self.exportBtn.frame = CGRectMake(12, 6, 140, 28);
    [self.exportBtn setTitle:@"📋 Copy All JSON" forState:UIControlStateNormal];
    [self.exportBtn setTitleColor:[UIColor whiteColor] forState:UIControlStateNormal];
    self.exportBtn.titleLabel.font = [UIFont systemFontOfSize:12];
    self.exportBtn.backgroundColor = [UIColor colorWithRed:0.15 green:0.4 blue:0.8 alpha:0.8];
    self.exportBtn.layer.cornerRadius = 6;
    [self.exportBtn addTarget:self action:@selector(copyAllToClipboard) forControlEvents:UIControlEventTouchUpInside];
    [self.footerView addSubview:self.exportBtn];

    // Clear button
    self.clearButton = [UIButton buttonWithType:UIButtonTypeSystem];
    self.clearButton.frame = CGRectMake(windowW - 92, 6, 80, 28);
    [self.clearButton setTitle:@"🗑 Clear" forState:UIControlStateNormal];
    [self.clearButton setTitleColor:[UIColor whiteColor] forState:UIControlStateNormal];
    self.clearButton.titleLabel.font = [UIFont systemFontOfSize:12];
    self.clearButton.backgroundColor = [UIColor colorWithRed:0.6 green:0.2 blue:0.2 alpha:0.8];
    self.clearButton.layer.cornerRadius = 6;
    [self.clearButton addTarget:self action:@selector(clearAll) forControlEvents:UIControlEventTouchUpInside];
    [self.footerView addSubview:self.clearButton];

    // 拖拽手势
    UIPanGestureRecognizer *pan = [[UIPanGestureRecognizer alloc]
        initWithTarget:self action:@selector(handlePan:)];
    [self.headerView addGestureRecognizer:pan];

    // 双击切换显示/隐藏
    UITapGestureRecognizer *doubleTap = [[UITapGestureRecognizer alloc]
        initWithTarget:self action:@selector(handleDoubleTap:)];
    doubleTap.numberOfTapsRequired = 2;
    [self.headerView addGestureRecognizer:doubleTap];

    NSLog(@"[ElemeFieldMonitor] Float window ready!");
}

#pragma mark - 手势处理

- (void)handlePan:(UIPanGestureRecognizer *)gesture {
    CGPoint translation = [gesture translationInView:self.window];
    CGPoint newCenter = CGPointMake(gesture.view.center.x + translation.x,
                                     gesture.view.center.y + translation.y);
    // 限制在屏幕范围内
    CGFloat halfW = self.containerView.bounds.size.width / 2;
    CGFloat halfH = self.containerView.bounds.size.height / 2;
    newCenter.x = MAX(halfW, MIN(self.window.bounds.size.width - halfW, newCenter.x));
    newCenter.y = MAX(halfH, MIN([UIScreen mainScreen].bounds.size.height - halfH, newCenter.y));
    gesture.view.center = newCenter;
    [gesture setTranslation:CGPointZero inView:self.window];
}

- (void)handleDoubleTap:(UITapGestureRecognizer *)gesture {
    [self toggleCollapse];
}

- (void)handleLongPress:(UILongPressGestureRecognizer *)gesture {
    if (gesture.state != UIGestureRecognizerStateBegan) return;
    UIView *container = gesture.view;
    // 找到 value label (第二个子视图)
    UILabel *valueLabel = nil;
    for (UIView *sub in container.subviews) {
        if ([sub isKindOfClass:[UILabel class]]) {
            UILabel *lbl = (UILabel *)sub;
            if (![lbl.text containsString:@":"] && ![lbl.text isEqualToString:@"(waiting..."]) {
                valueLabel = lbl;
            }
        }
    }
    if (valueLabel && valueLabel.text.length > 0) {
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
        CGFloat fullH = 380;
        CGFloat headerH = 88;
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
            self.scrollView.hidden = self.collapsed;
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
        self.urlLabel.text = [NSString stringWithFormat:@"URL: %@", display];
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
                        label.superview.backgroundColor = [UIColor colorWithRed:0.15 green:0.35 blue:0.15 alpha:0.9];
                    } completion:^(BOOL finished) {
                        [UIView animateWithDuration:0.5 delay:0.3 options:UIViewAnimationOptionCurveEaseOut animations:^{
                            label.superview.backgroundColor = [UIColor colorWithRed:0.1 green:0.1 blue:0.12 alpha:0.8];
                        } completion:nil];
                    }];
                }

                NSLog(@"[ElemeFieldMonitor] %@ = %@ (source: %@)", key, newValue, source);
            }
        }

        if (hasNewData || api) {
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

    self.statusLabel.text = [NSString stringWithFormat:@"Count: %ld | Source: %@ | %@",
                              (long)self.captureCount, self.lastSource, timeStr];

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
    json[@"_lastUpdate"] = self.lastUpdate ? [self.lastUpdate description] : @"-";

    NSData *data = [NSJSONSerialization dataWithJSONObject:json options:NSJSONWritingPrettyPrinted error:nil];
    NSString *jsonStr = [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];
    UIPasteboard.generalPasteboard.string = jsonStr;

    [self showToast:@"All fields copied!"];
}

- (void)clearAll {
    for (NSString *key in kTargetKeys()) {
        self.fieldValues[key] = nil;
        self.fieldSources[key] = nil;
        UILabel *label = self.fieldLabels[key];
        if (label) {
            label.text = @"(waiting...)";
            label.textColor = [UIColor colorWithRed:0.4 green:0.4 blue:0.4 alpha:1.0];
        }
    }
    self.captureCount = 0;
    self.lastAPI = @"-";
    self.lastSource = @"-";
    self.lastURL = @"-";
    self.lastUpdate = nil;
    self.urlLabel.text = @"URL: -";
    [self updateStatusBar];
    [self showToast:@"Cleared!"];
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
            if (results.count > 0) {
                // 尝试从 JSON 中提取 API 名称
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
                [[FloatWindowManager sharedInstance] updateWithDictionary:results
                                                                    source:@"JSONResponse"
                                                                       api:api];
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

    if (reqResults.count > 0) {
        [[FloatWindowManager sharedInstance] updateWithDictionary:reqResults
                                                            source:@"Request"
                                                               api:requestAPI];
    }

    // 更新 URL 显示
    if (url) {
        [[FloatWindowManager sharedInstance] updateURL:url.absoluteString];
    }

    // ---- 包装 completionHandler 拦截响应 ----
    void (^wrappedHandler)(NSData *, NSURLResponse *, NSError *) = ^(NSData *data, NSURLResponse *response, NSError *error) {
        if (data && data.length > 0) {
            @try {
                NSMutableDictionary *respResults = [NSMutableDictionary dictionary];
                [FieldHunter searchInBody:data results:respResults];
                if (respResults.count > 0) {
                    // 尝试从响应中提取 API 名称
                    NSString *respAPI = nil;
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
            } @catch (NSException *e) {}
        }
        if (completionHandler) completionHandler(data, response, error);
    };

    return %orig(request, wrappedHandler);
}

%end

// --- Hook 3: NSMutableURLRequest (拦截请求 body 设置) ---
%hook NSMutableURLRequest

- (void)setHTTPBody:(NSData *)body {
    %orig;

    if (body && body.length > 0) {
        @try {
            NSMutableDictionary *results = [NSMutableDictionary dictionary];
            [FieldHunter searchInBody:body results:results];
            if (results.count > 0) {
                // 尝试从 body 提取 API
                NSString *api = nil;
                id bodyJson = [NSJSONSerialization JSONObjectWithData:body
                                                              options:NSJSONReadingAllowFragments
                                                                error:nil];
                if ([bodyJson isKindOfClass:[NSDictionary class]]) {
                    api = bodyJson[@"api"] ?: bodyJson[@"apiName"];
                }
                [[FloatWindowManager sharedInstance] updateWithDictionary:results
                                                                    source:@"RequestBody"
                                                                       api:api];
            }
        } @catch (NSException *e) {}
    }
}

%end

// --- Hook 4: NSMutableDictionary setObject:forKey: (拦截字典写入) ---
// 仅 hook NSMutableDictionary 而非 NSDictionary，避免性能问题
%hook NSMutableDictionary

- (void)setObject:(id)anObject forKey:(id<NSCopying>)aKey {
    %orig;

    if ([(id)aKey isKindOfClass:[NSString class]] && [kTargetKeys() containsObject:(NSString *)aKey]) {
        NSString *key = (NSString *)aKey;
        NSString *value = [NSString stringWithFormat:@"%@", anObject];
        if (value.length > 0 && ![value isEqualToString:@"(null)"] && 
            ![anObject isKindOfClass:[NSNull class]]) {
            NSMutableDictionary *results = [NSMutableDictionary dictionary];
            results[key] = value;
            [[FloatWindowManager sharedInstance] updateWithDictionary:results
                                                                source:@"DictSet"
                                                                   api:nil];
        }
    }
}

%end

// ============================================================================
// MARK: - 构造函数
// ============================================================================

%ctor {
    NSLog(@"[ElemeFieldMonitor] ============================================");
    NSLog(@"[ElemeFieldMonitor] Tweak loaded into me.ele.ios.eleme");
    NSLog(@"[ElemeFieldMonitor] Monitoring: encryptSceneCode, encryptActCode, rightId, sourceFrom, sceneCode, actCode");
    NSLog(@"[ElemeFieldMonitor] ============================================");

    // 初始化悬浮窗管理器 (触发 dispatch_once 创建实例)
    [FloatWindowManager sharedInstance];

    // 延迟显示悬浮窗，确保 UI 已就绪
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(2.5 * NSEC_PER_SEC)),
                   dispatch_get_main_queue(), ^{
        [[FloatWindowManager sharedInstance] show];
        NSLog(@"[ElemeFieldMonitor] Float window shown!");
    });
}
