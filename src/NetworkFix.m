/*
 * NetworkFix — 侧载 / Apple ID 重签 / 改 Bundle ID 多开后「连不上网」的最小修复
 *
 * 根因（Telegram 13.x / BuildConfig + AppDelegate 启动链）：
 * 1) appGroupName = "group." + Bundle.main.bundleIdentifier
 *    containerURL(forSecurityApplicationGroupIdentifier:) 若 entitlement 无对应
 *    App Group（改标识符多开、免费证无 groups）→ 返回 nil → 账户/网络初始化直接 return。
 * 2) BuildConfig.bundleSeedId / keychainAccessGroupForBaseAppBundleId 依赖 SecItem，
 *    并用 "TEAMID.baseBundleId" 作为 kSecAttrAccessGroup；重签后 Team 变了或未声明
 *    keychain-access-groups → errSecMissingEntitlement(-34018) → 密钥/鉴权材料写不进
 *    Keychain，MTProto 会话起不来，表现也是「没网」。
 * 3) 主通道是 MTProto（内置 DC RSA），不是典型 HTTPS Cert Pinning；仍可选软放宽
 *    SecTrust，避免个别 HTTPS（备份 DC / CDN）在怪异 ATS/中间盒环境下失败。
 *
 * 本文件只做上述最小集合；无法用 dylib 伪造的系统 entitlement 见 README。
 */

#import <Foundation/Foundation.h>
#import <Security/Security.h>
#import <objc/runtime.h>
#import <dlfcn.h>
#import <stdio.h>
#import <string.h>
#import <stdarg.h>

#if __has_include("fishhook.h")
#  import "fishhook.h"
#  define TAR_HAS_FISHHOOK 1
#elif __has_include(<fishhook.h>)
#  import <fishhook.h>
#  define TAR_HAS_FISHHOOK 1
#endif

/* 设为 0 可关掉 SecTrust 软放行（更安全；主协议一般不需要） */
#ifndef TAR_HOOK_SECTRUST
#  define TAR_HOOK_SECTRUST 1
#endif

static void tar_log(NSString *fmt, ...) NS_FORMAT_FUNCTION(1, 2);
static void tar_log(NSString *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    NSString *msg = [[NSString alloc] initWithFormat:fmt arguments:ap];
    va_end(ap);
    NSLog(@"[TelegramAntiRecall/Net] %@", msg);
}

#pragma mark - App Group fallback

static NSURL *(*orig_containerURL)(id, SEL, NSString *) = NULL;

static NSURL *tar_fallback_group_url(NSString *groupId) {
    if (groupId.length == 0) return nil;
    NSArray<NSString *> *bases = NSSearchPathForDirectoriesInDomains(
        NSLibraryDirectory, NSUserDomainMask, YES);
    if (bases.count == 0) return nil;
    NSString *root = [bases[0] stringByAppendingPathComponent:@"Application Support/TARNetFix/appgroups"];
    /* 用 groupId 做目录名：去掉非法路径字符 */
    NSString *safe = [[groupId componentsSeparatedByCharactersInSet:
        [NSCharacterSet characterSetWithCharactersInString:@"/\\:"]]
        componentsJoinedByString:@"_"];
    NSString *path = [root stringByAppendingPathComponent:safe];
    NSError *err = nil;
    if (![[NSFileManager defaultManager] createDirectoryAtPath:path
                                   withIntermediateDirectories:YES
                                                    attributes:nil
                                                         error:&err]) {
        tar_log(@"fallback mkdir fail %@: %@", path, err);
        return nil;
    }
    return [NSURL fileURLWithPath:path isDirectory:YES];
}

static NSURL *tar_try_alternate_group(NSFileManager *fm, NSString *groupId) {
    NSString *bid = [NSBundle mainBundle].bundleIdentifier ?: @"";
    if (bid.length == 0) return nil;

    NSMutableArray<NSString *> *candidates = [NSMutableArray array];
    NSString *expected = [@"group." stringByAppendingString:bid];
    if (![groupId isEqualToString:expected])
        [candidates addObject:expected];
    /* 常见：改了 Bundle 但仍请求官方 group.ph.telegra.Telegraph */
    if (![groupId isEqualToString:@"group.ph.telegra.Telegraph"])
        [candidates addObject:@"group.ph.telegra.Telegraph"];
    /* 去掉最后一段（扩展式 Bundle → base） */
    NSRange r = [bid rangeOfString:@"." options:NSBackwardsSearch];
    if (r.location != NSNotFound) {
        NSString *base = [bid substringToIndex:r.location];
        NSString *g = [@"group." stringByAppendingString:base];
        if (![candidates containsObject:g] && ![g isEqualToString:groupId])
            [candidates addObject:g];
    }

    for (NSString *g in candidates) {
        NSURL *u = NULL;
        if (orig_containerURL)
            u = orig_containerURL(fm, @selector(containerURLForSecurityApplicationGroupIdentifier:), g);
        else
            u = [fm containerURLForSecurityApplicationGroupIdentifier:g];
        if (u) {
            tar_log(@"appgroup remap %@ -> %@ (%@)", groupId, g, u.path);
            return u;
        }
    }
    return nil;
}

static NSURL *hooked_containerURL(id self, SEL _cmd, NSString *groupId) {
    NSURL *u = orig_containerURL ? orig_containerURL(self, _cmd, groupId) : nil;
    if (u) return u;

    NSURL *alt = tar_try_alternate_group((NSFileManager *)self, groupId ?: @"");
    if (alt) return alt;

    NSURL *fb = tar_fallback_group_url(groupId);
    if (fb)
        tar_log(@"appgroup FALLBACK %@ -> %@", groupId, fb.path);
    else
        tar_log(@"appgroup still nil for %@", groupId);
    return fb;
}

static BOOL tar_swizzle_appgroup(void) {
    Class cls = [NSFileManager class];
    SEL sel = @selector(containerURLForSecurityApplicationGroupIdentifier:);
    Method m = class_getInstanceMethod(cls, sel);
    if (!m) {
        tar_log(@"no containerURL selector");
        return NO;
    }
    orig_containerURL = (void *)method_getImplementation(m);
    method_setImplementation(m, (IMP)hooked_containerURL);
    tar_log(@"swizzled containerURLForSecurityApplicationGroupIdentifier:");
    return YES;
}

#pragma mark - SecItem: strip kSecAttrAccessGroup

typedef OSStatus (*tar_SecItem_fn)(CFDictionaryRef, CFTypeRef *);
typedef OSStatus (*tar_SecItem_one_fn)(CFDictionaryRef);

static tar_SecItem_fn orig_SecItemAdd = NULL;
static tar_SecItem_fn orig_SecItemCopyMatching = NULL;

static tar_SecItem_one_fn orig_SecItemDelete = NULL;

/* SecItemUpdate has different signature */
typedef OSStatus (*tar_SecItemUpdate_fn)(CFDictionaryRef, CFDictionaryRef);
static tar_SecItemUpdate_fn orig_SecItemUpdate2 = NULL;

static CFDictionaryRef tar_dict_without_access_group(CFDictionaryRef query, BOOL *outCopied) {
    *outCopied = NO;
    if (!query) return query;
    if (!CFDictionaryContainsKey(query, kSecAttrAccessGroup)) return query;
    CFMutableDictionaryRef m = CFDictionaryCreateMutableCopy(kCFAllocatorDefault, 0, query);
    if (!m) return query;
    CFDictionaryRemoveValue(m, kSecAttrAccessGroup);
    *outCopied = YES;
    return m;
}

static OSStatus hooked_SecItemAdd(CFDictionaryRef attributes, CFTypeRef *result) {
    BOOL copied = NO;
    CFDictionaryRef q = tar_dict_without_access_group(attributes, &copied);
    OSStatus st = orig_SecItemAdd(q, result);
    if (copied) CFRelease(q);
    if (st == errSecMissingEntitlement && attributes) {
        /* 再试：已剥离仍失败则原样（极少） */
        tar_log(@"SecItemAdd after strip => %d", (int)st);
    }
    return st;
}

static OSStatus hooked_SecItemCopyMatching(CFDictionaryRef query, CFTypeRef *result) {
    BOOL copied = NO;
    CFDictionaryRef q = tar_dict_without_access_group(query, &copied);
    OSStatus st = orig_SecItemCopyMatching(q, result);
    if (copied) CFRelease(q);
    return st;
}

static OSStatus hooked_SecItemUpdate(CFDictionaryRef query, CFDictionaryRef attrsToUpdate) {
    BOOL c1 = NO, c2 = NO;
    CFDictionaryRef q = tar_dict_without_access_group(query, &c1);
    CFDictionaryRef a = tar_dict_without_access_group(attrsToUpdate, &c2);
    OSStatus st = orig_SecItemUpdate2(q, a);
    if (c1) CFRelease(q);
    if (c2) CFRelease(a);
    return st;
}

static OSStatus hooked_SecItemDelete(CFDictionaryRef query) {
    BOOL copied = NO;
    CFDictionaryRef q = tar_dict_without_access_group(query, &copied);
    OSStatus st = orig_SecItemDelete(q);
    if (copied) CFRelease(q);
    return st;
}

static BOOL tar_hook_secitem(void) {
#if !TAR_HAS_FISHHOOK
    tar_log(@"fishhook missing; SecItem hooks skipped");
    return NO;
#else
    orig_SecItemAdd = (tar_SecItem_fn)dlsym(RTLD_DEFAULT, "SecItemAdd");
    orig_SecItemCopyMatching = (tar_SecItem_fn)dlsym(RTLD_DEFAULT, "SecItemCopyMatching");
    orig_SecItemUpdate2 = (tar_SecItemUpdate_fn)dlsym(RTLD_DEFAULT, "SecItemUpdate");
    orig_SecItemDelete = (tar_SecItem_one_fn)dlsym(RTLD_DEFAULT, "SecItemDelete");
    if (!orig_SecItemAdd || !orig_SecItemCopyMatching || !orig_SecItemUpdate2 || !orig_SecItemDelete) {
        tar_log(@"dlsym SecItem* incomplete");
        return NO;
    }
    struct rebinding rebs[4] = {
        { "SecItemAdd", (void *)hooked_SecItemAdd, (void **)&orig_SecItemAdd },
        { "SecItemCopyMatching", (void *)hooked_SecItemCopyMatching, (void **)&orig_SecItemCopyMatching },
        { "SecItemUpdate", (void *)hooked_SecItemUpdate, (void **)&orig_SecItemUpdate2 },
        { "SecItemDelete", (void *)hooked_SecItemDelete, (void **)&orig_SecItemDelete },
    };
    int rc = rebind_symbols(rebs, 4);
    tar_log(@"fishhook SecItem* => %d", rc);
    return rc == 0;
#endif
}

#pragma mark - BuildConfig keychainAccessGroup → nil（走默认 access group）

static id (*orig_keychainAccessGroup)(Class, SEL, NSString *) = NULL;

static id hooked_keychainAccessGroup(Class cls, SEL _cmd, NSString *baseAppBundleId) {
    (void)cls; (void)_cmd; (void)baseAppBundleId;
    /* 返回 nil：与开源 BuildConfig 在 seed 为空时行为一致；
     * 真正写 Keychain 的路径我们已剥掉 kSecAttrAccessGroup。 */
    return nil;
}

static BOOL tar_swizzle_buildconfig(void) {
    Class cls = objc_getClass("BuildConfig");
    if (!cls) {
        tar_log(@"BuildConfig class not loaded yet");
        return NO;
    }
    SEL sel = sel_registerName("keychainAccessGroupForBaseAppBundleId:");
    Method m = class_getClassMethod(cls, sel);
    if (!m) {
        tar_log(@"no keychainAccessGroupForBaseAppBundleId:");
        return NO;
    }
    orig_keychainAccessGroup = (void *)method_getImplementation(m);
    method_setImplementation(m, (IMP)hooked_keychainAccessGroup);
    tar_log(@"swizzled BuildConfig keychainAccessGroupForBaseAppBundleId: -> nil");
    return YES;
}

#pragma mark - SecTrust soft-allow（可选）

#if TAR_HOOK_SECTRUST
typedef OSStatus (*tar_SecTrustEvaluate_fn)(SecTrustRef, SecTrustResultType *);
typedef bool (*tar_SecTrustEvaluateWithError_fn)(SecTrustRef, CFErrorRef *);

static tar_SecTrustEvaluate_fn orig_SecTrustEvaluate = NULL;
static tar_SecTrustEvaluateWithError_fn orig_SecTrustEvaluateWithError = NULL;

static OSStatus hooked_SecTrustEvaluate(SecTrustRef trust, SecTrustResultType *result) {
    OSStatus st = orig_SecTrustEvaluate ? orig_SecTrustEvaluate(trust, result) : errSecSuccess;
    if (st != errSecSuccess || (result && (*result == kSecTrustResultDeny ||
                                           *result == kSecTrustResultFatalTrustFailure ||
                                           *result == kSecTrustResultRecoverableTrustFailure))) {
        if (result) *result = kSecTrustResultProceed;
        return errSecSuccess;
    }
    return st;
}

static bool hooked_SecTrustEvaluateWithError(SecTrustRef trust, CFErrorRef *error) {
    if (orig_SecTrustEvaluateWithError) {
        bool ok = orig_SecTrustEvaluateWithError(trust, error);
        if (ok) return true;
        if (error && *error) {
            CFRelease(*error);
            *error = NULL;
        }
        return true;
    }
    return true;
}

static BOOL tar_hook_sectrust(void) {
#if !TAR_HAS_FISHHOOK
    return NO;
#else
    orig_SecTrustEvaluate = (tar_SecTrustEvaluate_fn)dlsym(RTLD_DEFAULT, "SecTrustEvaluate");
    orig_SecTrustEvaluateWithError =
        (tar_SecTrustEvaluateWithError_fn)dlsym(RTLD_DEFAULT, "SecTrustEvaluateWithError");
    int n = 0;
    struct rebinding rebs[2];
    if (orig_SecTrustEvaluate) {
        rebs[n++] = (struct rebinding){
            "SecTrustEvaluate", (void *)hooked_SecTrustEvaluate, (void **)&orig_SecTrustEvaluate
        };
    }
    if (orig_SecTrustEvaluateWithError) {
        rebs[n++] = (struct rebinding){
            "SecTrustEvaluateWithError", (void *)hooked_SecTrustEvaluateWithError,
            (void **)&orig_SecTrustEvaluateWithError
        };
    }
    if (n == 0) {
        tar_log(@"SecTrust* not found");
        return NO;
    }
    int rc = rebind_symbols(rebs, n);
    tar_log(@"fishhook SecTrust* (n=%d) => %d", n, rc);
    return rc == 0;
#endif
}
#endif /* TAR_HOOK_SECTRUST */

#pragma mark - Install

static void tar_net_install(void) {
    tar_swizzle_appgroup();
    tar_hook_secitem();
#if TAR_HOOK_SECTRUST
    tar_hook_sectrust();
#endif
    if (!tar_swizzle_buildconfig()) {
        /* TelegramUI 稍后才加载时再试 */
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(0.8 * NSEC_PER_SEC)),
                       dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
            tar_swizzle_buildconfig();
        });
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(2.5 * NSEC_PER_SEC)),
                       dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
            tar_swizzle_buildconfig();
        });
    }
}

__attribute__((constructor))
static void TelegramAntiRecall_NetworkFix_init(void) {
    @autoreleasepool {
        NSString *bid = [NSBundle mainBundle].bundleIdentifier ?: @"?";
        tar_log(@"init bid=%@", bid);
        tar_net_install();
    }
}
