/*
 * TelegramAntiRecall — 防撤回 dylib
 *
 * 样本：ph.telegra.Telegraph 13.0 (35303)，PostboxFramework 导出下列 Swift 符号。
 * 安装优先级：
 *   1) MSHookFunction（ElleKit / Substrate）
 *   2) libhooker LHHookFunctions
 *   3) fishhook rebind_symbols（重绑调用方 GOT）
 *   4) 运行时对导出函数入口写 ARM64 RET（与静态补丁等价）
 *
 * 故意不碰 deleteMessagesInRange。
 */

#import <Foundation/Foundation.h>
#import <dlfcn.h>
#import <mach-o/dyld.h>
#import <mach/mach.h>
#import <sys/mman.h>
#import <libkern/OSCacheControl.h>
#import <string.h>
#import <stdio.h>
#import <stdint.h>
#import <stdarg.h>
#import <errno.h>

#if __has_include(<ptrauth.h>)
#  include <ptrauth.h>
#endif

#if __has_include(<substrate.h>)
#  import <substrate.h>
#  define AR_HAS_MSHOOK 1
#endif

#if __has_include(<libhooker/libhooker.h>)
#  import <libhooker/libhooker.h>
#  define AR_HAS_LIBHOOKER 1
#endif

#if __has_include("fishhook.h")
#  import "fishhook.h"
#  define AR_HAS_FISHHOOK 1
#elif __has_include(<fishhook.h>)
#  import <fishhook.h>
#  define AR_HAS_FISHHOOK 1
#endif

/* Postbox.Transaction.deleteMessages(_:forEachMedia:) */
static const char *kSymDeleteMessages =
    "_$s7Postbox11TransactionC14deleteMessages_12forEachMediaySayAA9MessageIdVG_yAA0G0_pcSgtF";
/* Postbox.Transaction.deleteMessagesWithGlobalIds(_:forEachMedia:) */
static const char *kSymDeleteWithGlobalIds =
    "_$s7Postbox11TransactionC27deleteMessagesWithGlobalIds_12forEachMediaySays5Int32VG_yAA0J0_pcSgtF";

/*
 * 偏移 fallback — 仅绑定 Telegram 13.0 (35303) 的 PostboxFramework。
 * 本样本中导出符号 VM 地址 == 文件偏移；运行时地址 = dyld_slide + off。
 * 符号能 dlsym 时不会走这里。换版必须重核 rabin2/nm。
 */
#define AR_OFF_DELETE_MESSAGES         0x163940ull
#define AR_OFF_DELETE_WITH_GLOBAL_IDS  0x164a0cull

static const uint32_t kArm64Ret = 0xD65F03C0u;

static void (*orig_deleteMessages)(void) = NULL;
static void (*orig_deleteWithGlobalIds)(void) = NULL;

static void ar_log(NSString *fmt, ...) NS_FORMAT_FUNCTION(1, 2);
static void ar_log(NSString *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    NSString *msg = [[NSString alloc] initWithFormat:fmt arguments:ap];
    va_end(ap);
    NSLog(@"[TelegramAntiRecall] %@", msg);
}

static void *ar_strip(void *p) {
    if (!p) return NULL;
#if defined(__arm64e__) && __has_include(<ptrauth.h>)
    return ptrauth_strip(p, ptrauth_key_function_pointer);
#else
    return p;
#endif
}

static void hooked_deleteMessages(void) {
    return;
}

static void hooked_deleteWithGlobalIds(void) {
    return;
}

static const struct mach_header_64 *ar_find_postbox_header(intptr_t *outSlide) {
    uint32_t count = _dyld_image_count();
    for (uint32_t i = 0; i < count; i++) {
        const char *name = _dyld_get_image_name(i);
        if (!name || strstr(name, "PostboxFramework") == NULL) continue;
        if (outSlide) *outSlide = _dyld_get_image_vmaddr_slide(i);
        return (const struct mach_header_64 *)_dyld_get_image_header(i);
    }
    return NULL;
}

static void *ar_dlsym_postbox(const char *sym) {
    void *p = dlsym(RTLD_DEFAULT, sym);
    if (p) return ar_strip(p);

    uint32_t count = _dyld_image_count();
    for (uint32_t i = 0; i < count; i++) {
        const char *name = _dyld_get_image_name(i);
        if (!name || strstr(name, "PostboxFramework") == NULL) continue;
        void *h = dlopen(name, RTLD_NOW | RTLD_NOLOAD);
        if (!h) h = dlopen(name, RTLD_NOW);
        if (!h) continue;
        p = dlsym(h, sym);
        if (p) return ar_strip(p);
    }

    static const char *names[] = {
        "PostboxFramework.framework/PostboxFramework",
        "@rpath/PostboxFramework.framework/PostboxFramework",
        NULL
    };
    for (int i = 0; names[i]; i++) {
        void *h = dlopen(names[i], RTLD_NOW | RTLD_NOLOAD);
        if (!h) h = dlopen(names[i], RTLD_NOW);
        if (!h) continue;
        p = dlsym(h, sym);
        if (p) return ar_strip(p);
    }
    return NULL;
}

static void *ar_addr_by_offset(uint64_t fileOff) {
    intptr_t slide = 0;
    if (!ar_find_postbox_header(&slide)) return NULL;
    return (void *)((uintptr_t)slide + (uintptr_t)fileOff);
}

static BOOL ar_write_ret(void *addr) {
    if (!addr) return NO;
    addr = ar_strip(addr);
    uintptr_t start = (uintptr_t)addr;
    uintptr_t page = start & ~(uintptr_t)(PAGE_SIZE - 1);
    size_t len = PAGE_SIZE;
    if ((start + sizeof(uint32_t)) > (page + PAGE_SIZE))
        len = PAGE_SIZE * 2;

    if (mprotect((void *)page, len, PROT_READ | PROT_WRITE | PROT_EXEC) != 0) {
        if (mprotect((void *)page, len, PROT_READ | PROT_WRITE) != 0) {
            ar_log(@"mprotect fail errno=%d @ %p", errno, addr);
            return NO;
        }
    }
    *((volatile uint32_t *)addr) = kArm64Ret;
    sys_icache_invalidate(addr, sizeof(uint32_t));
    mprotect((void *)page, len, PROT_READ | PROT_EXEC);
    return YES;
}

static BOOL ar_install(void) {
    void *pDel = ar_dlsym_postbox(kSymDeleteMessages);
    void *pGid = ar_dlsym_postbox(kSymDeleteWithGlobalIds);
    ar_log(@"dlsym deleteMessages=%p withGlobalIds=%p", pDel, pGid);

    BOOL usedOffset = NO;
    if (!pDel) {
        pDel = ar_addr_by_offset(AR_OFF_DELETE_MESSAGES);
        usedOffset = YES;
        ar_log(@"offset fallback deleteMessages=%p (13.0/35303 only)", pDel);
    }
    if (!pGid) {
        pGid = ar_addr_by_offset(AR_OFF_DELETE_WITH_GLOBAL_IDS);
        usedOffset = YES;
        ar_log(@"offset fallback withGlobalIds=%p (13.0/35303 only)", pGid);
    }
    if (!pDel || !pGid) {
        ar_log(@"resolve failed");
        return NO;
    }
    if (usedOffset)
        ar_log(@"WARNING: version-bound offsets in use; re-verify on upgrade");

#if AR_HAS_MSHOOK
    MSHookFunction(pDel, (void *)hooked_deleteMessages, (void **)&orig_deleteMessages);
    MSHookFunction(pGid, (void *)hooked_deleteWithGlobalIds, (void **)&orig_deleteWithGlobalIds);
    ar_log(@"MSHookFunction installed");
    return YES;
#elif AR_HAS_LIBHOOKER
    struct LHFunctionHook hooks[2] = {
        { pDel, (void *)hooked_deleteMessages, (void **)&orig_deleteMessages, NULL },
        { pGid, (void *)hooked_deleteWithGlobalIds, (void **)&orig_deleteWithGlobalIds, NULL },
    };
    int n = LHHookFunctions(hooks, 2);
    ar_log(@"LHHookFunctions => %d", n);
    if (n == 2) return YES;
#endif

#if AR_HAS_FISHHOOK
    struct rebinding rebs[2] = {
        { kSymDeleteMessages, (void *)hooked_deleteMessages, (void **)&orig_deleteMessages },
        { kSymDeleteWithGlobalIds, (void *)hooked_deleteWithGlobalIds, (void **)&orig_deleteWithGlobalIds },
    };
    int rc = rebind_symbols(rebs, 2);
    ar_log(@"fishhook => %d", rc);
#endif

    BOOL w1 = ar_write_ret(pDel);
    BOOL w2 = ar_write_ret(pGid);
    ar_log(@"RET patch => del=%d gid=%d", w1, w2);
    return w1 && w2;
}

__attribute__((constructor))
static void TelegramAntiRecall_init(void) {
    @autoreleasepool {
        ar_log(@"init (sample Telegraph 13.0 / 35303)");
        if (ar_install()) return;
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(1.5 * NSEC_PER_SEC)),
                       dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
            @autoreleasepool {
                ar_log(@"retry");
                ar_install();
            }
        });
    }
}
