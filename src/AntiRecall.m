/*
 * TelegramAntiRecall — 纯防撤回 dylib（深入 v1 点位）
 *
 * 绑定样本：ph.telegra.Telegraph 13.0 (35303)
 * 目标镜像：PostboxFramework（__TEXT.vmaddr == 0，故 fileoff == vmaddr）
 *
 * 调用链（本包反汇编依据，见 README / ANALYSIS.md）：
 *
 *   服务端 updateDeleteMessages / updateDeleteChannelMessages
 *     → AccountState 累积 DeleteMessages / DeleteMessagesWithGlobalIds
 *     → Postbox.Transaction 落库删除
 *
 *   0x163940  deleteMessages 公开入口 = 跳板
 *             adrp/add 把「真实现」地址 0x16394c 装进 x3，再 b 公共 trampoline
 *   0x16394c  deleteMessages 真正删库实现（约 0x1c4 字节，至 0x163b10 的 RET）
 *   0x164a0c  deleteMessagesWithGlobalIds 入口
 *             内部在 0x164a40 处 `bl 0x16394c`，**直调实现、绕过 0x163940 跳板**
 *
 * 因此只 RET 跳板不够：WithGlobalIds 仍会删库。本 dylib 对下列三处写 ARM64 RET：
 *   - 0x164a0c  （v1）
 *   - 0x163940  （v1）
 *   - 0x16394c  （深入：真实删库；挡住 bl 直调）
 *
 * 故意不碰 deleteMessagesInRange / clearHistory（降低误伤清聊天）。
 *
 * 安装方式：不依赖导出符号。运行时地址 = dyld_slide + 文件偏移，
 * 校验原指令后 mprotect + 写 0xD65F03C0。越狱下可附带 MSHook（若 dlsym 成功）。
 */

#import <Foundation/Foundation.h>
#import <dlfcn.h>
#import <mach-o/dyld.h>
#import <mach-o/loader.h>
#import <sys/mman.h>
#import <libkern/OSCacheControl.h>
#import <string.h>
#import <stdio.h>
#import <stdint.h>
#import <stdarg.h>
#import <errno.h>
#import <unistd.h>

#if __has_include(<ptrauth.h>)
#  include <ptrauth.h>
#endif

#if __has_include(<substrate.h>)
#  import <substrate.h>
#  define AR_HAS_MSHOOK 1
#endif

/* ---------- 版本绑定偏移（仅 13.0 / 35303） ---------- */

#define AR_OFF_DELETE_MESSAGES_THUNK   0x163940ull  /* 跳板入口（v1） */
#define AR_OFF_DELETE_MESSAGES_IMPL    0x16394cull  /* 真实现（深入） */
#define AR_OFF_DELETE_WITH_GLOBAL_IDS  0x164a0cull  /* WithGlobalIds（v1） */

/* 写 RET 前必须匹配的原指令（小端 4 字节） */
static const uint32_t kOrigThunk  = 0x90000003u; /* adrp x3, ... */
static const uint32_t kOrigImpl   = 0xD10683FFu; /* sub  sp, sp, #0x1a0 */
static const uint32_t kOrigGlobal = 0xA9BD57F6u; /* stp  x22, x21, [sp, #-0x30]! */

static const uint32_t kArm64Ret   = 0xD65F03C0u;

/* 可选：mangled 名，仅给 MSHook / 诊断用 */
static const char *kSymDeleteMessages =
    "_$s7Postbox11TransactionC14deleteMessages_12forEachMediaySayAA9MessageIdVG_yAA0G0_pcSgtF";
static const char *kSymDeleteWithGlobalIds =
    "_$s7Postbox11TransactionC27deleteMessagesWithGlobalIds_12forEachMediaySays5Int32VG_yAA0J0_pcSgtF";

typedef struct {
    const char *name;
    uint64_t    fileOff;
    uint32_t    expectOrig;
} ARPatchSite;

static const ARPatchSite kSites[] = {
    { "deleteMessagesWithGlobalIds", AR_OFF_DELETE_WITH_GLOBAL_IDS, kOrigGlobal },
    { "deleteMessages_thunk",        AR_OFF_DELETE_MESSAGES_THUNK,  kOrigThunk  },
    { "deleteMessages_impl",         AR_OFF_DELETE_MESSAGES_IMPL,   kOrigImpl   },
};
static const size_t kSiteCount = sizeof(kSites) / sizeof(kSites[0]);

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

/* ---------- 定位 PostboxFramework ---------- */

static const struct mach_header_64 *ar_find_postbox(intptr_t *outSlide, const char **outPath) {
    uint32_t n = _dyld_image_count();
    for (uint32_t i = 0; i < n; i++) {
        const char *name = _dyld_get_image_name(i);
        if (!name) continue;
        if (strstr(name, "PostboxFramework") == NULL) continue;
        /* 排除字符串碰巧命中的无关镜像 */
        if (strstr(name, "PostboxFramework.framework/PostboxFramework") == NULL &&
            strstr(name, "/PostboxFramework.framework/") == NULL &&
            strcmp(name + (strlen(name) > 16 ? strlen(name) - 16 : 0), "PostboxFramework") != 0) {
            /* 仍接受路径末尾为 PostboxFramework 的 */
            const char *base = strrchr(name, '/');
            base = base ? base + 1 : name;
            if (strcmp(base, "PostboxFramework") != 0) continue;
        }
        if (outSlide) *outSlide = _dyld_get_image_vmaddr_slide(i);
        if (outPath)  *outPath  = name;
        return (const struct mach_header_64 *)_dyld_get_image_header(i);
    }
    return NULL;
}

/*
 * slide 算法（本样本）：
 *   PostboxFramework 的 __TEXT.vmaddr = 0，__text 等段 fileoff == vmaddr。
 *   dyld 加载后：runtime = slide + file_offset
 *              = slide + vmaddr（对本样本等价）
 * 换版本时务必用 otool -l 核对 __TEXT.vmaddr / section fileoff，
 * 不要假设永远为 0。
 */
static void *ar_runtime_addr(intptr_t slide, uint64_t fileOff) {
    return (void *)((uintptr_t)slide + (uintptr_t)fileOff);
}

/* ---------- 写 RET ---------- */

static BOOL ar_mprotect_rwx(uintptr_t addr, size_t need) {
    uintptr_t page = addr & ~(uintptr_t)(PAGE_SIZE - 1);
    size_t len = PAGE_SIZE;
    if (addr + need > page + PAGE_SIZE)
        len = PAGE_SIZE * 2;
    if (mprotect((void *)page, len, PROT_READ | PROT_WRITE | PROT_EXEC) == 0)
        return YES;
    if (mprotect((void *)page, len, PROT_READ | PROT_WRITE) == 0)
        return YES;
    return NO;
}

static void ar_mprotect_rx(uintptr_t addr, size_t need) {
    uintptr_t page = addr & ~(uintptr_t)(PAGE_SIZE - 1);
    size_t len = PAGE_SIZE;
    if (addr + need > page + PAGE_SIZE)
        len = PAGE_SIZE * 2;
    mprotect((void *)page, len, PROT_READ | PROT_EXEC);
}

static BOOL ar_write_ret_at(void *addr, uint32_t expectOrig, const char *name) {
    if (!addr) return NO;
    addr = ar_strip(addr);
    uint32_t cur = *(volatile uint32_t *)addr;
    if (cur == kArm64Ret) {
        ar_log(@"%@ @ %p 已是 RET，跳过", [NSString stringWithUTF8String:name], addr);
        return YES;
    }
    if (cur != expectOrig) {
        ar_log(@"%@ @ %p 原指令不匹配 expect=0x%08x got=0x%08x（版本不对或已改）",
               [NSString stringWithUTF8String:name], addr, expectOrig, cur);
        return NO;
    }
    uintptr_t start = (uintptr_t)addr;
    if (!ar_mprotect_rwx(start, sizeof(uint32_t))) {
        ar_log(@"%@ mprotect 失败 errno=%d @ %p（非越狱重签常被拒，需静态补丁或放行代码签名）",
               [NSString stringWithUTF8String:name], errno, addr);
        return NO;
    }
    *(volatile uint32_t *)addr = kArm64Ret;
    sys_icache_invalidate(addr, sizeof(uint32_t));
    ar_mprotect_rx(start, sizeof(uint32_t));
    ar_log(@"%@ @ %p  0x%08x -> RET 成功", [NSString stringWithUTF8String:name], addr, expectOrig);
    return YES;
}

/* ---------- 可选 MSHook（符号能解析时） ---------- */

#if AR_HAS_MSHOOK
static void (*orig_deleteMessages)(void) = NULL;
static void (*orig_deleteWithGlobalIds)(void) = NULL;
static void hooked_nop(void) { return; }

static void *ar_dlsym_postbox(const char *sym) {
    void *p = dlsym(RTLD_DEFAULT, sym);
    if (p) return ar_strip(p);
    uint32_t n = _dyld_image_count();
    for (uint32_t i = 0; i < n; i++) {
        const char *name = _dyld_get_image_name(i);
        if (!name || strstr(name, "PostboxFramework") == NULL) continue;
        void *h = dlopen(name, RTLD_NOW | RTLD_NOLOAD);
        if (!h) continue;
        p = dlsym(h, sym);
        if (p) return ar_strip(p);
    }
    return NULL;
}

static void ar_try_mshook(void) {
    void *p1 = ar_dlsym_postbox(kSymDeleteMessages);
    void *p2 = ar_dlsym_postbox(kSymDeleteWithGlobalIds);
    if (p1) {
        MSHookFunction(p1, (void *)hooked_nop, (void **)&orig_deleteMessages);
        ar_log(@"MSHook deleteMessages @ %p", p1);
    } else {
        ar_log(@"dlsym deleteMessages 失败（可忽略，已走偏移写 RET）");
    }
    if (p2) {
        MSHookFunction(p2, (void *)hooked_nop, (void **)&orig_deleteWithGlobalIds);
        ar_log(@"MSHook deleteMessagesWithGlobalIds @ %p", p2);
    } else {
        ar_log(@"dlsym WithGlobalIds 失败（可忽略，已走偏移写 RET）");
    }
}
#endif

/* ---------- 诊断落盘 ---------- */

static void ar_write_marker(int okCount, int total, intptr_t slide, const char *path) {
    @autoreleasepool {
        NSString *doc = NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES).firstObject;
        if (!doc) return;
        NSString *fp = [doc stringByAppendingPathComponent:@"TelegramAntiRecall_loaded.txt"];
        NSString *body = [NSString stringWithFormat:
            @"TelegramAntiRecall pure v1-deep\n"
            @"ok=%d/%d slide=0x%lx\n"
            @"postbox=%s\n"
            @"sites: WithGlobalIds=0x%llx thunk=0x%llx impl=0x%llx\n"
            @"note: RET at impl blocks bl from WithGlobalIds@+0x34\n",
            okCount, total, (unsigned long)slide,
            path ? path : "(null)",
            (unsigned long long)AR_OFF_DELETE_WITH_GLOBAL_IDS,
            (unsigned long long)AR_OFF_DELETE_MESSAGES_THUNK,
            (unsigned long long)AR_OFF_DELETE_MESSAGES_IMPL];
        [body writeToFile:fp atomically:YES encoding:NSUTF8StringEncoding error:nil];
    }
}

/* ---------- 入口 ---------- */

static void ar_install(void) {
    ar_log(@"install begin (pure anti-recall, v1 sites + impl)");

    intptr_t slide = 0;
    const char *path = NULL;
    const struct mach_header_64 *hdr = ar_find_postbox(&slide, &path);
    if (!hdr) {
        ar_log(@"未找到 PostboxFramework，稍后重试");
        return;
    }
    ar_log(@"PostboxFramework path=%s slide=0x%lx hdr=%p", path, (unsigned long)slide, hdr);

    int ok = 0;
    for (size_t i = 0; i < kSiteCount; i++) {
        void *addr = ar_runtime_addr(slide, kSites[i].fileOff);
        if (ar_write_ret_at(addr, kSites[i].expectOrig, kSites[i].name))
            ok++;
    }

#if AR_HAS_MSHOOK
    ar_try_mshook();
#endif

    ar_write_marker(ok, (int)kSiteCount, slide, path);
    ar_log(@"install done ok=%d/%zu", ok, kSiteCount);
}

static void ar_retry(void) {
    /* Postbox 有时晚于本 dylib 加载；短延迟再试一次 */
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(1.5 * NSEC_PER_SEC)),
                   dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
        intptr_t slide = 0;
        if (!ar_find_postbox(&slide, NULL)) {
            ar_log(@"retry: 仍无 PostboxFramework");
            return;
        }
        /* 若已全部是 RET 则 ar_write_ret_at 会跳过 */
        int ok = 0;
        for (size_t i = 0; i < kSiteCount; i++) {
            void *addr = ar_runtime_addr(slide, kSites[i].fileOff);
            if (ar_write_ret_at(addr, kSites[i].expectOrig, kSites[i].name))
                ok++;
        }
        ar_log(@"retry done ok=%d/%zu", ok, kSiteCount);
    });
}

__attribute__((constructor))
static void TelegramAntiRecall_init(void) {
    ar_install();
    ar_retry();
}
