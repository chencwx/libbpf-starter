#include <linux/bpf.h>
#include <linux/errno.h>

// 定义一个宏 SEC，用于为后续的函数或变量指定 section 属性
// used 属性确保在链接时不会丢弃该 section
#define SEC(NAME) __attribute__((section(NAME), used))

// 声明一个函数指针 bpf_trace_printk，用于调用 BPF_FUNC_trace_printk 函数
// BPF_FUNC_trace_printk 是一个用于打印调试消息的 BPF 辅助函数
static int (*bpf_trace_printk)(const char *fmt, int fmt_size, ...) = (void *)BPF_FUNC_trace_printk;

// 声明一个函数指针 bpf_override_return，用于调用 BPF_FUNC_override_return 函数
// BPF_FUNC_override_return 是一个用于覆盖内核函数返回值的 BPF 辅助函数
static int (*bpf_override_return)(void *ctx, __u64 rc) = (void *)BPF_FUNC_override_return;

// 定义一个 BPF 程序，将其附加到 tracepoint "syscalls/sys_enter_execve"
SEC("tracepoint/syscalls/sys_enter_execve")
int bpf_prog(void *ctx) {
    // 定义一个字符数组 msg，包含要打印的消息
    char msg[] = "Hello, the process is running!";
    
    // 调用 bpf_trace_printk 函数打印消息
    // sizeof(msg) 返回消息的大小，包括空终止符
    bpf_trace_printk(msg, sizeof(msg));
    
    // 使用 -EPERM（操作不允许）覆盖内核函数的返回值
    bpf_override_return(ctx, -EPERM);
    
    // 返回 0 表示成功
    return 0;
}

// 定义一个字符数组 _license，指定 BPF 程序的许可证
// 这对于加载到内核中的 BPF 程序是必需的
char _license[] SEC("license") = "GPL";
