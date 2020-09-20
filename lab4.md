# 理论补充

## SMP

### 处理器分类
对称多处理（SMP - Symmetric Multiprocessing）所使用的处理器可分为：
1. 引导处理器（BSP - Bootstrap Processor）：在启动操作系统的时候，初始化系统的时候使用（目前为止，JOS 所使用的处理器）；
2. 应用程序处理器（APs - Application Processors）：仅当在操作系统已经启动好后，被 BSP 激活；

### BSP 选举
通电后，所有处理器都开始自检（BIST - Built In Self Test），在 BNR（Bus Not Ready）停止翻转后，第一个向总线成功发出 NOP 的将成为 BSP，其他的处理器进入 wait for SIPI 状态，等待 BSP 激活

### 激活 APs
* 处理器通过 MMIO（Memory-Mapped I/O）来访问 Local APIC，物理地址一样，映射到当前运行处理器；
* 处理器之间可以通过 Local APIC 向总线发送（或接收）IPI（InterProcessor Interrupt）来通信，如最开始 BSP 创建 MP 配置表（Configuration Table），并将自己登记为 0 号，接着会向 APs 发送一个 INIT IPI 让 APs 到近似复位的状态（warm reset），然后发送 SIPI（Start-up IPI）激活 APs 也去其中登记

## BIOS 数据区
* BDA（BIOS Data Area）：0x400~0x4FF，包含有关系统环境的信息，例如：
	* 偏移 0xE 和 0xF 分别保存着 EBDA 的段地址低 8bit 和高 8bit，EBDA 的物理地址即段地址左移 4；
	* 偏移 0x13 和 0x14 分别保存着 basemem 大小（单位为 KB）的低 8bit 和高 8bit；
* EBDA（Extended BIOS Data Area）：首 1KB 中可能包含 MP Floating Pointer Structure；

## MP 配置表
MP 配置表（Configuration Table）中记录了所有处理器的信息，最开始由 BSP 创建 ，并将自己登记为 0 号，APs 收到 SIPI 后也会去其中登记

### MP Floating Pointer Structure
MP Floating Pointer Structure 通常位于内存的如下三个位置，操作系统通常按如下顺序搜索：
1. 在 EBDA（Extended BIOS Data Area）的首 1KB 寻找；
2. 如果 EBDA 未定义，则在 basemem 的最后 1KB 寻找；
3. 如果没找到，则在 BIOS ROM（0xF0000~0xFFFFF）寻找；

MP Floating Pointer Structure 的结构特点：
1. 开头 4 个字节为`__MP__`；
2. 所有字节的值加起来为 0；
3. 紧接着`__MP__`后记录了 MP 配置表的地址；

### MP 配置表
MP 配置表分为表头和扩展表（紧跟表头），表头结构特点如下：
1. 开头 4 个字节为`PCMP`；
2. 所有字节的值加起来为 0；

扩展表中包含若干表项，但表项由于类型的不同长度可能不一，于是表项首字节标注表项类型

## 中断模式
* PIC Mode：中断由 Master PIC 接收并转发到 BSP，通过更改 IMCR 寄存器退出该模式；
* Symmetric I/O Mode：中断由 I/O APIC 接收，并通过总线分发至所有处理器的 Local APIC；

## 大内核锁
利用大内核锁（Big Kernel Lock）可以保证同一时刻，只有一个处理器处于内核态

## HALT
当处理器空闲时，可以通过`hlt`指令进入 HALT 状态，该状态会停止指令的执行并关闭处理器的部分功能模块，从而降低功耗。但 Local APIC 仍然能接收中断，从而能在接到中断时从 HALT 状态恢复，并继续之前的执行。Idle 进程本质上就是循环执行`hlt`指令

# 代码解析

## 获取处理器信息
kern/mpconfig.c 中定义了 MP Floating Pointer Structure 以及 MP 配置表的结构：
```c
struct mp {             // MP Floating Pointer Structure
	uint8_t signature[4];           // "_MP_"
	physaddr_t physaddr;            // MP 配置表物理地址
	// ...
} __attribute__((__packed__));

struct mpconf {         // MP 配置表
	uint8_t signature[4];           // "PCMP"
	uint16_t length;                // 结构长度
	// ...
	uint16_t entry;                 // 扩展表 entry 数
	physaddr_t lapicaddr;           // Local APIC MMIO 物理地址
	uint16_t xlength;               // 扩展表长度
	// ...
	uint8_t entries[0];             // 扩展表起始
} __attribute__((__packed__));

```
kern/mpconfig.c 中的`mpconfig`用于定位 MP 配置表：
```c
static uint8_t
sum(void *addr, int len)
{
	int i, sum;

	sum = 0;
	for (i = 0; i < len; i++)
		sum += ((uint8_t *)addr)[i];
	return sum;
}

static struct mp *
mpsearch1(physaddr_t a, int len)
{
	struct mp *mp = KADDR(a), *end = KADDR(a + len);

	for (; mp < end; mp++)
		if (memcmp(mp->signature, "_MP_", 4) == 0 &&
		    sum(mp, sizeof(*mp)) == 0)
			return mp;
	return NULL;
}

static struct mp *
mpsearch(void)
{
	uint8_t *bda;
	uint32_t p;
	struct mp *mp;

	static_assert(sizeof(*mp) == 16);

	// BDA 地址
	bda = (uint8_t *) KADDR(0x40 << 4);

  // 判断是否存在 EBDA
	// 利用 x86 小端特点，一次性将 BDA[0x0E], BDA[0x0F] 读进 p
	if ((p = *(uint16_t *) (bda + 0x0E))) {
		p <<= 4;
    // 搜索 EBDA 1KB
		if ((mp = mpsearch1(p, 1024)))
			return mp;
	} else {
		// 不在 EBDA，从 basemem 末 1KB 搜索
    // 利用 x86 小端特点，一次性将 BDA[0x13], BDA[0x14] 读进 p
		p = *(uint16_t *) (bda + 0x13) * 1024;
		if ((mp = mpsearch1(p - 1024, 1024)))
			return mp;
	}
  // 在 BIOS ROM 搜索
	return mpsearch1(0xF0000, 0x10000);
}

static struct mpconf *
mpconfig(struct mp **pmp)
{
	struct mpconf *conf;
	struct mp *mp;

	// 定位 MP Floating Pointer Structure
	if ((mp = mpsearch()) == 0)
		return NULL;
	// 检查 MP Floating Pointer Structure 的合法性
	if (mp->physaddr == 0 || mp->type != 0) {
		cprintf("SMP: Default configurations not implemented\n");
		return NULL;
	}
	// 取得 MP 配置表，并检查其合法性
	conf = (struct mpconf *) KADDR(mp->physaddr);
	if (memcmp(conf, "PCMP", 4) != 0) {
		cprintf("SMP: Incorrect MP configuration table signature\n");
		return NULL;
	}
	if (sum(conf, conf->length) != 0) {
		cprintf("SMP: Bad MP configuration checksum\n");
		return NULL;
	}
	if (conf->version != 1 && conf->version != 4) {
		cprintf("SMP: Unsupported MP version %d\n", conf->version);
		return NULL;
	}
	if ((sum((uint8_t *)conf + conf->length, conf->xlength) + conf->xchecksum) & 0xff) {
		cprintf("SMP: Bad MP configuration extended checksum\n");
		return NULL;
	}
  // MP Floating Pointer Structure 保存到全局变量中
	*pmp = mp;
	return conf;
}
```
kern/mpconfig.c 中定义了结构体数组`cpus`来维护处理器信息，结构体定义于 kern/cpu.h：
```c
struct CpuInfo {
	uint8_t cpu_id;                // Local APIC ID，等同 cpus 的下标
	volatile unsigned cpu_status;  // 处理器状态
	struct Env *cpu_env;           // 当前运行的进程（curenv 被重定义了为 thiscpu->cpu_env）
	struct Taskstate cpu_ts;       // TSS（不再使用 Lab 2 的 TSS）
};

// 当前处理器
#define thiscpu (&cpus[cpunum()]) // cpunum() 获取当前运行的处理器 ID
```
kern/init.c 中的`i386_init`增加了对 kern/mpconfig.c 中`mp_init`的调用，用于统计处理器信息：
```c
void
mp_init(void)
{
	struct mp *mp;
	struct mpconf *conf;
	struct mpproc *proc;
	uint8_t *p;
	unsigned int i;

  // 先初始化 BSP，以防 MP 配置表解析失败不进入 case MPPROC
	bootcpu = &cpus[0];
	// 获取 MP 配置表
	if ((conf = mpconfig(&mp)) == 0)
		return;
	ismp = 1;
  // Local APIC MMIO 物理地址保存到全局变量
  // 所有 Local APIC MMIO 的
	lapicaddr = conf->lapicaddr;

  // 解析 MP 配置表表项
	for (p = conf->entries, i = 0; i < conf->entry; i++) {
		switch (*p) {
		case MPPROC: // 处理器表项
			proc = (struct mpproc *)p;
			if (proc->flags & MPPROC_BOOT) // 确定 BSP
				bootcpu = &cpus[ncpu];
			if (ncpu < NCPU) { // NCPU 为 JOS 支持的最大处理器数
				cpus[ncpu].cpu_id = ncpu;
				ncpu++; // 处理器数量
			} else {
				cprintf("SMP: too many CPUs, CPU %d disabled\n",
					proc->apicid);
			}
			p += sizeof(struct mpproc);
			continue;
		case MPBUS:
		case MPIOAPIC:
		case MPIOINTR:
		case MPLINTR:
			p += 8;
			continue;
		default:
			cprintf("mpinit: unknown config type %x\n", *p);
			ismp = 0; // 不是有效的 MP 配置表
			i = conf->entry;
		}
	}

  // BSP 设为已启动状态
	bootcpu->cpu_status = CPU_STARTED;
	if (!ismp) {
		// 不是有效的 MP 配置表
		ncpu = 1;
		lapicaddr = 0;
		cprintf("SMP: configuration not found, SMP disabled\n");
		return;
	}
	cprintf("SMP: CPU %d found %d CPU(s)\n", bootcpu->cpu_id,  ncpu);

	if (mp->imcrp) {
		// 将中断模式由 PIC Mode 改为 Symmetric I/O Mode
		cprintf("SMP: Setting IMCR to switch from PIC mode to symmetric I/O mode\n");
		outb(0x22, 0x70);
		outb(0x23, inb(0x23) | 1);
	}
}
```

## 激活 APs
kern/init.c 中的`i386_init`在`mp_init`后通过 kern/lapic.c 中的`lapic_init`初始化 BSP 的 Local APIC：
```c
void
lapic_init(void)
{
	if (!lapicaddr)
		return;

	// 将 Local APIC MMIO 物理地址映射到特定虚拟地址
	lapic = mmio_map_region(lapicaddr, 4096);

	// 初始化
  // ...
}
```
`mmio_map_region`定义于 kern/pmap.c：

```c
void *
mmio_map_region(physaddr_t pa, size_t size)
{
	// 映射到特定虚拟地址
	static uintptr_t base = MMIOBASE;

	// Your code here:
	size = ROUNDUP((uint32_t)size, PGSIZE);
	pa = ROUNDDOWN((uint32_t)pa, PGSIZE);
	if (base + size > MMIOLIM || base + size < base)
		panic ("out of memory!") ;
	
	// PTE_PCD：读为 Cache Disable
	// PTE_PWT：写为 Write Through
	boot_map_region (kern_pgdir, base, size, pa, PTE_PCD | PTE_PWT | PTE_W) ;
	// 下次从 base + size 处映射
  base += size ;
	
  // 返回虚拟地址
	return (void *)(base - size) ;
}
```
kern/init.c 中的`i386_init`接着通过 kern/picirq.c 中的`pic_init`对 Master PIC 进行了初始化，然后获取大内核锁，以防 BSP 还未激活完所有 APs 就被其他处理器抢占，接着通过`boot_aps`激活 APs，让 APs 以 kern/mpentry.S 作为 Entry Code（相当于 Boot Loader）：
```c
static void
boot_aps(void)
{
	// mpentry.S 的起始和终止地址
	extern unsigned char mpentry_start[], mpentry_end[];
	void *code;
	struct CpuInfo *c;

	// 将其加载到固定物理地址，因为 APs 在实模式下启动，所以 MPENTRY_PADDR < 640KB
	code = KADDR(MPENTRY_PADDR);
	memmove(code, mpentry_start, mpentry_end - mpentry_start);

	// 挨个激活 APs
	for (c = cpus; c < cpus + ncpu; c++) {
		// 不需要激活当前处理器（BSP）
		if (c == cpus + cpunum())
			continue;

		// c 的内核栈，用于 mpentry.S 中设置 ESP
		mpentry_kstack = percpu_kstacks[c - cpus] + KSTKSIZE;
		// 激活 c
		lapic_startap(c->cpu_id, PADDR(code));
		// 等待 c 被激活
		while(c->cpu_status != CPU_STARTED)
			;
	}
}
```
`lapic_startap`位于 kern/lapic.c：
```c
void
lapic_startap(uint8_t apicid, uint32_t addr)
{
	int i;
	uint16_t *wrv;

	// 一些初始化
  // ...

	// 将 apicid 写入 Local APIC，为 cpunum() 使用
	lapicw(ICRHI, apicid << 24);
  // 发送 INIT IPI
	lapicw(ICRLO, INIT | LEVEL | ASSERT);
	microdelay(200);
	lapicw(ICRLO, INIT | LEVEL);
	microdelay(100);

	// 发送 SIPI，Intel 官方规定要发送两次
	for (i = 0; i < 2; i++) {
		lapicw(ICRHI, apicid << 24);
		lapicw(ICRLO, STARTUP | (addr >> 12));
		microdelay(200);
	}
}
```
kern/mpentry.S 所做的工作与 Boot Loader 类似，但最后会跳到 kern/init.c 的`mp_main`：
```c
void
mp_main(void)
{
	// 装载页目录
	lcr3(PADDR(kern_pgdir));
	cprintf("SMP: CPU %d starting\n", cpunum());

  // 初始化 Local APIC
	lapic_init();
  // 初始化 GDTR
	env_init_percpu();
  // 初始化 TSS, IDTR, TR
	trap_init_percpu();
  // 将当前处理器设置为已启动状态
	xchg(&thiscpu->cpu_status, CPU_STARTED);

	// Your code here:
  // 取得大内核锁后进入调度
  lock_kernel();
  sched_yield();
}
```

## 更新空闲页链表
需要将`MPENTRY_PADDR`所在的页从空闲页链表中剔除，kern/pmap.c 中的`page_init`修改为：
```c
void
page_init(void)
{
	struct PageInfo* mp_entry_page = pa2page(MPENTRY_PADDR);
	
	size_t i;
	pages[0].pp_ref = 1 ;
	for (i = 1; i < npages_basemem; i++)
	{
		if (pages + i == mp_entry_page)
			continue ;
		
		pages[i].pp_ref = 0 ;
		pages[i].pp_link = page_free_list ;
		page_free_list = &pages[i] ;
	}
	
	// ...
}
```

## 映射内核栈
kern/mpconfig.c 中为所有处理器开辟了内核栈：
```c
unsigned char percpu_kstacks[NCPU][KSTKSIZE]
__attribute__ ((aligned(PGSIZE)));
```
kern/pmap.c 中的`mem_init`调用`mem_init_mp`将内核栈在虚拟地址中映射成期望的布局，目前 BSP 的内核栈仍然在 Lab 2 设置的`bootstack`处，经过如下设置，也会被设置为`percpu_kstacks`：
```c
static void
mem_init_mp(void)
{
	// LAB 4: Your code here:
  uint32_t kstacktop_i = KSTACKTOP ;
	for (int i = 0; i < NCPU; i++)
	{
		boot_map_region (kern_pgdir, kstacktop_i - KSTKSIZE, KSTKSIZE, 
			PADDR(percpu_kstacks[i]), PTE_W | PTE_P) ;
		
		kstacktop_i -= KSTKSIZE ;
		kstacktop_i -= KSTKGAP ;
	}
}
```

## 初始化 TSS
由于每个处理器有独立的内核栈，所以也需要有独立的 TSS，kern/trap.c 中`trap_init_percpu`修改为：
```c
void
trap_init_percpu(void)
{
  // 初始化 TSS
	thiscpu->cpu_ts.ts_esp0 = (uint32_t)percpu_kstacks[thiscpu->cpu_id];
	thiscpu->cpu_ts.ts_ss0 = GD_KD;
	thiscpu->cpu_ts.ts_iomb = sizeof(struct Taskstate);

  // 在 GDT 中设置 TSS
	gdt[(GD_TSS0 >> 3) + thiscpu->cpu_id] = SEG16(STS_T32A, (uint32_t) (&thiscpu->cpu_ts),
					sizeof(struct Taskstate) - 1, 0);
	gdt[(GD_TSS0 >> 3) + thiscpu->cpu_id].sd_s = 0;

  // 初始化 TR
	ltr(GD_TSS0 + (thiscpu->cpu_id << 3));

	// 初始化 IDTR
	lidt(&idt_pd);
}
```

## 大内核锁

inc/x86.h 中的`xchg(x,y)`原子地交换`x,y`的值，并返回`y`，可以用其实现自旋锁。自旋锁的实现定义于 kern/spinlock.c：
```c
void
spin_lock(struct spinlock *lk)
{
  // lk->locked 原值为 1 则自旋
	while (xchg(&lk->locked, 1) != 0) 
		asm volatile ("pause"); // 处理器短暂延时
}

spin_unlock(struct spinlock *lk)
{
	xchg(&lk->locked, 0);
}
```
大内核锁基于自旋锁，其锁结构定义于 kern/spinlock.c：
```c
// 依靠编译器为其分配 1B
struct spinlock kernel_lock = {};
```
大内核锁的实现定义于 kern/spinlock.h：
```c
static inline void
lock_kernel(void)
{
	spin_lock(&kernel_lock);
}

static inline void
unlock_kernel(void)
{
	spin_unlock(&kernel_lock);

	// 以防当前处理器时间片过长，当前处理器在其他处理器获得锁之前重新获得锁
	asm volatile("pause");
}
```

## 进程销毁
为了防止销毁其他处理器上正在运行的进程，kern/env.c 的`env_destroy`做了如下修改：
```C
void
env_destroy(struct Env *e)
{
	// 如果进程运行于其他处理器
	if (e->env_status == ENV_RUNNING && curenv != e) {
		// 标为僵死，进程下次 trap 时回收进程描述符
		e->env_status = ENV_DYING;
		return;
	}

	env_free(e);

  // 如果销毁的是正运行的进程，重新调度
	if (curenv == e) {
		curenv = NULL;
		sched_yield();
	}
}
```

## 陷入内核
要在 kern/trap.c 的`trap`中加锁：

```c
void
trap(struct Trapframe *tf)
{
	asm volatile("cld" ::: "cc");

  // 如果其他处理器调用过 panic，处理器 HALT
	extern char *panicstr;
	if (panicstr)
		asm volatile("hlt");

	// CPU_HALTED 意味着无锁，先加锁
	if (xchg(&thiscpu->cpu_status, CPU_STARTED) == CPU_HALTED)
		lock_kernel();
	// 确保中断已被关
	assert(!(read_eflags() & FL_IF));

	if ((tf->tf_cs & 3) == 3) {
		// 中断发生于用户态，此时要进入内核态，先加锁
		// LAB 4: Your code here.
    lock_kernel();
		assert(curenv);

    // 如果为僵死进程，回收进程描述符并重新调度
		if (curenv->env_status == ENV_DYING) {
			env_free(curenv);
			curenv = NULL;
			sched_yield();
		}

		// 将保存的现场拷贝到进程描述符，下一次运行进程时，将从中断处继续运行
		curenv->env_tf = *tf;
		tf = &curenv->env_tf;
	}

	// 维护全局变量 last_tf，以供今后 debug
	last_tf = tf;

	// 处理中断
	trap_dispatch(tf);

	// 恢复进程运行
	if (curenv && curenv->env_status == ENV_RUNNING)
		env_run(curenv);
	else
		sched_yield();
}
```

## 进程运行
进程的运行标志着退出内核，需要解锁，kern/env.c 的`env_run`修改为：
```c
void
env_run(struct Env *e)
{
	// ...
	lcr3(PADDR(curenv->env_pgdir)) ;
	unlock_kernel();
	env_pop_tf(&curenv->env_tf) ;
}
```

## 进程调度
JOS 的进程调度采用 Round-Robin，实现于 kern/sched.c：
```c
void
sched_yield(void)
{
	struct Env *idle;
	
	// LAB 4: Your code here.
	idle = (curenv == NULL) ? envs : curenv ;
	int cur_id = idle - envs ;
	for (int i = 1; i <= NENV; i++)
	{
    // 从当前进程的下一个开始轮训
		int nxt_id = (cur_id + i) % NENV ;
		if (envs[nxt_id].env_status == ENV_RUNNABLE)
			env_run (envs + nxt_id) ;
	}

	// 当前没有任何进程可运行，进入 HALT
	sched_halt();
}
```
`sched_halt()` 实现与 kern/sched.c：

```c
void
sched_halt(void)
{
	int i;

  // 当没有任何进程存在时，进入命令行（不释放锁）
	for (i = 0; i < NENV; i++) {
		if ((envs[i].env_status == ENV_RUNNABLE ||
		     envs[i].env_status == ENV_RUNNING ||
		     envs[i].env_status == ENV_DYING))
			break;
	}
	if (i == NENV) {
		cprintf("No runnable environments in the system!\n");
		while (1)
			monitor(NULL);
	}

	curenv = NULL;
	lcr3(PADDR(kern_pgdir));

	// CPU_HALTED 意味着当前没有锁，脱离 HALT 重回内核时应该首先加锁
	xchg(&thiscpu->cpu_status, CPU_HALTED);
	unlock_kernel();

	// 将 ESP 保存到 TSS，EBP 压栈，然后执行 hlt
	asm volatile (
		"movl $0, %%ebp\n"
		"movl %0, %%esp\n"
		"pushl $0\n"
		"pushl $0\n"
		// Uncomment the following line after completing exercise 13
		//"sti\n"
		"1:\n"
		"hlt\n"
		"jmp 1b\n"
	: : "a" (thiscpu->cpu_ts.ts_esp0));
}
```

## 系统调用

### 释放控制权
在 kern/syscall.c 中提供`sys_yield`系统调用使得用户可以主动释放控制权：
```c
static void
sys_yield(void)
{
	sched_yield();
}

int32_t
syscall(uint32_t syscallno, uint32_t a1, uint32_t a2, uint32_t a3, uint32_t a4, uint32_t a5)
{
	switch (syscallno) {
	// ...
	case SYS_yield:
		sys_yield();
		return 0;
	// ...
	}
}
```

### fork
在 kern/syscall.c 中提供`sys_exofork`系统调用使得用户可以 fork 当前进程：
```c
static envid_t
sys_exofork(void)
{
	// LAB 4: Your code here.
	struct Env *child_env ;
	
  // 分配进程描述符
	envid_t r ;
	if ((r = env_alloc(&child_env, curenv->env_id)) < 0)
		return r ;
		
  // 让子进程拥有同样的上下文
	child_env->env_tf = curenv->env_tf ;
	child_env->env_status = ENV_NOT_RUNNABLE ;
  // 在子进程中，该函数返回 0
	child_env->env_tf.tf_regs.reg_eax = 0 ;
	
	return child_env->env_id ;
}

int32_t
syscall(uint32_t syscallno, uint32_t a1, uint32_t a2, uint32_t a3, uint32_t a4, uint32_t a5)
{
	switch (syscallno) {
	// ...
	case SYS_exofork:
		sys_exofork();
		return 0;
	// ...
	}
}
```

### 修改进程状态
在 kern/syscall.c 中提供`sys_env_set_status`系统调用使得用户可以修改进程（当前进程或当前进程的子进程）状态：
```c
static int
sys_env_set_status(envid_t envid, int status)
{
	// LAB 4: Your code here.
	// 不能将状态设为 ENV_RUNNABLE, ENV_NOT_RUNNABLE 以外
	if (status != ENV_RUNNABLE && status != ENV_NOT_RUNNABLE)
		return -E_BAD_ENV ;
	
	// 进程 ID 不合法
	struct Env *e ;
	int r ;
	if ((r = envid2env(envid, &e, 1)) < 0)
		return r ;
	
	e->env_status = status ;
	return 0 ;
}

int32_t
syscall(uint32_t syscallno, uint32_t a1, uint32_t a2, uint32_t a3, uint32_t a4, uint32_t a5)
{
	switch (syscallno) {
	// ...
	case SYS_env_set_status:
		sys_env_set_status();
		return 0;
	// ...
	}
}
```

### 分配页
在 kern/syscall.c 中提供`sys_page_alloc`系统调用使得用户可以为进程（当前进程或当前进程的子进程）申请页：
```c
static int
sys_page_alloc(envid_t envid, void *va, int perm)
{
	// LAB 4: Your code here.
	// 虚拟地址不合法
	if ((uint32_t)va >= UTOP || (uint32_t)va % PGSIZE)
		return -E_INVAL ;
	
	// 权限不合法
	if (!(perm & PTE_U) || (perm & ~PTE_SYSCALL))
		return -E_INVAL ;
	
	// 进程 ID 不合法
	struct Env *e ;
	int r ;
	if ((r = envid2env(envid, &e, 1)) < 0)
		return r ;
	
	// 分配物理页
	struct PageInfo *pg = page_alloc (ALLOC_ZERO) ;
	if (!pg)
		return -E_NO_MEM ;
	
	// 映射到指定虚拟地址
	if ((r = page_insert(e->env_pgdir, pg, va, perm)) < 0)
	{
		page_free(pg); // 映射失败则回收物理页
		return r;
	}
	
	return 0 ;
}

int32_t
syscall(uint32_t syscallno, uint32_t a1, uint32_t a2, uint32_t a3, uint32_t a4, uint32_t a5)
{
	switch (syscallno) {
	// ...
	case SYS_page_alloc:
		sys_page_alloc();
		return 0;
	// ...
	}
}
```

### 共享映射
在 kern/syscall.c 中提供`sys_page_map`系统调用使得用户可以为使两个进程（当前进程或当前进程的子进程）共享映射：
```c
static int
sys_page_map(envid_t srcenvid, void *srcva,
	     envid_t dstenvid, void *dstva, int perm)
{
	// LAB 4: Your code here.
	// 虚拟地址不合法
	if ((uint32_t)srcva >= UTOP || (uint32_t)srcva % PGSIZE ||
	     (uint32_t)dstva >= UTOP || (uint32_t)dstva % PGSIZE)
		return -E_INVAL ;
	
	// 权限不合法
	if (!(perm & PTE_U) || (perm & ~PTE_SYSCALL))
			return -E_INVAL ;
	
	// 进程 ID 不合法
	struct Env *srcenv, *dstenv ;
	int r ;
	if ((r = envid2env(srcenvid, &srcenv, 1) < 0) ||
	     (r = envid2env(dstenvid, &dstenv, 1) < 0))
		return r ;
	
	// 查找 srcva 的物理地址
	struct PageInfo *srcpa ;
	pte_t *pte ;
	if ((srcpa = page_lookup(srcenv->env_pgdir, srcva, &pte)) == NULL)
		return -E_INVAL ;
	
	// 如果 srcva 没有写权限，但却要给 dstva 分配写权限
	if (!(*pte & PTE_W) && (perm & PTE_W))
		return -E_INVAL ;
	
	// 将 dstva 映射到 srcva 的物理地址处
	return page_insert(dstenv->env_pgdir, srcpa, dstva, perm);
}

int32_t
syscall(uint32_t syscallno, uint32_t a1, uint32_t a2, uint32_t a3, uint32_t a4, uint32_t a5)
{
	switch (syscallno) {
	// ...
	case SYS_page_map:
		sys_page_map();
		return 0;
	// ...
	}
}
```

### 解除映射
在 kern/syscall.c 中提供`sys_page_unmap`系统调用使得用户可以将进程（当前进程或当前进程的子进程）指定虚拟内存解除映射：
```c
static int
sys_page_unmap(envid_t envid, void *va)
{
	// LAB 4: Your code here.
	// 进程 ID 不合法
	struct Env *e ;
	int r ;
	if ((r = envid2env(envid, &e, 1)) < 0)
		return r ;
	
	// 虚拟地址不合法
	if ((uint32_t)va >= UTOP || (uint32_t)va % PGSIZE)
		return -E_INVAL ;
		
	page_remove(e->env_pgdir, va) ;
	return 0 ;
}

int32_t
syscall(uint32_t syscallno, uint32_t a1, uint32_t a2, uint32_t a3, uint32_t a4, uint32_t a5)
{
	switch (syscallno) {
	// ...
	case SYS_page_unmap:
		sys_page_unmap();
		return 0;
	// ...
	}
}
```

# Questions
> It seems that using the big kernel lock guarantees that only one CPU can run the kernel code at a time. Why do we still need separate kernel stacks for each CPU? Describe a scenario in which using a shared kernel stack will go wrong, even with the protection of the big kernel lock.

当一个处理器刚陷入内核时要向内核栈中压入一些中断信息，此时没有加锁，为了防止此时另一个处理器同时陷入，所以每个处理器的内核栈需要独立