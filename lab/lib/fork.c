// implement fork from user space

#include <inc/string.h>
#include <inc/lib.h>

// PTE_COW marks copy-on-write page table entries.
// It is one of the bits explicitly allocated to user processes (PTE_AVAIL).
#define PTE_COW		0x800

//
// Custom page fault handler - if faulting page is copy-on-write,
// map in our own private writable copy.
//
static void
pgfault(struct UTrapframe *utf)
{
	void *addr = (void *) utf->utf_fault_va;
	uint32_t err = utf->utf_err;
	int r;

	// Check that the faulting access was (1) a write, and (2) to a
	// copy-on-write page.  If not, panic.
	// Hint:
	//   Use the read-only page table mappings at uvpt
	//   (see <inc/memlayout.h>).

	// LAB 4: Your code here.
	if (!(err & FEC_WR) || !(uvpt[PGNUM(addr)] & PTE_COW))
		panic ("page fault!") ;

	// Allocate a new page, map it at a temporary location (PFTEMP),
	// copy the data from the old page to the new page, then move the new
	// page to the old page's address.
	// Hint:
	//   You should make three system calls.

	// LAB 4: Your code here.

	// panic("pgfault not implemented");
	
	if ((r = sys_page_alloc(0, (void *)PFTEMP, PTE_P | PTE_U | PTE_W)) < 0)
	{
		cprintf ("page alloc failed, error code: %d", -r) ;
		return ;
	}
		
	addr = (void *)ROUNDDOWN((uint32_t)addr, PGSIZE) ;
	memmove ((void *)PFTEMP, addr, PGSIZE) ;
	
	if ((r = sys_page_map(0, (void *)PFTEMP, 0, addr, PTE_P | PTE_U | PTE_W)) < 0)
	{
		cprintf ("page map failed, error code: %d", -r) ;
		return ;
	}
		
	if ((r = sys_page_unmap(0, (void *)PFTEMP)) < 0)
	{
		cprintf ("page unmap failed, error code: %d", -r) ;
		return ;
	}
}

//
// Map our virtual page pn (address pn*PGSIZE) into the target envid
// at the same virtual address.  If the page is writable or copy-on-write,
// the new mapping must be created copy-on-write, and then our mapping must be
// marked copy-on-write as well.  (Exercise: Why do we need to mark ours
// copy-on-write again if it was already copy-on-write at the beginning of
// this function?)
//
// Returns: 0 on success, < 0 on error.
// It is also OK to panic on error.
//
static int
duppage(envid_t envid, unsigned pn)
{
	int r;

	// LAB 4: Your code here.
	//panic("duppage not implemented");
	void *va = (void *)(pn * PGSIZE) ;
	pte_t pte = uvpt[pn] ;
	if ((pte & PTE_COW) || ((pte & PTE_W) && !(pte & PTE_SHARE)))
	{
		if ((r = sys_page_map(0, va, envid, va, PTE_P | PTE_U | PTE_COW)) < 0)
			return r ;
			
		if ((r = sys_page_map(0, va, thisenv->env_id, va, PTE_P | PTE_U | PTE_COW)) < 0)
			return r ;
	}
	else if (pte & PTE_SHARE)
	{
		if ((r = sys_page_map(0, va, envid, va, pte & PTE_SYSCALL)) < 0)
			return r ;
	}
	else if ((r = sys_page_map(0, va, envid, va, PTE_P | PTE_U)) < 0)
		return r ;
	
	return 0;
}

//
// User-level fork with copy-on-write.
// Set up our page fault handler appropriately.
// Create a child.
// Copy our address space and page fault handler setup to the child.
// Then mark the child as runnable and return.
//
// Returns: child's envid to the parent, 0 to the child, < 0 on error.
// It is also OK to panic on error.
//
// Hint:
//   Use uvpd, uvpt, and duppage.
//   Remember to fix "thisenv" in the child process.
//   Neither user exception stack should ever be marked copy-on-write,
//   so you must allocate a new page for the child's user exception stack.
//
envid_t
fork(void)
{
	// LAB 4: Your code here.
	// panic("fork not implemented");
	envid_t child_id = sys_exofork() ;
	if (child_id < 0)
		return child_id ;
		
	if (child_id == 0)
	{
		thisenv = &envs[ENVX(sys_getenvid())];
		return 0 ;
	}
	
	set_pgfault_handler (pgfault) ;
	extern void _pgfault_upcall(void);
	sys_env_set_pgfault_upcall (child_id, _pgfault_upcall) ;
	
	for (uint32_t va = 0; va < USTACKTOP; va += PGSIZE)
		if ((uvpd[PDX(va)] & PTE_P) && (uvpt[PGNUM(va)] & PTE_P))
			duppage (child_id, PGNUM(va)) ;
	
	int r ;
	if ((r = sys_page_alloc(child_id, (void *)(UXSTACKTOP - PGSIZE), PTE_P | PTE_U | PTE_W)) < 0)
		return r ;
		
	if ((r = sys_env_set_status(child_id, ENV_RUNNABLE)) < 0)
		return r ;
	
	return child_id ;
}

// Challenge!
int
sfork(void)
{
	panic("sfork not implemented");
	return -E_INVAL;
}
