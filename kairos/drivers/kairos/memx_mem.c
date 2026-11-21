// SPDX-License-Identifier: GPL-2.0
/*
 * memx_mem.c — 物理内存层（built-in 版）
 *
 * 与 .ko 版相比的核心优化：
 *   1. **删掉全部硬编码偏移**：mm->pgd / mm->mmap_lock / task->mm / task->alloc_lock
 *      全部用真实成员访问，不再依赖 6.6.127 的特定布局（原版写死 112/144/1440/2312）
 *   2. **删掉内联展开的 pfn_valid / pfn_to_page**：直接用内核 API
 *   3. **删掉手写的 3 级 walk 索引算术**：用 pgd_offset/p4d_offset/pud_offset/pmd_offset
 *      （在 39-bit VA + 4K page 配置下，p4d/pud 会自动折叠，生成的代码和原版等价）
 *   4. **写路径默认走 GUP**：原版直接改线性映射会踩坏 COW 共享页，这里默认安全路径，
 *      只有确认 mapcount==1 且 PageAnon 才走快速路径
 */
#include <linux/kernel.h>
#include <linux/mm.h>
#include <linux/sched.h>
#include <linux/sched/mm.h>
#include <linux/sched/task.h>
#include <linux/pid.h>
#include <linux/rcupdate.h>
#include <linux/swap.h>
#include <linux/swapops.h>
#include <linux/blkdev.h>
#include <linux/bio.h>
#include <linux/highmem.h>
#include <linux/pgtable.h>

#include "memx.h"

/*
 * swap_cache_get_folio() 在 6.6 里是 mm/swap_state.c 的全局函数，
 * 但**没有任何头文件给它原型**（只在 mm/internal.h 之外隐式可见）。
 * 驱动里 include 不到 mm/internal.h，所以自己按 6.6.127 的定义补一个：
 *     struct folio *swap_cache_get_folio(swp_entry_t entry,
 *                                        struct vm_area_struct *vma,
 *                                        unsigned long addr);
 * 换内核版本若签名变了，这里会立刻链接失败 —— 比悄悄错位好。
 */
struct folio *swap_cache_get_folio(swp_entry_t entry,
				   struct vm_area_struct *vma,
				   unsigned long addr);

/* ================================================================== */
/* 1. 取 mm                                                            */
/* ================================================================== */
struct mm_struct *memx_grab_mm_by_pid(pid_t pid)
{
	struct task_struct *task;
	struct mm_struct *mm = NULL;
	struct pid *vpid;

	rcu_read_lock();
	vpid = find_vpid(pid);
	if (!vpid)
		goto out;

	task = pid_task(vpid, PIDTYPE_PID);
	if (!task)
		goto out;

	/* 原版是 raw_spin_lock(&task->alloc_lock) + atomic_inc(&mm->mm_count) 的裸实现，
	 * 这里直接用 mmget()，语义一致、还省掉一次手写锁 */
	mm = get_task_mm(task);
out:
	rcu_read_unlock();
	return mm;
}

/* ================================================================== */
/* 2. VA -> PA（lockless）                                             */
/*                                                                     */
/* 原版自己算索引 + 自己读页表；这里用宏，可读性/可移植性都更好：       */
/*   pgd_offset(mm, va) → p4d_offset → pud_offset → pmd_offset → pte   */
/* 39-bit VA 下 p4d/pud 折叠，最终就是 3 次查表，和原版指令序列等价。    */
/* 全部用 READ_ONCE 读取，配合 RCU 保证不撕裂。                        */
/* ================================================================== */
struct memx_va_result {
	unsigned long	pa;
	u64		*pte_slot;	/* 指回最后一层表项，调用方拷完复核 */
	bool		block;		/* true = PMD 块映射(2MB) */
};

static bool memx_va_to_pa(struct mm_struct *mm, unsigned long va,
			    bool for_write, struct memx_va_result *out)
{
	pgd_t *pgd;
	p4d_t *p4d;
	pud_t *pud;
	pmd_t *pmd;
	pte_t *pte;

	out->pa = 0;
	out->pte_slot = NULL;
	out->block = false;

	pgd = pgd_offset(mm, va);
	if (!pgd_present(READ_ONCE(*pgd)))
		return false;

	p4d = p4d_offset(pgd, va);
	pud = pud_offset(p4d, va);
	if (!pud_present(*pud))
		return false;

	pmd = pmd_offset(pud, va);
	if (pmd_none(READ_ONCE(*pmd)))
		return false;

	/* ---- 2MB 块映射 ---- */
	if (pmd_leaf(READ_ONCE(*pmd))) {
		phys_addr_t pa;

		if (for_write && !pmd_write(READ_ONCE(*pmd)))
			return false;
		pa = __pfn_to_phys(pmd_pfn(READ_ONCE(*pmd))) | (va & ~PMD_MASK);
		out->pa = pa;
		out->pte_slot = (u64 *)pmd;
		out->block = true;
		return true;
	}

	if (!pmd_table(READ_ONCE(*pmd)))
		return false;

	/* ---- 4K 页 ---- */
	pte = pte_offset_kernel(pmd, va);

	if (!pte_present(READ_ONCE(*pte)))		/* 换出 / 未建立 → 交给 swap 路径 */
		return false;

	/* 原版拒绝设备内存（AttrIndx != 0）与软件保留位，这里用 pte_special 等价判断 */
	if (pte_special(*pte))
		return false;

	if (for_write && !pte_write(*pte))
		return false;

	out->pa = __pfn_to_phys(pte_pfn(*pte)) | (va & ~PAGE_MASK);
	out->pte_slot = (u64 *)pte;
	out->block = false;
	return true;
}

/*
 * 拷完复核：页表项还在、还指向同一物理页。
 *
 * 这里原来有两个 bug（实测才发现，读取永远返回 0 字节）：
 *   1. 掩码算错：((pte >> 12) & GENMASK_ULL(47,0)) 实际取的是原 PTE 的
 *      bit12..59，把 AF/SH/AP 这些属性位也当成了 PFN，比较必然不等。
 *      正确做法是用 pte_pfn()/pmd_pfn()，它们只取输出地址位。
 *   2. 块映射判断写成了 (val & 3) == 3，那是 PMD_TYPE_TABLE；
 *      arm64 的块映射是 PMD_TYPE_SECT == 1。
 * 直接改用内核的 pmd_sect()/pmd_pfn()/pte_present()/pte_pfn() 最稳。
 */
static bool memx_pte_still_same(struct memx_va_result *v)
{
	if (v->block) {
		pmd_t now = READ_ONCE(*(pmd_t *)v->pte_slot);

		/*
		 * 注意：pmd_pfn() 给的是 2MB 大页的**基址** PFN，
		 * 而 v->pa 是「基址 + 2MB 内偏移」。直接拿 (v->pa >> PAGE_SHIFT)
		 * 去比，只要偏移不为 0 就永远不相等 → 复核判假 → 读取返回 0 字节。
		 * 这就是"读自己栈（4KB PTE）没问题、读游戏内存（2MB 大页）没数据"的原因。
		 * 正确做法：把 v->pa 的 2MB 内偏移抹掉再比。
		 */
		return pmd_sect(now) &&
		       pmd_pfn(now) == (unsigned long)((v->pa & PMD_MASK) >> PAGE_SHIFT);
	}
	{
		pte_t now = READ_ONCE(*(pte_t *)v->pte_slot);

		return pte_present(now) &&
		       pte_pfn(now) == (unsigned long)(v->pa >> PAGE_SHIFT);
	}
}

/* ================================================================== */
/* 3. swap 读取                                                        */
/*                                                                     */
/* 原 .ko 版靠 kallsyms 自举拿 swap_info[] 和 lookup_swap_cache 的地址。 */
/* built-in 后可以直接调用，但要注意：swap_info[] 是 static，永远引用不 */
/* 到 —— 必须走 get_swap_device()（EXPORT_SYMBOL_GPL）。                */
/* ================================================================== */
static bool memx_read_swap_page(swp_entry_t entry, void *dst,
				  unsigned int off, size_t n)
{
	struct page *page;

	/* 先查 swap cache（快路径） */
	{
		struct folio *folio = swap_cache_get_folio(entry, NULL, 0);

		if (!IS_ERR_OR_NULL(folio)) {
			void *kaddr;

			page = folio_page(folio, 0);
			kaddr = kmap_local_page(page);
			memcpy(dst, (char *)kaddr + off, n);
			kunmap_local(kaddr);
			folio_put(folio);
			return true;
		}
	}

	/*
	 * 慢路径：自己发 bio 读块设备（原版的 swap 直读）。
	 *
	 * 注意 swap_info[] 在 mm/swapfile.c 里是 static，任何外部代码都引用不到；
	 * 官方访问器是 get_swap_device()（EXPORT_SYMBOL_GPL），它顺带把 swap
	 * 设备的引用 pin 住，防止读到一半被 swapoff 掉 —— 原版没做这层保护，
	 * 在 swapoff 并发时是会踩空指针的。
	 */
	{
		struct swap_info_struct *si;
		struct bio *bio;
		int ret;

		si = get_swap_device(entry);
		if (!si || swp_type(entry) >= MAX_SWAPFILES)
			return false;
		if (!si->bdev) {
			put_swap_device(si);
			return false;
		}

		page = alloc_page(GFP_NOIO);
		if (!page) {
			put_swap_device(si);
			return false;
		}

		bio = bio_alloc(si->bdev, 1, REQ_OP_READ, GFP_NOIO);
		if (!bio) {
			__free_page(page);
			put_swap_device(si);
			return false;
		}
		bio->bi_iter.bi_sector = (sector_t)swp_offset(entry) * (PAGE_SIZE >> 9);
		__bio_add_page(bio, page, PAGE_SIZE, 0);

		ret = submit_bio_wait(bio);
		bio_put(bio);
		put_swap_device(si);
		if (ret) {
			__free_page(page);
			return false;
		}

		memcpy(dst, page_address(page) + off, n);
		__free_page(page);
	}
	return true;
}

/* ================================================================== */
/* 4. 读：VA -> kbuf                                                   */
/* ================================================================== */
/*
 * 单页 GUP 读取兜底。
 *
 * 直接走页表读不到的情况有两类：
 *   1) 页已换出 —— 走 swap 路径
 *   2) 页**从未被访问过**（PTE 是 none，比如 ART 的 non-moving heap 里还没碰过的页）
 * 第 2 类原版也是直接放弃；这里用 GUP 触发一次缺页把它读进来，
 * 返回内容和 /proc/<pid>/mem 一致（零页），但不会让整次读取失败。
 */
static unsigned long memx_read_gup_page(struct mm_struct *mm, unsigned long va,
					  void *dst, size_t n)
{
	struct page *page = NULL;
	unsigned long page_off = va & ~PAGE_MASK;
	long got;

	if (mmap_read_lock_killable(mm))
		return 0;

	got = pin_user_pages_remote(mm, va, 1, FOLL_FORCE, &page, NULL);
	mmap_read_unlock(mm);

	if (got != 1 || !page)
		return 0;

	{
		void *kaddr = kmap_local_page(page);

		memcpy(dst, (char *)kaddr + page_off, n);
		kunmap_local(kaddr);
	}
	unpin_user_page(page);
	return n;
}

unsigned long memx_read_to_kbuf(struct mm_struct *mm, unsigned long va,
				  void *kbuf, unsigned long len)
{
	unsigned long done = 0;

	while (done < len) {
		unsigned long page_off = (va + done) & ~PAGE_MASK;
		size_t n = min_t(size_t, PAGE_SIZE - page_off, len - done);
		struct memx_va_result v;
		bool ok = false;

		rcu_read_lock();
		if (memx_va_to_pa(mm, va + done, false, &v) &&
		    memx_pte_still_same(&v)) {
			/* 注意：v.pa 里**已经带了页内偏移**（va & ~PAGE_MASK），
			 * 这里不能再加 page_off，否则会读到 pa + 2*offset。 */
			memcpy((char *)kbuf + done,
			       (char *)phys_to_virt(v.pa), n);
			ok = true;
		} else {
			/* 未建立或已换出：取 swap entry */
			pgd_t *pgd = pgd_offset(mm, va + done);
			pud_t *pud;
			pmd_t *pmd;
			pte_t *pte;

			if (pgd_present(*pgd)) {
				pud = pud_offset(p4d_offset(pgd, va + done), va + done);
				if (pud_present(*pud)) {
					pmd = pmd_offset(pud, va + done);
					if (pmd_present(*pmd) && !pmd_leaf(*pmd)) {
						pte = pte_offset_kernel(pmd, va + done);
						if (!pte_present(*pte) && !pte_none(*pte)) {
							swp_entry_t e = pte_to_swp_entry(*pte);

							rcu_read_unlock();
							if (!memx_read_swap_page(e,
								(char *)kbuf + done,
								page_off, n))
								goto out;
							done += n;
							continue;
						}
					}
				}
			}
		}
		rcu_read_unlock();
		if (!ok) {
			/* 页表直读不可用（未缺页 / 特殊页）：GUP 兜底 */
			unsigned long got;

			got = memx_read_gup_page(mm, va + done,
						   (char *)kbuf + done, n);
			if (!got)
				break;
			done += got;
			continue;
		}
		done += n;
	}
out:
	return done;
}

/* ================================================================== */
/* 5. 写                                                              */
/*                                                                     */
/* 安全修复（相对原版）：                                               */
/*   原版 __write_from_kbuf 直接 memcpy 到线性映射，完全不处理 COW。    */
/*   若目标页被 fork 共享（mapcount > 1），改写会同步污染父/子进程。    */
/*   这里默认走 GUP（走正规 COW），只有显式 fast=true 且确认独占才直写。*/
/* ================================================================== */
static unsigned long memx_write_fast(struct mm_struct *mm, unsigned long va,
				       const void *kbuf, unsigned long len)
{
	unsigned long done = 0;

	while (done < len) {
		unsigned long page_off = (va + done) & ~PAGE_MASK;
		size_t n = min_t(size_t, PAGE_SIZE - page_off, len - done);
		struct memx_va_result v;
		struct page *page;

		rcu_read_lock();
		if (!memx_va_to_pa(mm, va + done, true, &v) ||
		    !memx_pte_still_same(&v)) {
			rcu_read_unlock();
			break;
		}

		page = pfn_to_online_page(v.pa >> PAGE_SHIFT);
		if (!page) {
			rcu_read_unlock();
			break;
		}
		if (!PageAnon(page) || page_mapcount(page) != 1) {
			rcu_read_unlock();
			break;
		}
		/* 6.6 没有 page_ref_inc_not_zero()，等价的公开 API 是
		 * get_page_unless_zero()（内部就是 page_ref_add_unless(page,1,0)） */
		if (!get_page_unless_zero(page)) {
			rcu_read_unlock();
			break;
		}

		/* 同上：v.pa 已含页内偏移 */
		memcpy((char *)phys_to_virt(v.pa),
		       (const char *)kbuf + done, n);
		set_page_dirty(page);
		rcu_read_unlock();
		put_page(page);
		done += n;
	}
	return done;
}

static unsigned long memx_write_gup(struct mm_struct *mm, unsigned long va,
				      const void *kbuf, unsigned long len)
{
	unsigned long done = 0;

	while (done < len) {
		unsigned long page_off = (va + done) & ~PAGE_MASK;
		size_t n = min_t(size_t, PAGE_SIZE - page_off, len - done);
		struct page *page = NULL;
		long got;

		if (mmap_read_lock_killable(mm))
			break;

		/* locked 参数传 NULL：mmap 锁由我们自己管，不让 GUP 参与
		 * “是否已持锁”的状态机。之前传 &locked 且初值为 0，
		 * GUP 会以为没持锁、遇到缺页时不去释放，直接死锁。 */
		got = pin_user_pages_remote(mm, va + done, 1,
					    FOLL_WRITE | FOLL_FORCE,
					    &page, NULL);
		mmap_read_unlock(mm);

		if (got != 1 || !page)
			break;

		{
			void *kaddr = kmap_local_page(page);

			memcpy((char *)kaddr + page_off,
			       (const char *)kbuf + done, n);
			kunmap_local(kaddr);
		}
		set_page_dirty_lock(page);
		unpin_user_page(page);
		done += n;
	}
	return done;
}

unsigned long memx_write_to_mm(struct mm_struct *mm, unsigned long va,
				 const void *kbuf, unsigned long len, bool fast)
{
	return fast ? memx_write_fast(mm, va, kbuf, len)
		    : memx_write_gup(mm, va, kbuf, len);
}
