/* CVE-2018-17182
   ref. https://googleprojectzero.blogspot.com/2018/09/a-cache-invalidation-bug-in-linux.html */

/* mm by a process, vmacache per thread
   current->vmcache.seqnum indicates the current version of vmcache
   mm->vmcache_seqnum indicates the global version

   current->vmcache.seqnum != mm->vmcache_seqnum indicates that the vmcache
   contains dangled (i.e., free()) pointers. Is there any path that a
   dangled pointer might be considered valid (i.e., wrapped?)? */

/* find vma of addr in mm */
struct vm_area_struct *vmacache_find(struct mm_struct *mm, unsigned long addr) {
  int idx = VMACACHE_HASH(addr);
  if (!vmacache_valid(mm))
    return NULL;
  for (int i = 0; i < VMACACHE_SIZE; i++) {
    struct vm_area_struct *vma = current->vmacache.vmas[idx];
    if (vma)
      if (vma->vm_start <= addr && vma->vm_end > addr)
        return vma;
    if (++idx == VMACACHE_SIZE)
      idx = 0;
  }
  return NULL;
}

/* Flush vma caches for threads that share a given mm. */
void vmacache_flush_all(struct mm_struct *mm) {
  struct task_struct *g, *p;
  /* Single threaded tasks need not iterate the entire list of
   * process. We can avoid the flushing as well since the mm's seqnum
   * was increased and don't have to worry about other threads'
   * seqnum. Current's flush will occur upon the next lookup. */
  if (atomic_read(&mm->mm_users) == 1)
    return;
  rcu_read_lock();
  for_each_process_thread(g, p) {
    /* Only flush the vmacache pointers as the mm seqnum is already
     * set and curr's will be set upon invalidation when the next
     * lookup is done. */
    if (mm == p->mm)
      vmacache_flush(p);
  }
  rcu_read_unlock();
}

static bool vmacache_valid(struct mm_struct *mm) {
  if (!vmacache_valid_mm(mm))
    return false;
  if (mm->vmacache_seqnum != current->vmacache.seqnum) {
    /* First attempt will always be invalid, initialize the new cache
     * for this task here. */
    current->vmacache.seqnum = mm->vmacache_seqnum;
    vmacache_flush(current);
    return false;
  }
  return true;
}
