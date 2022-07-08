# Studying the KVM MMU with ftrace

The goal here is to get an overview of the KVM memory management internals by analyzing the tracing output of ftrace for the execution of [a minimal KVM example](https://github.com/dpw/kvm-hello-world){:target="_blank"}
(`kvm-hello-world`), on an Intel architecture, running Linux 5.18.4. Our analysis focuses on the KVM MMU with support for two dimensional paging (TDP), also known as Second-Level Address Translation (SLAT). On Intel architecture this technology is called Extended Page Tables (EPT):

> The extended page-table mechanism (EPT) is a feature that can be used to support the virtualization of physical
memory. When EPT is in use, certain addresses that would normally be treated as physical addresses (and used to
access memory) are instead treated as guest-physical addresses. Guest-physical addresses are translated by
traversing a set of EPT paging structures to produce physical addresses that are used to access memory.  "Intel SDM Chapter 28, Section 28.2 of Volume 3C"

> EPT is used when the “enable EPT” VM-execution control is 1. It translates the guest-physical addresses used in
VMX non-root operation and those used by VM entry for event injection. The translation from guest-physical addresses to physical addresses is determined by a set of EPT paging structures. The EPT paging structures are similar to those used to translate linear addresses while the processor is in IA-32e mode. "Intel SDM Chapter 28, Section 28.2.1 of Volume 3C" 

In this mode, KVM lets the guest control CR3 and programs the EPT paging structures with the GPA -> HPA mapping. To construct such mapping, KVM uses the set of memory slots (KVM's memslots) that are setup via the `KVM_SET_USER_MEMORY_REGION` ioctl(), which maps GPA to HVA. 

Since Linux 5.10, the KVM x86 MMU brings [some improvements to the TDP direct case](https://lwn.net/Articles/832835/){:target="_blank"}. This new implementation is referred to as the TDP MMU and is the [default](https://lore.kernel.org/all/20210726163106.1433600-1-pbonzini@redhat.com/T/){:target="_blank"} one since Linux 5.15. Up to this moment (Linux 5.18) both implementations coexist and they can be controlled by the module parameter `tdp_mmu`. For more info on the improvements of the TDP MMU, see [this](https://kvmforum2019.sched.com/event/Tn1S/improving-mmu-scalability-in-x86-kvm-ben-gardon-google){:target="_blank"} talk by one of the authors Ben Gardon.

We run `kvm-hello-world` with the `-l` option, which will set up and run the VM in x86 long mode:

    rafael@macondo:~/repo/kvm-hello-world$ ./kvm-hello-world -l
    Testing 64-bit mode
    Hello, world!
    
We set the ftrace filter to trace the functions belonging to the `kvm` and `kvm_intel` modules and use the `function_graph` tracer.  The full ftrace output for the execution of `kvm-hello-world` is [here](./trace-kvm-hello-world-l.txt){:target="_blank"}. It will be the base for our study.
    
The analysis is done is two in two parts: In Section 1 we see how KVM gets the user space memory information through the `KVM_SET_USER_MEMORY_REGION` ioctl() and stores it as KVM's memslots, and in Section 2 we see how the KMV MMU uses the memslots, among other information, to program the EPT paging structures with the GPA -> HPA mapping.

We use the following acronyms to distinguish memory:
 - GVA - guest virtual address
 - GPA - guest physical address
 - HVA - host virtual address
 - HPA - host physical address

## 1. Create memory region

The "physical" address space, as seen from the guest, is passed to KVM via the `KVM_SET_USER_MEMORY_REGION` ioctl(). Below are the parts of the code where this takes place in `kvm-hello-world`:

    void vm_init(struct vm *vm, size_t mem_size)
    {
        struct kvm_userspace_memory_region memreg;
        ...
        vm->mem = mmap(NULL, mem_size, PROT_READ | PROT_WRITE,
                   MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE, -1, 0);
        ...
        memreg.slot = 0;
        memreg.flags = 0;
        memreg.guest_phys_addr = 0;
        memreg.memory_size = mem_size;
        memreg.userspace_addr = (unsigned long)vm->mem;
        ...
        ioctl(vm->fd, KVM_SET_USER_MEMORY_REGION, &memreg)
        ...
    }

The `KVM_SET_USER_MEMORY_REGION` ioctl()  takes the struct `kvm_userspace_memory_region` as parameter:

    // kvm.h
    struct kvm_userspace_memory_region {
        __u32 slot;
        __u32 flags;
        __u64 guest_phys_addr;
        __u64 memory_size; /* bytes */
        __u64 userspace_addr; /* start of the userspace allocated memory */
    };
   
`guest_phys_addr` specifies the base "physical" address as seen from the guest, and `userspace_addr` points to the backing memory in `kvm-hello-world` that was allocated with `mmap()`. 
KVM keeps track of the guest physical memory using what is called **memory slots**. If we look at the `struct kvm` (`kvm_host.`h) we see the fields `__memslots` and `*memslots`.

    // kvm_host.h
    struct kvm {
          ...
          struct mm_struct *mm; /* userspace tied to this vm */                                                                                                                  
          unsigned long nr_memslot_pages;                                                                                                                                        
          /* The two memslot sets - active and inactive (per address space) */                                                                                                   
          struct kvm_memslots __memslots[KVM_ADDRESS_SPACE_NUM][2];                                                                                                              
          /* The current active memslot set for each address space */                                                                                                            
          struct kvm_memslots __rcu *memslots[KVM_ADDRESS_SPACE_NUM];
          ...
    }
    
KVM keeps two memory slot sets: one active and one inactive. The current active memslot is pointed by `*memslots`. These are necessary so the VM continues to run on one memslot set while the other is being modified. These two memslot sets normally point to the same set of memslots. They can, however, be desynchronized when performing a memslot management operation by replacing the memslot to be modified by its copy. After the operation is complete, both memslot sets once again point to the same, common set of memslot data. For more information [see](https://lwn.net/Articles/856392/){:target="_blank"}.

Additionally, the memory slots are stored in two ways: as a [red-black tree](https://patchwork.kernel.org/project/kvm/patch/20211104002531.1176691-27-seanjc@google.com/){:target="_blank"}, and also as an [interval tree](https://patchwork.kernel.org/project/kvm/patch/20211104002531.1176691-25-seanjc@google.com/){:target="_blank"}:

     // kvm_host.h
     struct kvm_memslots {
           ...
           struct rb_root_cached hva_tree;
           struct rb_root gfn_tree;
           ...
    } 
    
The reason for this is explained [in](https://lwn.net/Articles/856392/){:target="_blank"}:
> The implementation uses two trees to perform quick lookups:
> - For tracking of gfn an ordinary rbtree is used since memslots cannot overlap in the guest address space and so this data structure is sufficient for ensuring that lookups are done quickly.
> - For tracking of hva, however, an interval tree is needed since they can overlap between memslots.

Finally, the memory slot itself looks like this:

    // kvm_host.h
    struct kvm_memory_slot {
        ...
        struct interval_tree_node hva_node[2];
        struct rb_node gfn_node[2];
        gfn_t base_gfn;
        ...
        unsigned long userspace_addr
        ...
    }

### Code analysis:

Now let's see what KVM does when we call the `KVM_SET_USER_MEMORY_REGION` ioctl(). The analysis of this part is based on lines 68 to 88 of the ftrace output. The main functions called in this part of the trace are placed below. I also listed some functions that were not available to ftrace (e.g., inline functions).

    - kvm_vm_ioctl [kvm_main.c]
        - kvm_vm_ioctl_set_memory_region [kvm_main.c]
            - kvm_set_memory_region [kvm_main.c]
                - __kvm_set_memory_region [kvm_main.c]
                    - struct kvm_memory_slot *new;
                    - ...
                    - new = kzalloc(sizeof(*new), GFP_KERNEL_ACCOUNT);
                    - ...
                    - kvm_set_memslot [kvm_main.c]
                        - kvm_create_memslot [kvm_main.c]
                            - kvm_replace_memslot [kvm_main.c]
                                - interval_tree_insert [interval_tree.h]
                                - kvm_insert_gfn_node [kvm_main.c]
                                    - rb_link_node [rbtree.c]
                                    - rb_insert_color [rbtree.c]
                            - kvm_activate_memslot [kvm_main.c]
                                - kvm_swap_active_memslots [kvm_main.c]
                        - kvm_commit_memory_region [kvm_main.c]
                            - kvm_arch_commit_memory_region [x86.c]

The first part of the code (until `kvm_set_memslot()`) allocates the new memory slot `new` and populate the struct with the data from the `struct kvm_userspace_memory_region`. Below are some highlights of the `__kvm_set_memory_region()` to get some intuition of what is implemented:

    __kvm_set_memory_region [kvm_main.c]
        ...
        struct kvm_memory_slot *new;
        ...
        base_gfn = (mem->guest_phys_addr >> PAGE_SHIFT)
        ...
        new = kzalloc(sizeof(*new), GFP_KERNEL_ACCOUNT);
        ...
        new->as_id = as_id;
        new->id = id;
        new->base_gfn = base_gfn;
        new->npages = npages;
        new->flags = mem->flags;
        new->userspace_addr = mem->userspace_addr;
        ...
        kvm_set_memslot(kvm, old, new, change); 

In the end, there is a call to `kvm_set_memslot`, which adds the new memory slot to the inactive set and activate. The new memory slot is added to the inactive set (rbtree and the interval tree) using the `kvm_replace_memslot` function:

    kvm_replace_memslot [kvm_main.c]
        ...
        new->hva_node[idx].start = new->userspace_addr
        new->hva_node[idx].last = new->userspace_addr + (new->npages << PAGE_SHIFT) - 1;
        ...
        interval_tree_insert(&new->hva_node[idx], &slots->hva_tree);
        ...
        kvm_insert_gfn_node(slots, new)

The insertion in the red-black tree is done by another function called `kvm_insert_gfn_node`:

    kvm_insert_gfn_node [kvm_main.c]
        ...
        rb_link_node(&slot->gfn_node[idx], parent, node);
        rb_insert_color(&slot->gfn_node[idx], gfn_tree);

Even though a pointer to `hva_node` and `gfn_node` is inserted, it is possible to retrieve the slot using the function `container_of` as such:

    slot = container_of(node, struct kvm_memory_slot, hva_node[slots->node_idx]);
    slot = container_of(node, struct kvm_memory_slot, gfn_node[idx]);

## 2. Handle EPT violation

After `kvm-hello-world` issues the first `KVM_RUN` ioctl(), the processor enters VMX non-root operation and starts the execution of the guest code with RIP = 0x0000. In the trace, we see that in the first execution of `KVM_RUN` ioctl() there were 4 VM exits caused by EPT violation and 1 caused by IO (`outb` of char "H') (ftrace output lines 537-1143), then for each execution of the next 13 executions of `KVM_RUN` ioctl() there was at least one VM-exit caused by IO (one exit for each of the 13-length string "ello, world!\n") (ftrace output lines 1146-2465), and the last `KVM_RUN` had a VM-exit caused by the `halt` instruction (ftrace output lines 2466-2552). Since our focus here is on memory virtualization, we only examine the first 4 VM exits, that were caused by EPT violations.

One of the situations in which an **EPT violation** occurs is when a translation of the guest-physical address encounters an EPT paging-structure entry that is not present. An EPT violation causes a VM exit. In exit qualification phase, KVM determines that it is an EPT page-fault and it will read the page faulting GPA (guest physical address) from the VMCS exit information fields. Given the GPA, KVM finds the corresponding KVM memory slot, which will hold sufficient information to get the HVA needed to fault-in the page and then install the page tables.

Why do we see 4 EPT violations? To answer that let's take a look of how `kvm-hello-world` (in long mode) set up the guest page table:  

    static void setup_long_mode(struct vm *vm, struct kvm_sregs *sregs)
    {
        uint64_t pml4_addr = 0x2000;
        uint64_t *pml4 = (void *)(vm->mem + pml4_addr);
        
        uint64_t pdpt_addr = 0x3000;
        uint64_t *pdpt = (void *)(vm->mem + pdpt_addr);
        
        uint64_t pd_addr = 0x4000;
        uint64_t *pd = (void *)(vm->mem + pd_addr);
        
        pml4[0] = PDE64_PRESENT | PDE64_RW | PDE64_USER | pdpt_addr;
        pdpt[0] = PDE64_PRESENT | PDE64_RW | PDE64_USER | pd_addr;
        pd[0] = PDE64_PRESENT | PDE64_RW | PDE64_USER | PDE64_PS;
        
        sregs->cr3 = pml4_addr;
        ...
    }

When the guest touches the GVA 0x0000 for the first time, the processor (in VMX non-root) performs paging by traversing a 4-level hierarchy of paging structures whose root structure resides at the physical address in CR3 of the guest. However, when EPT is in use, the addresses in the guest page table are also treated as guest-physical address, and are not used to access memory directly, Instead, those addresses in the guest page tables are also translated using EPT. This is what happens in more detail:

1. Guest starts with the RIP=0x0000 (GVA) in VMX non-root operation
2. Guest needs to translate the GVA and uses CR3 to locate the first paging-structure in the hierarchy (PML4), which is located at the guest-physical address (GPA) 0x2000. Since the EPT cannot translate this GPA, it causes an EPT violation.
3. KVM set up the EPT page hierarchy to translate GPA 0x2000 -> some HPA
4. EPT is now able to get the HPA of 0x2000 and load its value, which will hold the still unmapped GPA 0x3000 (PDPT).  EPT violation.
5. KVM set up the EPT page hierarchy to translate GPA 0x3000 -> some HPA
6.  EPT is now able to get the HPA of 0x3000 and load its value, which will hold the GPA 0x4000  (PD).  EPT violation.
7. KVM set up the EPT page hierarchy to translate GPA 0x4000 -> some HPA
8.  EPT is now able to get the HPA of 0x4000 and load its value, which will hold the GPA 0x0000.  EPT violation.
9. KVM set up the EPT page hierarchy to translate GPA 0x0000 -> some HPA
10. Guest is now able to fetch the instruction from the current RIP - the MMU hardware in non-root mode can now page walk its entire hierarchy to get the GVA->GPA translation, and EPT can also get the GPA->HPA translation.

Now let's look of how KVM handles an EPT violation. We split our analysis into two parts: Section 2.1 shows how KVM finds the corresponding KVM memory slot of a given guest frame number, which will hold sufficient information to get the HVA needed to fault-in the page, and in Section 2.2 we show how KVM installs the EPT page tables. In the same way as was done in the previous section, the main functions called in this part of the trace are placed below (left brackets indicates which part of the snippet is analyzed in each section) :

           - vmx_handle_exit  [vmx.c]
              - __vmx_handle_exit [vmx.c]
                - handle_ept_violation [vmx.c]
                  - gpa = vmcs_read64(GUEST_PHYSICAL_ADDRESS);
                  - kvm_mmu_page_fault(..., gpa, ...) [mmu.c]
                    - kvm_mmu_do_page_fault [mmu.h]
                      - kvm_tdp_page_fault [mmu.c]
                  _     - direct_page_fault [mmu.c]
                 |        - fault->gfn = fault->addr >> PAGE_SHIFT
                 |        - fault->slot = kvm_vcpu_gfn_to_memslot
                 |        - fast_page_fault [mmu.c]
                 |        - kvm_faultin_pfn [mmu.c]
        Sec 2.1 -|          - fault->pfn = __gfn_to_pfn_memslot [kvm_main.c]
                 |            - __gfn_to_hva_many
                 |            - hva_to_pfn [kvm_main.c]
                 |              - hva_to_pfn_fast [kvm_main.c]
                 |                - get_user_page_fast_only [mm.h]
                 |              - hva_to_pfn_slow [kvm_main.c]
                 |_               - get_user_pages_unlocked [mm.h]
                  _       - kvm_tdp_mmu_map [tdp_mmu.c]
                 |          - tdp_mmu_for_each_pte
                 |            - tdp_mmu_alloc_sp [tdp_mmu.c]
                 |            - tdp_mmu_init_child_sp [tdp_mmu.c]
                 |              - tdp_mmu_init_sp [tdp_mmu.c]
                 |            - tdp_mmu_link_sp [tdp_mmu.c]
        Sec 2.2 -|              - u64 spte = make_nonleaf_spte [spte.c]
                 |              - tdp_mmu_set_spte_atomic(..., spte) [tdp_mmu.c]
                 |          - tdp_mmu_map_handle_target_level [tdp_mmu.c]
                 |            - make_spte(..., fault->pfn, ..., &new_spte) [spte.c]
                 |_           - tdp_mmu_set_spte_atomic(..., new_spte) [tdp_mmu.c]
                          - kvm_release_pfn_clean(fault->pfn) [kvm_main.c]

### 2.1 Code analysis: Fault-in path

#### GFN to KVM Memory Slot

From the above we see that the slot is returned by the function `kvm_vcpu_gfn_to_memslot`, which will simply search the memory slot in the rbtree and return it:

    - kvm_vcpu_gfn_to_memslot [kvm_main.c]
        - kvm_memslots *slots = kvm_vcpu_memslots(vcpu)  [kvm_main.c]
        - ...
        - search_memslots [kvm_host.h]
            // Search node in rbtree (use container_of to retrieve slot)
            
#### GFN -> HVA
            
Then we get the host address from the memory slot:

    - __gfn_to_hva_many
        - __gfn_to_hva_memslot
            - offset = gfn - slot->base_gfn
            - offset = array_index_nospec(offset, slot->npages);
            - return slot->userspace_addr + offset * PAGE_SIZE
        
#### HVA -> PFN

Finally, KVM uses the `get_user_pages*()` family to fault in the guest page. This maps the user memory (registered using the `KVM_SET_USER_MEMORY_REGION`  ioctl()) into kernel space and returns the physical page frame number (PFN) to be installed into the EPT page tables.

    - hva_to_pfn [kvm_main.c]
        - hva_to_pfn_fast [kvm_main.c]
            - get_user_page_fast_only [mm.h]

### 2.2 Code analysis: Creation of page tables and SPTEs

After the page has been faulted in, now we look at how KVM programs EPT page tables to create a relation between guest physical address to host physical address (GPA -> HPA). If you are familiar with paging on Intel x86-64 you will find it very similar. As stated before, when EPT is active the addresses used and produced by the guest are not used as physical addresses to reference in memory. Instead, the processor interprets them as guest physical addresses and translates them to physical addresses. The translation mechanism works by traversing a 4-level hierarchy of paging structures (PML4Es, then PDPTEs, then PDEs, and finally, PEs) whose root structure resides at the physical address in the EPT pointer (EPTP) in the VMCS. Each paging structure is 4-KBytes in size and comprises 512 64-bit entries.

KVM abstracts each EPT page table with a generic concept called SPT (Shadow Page Table). Each entry in the SPT is called SPTE (Shadow Page Table Entry). Why this name? My intuition is that since the SPTE format is [common to both the shadow MMU and the TDP MMU](https://patchwork.kernel.org/project/kvm/patch/20201023163024.2765558-5-pbonzini@redhat.com/){:target="_blank"} (e.g., AMD's NPT and Intel's EPT), it's a generic and vendor-neutral term. In summary, in KVM terminology, the page structure of the EPT is a SPT, and each entry in the page structure is the SPTE.

Additionally, in KVM terminology, a page table entry at the middle level is called a **nonleaf  SPTE**, and the entry pointing to a physical page at the lowest level is called a **leaf SPTE** (leaf page table entry).

> A nonleaf spte allows the hardware mmu to reach the leaf pages and is not related to a translation directly.  It points to other shadow pages. [https://www.kernel.org/doc/Documentation/virtual/kvm/mmu.txt](https://www.kernel.org/doc/Documentation/virtual/kvm/mmu.txt)

The pointer to each SPT is stored in the data structure `struct kvm_mmu_page`, which is referred to as a shadow page:

    // mmu_internal.h
    struct kvm_mmu_page {
        ...
        gfn_t gfn;
        union kvm_mmu_page_role role;
        u64 *spt;
        ...
    }

The core member is the `spt`, which points to the base address of a physical page and stores 512 page table entries (SPTEs). As shown above, this structure also stores other information besides `spt`, that are not directly used by the EPT mechanism, but that are import to the KVM, such as the role of page structure in the EPT page hierarchy.

The diagram below gives an overview of the main data structures examined in this section. The blue part corresponds to what Intel's EPT hardware mechanism sees.

![](./ept_data_struct.svg)

All the mapping we discussed above is handled by function `kvm_tdp_mmu_map` (`tdp_mmu.c`). The function header comment of this function states: "Handle a TDP page fault (NPT/EPT violation/misconfiguration) by installing page tables and SPTEs to translate the faulting guest physical address". The function iterates the EPT paging struct and from each level it: allocates memory for the shadow page and the SPT, initializes them and links the parent level SPTE to point to the current level SPTE:

    - kvm_tdp_mmu_map [tdp_mmu.c]
     - tdp_mmu_for_each_pte
       - tdp_mmu_alloc_sp
       - tdp_mmu_init_child_sp
       - tdp_mmu_link_sp
     - tdp_mmu_map_handle_target_level

We now examine the code each of these 3 steps separately:

#### Shadow page and SPTEs allocation (`tdp_mmu_alloc_sp`)

    - struct kvm_mmu_page *sp;
    - ...
    - sp = tdp_mmu_alloc_sp
        - sp = kvm_mmu_memory_cache_alloc(&vcpu->arch.mmu_page_header_cache)
        - sp->spt = kvm_mmu_memory_cache_alloc(&vcpu->arch.mmu_shadow_page_cache)

The difference between these two allocations is as follows:
- `mmu_page_header_cache`: it allocates the shadow page of size `sizeof(struct kvm_mmu_page)` and uses a slab allocator for it
- `mmu_shadow_page_cache`: it allocates a page table holding the 512 page table entries (SPTEs) and uses a page allocator

Both `mmu_page_header_cache` and `mmu_shadow_page_cache` are of type struct `kvm_mmu_memory_cache`, which has a pointer, named `kmem_cache`, to (guess what) a `kmem_cache` struct. If `kmem_cache` is set, then it will use a SLAB allocator, otherwise, it will get a page allocator:

        void *kvm_mmu_memory_cache_alloc(struct kvm_mmu_memory_cache *mc)
        {
                void *p;
        
                if (WARN_ON(!mc->nobjs))
                        p = mmu_memory_cache_alloc_obj(mc, GFP_ATOMIC | __GFP_ACCOUNT);
                else
                        p = mc->objects[--mc->nobjs];
                BUG_ON(!p);
                return p;
        }
        ...
        static inline void *mmu_memory_cache_alloc_obj(struct kvm_mmu_memory_cache *mc,
                                                       gfp_t gfp_flags)
        {                                      
                gfp_flags |= mc->gfp_zero;

                if (mc->kmem_cache)                                     
                        return kmem_cache_alloc(mc->kmem_cache, gfp_flags);
                else                       
                        return (void *)__get_free_page(gfp_flags);
        }
        
##### Extra: Creation of the shadow page cache

The `mmu_page_header_cache` cache is created in the module initialization, which is not shown in the ftrace output I posted in here:

    - vmx_init [vmx.c] // module_init(vmx_init)
        - kvm_init [kvm_main.c]
            - kvm_arch_init [x86.c]
                - kvm_mmu_vendor_module_init [mmu.c]
                    - mmu_page_header_cache = kmem_cache_create("kvm_mmu_page_header", sizeof(struct kvm_mmu_page),0, SLAB_ACCOUNT, NULL);

and it is set to the VMM in: 

    - kvm_vm_ioctl_create_vcpu [kvm_main.c]  
        - kvm_arch_vcpu_create [x86.c]
            - kvm_mmu_create [mmu.c]
                - vcpu->arch.mmu_page_header_cache.kmem_cache = mmu_page_header_cache;

#### Shadow page initialization (`tdp_mmu_init_child_sp`)

Fill in the shadow page fields such as the role - the level of the page structure in the EPT page hierarchy:

    - tdp_mmu_init_child_sp [tdp_mmu.c]
        - parent_sp = sptep_to_sp(rcu_dereference(iter->sptep));
        - role = parent_sp->role;
        - role.level--;
        - tdp_mmu_init_sp [tdp_mmu.c]
            - sp->role = role;
            - sp->gfn = gfn;
            - sp->ptep = sptep;
            - sp->tdp_mmu_page = true;

#### Nonleaf SPTEs mapping (`tdp_mmu_link_sp`)

Replace the corresponding SPTE in the previous page table entry (level - 1):

    - tdp_mmu_link_sp [tdp_mmu.c]
        - u64 spte = make_nonleaf_spte(sp->spt, !shadow_accessed_mask) [spte.c]
            - return __pa(child_pt)
        - tdp_mmu_set_spte_atomic(kvm, iter, spte) [tdp_mmu.c]
        - list_add(&sp->link, &kvm->arch.tdp_mmu_pages)

Using Intel's EPT, the `make_nonleaf_spte()` function will return an entry in the expected format of an EPT entry (PML4E, PDPTE, or PDE). It uses the masks set by the `kvm_mmu_set_ept_masks` function:

    u64 make_nonleaf_spte(u64 *child_pt, bool ad_disabled)
    {
            u64 spte = SPTE_MMU_PRESENT_MASK;
    
            spte |= __pa(child_pt) | shadow_present_mask | PT_WRITABLE_MASK |
                    shadow_user_mask | shadow_x_mask | shadow_me_mask;
    
            if (ad_disabled)
                    spte |= SPTE_TDP_AD_DISABLED_MASK;
            else
                    spte |= shadow_accessed_mask;
    
            return spte;
    }

`kvm_mmu_set_ept_masks` gets called in the module initialization, which is not shown in the ftrace output I posted in here. The execution path looks something like this:

    - vmx_init [vmx.c] // module_init(vmx_init)
        - kvm_init [kvm_main.c]
          - kvm_arch_hardware_setup [x86.c]
            - hardware_setup [vmx.c]
                - kvm_mmu_set_ept_masks [spte.c]

#### The leaf SPTE mapping (`tdp_mmu_map_handle_target_level`)

Above we describe the process of filling non-leaf page table entries. The leaf SPTE (leaf page table entry, the one finally holding an entry pointing to a physical page) is set up in `tdp_mmu_map_handle_target_level()`:

    - tdp_mmu_map_handle_target_level
      - u64 new_spte
      - ...
      - make_spte(..., fault->pfn, ..., &new_spte) [spte.c]
      - ...
      - tdp_mmu_set_spte_atomic(..., new_spte)

Function `make_spte()` works in a similar way to the `make_nonleaf_spte()`: it will use some masks set by `kvm_mmu_set_ept_masks()` to set up a valid EPT page entry.

#### What about the root page table?

The root page (the PML4 table on Intel's EPT) gets created and initialized in `kvm_mmu_load()` function, which will also set the EPT pointer to it. It will also use the `tdp_mmu_alloc_sp()` and `tdp_mmu_init_sp()` that we discussed above. The execution path looks something like this:

    - kvm_mmu_load [mmu.c]
        - mmu_alloc_direct_roots [mmu.c]
            - root = kvm_tdp_mmu_get_vcpu_root_hpa(vcpu) [tdp_mmu.c]
                - root = tdp_mmu_alloc_sp(vcpu);
                - tdp_mmu_init_sp(root, NULL, 0, role);
                - return __pa(root->spt)
            - mmu->root.hpa = root;
        - kvm_mmu_load_pgd [mmu.h]
            - u64 root_hpa = vcpu->arch.mmu->root.hpa;
            - vmx_load_mmu_pgd(..., root_hpa, ...) [vmx.c]
                - construct_eptp(..., root_hpa, ...) [vmx.c]
                - vmcs_write64(EPT_POINTER, eptp)

#### Summary

Figure below summarizes the main steps examined is this section:
![](./ept_construction.svg)

//TODO: release the reference to the struct page - kvm_release_pfn_clean

//TODO: MMU notifiers

# References

- E. Bugnion, J. Nieh, and D. Tsafrir. 2017. Hardware and Software Support for Virtualization. Morgan 8 Claypool.

- Intel® 64 and IA-32 Architectures Software Developer’s Manual Volume 3C: System Programming Guide, Part 3;

- The x86 kvm shadow mmu. [https://www.kernel.org/doc/Documentation/virtual/kvm/mmu.txt](https://www.kernel.org/doc/Documentation/virtual/kvm/mmu.txt)

- Extending KVM with new Intel ® Virtualization technology. [https://www.linux-kvm.org/images/c/c7/KvmForum2008%24kdf2008_11.pdf](https://www.linux-kvm.org/images/c/c7/KvmForum2008%24kdf2008_11.pdf)

- MMU Virtualization Via Intel EPT: Technical Details. [https://revers.engineering/mmu-ept-technical-details/](https://revers.engineering/mmu-ept-technical-details/)

- KVM QEMU analysis of Linux Virtualization (V) memory virtualization. [https://javamana.com/2020/11/20201108000000058p.html](https://javamana.com/2020/11/20201108000000058p.html)

- Nested paging hardware and software. [http://www.linux-kvm.org/images/c/c8/KvmForum2008%24kdf2008_21.pdf](http://www.linux-kvm.org/images/c/c8/KvmForum2008%24kdf2008_21.pdf)

- 5-Level Paging and 5-Level EPT. [https://mobt3ath.com/uplode/books/book-51381.pdf](https://mobt3ath.com/uplode/books/book-51381.pdf)

- Patch: KVM: Scalable memslots implementation. [https://patchwork.kernel.org/project/kvm/cover/20211104002531.1176691-1-seanjc@google.com/](https://patchwork.kernel.org/project/kvm/cover/20211104002531.1176691-1-seanjc@google.com/)

- [https://blog.csdn.net/yiyeguzhou100/article/details/123884369](https://blog.csdn.net/yiyeguzhou100/article/details/123884369) (Chinese)

- [https://blog.csdn.net/huang987246510/article/details/105645656](https://blog.csdn.net/huang987246510/article/details/105645656) (Chinese)

- [http://ningfxkvm.blogspot.com/2015/11/kvmmmupage.html](http://ningfxkvm.blogspot.com/2015/11/kvmmmupage.html) (Chinese)

# Contributing

I'm new to the area of virtualization and I'm studying the subject as a way to contribute to some open source project in the area. I would be very grateful if you [suggest](mailto:rafaelmendsr@gmail.com) enhancements, send [pull requests](https://github.com/rafaelmsoares/rafaelmsoares.github.io/pulls){:target="_blank"} or create [an issue](https://github.com/rafaelmsoares/rafaelmsoares.github.io/issues){:target="_blank"}.
