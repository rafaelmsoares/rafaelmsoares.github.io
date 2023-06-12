#  Open Source contributions

## Linux Kernel
### Signed-off-by (29):
* [virtio_blk: Fix signedness bug in virtblk_prep_rq()](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=a26116c1e74028914f281851488546c91cbae57d)
* [tracing/eprobe: Fix warning in filter creation](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=342a4a2f99431ee3c72ef5cfff6449ccf2abd346)
* [tracing/eprobe: Fix memory leak of filter string](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=d1776c0202aac8251e6b4cbe096ad2950ed6c506)
* [perf/x86: Remove unused variable 'cpu_type'](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=8e356858be2989355aafcc96af541fedf9fb486f)
* [uio: uio_dmem_genirq: Use non-atomic bit operations in irq config and handling](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=a3fc57bc49a24960fd6a907457f9360a3e65b968)
* [uio: uio_dmem_genirq: Fix deadlock between irq config and handling](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=118b918018175d9fcd8db667f905012e986cc2c9)
* [uio: uio_dmem_genirq: Fix missing unlock in irq configuration](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=9de255c461d1b3f0242b3ad1450c3323a3e00b34)
* [vfio: platform: Do not pass return buffer to ACPI _RST method](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=e67e070632a665c932d534b8b800477bb3111449)
* [x86/kvm: Remove unused virt to phys translation in kvm_guest_cpu_init()](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=00009406f0dbc53b95b9062c0cc297d6893ff394)
* [KVM: s390: pci: Fix allocation size of aift kzdev elements](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=b6662e37772715447aeff2538444ff291e02ea31)
* [fprobe: Check rethook_alloc() return in rethook initialization](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=d05ea35e7eea14d32f29fd688d3daeb9089de1a5)
* [virt/sev-guest: Remove unnecessary free in init_crypto()](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=c6fbb759d68898aad40e57d09ed18df6094a1874)
* [media: i2c: ov5648: Free V4L2 fwnode data on unbind](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=c95770e4fc172696dcb1450893cda7d6324d96fc)
* [media: i2c: hi846: Fix memory leak in hi846_parse_dt()](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=80113026d415e27483669db7a88b548d1ec3d3d1)
* [drm/amdkfd: Fix memory leak in kfd_mem_dmamap_userptr()](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=90bfee142af0f0e9d3bec80e7acd5f49b230acf7)
* [drm/amdkfd: Fix memory leak in kfd_mem_dmamap_userptr()](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=7b5a4d7b9e2952a15c8d2b2391dfacd7ce841a1a)
* [io-wq: Fix memory leak in worker creation](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=996d3efeb091c503afd3ee6b5e20eabf446fd955)
* [drm/amdgpu/powerplay/psm: Fix memory leak in power state init](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=8f8033d5663b18e6efb33feb61f2287a04605ab5)
* [scsi: lpfc: Fix memory leak in lpfc_create_port()](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=dc8e483f684a24cc06e1d5fa958b54db58855093)
* [scsi: qla2xxx: Fix serialization of DCBX TLV data request](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=3ddeabd1536a71abf2b66a577c90df84514a0af2)
* [wifi: mac80211: mlme: Fix double unlock on assoc success handling](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=6546646a7fb0d7fe1caef947889497c16aaecc8c)
* [wifi: mac80211: mlme: Fix missing unlock on beacon RX](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=883b8dc1a8766464d5bde4d97e1d7c795d990d31)
* [cxgb4: fix missing unlock on ETHOFLD desc collect fail path](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=c635ebe8d911a93bd849a9419b01a58783de76f1)
* [ACPI: PCC: Release resources on address space setup failure path](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=f890157e61b85ce8ae01a41ffa375e3b99853698)
* [xhci: dbc: Fix memory leak in xhci_alloc_dbc()](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=d591b32e519603524a35b172156db71df9116902)
* [drm/vmwgfx: Fix memory leak in vmw_mksstat_add_ioctl()](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=a40c7f61d12fbd1e785e59140b9efd57127c0c33)
* [scsi: qla2xxx: Fix memory leak in __qlt_24xx_handle_abts()](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=601be20fc6a1b762044d2398befffd6bf236cebf)
* [drm/amdgpu: Fix memory leak in hpd_rx_irq_create_workqueue()](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=7136f956c73c4ba50bfeb61653dfd6a9669ea915)
* [block: Do not call blk_put_queue() if gendisk allocation fails](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=aa0c680c3aa96a5f9f160d90dd95402ad578e2b0)

### Reported-by (3):
* [tracing/probes: Handle system names with hyphens](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=575b76cb885532aae13a9d979fd476bb2b156cb9)
* [tracing: Fix race where eprobes can be called before the event](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=94eedf3dded5fb472ce97bfaf3ac1c6c29c35d26)
* [tracing/eprobe: Fix eprobe filter to make a filter correctly](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=40adaf51cb318131073d1ba8233d473cc105ecbf)

## Cloud Hypervisor
### Signed-off-by (3):
* [docs: Fix broken link to macvtap doc in custom-image.md](https://github.com/cloud-hypervisor/cloud-hypervisor/pull/5481)
* [Fix error propagation if starting the VM fails](https://github.com/cloud-hypervisor/cloud-hypervisor/pull/5453)
* [misc: Remove unnecessary clippy directives](https://github.com/cloud-hypervisor/cloud-hypervisor/pull/5379)

### Reported-by (1):
* [VM hangs when stressing CPU hotplug](https://github.com/cloud-hypervisor/cloud-hypervisor/issues/5419)
