
#include "pci.h"
#include "exec-memory.h"

#include <libpscnv.h>
#include <xf86drm.h>
#include <sys/mman.h>

#define PAGE_SHIFT 12
#define PAGE_SIZE (1 << PAGE_SHIFT)
#define PAGE_MASK (PAGE_SIZE - 1)

#define PSCNV_DEBUG_IO

#define PSCNV_VIRT_MMIO_SIZE 0x1000
#define PSCNV_CALL_SLOT_SIZE 0x100
#define PSCNV_CALL_SLOT_COUNT 32
#define PSCNV_CALL_AREA_SIZE (PSCNV_CALL_SLOT_COUNT * PSCNV_CALL_SLOT_SIZE)
#define PSCNV_VIRT_VRAM_SIZE 0x10000000
#define VRAM_PAGE_COUNT (PSCNV_VIRT_VRAM_SIZE >> PAGE_SHIFT)

#define PSCNV_VIRT_CHAN_COUNT 128

#define EXECUTE_CALL_REG 0x0
#define PTIMER_TIME_REG 0x4
#define GPU_INFO_REG_BASE 0x8

#define PSCNV_INFO_PCI_VENDOR   0
#define PSCNV_INFO_PCI_DEVICE   1
#define PSCNV_INFO_BUS_TYPE     2
#define PSCNV_INFO_CHIPSET_ID   3
#define PSCNV_INFO_GRAPH_UNITS  4
#define PSCNV_INFO_GPC_COUNT    5
#define PSCNV_INFO_TP_COUNT_IDX 6
#define PSCNV_INFO_MP_COUNT     7
#define PSCNV_INFO_COUNT        8

#define PSCNV_CMD_GET_PARAM 1
#define PSCNV_CMD_MEM_ALLOC 2
#define PSCNV_CMD_MAP 3
#define PSCNV_CMD_MEM_FREE 4
#define PSCNV_CMD_VSPACE_ALLOC 5
#define PSCNV_CMD_VSPACE_FREE 6
#define PSCNV_CMD_CHAN_NEW 7
#define PSCNV_CMD_CHAN_FREE 8
#define PSCNV_CMD_VSPACE_MAP 9
#define PSCNV_CMD_VSPACE_UNMAP 10

#define PSCNV_RESULT_NO_ERROR 0x80000000
#define PSCNV_RESULT_UNKNOWN_CMD 0x80000001
#define PSCNV_RESULT_ERROR 0x80000002

struct pscnv_page {
    unsigned int next;
    struct pscnv_map_page *mapped;
};

struct pscnv_map_page {
    uint32_t handle;
    MemoryRegion vram_area;
};

struct pscnv_memory_allocation {
    uint64_t size;
    uint64_t map_handle;
    uint32_t handle;
    uint32_t next;
    uint32_t mapped_page;
    uint32_t cid;
};

typedef struct {
    PCIDevice pci_dev;
    MemoryRegion mmio_bar;
    MemoryRegion call_area_bar;
    MemoryRegion vram_bar;
    unsigned int chan_bar_size;
    MemoryRegion chan_bar;
    char *call_area_memory;
    /*qemu_irq irq;*/

    int drm_fd;
    uint32_t gpu_info[PSCNV_INFO_COUNT];

    struct pscnv_memory_allocation *alloc_data;
    uint32_t alloc_count;
    uint32_t alloc_freelist;

    struct pscnv_page *vram_pages;
    unsigned int free_vram_page;

    /* index into alloc_data for chan chan entries */
    MemoryRegion chan[PSCNV_VIRT_CHAN_COUNT];

    int is_nv50;
} PscnvState;

struct pscnv_alloc_mem_cmd {
    uint32_t command;
    uint32_t flags;
    uint64_t size;
    uint32_t tile_flags;
    uint32_t cookie;
    uint32_t handle;
};

struct pscnv_map_cmd {
    uint32_t command;
    uint32_t handle;
    uint64_t result_table;
    uint32_t page_count;
};

struct pscnv_vspace_cmd {
    uint32_t command;
    uint32_t vid;
};

struct pscnv_chan_new_cmd {
    uint32_t command;
    uint32_t vid;
    uint32_t cid;
};

struct pscnv_chan_free_cmd {
    uint32_t command;
    uint32_t cid;
};

struct pscnv_vspace_map_cmd {
    uint32_t command;
    uint32_t vid;
    uint32_t handle;
    uint32_t back;
    uint64_t start;
    uint64_t end;
    uint64_t offset;
    uint32_t flags;
};

struct pscnv_vspace_unmap_cmd {
    uint32_t command;
    uint32_t vid;
    uint64_t offset;
};

static unsigned int allocate_page(PscnvState *d) {
    unsigned int page = d->free_vram_page;

    if (page == (unsigned int)-1) {
        return page;
    }
    d->free_vram_page = d->vram_pages[page].next;
    d->vram_pages[page].next = (unsigned int)-1;
    return page;
}

/*static void free_page(PscnvState *d, unsigned int page) {
    assert(d->vram_pages[page].mapped == NULL);

    d->vram_pages[page].next = d->free_vram_page;
    d->free_vram_page = page;
}*/

static uint32_t add_allocation_entry(PscnvState *d,
                                     struct pscnv_memory_allocation *entry) {
    uint32_t result, next;

    if (d->alloc_freelist == (uint32_t)-1) {
        uint32_t i;
        uint32_t new_count = d->alloc_count * 2;
        d->alloc_data = realloc(d->alloc_data,
                new_count * sizeof(struct pscnv_memory_allocation));
        for (i = d->alloc_count; i < new_count; i++) {
            d->alloc_data[i].size = 0xffffffffffffffff;
            d->alloc_data[i].next = i + 1;
        }
        d->alloc_data[new_count - 1].next = (uint32_t)-1;
        d->alloc_freelist = d->alloc_count;
        d->alloc_count = new_count;
    }
    next = d->alloc_data[d->alloc_freelist].next;
    d->alloc_data[d->alloc_freelist] = *entry;
    result = d->alloc_freelist;
    d->alloc_freelist = next;
    return result;
}

static void pscnv_execute_mem_alloc(PscnvState *d,
                                    volatile struct pscnv_alloc_mem_cmd *cmd) {
    int ret;
    struct pscnv_memory_allocation result;

    fprintf(stderr, "vm wants to allocate %"PRIx64" bytes\n", cmd->size);
    /* allocate a gem object */
    ret = pscnv_gem_new(d->drm_fd, cmd->cookie, cmd->flags, cmd->tile_flags,
                        cmd->size, NULL, &result.handle, &result.map_handle);
    if (ret != 0) {
        cmd->command = PSCNV_RESULT_ERROR;
        return;
    }
    result.size = cmd->size;
    result.mapped_page = (uint32_t)-1;
    result.cid = (uint32_t)-1;
    cmd->handle = add_allocation_entry(d, &result);
    fprintf(stderr, "pscnv_virt: allocated %"PRIx64" bytes, handle %d\n",
            cmd->size, cmd->handle);

    cmd->command = PSCNV_RESULT_NO_ERROR;
}

static int return_page_list(PscnvState *d, unsigned int first_page,
                            unsigned int page_count, uint64_t destination) {
    MemoryRegionSection section;
    void *memory;
    uint32_t *list;
    unsigned int i, page;

    section = memory_region_find(get_system_memory(),
                                 destination, page_count * 4);
    if (section.size == 0) {
        return -1;
    }
    if (memory_region_is_ram(section.mr) == 0) {
        return -1;
    }

    memory = memory_region_get_ram_ptr(section.mr);
    list = (uint32_t*)((char*)memory + section.offset_within_region);
    page = first_page;
    for (i = 0; i < page_count; i++) {
        assert(page != (unsigned int)-1);
        *list++ = page;
        page = d->vram_pages[page].next;
    }
    return 0;
}

static void pscnv_execute_map(PscnvState *d,
                              volatile struct pscnv_map_cmd *cmd) {
    void *mapped;
    struct pscnv_memory_allocation *obj;
    unsigned int page_count, i, prev_page, first_page = 0;

    fprintf(stderr, "vm wants to map %d\n", cmd->handle);

    /* TODO: check whether the object is already mapped */

    if (cmd->handle >= d->alloc_count
            || d->alloc_data[cmd->handle].size == (uint64_t)-1) {
        fprintf(stderr, "pscnv_virt: invalid handle %d (size: %"PRIx64", objects: %d)\n",
                cmd->handle, d->alloc_data[cmd->handle].size, d->alloc_count);
        cmd->command = PSCNV_RESULT_ERROR;
        return;
    }
    obj = &d->alloc_data[cmd->handle];
    /* map the gem object */
    /* TODO: access rights? */
    mapped = mmap(0, obj->size, PROT_READ | PROT_WRITE, MAP_SHARED, d->drm_fd,
            obj->map_handle);
    if (((uintptr_t)mapped & PAGE_MASK) != 0) {
        fprintf(stderr, "pscnv_virt: mapped data not page-aligned: %p\n",
                mapped);
        cmd->command = PSCNV_RESULT_ERROR;
        return;
    }
    /* allocate some pages from the bar */
    page_count = (obj->size + PAGE_MASK) >> PAGE_SHIFT;
    /* map the data into the bar */
    for (i = 0; i < page_count; i++) {
        unsigned int page = allocate_page(d);
        if (page == (unsigned int)-1) {
            fprintf(stderr, "pscnv_virt: no virtual vram left\n");
            /* TODO */
            cmd->command = PSCNV_RESULT_ERROR;
            return;
        }
        if (i != 0) {
            d->vram_pages[prev_page].next = page;
        } else {
            first_page = page;
        }
        d->vram_pages[page].mapped = calloc(sizeof(struct pscnv_map_page), 1);
        d->vram_pages[page].mapped->handle = cmd->handle;
        memory_region_init_ram_ptr(&d->vram_pages[page].mapped->vram_area,
                                   "vram_page",
                                   PAGE_SIZE,
                                   (char*)mapped + i * PAGE_SIZE);
        memory_region_add_subregion(&d->vram_bar, page * PAGE_SIZE,
                &d->vram_pages[page].mapped->vram_area);
        prev_page = page;
    }
    /* return the addresses to the guest */
    if (return_page_list(d, first_page, page_count, cmd->result_table)) {
        fprintf(stderr, "pscnv_virt: invalid map result destination\n");
        cmd->command = PSCNV_RESULT_ERROR;
    }
    cmd->command = PSCNV_RESULT_NO_ERROR;
}

static void pscnv_execute_vspace_alloc(PscnvState *d,
                                       volatile struct pscnv_vspace_cmd *cmd)
{
    uint32_t vid;
    int ret;

    ret = pscnv_vspace_new(d->drm_fd, &vid);
    if (ret) {
        fprintf(stderr, "pscnv_virt: pscnv_vspace_new failed (%d)\n", ret);
        cmd->command = PSCNV_RESULT_ERROR;
        return;
    }
    cmd->vid = vid;
    cmd->command = PSCNV_RESULT_NO_ERROR;
}

static void pscnv_execute_vspace_free(PscnvState *d,
                                      volatile struct pscnv_vspace_cmd *cmd)
{
    int ret;

    ret = pscnv_vspace_free(d->drm_fd, cmd->vid);
    if (ret) {
        fprintf(stderr, "pscnv_virt: pscnv_vspace_free failed (%d)\n", ret);
        cmd->command = PSCNV_RESULT_ERROR;
        return;
    }
    cmd->command = PSCNV_RESULT_NO_ERROR;
}

static void pscnv_execute_vspace_map(PscnvState *d,
                                     volatile struct pscnv_vspace_map_cmd *cmd)
{
    int ret;
    uint64_t offset;

    if (cmd->handle >= d->alloc_count
            || d->alloc_data[cmd->handle].size == (uint64_t)-1) {
        fprintf(stderr, "pscnv_virt: invalid handle %d (size: %"PRIx64", objects: %d)\n",
                cmd->handle, d->alloc_data[cmd->handle].size, d->alloc_count);
        cmd->command = PSCNV_RESULT_ERROR;
        return;
    }

    ret = pscnv_vspace_map(d->drm_fd, cmd->vid,
                           d->alloc_data[cmd->handle].handle, cmd->start,
                           cmd->end, cmd->back, cmd->flags, &offset);
    if (ret != 0) {
        fprintf(stderr, "pscnv_vspace_map failed (%d)\n", ret);
        cmd->command = PSCNV_RESULT_ERROR;
        return;
    }
    cmd->offset = offset;
    cmd->command = PSCNV_RESULT_NO_ERROR;
}

static void pscnv_execute_vspace_unmap(PscnvState *d,
                                       volatile struct pscnv_vspace_unmap_cmd *cmd)
{
    int ret;

    ret = pscnv_vspace_unmap(d->drm_fd, cmd->vid, cmd->offset);
    if (ret != 0) {
        fprintf(stderr, "pscnv_vspace_unmap failed (%d)\n", ret);
        cmd->command = PSCNV_RESULT_ERROR;
        return;
    }
    cmd->command = PSCNV_RESULT_NO_ERROR;
}

static void pscnv_execute_chan_new(PscnvState *d,
                                   volatile struct pscnv_chan_new_cmd *cmd)
{
    uint32_t cid;
    uint64_t map_handle;
    int ret;
    unsigned int chsize;
    void *chmem;

    ret = pscnv_chan_new(d->drm_fd, cmd->vid, &cid, &map_handle);
    if (ret) {
        fprintf(stderr, "pscnv_virt: pscnv_chan_new failed (%d)\n", ret);
        cmd->command = PSCNV_RESULT_ERROR;
        return;
    }
    if (cid >= PSCNV_VIRT_CHAN_COUNT) {
        fprintf(stderr, "pscnv_virt: Bug: invalid cid %d\n", cid);
        cmd->command = PSCNV_RESULT_ERROR;
        return;
    }
    /* map the channel into the channel BAR */
    chsize = d->is_nv50 ? 0x2000 : 0x1000;
    chmem = mmap(0, chsize, PROT_READ | PROT_WRITE, MAP_SHARED, d->drm_fd,
                 map_handle);
    if (chmem == MAP_FAILED) {
        fprintf(stderr, "pscnv_virt: Could not map channel %d\n", cid);
        cmd->command = PSCNV_RESULT_ERROR;
        return;
    }
    memory_region_init_ram_ptr(&d->chan[cid],
                               "chan",
                               chsize,
                               chmem);
    memory_region_add_subregion(&d->chan_bar, cid * chsize, &d->chan[cid]);
#if 0
    /* channels can be mapped, so we create an allocation list entry */
    result.size = 0x1000; /* TODO: for nv50 this should be 0x2000 */
    result.map_handle = map_handle;
    result.handle = 0;
    result.mapped_page = (uint32_t)-1;
    result.cid = cid;
    d->chan[cid] = add_allocation_entry(d, &result);
    cmd->map_handle = d->chan[cid];
#endif
    cmd->cid = cid;
    cmd->command = PSCNV_RESULT_NO_ERROR;

}
static void pscnv_execute_chan_free(PscnvState *d,
                                    volatile struct pscnv_chan_free_cmd *cmd)
{
    int ret;
    void *chmem;

    /* delete that channel */
    ret = pscnv_chan_free(d->drm_fd, cmd->cid);
    if (ret) {
        fprintf(stderr, "pscnv_virt: pscnv_chan_free failed (%d)\n", ret);
        cmd->command = PSCNV_RESULT_ERROR;
        return;
    }

    /* unmap the channel */
    chmem = memory_region_get_ram_ptr(&d->chan[cmd->cid]);
    memory_region_del_subregion(&d->chan_bar, &d->chan[cmd->cid]);
    memory_region_destroy(&d->chan[cmd->cid]);
    munmap(chmem, d->is_nv50 ? 0x2000 : 0x1000);

    cmd->command = PSCNV_RESULT_NO_ERROR;

}

static void pscnv_execute_hypercall(PscnvState *d, uint32_t call_addr)
{
    volatile uint32_t *call_data = (uint32_t*)(d->call_area_memory + call_addr);
    uint32_t command = call_data[0];

    fprintf(stderr, "pscnv_virt: command 0x%x.\n", command);
    switch (command) {
    case PSCNV_CMD_GET_PARAM:
        /* TODO: remove this */
        fprintf(stderr, "pscnv_virt: PSCNV_CMD_GET_PARAM.\n");
        call_data[1] = 0x12345678;
        call_data[0] = PSCNV_RESULT_NO_ERROR;
        break;
    case PSCNV_CMD_MEM_ALLOC:
        pscnv_execute_mem_alloc(d,
                (volatile struct pscnv_alloc_mem_cmd*)call_data);
        break;
    case PSCNV_CMD_MAP:
        pscnv_execute_map(d, (volatile struct pscnv_map_cmd*)call_data);
        break;
    case PSCNV_CMD_VSPACE_ALLOC:
        pscnv_execute_vspace_alloc(d, (volatile struct pscnv_vspace_cmd*)call_data);
        break;
    case PSCNV_CMD_VSPACE_FREE:
        pscnv_execute_vspace_free(d, (volatile struct pscnv_vspace_cmd*)call_data);
        break;
    case PSCNV_CMD_CHAN_NEW:
        pscnv_execute_chan_new(d, (volatile struct pscnv_chan_new_cmd*)call_data);
        break;
    case PSCNV_CMD_CHAN_FREE:
        pscnv_execute_chan_free(d, (volatile struct pscnv_chan_free_cmd*)call_data);
        break;
    case PSCNV_CMD_VSPACE_MAP:
        pscnv_execute_vspace_map(d, (volatile struct pscnv_vspace_map_cmd*)call_data);
        break;
    case PSCNV_CMD_VSPACE_UNMAP:
        pscnv_execute_vspace_unmap(d, (volatile struct pscnv_vspace_unmap_cmd*)call_data);
        break;
    default:
        call_data[0] = PSCNV_RESULT_UNKNOWN_CMD;
        break;
    }
}

static void pscnv_mmio_writeb(void *opaque, target_phys_addr_t addr, uint32_t val)
{
    //PscnvState *d = opaque;
#ifdef PSCNV_DEBUG_IO
    fprintf(stderr, "pscnv_mmio_writeb addr=0x" TARGET_FMT_plx" val=0x%02x\n",
            addr, val);
#endif
    // TODO
}

static uint32_t pscnv_mmio_readb(void *opaque, target_phys_addr_t addr)
{
    //PscnvState *d = opaque;
    uint32_t val = -1;
#ifdef PSCNV_DEBUG_IO
    fprintf(stderr, "pscnv_mmio_readb addr=0x" TARGET_FMT_plx " val=0x%02x\n",
            addr, val & 0xff);
#endif
    // TODO
    return val;
}

static void pscnv_mmio_writew(void *opaque, target_phys_addr_t addr, uint32_t val)
{
    //PscnvState *d = opaque;
#ifdef PSCNV_DEBUG_IO
    fprintf(stderr, "pscnv_mmio_writew addr=0x" TARGET_FMT_plx " val=0x%04x\n",
            addr, val);
#endif
    // TODO
}

static uint32_t pscnv_mmio_readw(void *opaque, target_phys_addr_t addr)
{
    //PscnvState *d = opaque;
    uint32_t val = -1;
#ifdef PSCNV_DEBUG_IO
    fprintf(stderr, "pscnv_mmio_readw addr=0x" TARGET_FMT_plx" val = 0x%04x\n",
            addr, val & 0xffff);
#endif
    // TODO
    return val;
}

static void pscnv_mmio_writel(void *opaque, target_phys_addr_t addr, uint32_t val)
{
    PscnvState *d = opaque;
#ifdef PSCNV_DEBUG_IO
    fprintf(stderr, "pscnv_mmio_writel addr=0x" TARGET_FMT_plx" val=0x%08x\n",
            addr, val);
#endif
    if (addr == EXECUTE_CALL_REG) {
        pscnv_execute_hypercall(d, val);
    }
}

static uint32_t pscnv_mmio_readl(void *opaque, target_phys_addr_t addr)
{
    PscnvState *d = opaque;
    uint32_t val = -1;
    if (addr == PTIMER_TIME_REG) {
        /* TODO */
        val = 0xdeadc0de;
    } else if (addr >= GPU_INFO_REG_BASE
            && addr < GPU_INFO_REG_BASE + sizeof(d->gpu_info)) {
        /* TODO: this should be direct RAM accesses without mmio callbacks */
        val = d->gpu_info[(addr - GPU_INFO_REG_BASE) / 4];
    } else {
        /* TODO */
    }
#ifdef PSCNV_DEBUG_IO
    fprintf(stderr, "pscnv_mmio_readl addr=0x" TARGET_FMT_plx " val=0x%08x\n",
            addr, val);
#endif
    return val;
}

static const VMStateDescription vmstate_pci_pscnv = {
    .name = "pscnv",
    .version_id = 1,
    .minimum_version_id = 1,
    .minimum_version_id_old = 1,
    .fields      = (VMStateField []) {
        VMSTATE_PCI_DEVICE(pci_dev, PscnvState),
        VMSTATE_END_OF_LIST()
    }
};

/* PCI interface */

static const MemoryRegionOps pscnv_mmio_ops = {
    .old_mmio = {
        .read = { pscnv_mmio_readb, pscnv_mmio_readw, pscnv_mmio_readl },
        .write = { pscnv_mmio_writeb, pscnv_mmio_writew, pscnv_mmio_writel },
    },
    .endianness = DEVICE_NATIVE_ENDIAN,
};

/*static void pci_physical_memory_write(void *dma_opaque, target_phys_addr_t addr,
                                      uint8_t *buf, int len, int do_bswap)
{
    pci_dma_write(dma_opaque, addr, buf, len);
}

static void pci_physical_memory_read(void *dma_opaque, target_phys_addr_t addr,
                                     uint8_t *buf, int len, int do_bswap)
{
    pci_dma_read(dma_opaque, addr, buf, len);
}*/

static void pci_pscnv_uninit(PCIDevice *dev)
{
    PscnvState *d = DO_UPCAST(PscnvState, pci_dev, dev);

    close(d->drm_fd);

    memory_region_destroy(&d->mmio_bar);
    memory_region_destroy(&d->call_area_bar);
    memory_region_destroy(&d->vram_bar);
    memory_region_destroy(&d->chan_bar);
    //qemu_del_timer(d->timer);
    /*qemu_del_timer(d->state.poll_timer);
    qemu_free_timer(d->state.poll_timer);
    qemu_del_net_client(&d->state.nic->nc);*/
}

/*static void pscnv_virt_tick(void *opaque)
{
    PscnvState *d = opaque;
    d->irq_state = 1 - d->irq_state;
    qemu_set_irq(d->irq, d->irq_state);
    qemu_mod_timer_ns(d->timer, qemu_get_clock_ns(vm_clock) + 5000000);
}*/

static uint32_t read_gpu_info(PscnvState *d, uint32_t param) {
    uint64_t value;
    int status;

    status = pscnv_getparam(d->drm_fd, param,
                            &value);
    if (status != 0) {
        hw_error("%s: could not read pscnv device info (%d)\n", __func__,
                 param);
    }
    if (value > 0xffffffff) {
        hw_error("%s: pscnv device info too large (%d)\n", __func__,
                 param);
    }

    return value;
}

static int pci_pscnv_init(PCIDevice *pci_dev)
{
    PscnvState *d = DO_UPCAST(PscnvState, pci_dev, pci_dev);
    uint8_t *pci_conf;
    unsigned int i;

    /* initialize the gpu */
    d->drm_fd = drmOpen("pscnv", 0);
    if (d->drm_fd < 0) {
        hw_error("%s: could not open pscnv (%d)\n", __func__, d->drm_fd);
    }
    memset(d->gpu_info, 0, sizeof(d->gpu_info));
    d->gpu_info[PSCNV_INFO_PCI_VENDOR] =
            read_gpu_info(d, PSCNV_GETPARAM_PCI_VENDOR);
    d->gpu_info[PSCNV_INFO_PCI_DEVICE] =
            read_gpu_info(d, PSCNV_GETPARAM_PCI_DEVICE);
    d->gpu_info[PSCNV_INFO_BUS_TYPE] =
            read_gpu_info(d, PSCNV_GETPARAM_BUS_TYPE);
    d->gpu_info[PSCNV_INFO_CHIPSET_ID] =
            read_gpu_info(d, PSCNV_GETPARAM_CHIPSET_ID);
    d->alloc_data = calloc(sizeof(struct pscnv_memory_allocation), 16);
    d->alloc_count = 16;
    d->alloc_freelist = 0;
    for (i = 0; i < 16; i++) {
        d->alloc_data[i].size = -1;
        d->alloc_data[i].next = i + 1;
    }
    d->alloc_data[15].next = -1;
    /* TODO: build freelist and validity information */
    /* TODO: this does not work? o.O */
    /*d->gpu_info[PSCNV_INFO_GRAPH_UNITS] =
            read_gpu_info(d, PSCNV_GETPARAM_GRAPH_UNITS);*/
    /* TODO: these are not defined in libdrm_pscnv */
    /*d->gpu_info[PSCNV_INFO_GPC_COUNT] =
            read_gpu_info(d, PSCNV_GETPARAM_GPC_COUNT);
    d->gpu_info[PSCNV_INFO_TP_COUNT_IDX] =
            read_gpu_info(d, PSCNV_GETPARAM_TP_COUNT_IDX);
    d->gpu_info[PSCNV_INFO_MP_COUNT] =
            read_gpu_info(d, PSCNV_GETPARAM_MP_COUNT);*/

    /* NV50 has longer channels */
    d->is_nv50 = 0;
    d->chan_bar_size = PSCNV_VIRT_CHAN_COUNT * 0x1000;
    switch (d->gpu_info[PSCNV_INFO_CHIPSET_ID] & 0xf0) {
        case 0x50:
        case 0x80:
        case 0x90:
        case 0xa0:
            d->is_nv50 = 1;
            d->chan_bar_size = PSCNV_VIRT_CHAN_COUNT * 0x2000;
            break;
        default:
            break;
    }

    /* pci configuration */
    pci_conf = pci_dev->config;

    pci_set_word(pci_conf + PCI_STATUS,
                 PCI_STATUS_FAST_BACK | PCI_STATUS_DEVSEL_MEDIUM);

    pci_set_word(pci_conf + PCI_SUBSYSTEM_VENDOR_ID, 0x0);
    pci_set_word(pci_conf + PCI_SUBSYSTEM_ID, 0x0);

    pci_conf[PCI_INTERRUPT_PIN] = 1; /* interrupt pin A */
    pci_conf[PCI_MIN_GNT] = 0x06;
    pci_conf[PCI_MAX_LAT] = 0xff;

    /* pci BARs */
    memory_region_init_io(&d->mmio_bar, &pscnv_mmio_ops, d, "pscnv-mmio",
                          PSCNV_VIRT_MMIO_SIZE);
    pci_register_bar(pci_dev, 0, 0, &d->mmio_bar);

    memory_region_init_ram(&d->call_area_bar, "pscnv-call",
                           PSCNV_CALL_AREA_SIZE);
    d->call_area_memory = memory_region_get_ram_ptr(&d->call_area_bar);
    memset(d->call_area_memory, 0, PSCNV_CALL_AREA_SIZE);
    pci_register_bar(pci_dev, 1, 0, &d->call_area_bar);

    memory_region_init(&d->vram_bar, "pscnv-vram",
                          PSCNV_VIRT_VRAM_SIZE);
    pci_register_bar(pci_dev, 2, 0, &d->vram_bar);

    memory_region_init(&d->chan_bar, "pscnv-chan", d->chan_bar_size);
    pci_register_bar(pci_dev, 3, 0, &d->chan_bar);

    /* build a single linked list of the available vram pages */
    d->vram_pages = malloc(VRAM_PAGE_COUNT * sizeof(struct pscnv_page));
    for (i = 0; i < VRAM_PAGE_COUNT; i++) {
        d->vram_pages[i].next = i + 1;
    }
    d->vram_pages[VRAM_PAGE_COUNT - 1].next = (unsigned int)-1;
    d->free_vram_page = 0;

    /*d->irq = pci_dev->irq[0];*/

    return 0;
}

static void pci_reset(DeviceState *dev)
{
    //PscnvState *d = DO_UPCAST(PscnvState, pci_dev.qdev, dev);

    //pscnv_reset(&d->state);
    // TODO
}

static Property pscnv_properties[] = {
    DEFINE_PROP_END_OF_LIST(),
};

static void pscnv_class_init(ObjectClass *klass, void *data)
{
    DeviceClass *dc = DEVICE_CLASS(klass);
    PCIDeviceClass *k = PCI_DEVICE_CLASS(klass);

    k->init = pci_pscnv_init;
    k->exit = pci_pscnv_uninit;
    k->vendor_id = PCI_VENDOR_ID_REDHAT_QUMRANET;
    k->device_id = PCI_DEVICE_ID_PSCNV;
    k->revision = 0x10;
    k->class_id = PCI_CLASS_SYSTEM_OTHER;
    dc->reset = pci_reset;
    dc->vmsd = &vmstate_pci_pscnv;
    dc->props = pscnv_properties;
}

static TypeInfo pscnv_info = {
    .name          = "pscnv",
    .parent        = TYPE_PCI_DEVICE,
    .instance_size = sizeof(PscnvState),
    .class_init    = pscnv_class_init,
};

static void pci_pscnv_register_types(void)
{
    type_register_static(&pscnv_info);
}

type_init(pci_pscnv_register_types)
