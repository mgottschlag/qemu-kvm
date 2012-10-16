
#include "pci.h"

#include <libpscnv.h>
#include <xf86drm.h>

#define PSCNV_DEBUG_IO

#define PSCNV_VIRT_MMIO_SIZE 0x1000
#define PSCNV_CALL_SLOT_SIZE 0x100
#define PSCNV_CALL_SLOT_COUNT 32
#define PSCNV_CALL_AREA_SIZE (PSCNV_CALL_SLOT_COUNT * PSCNV_CALL_SLOT_SIZE)
#define PSCNV_VIRT_VRAM_SIZE 0x10000000

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

#define PSCNV_RESULT_NO_ERROR 0x80000000
#define PSCNV_RESULT_UNKNOWN_CMD 0x80000001
#define PSCNV_RESULT_ERROR 0x80000002

struct pscnv_memory_allocation {
    uint64_t size;
    uint64_t map_handle;
    uint32_t handle;
    uint32_t next;
};

typedef struct {
    PCIDevice pci_dev;
    MemoryRegion mmio_bar;
    MemoryRegion call_area_bar;
    MemoryRegion vram_bar;
    char *call_area_memory;
    /*qemu_irq irq;*/

    int drm_fd;
    uint32_t gpu_info[PSCNV_INFO_COUNT];

    struct pscnv_memory_allocation *alloc_data;
    uint32_t alloc_count;
    uint32_t alloc_freelist;
} PscnvState;

struct pscnv_alloc_mem_cmd {
    uint32_t command;
    uint32_t flags;
    uint64_t size;
    uint32_t tile_flags;
    uint32_t cookie;
    uint32_t handle;
};

static void pscnv_execute_mem_alloc(PscnvState *d,
                                    volatile struct pscnv_alloc_mem_cmd *cmd) {
    int ret;
    struct pscnv_memory_allocation result;
    uint32_t next;

    fprintf(stderr, "vm wants to allocate %"PRIx64" bytes\n", cmd->size);
    /* allocate a gem object */
    ret = pscnv_gem_new(d->drm_fd, cmd->cookie, cmd->flags, cmd->tile_flags,
                        cmd->size, NULL, &result.handle, &result.map_handle);
    if (ret != 0) {
        cmd->command = PSCNV_RESULT_ERROR;
        return;
    }
    result.size = cmd->size;
    /* create an allocation list table entry */
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
    d->alloc_data[d->alloc_freelist] = result;
    cmd->handle = d->alloc_freelist;
    d->alloc_freelist = next;

    cmd->command = PSCNV_RESULT_NO_ERROR;
}

static void pscnv_execute_hypercall(PscnvState *d, uint32_t call_addr)
{
    volatile uint32_t *call_data = (uint32_t*)(d->call_area_memory + call_addr);
    uint32_t command = call_data[0];

    fprintf(stderr, "pscnv_virt: command 0x%x.\n", command);
    switch (command) {
    case PSCNV_CMD_GET_PARAM: {
        fprintf(stderr, "pscnv_virt: PSCNV_CMD_GET_PARAM.\n");
        call_data[1] = 0x12345678;
        call_data[0] = PSCNV_RESULT_NO_ERROR;
        break;
    }
    case PSCNV_CMD_MEM_ALLOC: {
        pscnv_execute_mem_alloc(d,
                (volatile struct pscnv_alloc_mem_cmd*)call_data);
        break;
    }
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
    d->alloc_count = 0;
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
