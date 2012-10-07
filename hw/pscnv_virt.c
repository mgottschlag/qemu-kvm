
#include "pci.h"

#define PSCNV_VIRT_MMIO_SIZE 0x1000
#define PSCNV_VRAM_SIZE 0x10000000

typedef struct {
    PCIDevice pci_dev;
    MemoryRegion mmio_bar;
    MemoryRegion vram_bar;
} PscnvState;


static void pscnv_mmio_writeb(void *opaque, target_phys_addr_t addr, uint32_t val)
{
    //PscnvState *d = opaque;
#ifdef PSCNV_DEBUG_IO
    printf("pscnv_mmio_writeb addr=0x" TARGET_FMT_plx" val=0x%02x\n", addr,
           val);
#endif
    // TODO
}

static uint32_t pscnv_mmio_readb(void *opaque, target_phys_addr_t addr)
{
    //PscnvState *d = opaque;
    uint32_t val = -1;
#ifdef PSCNV_DEBUG_IO
    printf("pscnv_mmio_readb addr=0x" TARGET_FMT_plx " val=0x%02x\n", addr,
           val & 0xff);
#endif
    // TODO
    return val;
}

static void pscnv_mmio_writew(void *opaque, target_phys_addr_t addr, uint32_t val)
{
    //PscnvState *d = opaque;
#ifdef PSCNV_DEBUG_IO
    printf("pscnv_mmio_writew addr=0x" TARGET_FMT_plx " val=0x%04x\n", addr,
           val);
#endif
    // TODO
}

static uint32_t pscnv_mmio_readw(void *opaque, target_phys_addr_t addr)
{
    //PscnvState *d = opaque;
    uint32_t val = -1;
#ifdef PSCNV_DEBUG_IO
    printf("pscnv_mmio_readw addr=0x" TARGET_FMT_plx" val = 0x%04x\n", addr,
           val & 0xffff);
#endif
    // TODO
    return val;
}

static void pscnv_mmio_writel(void *opaque, target_phys_addr_t addr, uint32_t val)
{
    //PscnvState *d = opaque;
#ifdef PSCNV_DEBUG_IO
    printf("pscnv_mmio_writel addr=0x" TARGET_FMT_plx" val=0x%08x\n", addr,
           val);
#endif
    // TODO
}

static uint32_t pscnv_mmio_readl(void *opaque, target_phys_addr_t addr)
{
    //PscnvState *d = opaque;
    uint32_t val = -1;
#ifdef PSCNV_DEBUG_IO
    printf("pscnv_mmio_readl addr=0x" TARGET_FMT_plx " val=0x%08x\n", addr,
           val);
#endif
    // TODO
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

    memory_region_destroy(&d->mmio_bar);
    memory_region_destroy(&d->vram_bar);
    /*qemu_del_timer(d->state.poll_timer);
    qemu_free_timer(d->state.poll_timer);
    qemu_del_net_client(&d->state.nic->nc);*/
}

static int pci_pscnv_init(PCIDevice *pci_dev)
{
    PscnvState *d = DO_UPCAST(PscnvState, pci_dev, pci_dev);
    //PCNetState *s = &d->state;
    uint8_t *pci_conf;

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

    memory_region_init(&d->vram_bar, "pscnv-vram",
                          PSCNV_VRAM_SIZE);
    pci_register_bar(pci_dev, 1, 0, &d->vram_bar);

    /*s->irq = pci_dev->irq[0];
    s->phys_mem_read = pci_physical_memory_read;
    s->phys_mem_write = pci_physical_memory_write;
    s->dma_opaque = pci_dev;*/

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

