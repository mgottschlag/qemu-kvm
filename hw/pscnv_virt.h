
#ifndef PSCNV_VIRT_H_INCLUDED
#define PSCNV_VIRT_H_INCLUDED

#include "pci.h"
#include "exec-memory.h"
#include "vmstate.h"
#include "qemu-thread.h"

#define PAGE_SHIFT 12
#define PAGE_SIZE (1 << PAGE_SHIFT)
#define PAGE_MASK (PAGE_SIZE - 1)

//#define PSCNV_DEBUG_IO

#define PSCNV_VIRT_MMIO_SIZE 0x1000
#define PSCNV_CALL_SLOT_SIZE 0x100
#define PSCNV_CALL_SLOT_COUNT 32
#define PSCNV_CALL_AREA_SIZE (PSCNV_CALL_SLOT_COUNT * PSCNV_CALL_SLOT_SIZE)
#define PSCNV_VIRT_VRAM_SIZE 0x10000000

#define PSCNV_VIRT_CHAN_COUNT 128
#define PSCNV_VIRT_VSPACE_COUNT 128

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
#define PSCNV_CMD_OBJ_VDMA_NEW 11
#define PSCNV_CMD_OBJ_ENG_NEW 12
#define PSCNV_CMD_FIFO_INIT 13
#define PSCNV_CMD_FIFO_INIT_IB 14

#define PSCNV_RESULT_NO_ERROR 0x80000000
#define PSCNV_RESULT_UNKNOWN_CMD 0x80000001
#define PSCNV_RESULT_ERROR 0x80000002

/*#define DUMP_MMIO_ACCESS */
/*#define DUMP_HYPERCALLS*/
/*define PSCNV_DEBUG_CHAN_ACCESS*/
/*#define PSCNV_DEBUG_VRAM_ACCESS*/

struct pscnv_vspace_mapping {
    uint32_t obj;
    uint32_t vspace;
    uint64_t offset;
    uint32_t flags;
    struct pscnv_vspace_mapping *obj_prev;
    struct pscnv_vspace_mapping *obj_next;
    struct pscnv_vspace_mapping *vspace_prev;
    struct pscnv_vspace_mapping *vspace_next;
};

struct pscnv_memory_area {
    uint32_t start;
    uint32_t size;
    struct pscnv_memory_area *next;
    struct pscnv_memory_area *prev;
    uint32_t handle;
};

struct pscnv_memory_allocation {
    uint64_t size;
    uint64_t map_handle;
    uint32_t handle;
    uint32_t next;
    uint32_t cookie;
    uint32_t flags;
    uint32_t tile_flags;
    struct pscnv_memory_area *mapping;
    /*void *migration_mapping;*/
    struct pscnv_vspace_mapping *vspace_mapping;
};

struct pscnv_alloc_mem_cmd {
    uint32_t command;
    uint32_t flags;
    uint64_t size;
    uint32_t tile_flags;
    uint32_t cookie;
    uint32_t handle;
};

struct pscnv_free_mem_cmd {
    uint32_t command;
    uint32_t handle;
};

struct pscnv_map_cmd {
    uint32_t command;
    uint32_t handle;
    uint32_t start;
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

struct pscnv_obj_vdma_new_cmd {
    uint32_t command;
    uint32_t cid;
    uint32_t handle;
    uint32_t oclass;
    uint64_t start;
    uint64_t size;
    uint32_t flags;
    int32_t ret;
};

struct pscnv_fifo_init_cmd {
    uint32_t command;
    uint32_t cid;
    uint32_t pb_handle;
    uint32_t flags;
    uint64_t pb_start;
    uint32_t slimask;
    int32_t ret;
};

struct pscnv_fifo_init_ib_cmd {
    uint32_t command;
    uint32_t cid;
    uint32_t pb_handle;
    uint32_t flags;
    uint64_t ib_start;
    uint32_t slimask;
    uint32_t ib_order;
    int32_t ret;
};

struct pscnv_obj_eng_new_cmd {
    uint32_t command;
    uint32_t cid;
    uint32_t handle;
    uint32_t oclass;
    uint32_t flags;
    int32_t ret;
};

enum pscnv_migration_log_type {
    PSCNV_MIGRATION_LOG_ALLOC = 1,
    PSCNV_MIGRATION_LOG_FREE = 2,
    PSCNV_MIGRATION_LOG_MAP = 4,
    PSCNV_MIGRATION_LOG_UNMAP = 8
};

struct pscnv_migration_log_entry {
    struct pscnv_migration_log_entry *next;
    struct pscnv_migration_log_entry *prev;
    enum pscnv_migration_log_type type;
    uint32_t handle;
};

typedef struct {
    PCIDevice pci_dev;
    MemoryRegion mmio_bar;
    MemoryRegion call_area_bar;
    MemoryRegion vram_bar;
    unsigned int chan_bar_size;
    MemoryRegion chan_bar;
    char *call_area_memory;
    char *vram_bar_memory;
    char *chan_bar_memory;

    uint32_t chan_handle[PSCNV_VIRT_CHAN_COUNT];
    uint32_t chan_vspace[PSCNV_VIRT_CHAN_COUNT];
    struct pscnv_fifo_init_ib_cmd fifo_init[PSCNV_VIRT_CHAN_COUNT];
    /*void *channel_content;*/

    uint32_t vspace_handle[PSCNV_VIRT_VSPACE_COUNT];
    struct pscnv_vspace_mapping *vspace_mapping[PSCNV_VIRT_VSPACE_COUNT];

    int drm_fd;
    uint32_t gpu_info[PSCNV_INFO_COUNT];

    struct pscnv_memory_allocation *alloc_data;
    uint32_t alloc_count;
    uint32_t alloc_freelist;

    struct pscnv_memory_area *memory_areas;

    int is_nv50;

    int migration_active;
    QemuMutex migration_log_lock;
    struct pscnv_migration_log_entry *migration_log_start;
    struct pscnv_migration_log_entry *migration_log_end;
    int halted;
    int start_time;
    uint32_t chan_handle_tmp[PSCNV_VIRT_CHAN_COUNT];
} PscnvState;

extern SaveVMHandlers pscnv_save_handlers;

int pscnv_remove_migration_log_entries(PscnvState *d, uint32_t handle,
                                        int type_mask);
void pscnv_add_migration_log_entry(PscnvState *d, uint32_t handle,
                                  enum pscnv_migration_log_type type);

void pscnv_free_memory(PscnvState *d, struct pscnv_memory_area *area);

void pscnv_add_vspace_mapping(PscnvState *d, uint32_t vspace,
                              uint32_t obj_handle, uint64_t offset,
                              uint32_t flags);
void pscnv_remove_vspace_mapping(PscnvState *d,
                                 struct pscnv_vspace_mapping *mapping);

#endif

