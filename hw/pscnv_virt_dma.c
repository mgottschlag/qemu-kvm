
#include "pscnv_virt.h"

#include "pscnv/libpscnv.h"
#include "pscnv/libpscnv_ib.h"
#include <xf86drm.h>
#include <sys/mman.h>

#define GDEV_SUBCH_NV_M2MF 2

static void nvc0_memcpy_m2mf(struct pscnv_ib_chan *chan, uint64_t dst_addr,
                             uint64_t src_addr, uint32_t size)
{
    uint32_t mode1 = 0x102110; /* QUERY_SHORT|QUERY_YES|SRC_LINEAR|DST_LINEAR */
    uint32_t mode2 = 0x100110; /* QUERY_SHORT|SRC_LINEAR|DST_LINEAR */
    uint32_t page_size = 0x1000;
    uint32_t page_count = size / page_size;
    uint32_t rem_size = size - page_size * page_count;

    while (page_count) {
        int line_count = (page_count > 2047) ? 2047 : page_count;
        BEGIN_RING_NVC0(chan, GDEV_SUBCH_NV_M2MF, 0x238, 2);
        OUT_RING(chan, dst_addr >> 32); /* OFFSET_OUT_HIGH */
        OUT_RING(chan, dst_addr); /* OFFSET_OUT_LOW */
        BEGIN_RING_NVC0(chan, GDEV_SUBCH_NV_M2MF, 0x30c, 6);
        OUT_RING(chan, src_addr >> 32); /* OFFSET_IN_HIGH */
        OUT_RING(chan, src_addr); /* OFFSET_IN_LOW */
        OUT_RING(chan, page_size); /* SRC_PITCH_IN */
        OUT_RING(chan, page_size); /* DST_PITCH_IN */
        OUT_RING(chan, page_size); /* LINE_LENGTH_IN */
        OUT_RING(chan, line_count); /* LINE_COUNT */
        BEGIN_RING_NVC0(chan, GDEV_SUBCH_NV_M2MF, 0x300, 1);
        if (page_count == line_count && rem_size == 0)
            OUT_RING(chan, mode1); /* EXEC */
        else
            OUT_RING(chan, mode2); /* EXEC */
        page_count -= line_count;
        dst_addr += (page_size * line_count);
        src_addr += (page_size * line_count);
    }
    if (rem_size) {
        BEGIN_RING_NVC0(chan, GDEV_SUBCH_NV_M2MF, 0x238, 2);
        OUT_RING(chan, dst_addr >> 32); /* OFFSET_OUT_HIGH */
        OUT_RING(chan, dst_addr); /* OFFSET_OUT_LOW */
        BEGIN_RING_NVC0(chan, GDEV_SUBCH_NV_M2MF, 0x30c, 6);
        OUT_RING(chan, src_addr >> 32); /* OFFSET_IN_HIGH */
        OUT_RING(chan, src_addr); /* OFFSET_IN_LOW */
        OUT_RING(chan, rem_size); /* SRC_PITCH_IN */
        OUT_RING(chan, rem_size); /* DST_PITCH_IN */
        OUT_RING(chan, rem_size); /* LINE_LENGTH_IN */
        OUT_RING(chan, 1); /* LINE_COUNT */
        BEGIN_RING_NVC0(chan, GDEV_SUBCH_NV_M2MF, 0x300, 1);
        OUT_RING(chan, mode1); /* EXEC */
    }

    FIRE_RING(chan);
}

static uint64_t get_time(void) {
    uint64_t usecs;
    struct timespec time;
    clock_gettime(CLOCK_REALTIME, &time);
    usecs = time.tv_sec * 1000000;
    usecs += time.tv_nsec / 1000;
    return usecs;
}

struct pscnv_dma {
    int drm_fd;
    uint32_t vspace_handle;
#if 0
    uint32_t chan_handle;
    uint32_t *chan;
    uint32_t *ib;
    uint32_t *pb;
#endif
    struct pscnv_ib_chan *chan;
    struct pscnv_ib_bo *fence_bo;
    uint32_t *fence;
    uint64_t fence_addr;
};

int pscnv_dma_init(struct pscnv_dma **dma, int drm_fd) {
    int ret;
    struct pscnv_ib_chan *chan;
    int i;

    *dma = calloc(1, sizeof(struct pscnv_dma));
    (*dma)->drm_fd = drm_fd;
    /* create a virtual address space into which objects are mapped */
    ret = pscnv_vspace_new(drm_fd, &(*dma)->vspace_handle);
    if (ret) {
        fprintf(stderr, "pscnv_virt: Could not create DMA vspace.\n");
        free(*dma);
        return -1;
    }
#if 0
    /* create a channel for DMA commands */
    ret = pscnv_chan_new(drm_fd, (*dma)->vspace_handle, &(*dma)->chan_handle,
                         &chan_map_handle);
    if (ret) {
        fprintf(stderr, "pscnv_virt: Could not create DMA chan (%d)\n", ret);
        return -1;
    }
    /* TODO: channel size on nv50 */
    (*dma)->chan = mmap(NULL, 0x1000, PROT_READ | PROT_WRITE, MAP_SHARED,
                        drm_fd, chan_map_handle);
    if ((*dma)->chan == MAP_FAILED) {
        fprintf(stderr, "pscnv_virt: Could not map DMA channel.\n");
        return -1;
    }
    /* create indirect buffer and pushbuffer */
    // TODO
#endif
    /* create a channel for DMA commands */
    /* TODO: nv50 support? */
    ret = pscnv_ib_chan_new(drm_fd, (*dma)->vspace_handle, &chan,
                            0, 0, 0, 0xc0);
    if (ret) {
        fprintf(stderr, "pscnv_virt: Could not create DMA chan (%d)\n", ret);
        return -1;
    }
    (*dma)->chan = chan;
    /* create a fence buffer for m2mf operations */
    ret = pscnv_ib_bo_alloc((*dma)->drm_fd, (*dma)->vspace_handle, 0,
                            PSCNV_GEM_SYSRAM_SNOOP | PSCNV_GEM_MAPPABLE, 0,
                            0x1000, 0, &(*dma)->fence_bo);
    if (ret) {
        fprintf(stderr, "pscnv_virt: Could not create the DMA fence buffer.\n");
        return -1;
    }
    (*dma)->fence = (*dma)->fence_bo->map;
    (*dma)->fence_addr = (*dma)->fence_bo->vm_base;
    /* initialize M2MF for the channel */
    for (i = 0; i < 128/4; i++) {
        OUT_RING(chan, 0);
    }
    FIRE_RING(chan);
    BEGIN_RING_NVC0(chan, GDEV_SUBCH_NV_M2MF, 0, 1);
    OUT_RING(chan, 0x9039); /* M2MF */
    FIRE_RING(chan);
    return 0;
}
int pscnv_dma_uninit(struct pscnv_dma *dma) {
    /* TODO: free the channel */
    pscnv_ib_bo_free(dma->fence_bo);
    free(dma);
    return 0;
}
void *pscnv_dma_to_sysram(struct pscnv_dma *dma, uint32_t handle,
                          uint64_t size) {
    int ret;
    uint64_t src_offset;
    struct pscnv_ib_bo *dst;
    uint64_t dst_offset;
    void *result;

    /* map the buffer into the dma address space */
    ret = pscnv_vspace_map(dma->drm_fd, dma->vspace_handle, handle, 0x20000000,
                           1ull << 40, 0, 0, &src_offset);
    if (ret) {
        fprintf(stderr, "Could not map buffer into DMA address space.\n");
        return NULL;
    }
    /* allocate and map a new buffer for the result (in system RAM!) */
    ret = pscnv_ib_bo_alloc(dma->drm_fd, dma->vspace_handle, 0,
                            PSCNV_GEM_SYSRAM_SNOOP | PSCNV_GEM_MAPPABLE, 0,
                            size, 0, &dst);
    if (ret) {
        fprintf(stderr, "pscnv_virt: Could not create test data.\n");
        return NULL;
    }
    dst_offset = dst->vm_base;
    /* initialize the M2MF transfer */
    fprintf(stderr, "dst: %"PRIx64", std: %"PRIx64"\n", dst_offset, src_offset);
    *dma->fence = 0;
    BEGIN_RING_NVC0(dma->chan, GDEV_SUBCH_NV_M2MF, 0x32c, 3);
    OUT_RING(dma->chan, dma->fence_addr >> 32); /* QUERY_ADDRESS HIGH */
    OUT_RING(dma->chan, dma->fence_addr); /* QUERY_ADDRESS LOW */
    OUT_RING(dma->chan, 1); /* QUERY_SEQUENCE */
    FIRE_RING(dma->chan);
    nvc0_memcpy_m2mf(dma->chan, dst_offset, src_offset, size);
    /* wait for the transfer to end */
    while (*dma->fence != 1);
    /* remove the result buffer (the data is only freed when the caller calls
     * munmap on the return value) */
    result = dst->map;
    dst->map = NULL;
    pscnv_ib_bo_free(dst);
    return result;
}

int pscnv_dma_test(struct pscnv_dma *dma) {
    int ret;
    struct pscnv_ib_bo *src;
    uint64_t write_start = 0;
    uint64_t write_end = 0;
    uint64_t read_start = 0;
    uint64_t read_end = 0;
    uint64_t dma_start = 0;
    uint64_t dma_end = 0;
    uint64_t read_dma_start = 0;
    uint64_t read_dma_end = 0;
    uint64_t size = 0x1000000;
    void *read_buffer = malloc(size);
    void *copy;
    double read, write, dma_copy, read_dma;

    ret = pscnv_ib_bo_alloc(dma->drm_fd, 0, 0, PSCNV_GEM_MAPPABLE, 0,
                            size, 0, &src);
    if (ret) {
        fprintf(stderr, "pscnv_virt: Could not create test data.\n");
        return -1;
    }
    write_start = get_time();
    memset(src->map, 0x12, size);
    write_end = get_time();
    read_start = get_time();
    memcpy(read_buffer, src->map, size);
    read_end = get_time();

    dma_start = get_time();
    copy = pscnv_dma_to_sysram(dma, src->handle, size);
    if (copy == NULL) {
        fprintf(stderr, "pscnv_virt: DMA test failed.\n");
        return -1;
    }
    dma_end = get_time();
    read_dma_start = get_time();
    memcpy(read_buffer, copy, size);
    read_dma_end = get_time();
    
    read = (double)(read_end - read_start) / 1000;
    write = (double)(write_end - write_start) / 1000;
    fprintf(stderr, "without DMA: %lf ms write, %lf ms read\n", write, read);
    dma_copy = (double)(dma_end - dma_start) / 1000;
    read_dma = (double)(read_dma_end - read_dma_start) / 1000;
    fprintf(stderr, "DMA: %lf ms copy, %lf ms read\n", dma_copy, read_dma);

    fprintf(stderr, "data: %08x, %08x\n", ((uint32_t*)read_buffer)[0], ((uint32_t*)read_buffer)[0xffffff / 4]);

    pscnv_ib_bo_free(src);
    munmap(copy, size);
    free(read_buffer);
    return -1;
}

