
#include "pscnv_virt.h"

#include <libpscnv.h>
#include <xf86drm.h>
#include <sys/mman.h>

/**
 * Finds a free entry in the chan memory region.
 */
static char allocate_chan(PscnvState *d) {
    unsigned int i;
    for (i = 0; i < PSCNV_VIRT_CHAN_COUNT; i++) {
        if (d->chan_handle[i] == (uint32_t)-1) {
            return i;
        }
    }
    return -1;
}

static struct pscnv_memory_area *allocate_memory(PscnvState *d,
                                                 uint32_t size) {
    struct pscnv_memory_area *area = d->memory_areas;
    /* first-fit search for a memory area */
    while (area != NULL
            && (area->size < size || area->handle != (uint32_t)-1)) {
        area = area->next;
    }
    if (area == NULL) {
        return NULL;
    }
    if (area->size != size) {
        /* split the area */
        struct pscnv_memory_area *splitted = malloc(sizeof(*splitted));
        splitted->prev = area;
        splitted->next = area->next;
        splitted->start = area->start + size;
        splitted->size = area->size - size;
        splitted->handle = -1;
        area->next = splitted;
        area->size = size;
    }
    return area;
}

void pscnv_free_memory(PscnvState *d, struct pscnv_memory_area *area) {
    area->handle = -1;
    if (area->prev != NULL && area->prev->handle == (uint32_t)-1) {
        area = area->prev;
    }
    /* merge the area with adjacent free areas */
    struct pscnv_memory_area *next = area->next;
    while (next != NULL && next->handle == (uint32_t)-1) {
        area->next = next->next;
        if (next->next != NULL) {
            next->next->prev = area;
        }
        area->size += next->size;
        free(next);
        next = area->next;
    }
}

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

void pscnv_add_vspace_mapping(PscnvState *d, uint32_t vspace,
                              uint32_t obj_handle, uint64_t offset) {
    struct pscnv_memory_allocation *obj = &d->alloc_data[obj_handle];
    struct pscnv_vspace_mapping *mapping = malloc(sizeof(*mapping));
    mapping->obj = obj_handle;
    mapping->vspace = vspace;
    mapping->offset = offset;
    mapping->obj_prev = NULL;
    mapping->obj_next = obj->vspace_mapping;
    if (obj->vspace_mapping != NULL) {
        obj->vspace_mapping->obj_prev = mapping;
    }
    obj->vspace_mapping = mapping;
    mapping->vspace_prev = NULL;
    mapping->vspace_next = d->vspace_mapping[vspace];
    if (d->vspace_mapping[vspace] != NULL) {
        d->vspace_mapping[vspace]->vspace_prev = mapping;
    }
    d->vspace_mapping[vspace] = mapping;
}
void pscnv_remove_vspace_mapping(PscnvState *d,
                                 struct pscnv_vspace_mapping *mapping) {
    if (mapping->obj_prev != NULL) {
        mapping->obj_prev->obj_next = mapping->obj_next;
    } else {
        d->alloc_data[mapping->obj].vspace_mapping = mapping->obj_next;
    }
    if (mapping->obj_next != NULL) {
        mapping->obj_next->obj_prev = mapping->obj_prev;
    }
    if (mapping->vspace_prev != NULL) {
        mapping->vspace_prev->vspace_next = mapping->vspace_next;
    } else {
        d->vspace_mapping[mapping->vspace] = mapping->vspace_next;
    }
    if (mapping->vspace_next != NULL) {
        mapping->vspace_next->vspace_prev = mapping->vspace_prev;
    }
    free(mapping);
}

static void pscnv_execute_mem_alloc(PscnvState *d,
                                    volatile struct pscnv_alloc_mem_cmd *cmd) {
    int ret;
    struct pscnv_memory_allocation result;

#ifdef DUMP_HYPERCALLS
    fprintf(stderr, "pscnv_gem_new 0x%x 0x%x 0x%x 0x%"PRIx64"\n",
            cmd->cookie, cmd->flags, cmd->tile_flags, cmd->size);
#endif
    /* allocate a gem object */
    ret = pscnv_gem_new(d->drm_fd, cmd->cookie, cmd->flags, cmd->tile_flags,
                        cmd->size, NULL, &result.handle, &result.map_handle);
    if (ret != 0) {
        fprintf(stderr, "pscnv_gem_new failed: %d\n", ret);
        cmd->command = PSCNV_RESULT_ERROR;
        return;
    }
    result.cookie = cmd->cookie;
    result.flags = cmd->flags;
    result.tile_flags = cmd->tile_flags;
    result.size = (cmd->size + 0xfff) & ~0xfff;
    result.mapping = NULL;
    result.vspace_mapping = NULL;
    cmd->handle = add_allocation_entry(d, &result);
#ifdef DUMP_HYPERCALLS
    fprintf(stderr, "pscnv_gem_new: allocated %"PRIx64" bytes, handle %d\n",
            cmd->size, cmd->handle);
#endif

    cmd->command = PSCNV_RESULT_NO_ERROR;

    /* add an entry into the migration log if necessary */
    if (d->migration_active) {
        qemu_mutex_lock(&d->migration_log_lock);
        pscnv_add_migration_log_entry(d, cmd->handle, PSCNV_MIGRATION_LOG_ALLOC);
        qemu_mutex_unlock(&d->migration_log_lock);
    }
}

static void pscnv_execute_map(PscnvState *d,
                              volatile struct pscnv_map_cmd *cmd) {
    void *mapped;
    struct pscnv_memory_allocation *obj;
    /*unsigned int page_count, i, prev_page, first_page = 0;*/
    /*void *remapped;*/

#ifdef DUMP_HYPERCALLS
    fprintf(stderr, "pscnv_virt: vm wants to map %d\n", cmd->handle);
#endif

    if (cmd->handle >= d->alloc_count
            || d->alloc_data[cmd->handle].size == (uint64_t)-1) {
        fprintf(stderr, "pscnv_virt: invalid handle %d (size: %"PRIx64", objects: %d)\n",
                cmd->handle, d->alloc_data[cmd->handle].size, d->alloc_count);
        cmd->command = PSCNV_RESULT_ERROR;
        return;
    }
    obj = &d->alloc_data[cmd->handle];
    /* check whether the object is already mapped */
    if (obj->mapping != NULL) {
        cmd->start = obj->mapping->start;
        cmd->command = PSCNV_RESULT_NO_ERROR;
    }
    /* find some free space in the vram bar */
    obj->mapping = allocate_memory(d, obj->size);
    if (obj->mapping == NULL) {
        fprintf(stderr, "pscnv_virt: no space left to map %"PRIx64" bytes\n",
                obj->size);
        cmd->command = PSCNV_RESULT_ERROR;
        return;
    }
    obj->mapping->handle = cmd->handle;
    /* map the gem object */
    if (d->migration_active == 0) {
        /* TODO: access rights? */
        mapped = mmap(d->vram_bar_memory + obj->mapping->start, obj->size,
                PROT_READ | PROT_WRITE, MAP_SHARED | MAP_FIXED, d->drm_fd,
                obj->map_handle);
        if (((uintptr_t)mapped & PAGE_MASK) != 0) {
            fprintf(stderr, "pscnv_virt: mapped data not page-aligned: %p\n",
                    mapped);
            cmd->command = PSCNV_RESULT_ERROR;
            return;
        }
    } else {
        obj->migration_mapping = mmap(NULL, obj->size,
                PROT_READ | PROT_WRITE, MAP_SHARED, d->drm_fd,
                obj->map_handle);
        if (obj->migration_mapping == MAP_FAILED) {
            fprintf(stderr, "pscnv_virt: could not map obj: %d\n",
                    cmd->handle);
            cmd->command = PSCNV_RESULT_ERROR;
            return;
        }
        memcpy(d->vram_bar_memory + obj->mapping->start,
               obj->migration_mapping, obj->size);
    }
#ifdef DUMP_HYPERCALLS
        fprintf(stderr, "pscnv_virt: mapped %d to %x\n",
                cmd->handle, obj->mapping->start);
#endif
    cmd->start = obj->mapping->start;
    cmd->command = PSCNV_RESULT_NO_ERROR;

    /* add an entry into the migration log if necessary */
    if (d->migration_active) {
        qemu_mutex_lock(&d->migration_log_lock);
        pscnv_add_migration_log_entry(d, cmd->handle, PSCNV_MIGRATION_LOG_MAP);
        qemu_mutex_unlock(&d->migration_log_lock);
    }
}

static void pscnv_execute_mem_free(PscnvState *d,
                                   volatile struct pscnv_free_mem_cmd *cmd) {
    struct pscnv_memory_allocation *obj;
    void *result;
#ifdef DUMP_HYPERCALL
    fprintf(stderr, "pscnv_mem_free: %d\n", cmd->handle);
#endif
    if (cmd->handle >= d->alloc_count
            || d->alloc_data[cmd->handle].size == (uint64_t)-1) {
        fprintf(stderr, "pscnv_virt: invalid handle %d (size: %"PRIx64", objects: %d)\n",
                cmd->handle, d->alloc_data[cmd->handle].size, d->alloc_count);
        cmd->command = PSCNV_RESULT_ERROR;
        return;
    }
    obj = &d->alloc_data[cmd->handle];
    /* free the underlying gpu buffer */
    pscnv_gem_close(d->drm_fd, obj->handle);
    /* clear the mapping */
    if (obj->mapping != NULL) {
        result = mmap(d->vram_bar_memory + obj->mapping->start, obj->size,
                PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
        if (result == MAP_FAILED) {
            fprintf(stderr, "pscnv_virt: could not unmap %d\n", cmd->handle);
        }
        /* mark the memory area as free */
        pscnv_free_memory(d, obj->mapping);
    }
    /* free the allocation list entry */
    obj->next = d->alloc_freelist;
    d->alloc_freelist = cmd->handle;

    cmd->command = PSCNV_RESULT_NO_ERROR;

    /* add an entry into the migration log if necessary */
    if (d->migration_active) {
        int removed;
        qemu_mutex_lock(&d->migration_log_lock);
        removed = pscnv_remove_migration_log_entries(d, cmd->handle,
                                                     PSCNV_MIGRATION_LOG_ALLOC |
                                                     PSCNV_MIGRATION_LOG_MAP |
                                                     PSCNV_MIGRATION_LOG_UNMAP);
        if ((removed & PSCNV_MIGRATION_LOG_ALLOC) != 0) {
            pscnv_add_migration_log_entry(d, cmd->handle,
                                          PSCNV_MIGRATION_LOG_FREE);
        }
        qemu_mutex_unlock(&d->migration_log_lock);
    }
}
static void pscnv_execute_vspace_alloc(PscnvState *d,
                                       volatile struct pscnv_vspace_cmd *cmd)
{
    uint32_t vid;
    int ret;
    int i;
    uint32_t handle = (uint32_t)-1;

    ret = pscnv_vspace_new(d->drm_fd, &vid);
    if (ret) {
        fprintf(stderr, "pscnv_virt: pscnv_vspace_new failed (%d)\n", ret);
        cmd->command = PSCNV_RESULT_ERROR;
        return;
    }
#ifdef DUMP_HYPERCALLS
    fprintf(stderr, "pscnv_vspace_new: allocated %d\n", vid);
#endif
    for (i = 0; i < PSCNV_VIRT_VSPACE_COUNT; i++) {
        if (d->vspace_handle[i] == (uint32_t)-1) {
            d->vspace_handle[i] = vid;
            d->vspace_mapping[i] = NULL;
            handle = i;
            break;
        }
    }
    if (handle == (uint32_t)-1) {
        fprintf(stderr, "pscnv_vspace_new: Too many vspaces!\n");
    }
    cmd->vid = handle;
    cmd->command = PSCNV_RESULT_NO_ERROR;
}

static void pscnv_execute_vspace_free(PscnvState *d,
                                      volatile struct pscnv_vspace_cmd *cmd)
{
    int ret;
    uint32_t vid;

    if (cmd->vid >= PSCNV_VIRT_VSPACE_COUNT
            || d->vspace_handle[cmd->vid] == (uint32_t)-1) {
        fprintf(stderr, "pscnv_virt: pscnv_execute_vspace_free invalid vid %d\n", cmd->vid);
        cmd->command = PSCNV_RESULT_ERROR;
        return;
    }
    vid = d->vspace_handle[cmd->vid];
#ifdef DUMP_HYPERCALLS
    fprintf(stderr, "pscnv_vspace_free: freeing %d\n", cmd->vid);
#endif
    while (d->vspace_mapping[cmd->vid] != NULL) {
        pscnv_remove_vspace_mapping(d, d->vspace_mapping[cmd->vid]);
    }
    d->vspace_handle[cmd->vid] = (uint32_t)-1;
    ret = pscnv_vspace_free(d->drm_fd, vid);
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
    uint32_t vid;

#ifdef DUMP_HYPERCALLS
    fprintf(stderr, "pscnv_vspace_map: %d %d 0x%"PRIx64" 0x%"PRIx64" 0x%x 0x%x\n",
            cmd->vid, cmd->handle, cmd->start, cmd->end, cmd->back, cmd->flags);
#endif
    if (cmd->handle >= d->alloc_count
            || d->alloc_data[cmd->handle].size == (uint64_t)-1) {
        fprintf(stderr, "pscnv_virt: invalid handle %d (size: %"PRIx64", objects: %d)\n",
                cmd->handle, d->alloc_data[cmd->handle].size, d->alloc_count);
        cmd->command = PSCNV_RESULT_ERROR;
        return;
    }
    if (cmd->vid >= PSCNV_VIRT_VSPACE_COUNT
            || d->vspace_handle[cmd->vid] == (uint32_t)-1) {
        fprintf(stderr, "pscnv_virt: pscnv_execute_vspace_map invalid vid %d\n", cmd->vid);
        cmd->command = PSCNV_RESULT_ERROR;
        return;
    }
    vid = d->vspace_handle[cmd->vid];

    ret = pscnv_vspace_map(d->drm_fd, vid,
                           d->alloc_data[cmd->handle].handle, cmd->start,
                           cmd->end, cmd->back, cmd->flags, &offset);
    if (ret != 0) {
        fprintf(stderr, "pscnv_vspace_map failed (%d)\n", ret);
        cmd->command = PSCNV_RESULT_ERROR;
        return;
    }
    // add mapping list entry
    pscnv_add_vspace_mapping(d, cmd->vid, cmd->handle, offset);
#ifdef DUMP_HYPERCALLS
    fprintf(stderr, "pscnv_vspace_map: result 0x%"PRIx64"\n",
            offset);
#endif
    cmd->offset = offset;
    cmd->command = PSCNV_RESULT_NO_ERROR;
}

static void pscnv_execute_vspace_unmap(PscnvState *d,
                                       volatile struct pscnv_vspace_unmap_cmd *cmd)
{
    int ret;
    uint32_t vid;
    struct pscnv_vspace_mapping *mapping;

#ifdef DUMP_HYPERCALLS
    fprintf(stderr, "pscnv_vspace_unmap: %d 0x%"PRIx64"\n",
            cmd->vid, cmd->offset);
#endif
    if (cmd->vid >= PSCNV_VIRT_VSPACE_COUNT
            || d->vspace_handle[cmd->vid] == (uint32_t)-1) {
        fprintf(stderr, "pscnv_virt: pscnv_execute_vspace_unmap invalid vid %d\n", cmd->vid);
        cmd->command = PSCNV_RESULT_ERROR;
        return;
    }
    vid = d->vspace_handle[cmd->vid];

    ret = pscnv_vspace_unmap(d->drm_fd, vid, cmd->offset);
    if (ret != 0) {
        fprintf(stderr, "pscnv_vspace_unmap failed (%d)\n", ret);
        cmd->command = PSCNV_RESULT_ERROR;
        return;
    }

    // remove mapping list entry
    mapping = d->vspace_mapping[cmd->vid];
    while (mapping != NULL) {
        if (mapping->offset == cmd->offset) {
            pscnv_remove_vspace_mapping(d, mapping);
            break;
        }
    }

    cmd->command = PSCNV_RESULT_NO_ERROR;
}

static void pscnv_execute_chan_new(PscnvState *d,
                                   volatile struct pscnv_chan_new_cmd *cmd)
{
    uint32_t cid;
    uint32_t chan_index;
    uint64_t map_handle;
    int ret;
    unsigned int chsize;
    void *chmem;
    uint32_t vid;

#ifdef DUMP_HYPERCALLS
    fprintf(stderr, "pscnv_chan_new: %d\n", cmd->vid);
#endif
    if (cmd->vid >= PSCNV_VIRT_VSPACE_COUNT
            || d->vspace_handle[cmd->vid] == (uint32_t)-1) {
        fprintf(stderr, "pscnv_virt: pscnv_execute_vspace_unmap invalid vid %d\n", cmd->vid);
        cmd->command = PSCNV_RESULT_ERROR;
        return;
    }
    vid = d->vspace_handle[cmd->vid];

    if (d->migration_active == 0) {
        ret = pscnv_chan_new(d->drm_fd, vid, &cid, &map_handle);
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
        chan_index = allocate_chan(d);
        assert(chan_index < PSCNV_VIRT_CHAN_COUNT);
        chsize = d->is_nv50 ? 0x2000 : 0x1000;
        chmem = mmap(d->chan_bar_memory + chan_index * chsize, chsize,
                     PROT_READ | PROT_WRITE, MAP_SHARED | MAP_FIXED, d->drm_fd,
                     map_handle);
        if (chmem == MAP_FAILED) {
            fprintf(stderr, "pscnv_virt: Could not map channel %d\n", cid);
            cmd->command = PSCNV_RESULT_ERROR;
            return;
        }
    } else {
        chan_index = allocate_chan(d);
        cid = 0;
        chsize = d->is_nv50 ? 0x2000 : 0x1000;
        memset(d->chan_bar_memory + chan_index * chsize, 0, chsize);
    }
    d->chan_handle[chan_index] = cid;
    d->chan_vspace[chan_index] = cmd->vid;
    d->fifo_init[chan_index].command = -1;

#ifdef DUMP_HYPERCALLS
    fprintf(stderr, "pscnv_chan_new: result %d (%d)\n", cid, chan_index);
#endif
    cmd->cid = chan_index;
    cmd->command = PSCNV_RESULT_NO_ERROR;

}
static void pscnv_execute_chan_free(PscnvState *d,
                                    volatile struct pscnv_chan_free_cmd *cmd)
{
    int ret;
    void *chmem;
    unsigned int chsize;
    uint32_t cid;

    if (cmd->cid >= PSCNV_VIRT_CHAN_COUNT
            || d->chan_handle[cmd->cid] == (uint32_t)-1) {
        fprintf(stderr, "pscnv_virt: pscnv_chan_free invalid cid %d\n", cmd->cid);
        cmd->command = PSCNV_RESULT_ERROR;
        return;
    }
    cid = d->chan_handle[cmd->cid];
#ifdef DUMP_HYPERCALLS
    fprintf(stderr, "pscnv_chan_free: %d (%d)\n", cid, cmd->cid);
#endif
    if (d->migration_active == 0) {
        /* delete that channel */
        ret = pscnv_chan_free(d->drm_fd, cid);
        if (ret) {
            fprintf(stderr, "pscnv_virt: pscnv_chan_free failed (%d)\n", ret);
            cmd->command = PSCNV_RESULT_ERROR;
            return;
        }

        /* unmap the channel */
        chsize = d->is_nv50 ? 0x2000 : 0x1000;
        chmem = mmap(d->chan_bar_memory + cmd->cid * chsize, chsize, PROT_NONE,
                                  MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
        if (chmem == MAP_FAILED) {
            fprintf(stderr, "pscnv_virt: could not unmap channel %d\n", cmd->cid);
            cmd->command = PSCNV_RESULT_ERROR;
            return;
        }
    }

    d->chan_handle[cmd->cid] = (uint32_t)-1;

    cmd->command = PSCNV_RESULT_NO_ERROR;

}

static void pscnv_execute_obj_vdma_new(PscnvState *d,
                                    volatile struct pscnv_obj_vdma_new_cmd *cmd)
{
    uint32_t cid;

    if (cmd->cid >= PSCNV_VIRT_CHAN_COUNT
            || d->chan_handle[cmd->cid] == (uint32_t)-1) {
        fprintf(stderr, "pscnv_virt: pscnv_execute_obj_vdma_new invalid cid %d\n", cmd->cid);
        cmd->command = PSCNV_RESULT_ERROR;
        return;
    }
    cid = d->chan_handle[cmd->cid];
#ifdef DUMP_HYPERCALLS
    fprintf(stderr, "pscnv_obj_vdma_new: %d (%d) 0x%x 0x%x 0x%x 0x%"PRIx64" 0x%"PRIx64"\n",
            cid, cmd->cid, cmd->handle, cmd->oclass, cmd->flags, cmd->start, cmd->size);
#endif
    cmd->ret = pscnv_obj_vdma_new(d->drm_fd, cid, cmd->handle, cmd->oclass,
                                  cmd->flags, cmd->start, cmd->size);
    cmd->command = PSCNV_RESULT_NO_ERROR;
}

static void pscnv_execute_obj_eng_new(PscnvState *d,
                                    volatile struct pscnv_obj_eng_new_cmd *cmd)
{
    uint32_t cid;

    if (cmd->cid >= PSCNV_VIRT_CHAN_COUNT
            || d->chan_handle[cmd->cid] == (uint32_t)-1) {
        fprintf(stderr, "pscnv_virt: pscnv_execute_obj_eng_new invalid cid %d\n", cmd->cid);
        cmd->command = PSCNV_RESULT_ERROR;
        return;
    }
    cid = d->chan_handle[cmd->cid];
#ifdef DUMP_HYPERCALLS
    fprintf(stderr, "pscnv_obj_eng_new: %d (%d) 0x%x 0x%x 0x%x\n",
            cid, cmd->cid, cmd->handle, cmd->oclass, cmd->flags);
#endif
    cmd->ret = pscnv_obj_eng_new(d->drm_fd, cid, cmd->handle, cmd->oclass,
                                 cmd->flags);
    cmd->command = PSCNV_RESULT_NO_ERROR;
}

static void pscnv_execute_fifo_init(PscnvState *d,
                                    volatile struct pscnv_fifo_init_cmd *cmd)
{
    uint32_t cid;

    if (cmd->cid >= PSCNV_VIRT_CHAN_COUNT
            || d->chan_handle[cmd->cid] == (uint32_t)-1) {
        fprintf(stderr, "pscnv_virt: pscnv_execute_fifo_init invalid cid %d\n", cmd->cid);
        cmd->command = PSCNV_RESULT_ERROR;
        return;
    }
    cid = d->chan_handle[cmd->cid];
#ifdef DUMP_HYPERCALLS
    fprintf(stderr, "pscnv_fifo_init: %d (%d) 0x%x 0x%x 0x%x 0x%"PRIx64"\n",
            cid, cmd->cid, cmd->pb_handle, cmd->flags, cmd->slimask, cmd->pb_start);
#endif
    cmd->ret = pscnv_fifo_init(d->drm_fd, cid, cmd->pb_handle, cmd->flags,
                               cmd->slimask, cmd->pb_start);
    cmd->command = PSCNV_RESULT_NO_ERROR;
}

static void pscnv_execute_fifo_init_ib(PscnvState *d,
                                    volatile struct pscnv_fifo_init_ib_cmd *cmd)
{
    uint32_t cid;

    if (cmd->cid >= PSCNV_VIRT_CHAN_COUNT
            || d->chan_handle[cmd->cid] == (uint32_t)-1) {
        fprintf(stderr, "pscnv_virt: pscnv_execute_fifo_init_ib invalid cid %d\n", cmd->cid);
        cmd->command = PSCNV_RESULT_ERROR;
        return;
    }
    cid = d->chan_handle[cmd->cid];
#ifdef DUMP_HYPERCALLS
    fprintf(stderr, "pscnv_fifo_init_ib: %d (%d) 0x%x 0x%x 0x%x 0x%"PRIx64" 0x%x\n",
            cid, cmd->cid, cmd->pb_handle, cmd->flags, cmd->slimask, cmd->ib_start,
            cmd->ib_order);
#endif
    if (d->migration_active == 0) {
        cmd->ret = pscnv_fifo_init_ib(d->drm_fd, cid, cmd->pb_handle,
                                      cmd->flags, cmd->slimask, cmd->ib_start,
                                      cmd->ib_order);
    }
    cmd->command = PSCNV_RESULT_NO_ERROR;

    d->fifo_init[cmd->cid] = *cmd;
}

static void pscnv_execute_hypercall(PscnvState *d, uint32_t call_addr)
{
    volatile uint32_t *call_data = (uint32_t*)(d->call_area_memory + call_addr);
    uint32_t command = call_data[0];

    //fprintf(stderr, "pscnv_virt: command 0x%x.\n", command);
    switch (command) {
    case PSCNV_CMD_GET_PARAM:
        /* TODO: remove this */
        //fprintf(stderr, "pscnv_virt: PSCNV_CMD_GET_PARAM.\n");
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
    case PSCNV_CMD_MEM_FREE:
        pscnv_execute_mem_free(d, (volatile struct pscnv_free_mem_cmd*)call_data);
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
    case PSCNV_CMD_OBJ_VDMA_NEW:
        pscnv_execute_obj_vdma_new(d, (volatile struct pscnv_obj_vdma_new_cmd*)call_data);
        break;
    case PSCNV_CMD_OBJ_ENG_NEW:
        pscnv_execute_obj_eng_new(d, (volatile struct pscnv_obj_eng_new_cmd*)call_data);
        break;
    case PSCNV_CMD_FIFO_INIT:
        pscnv_execute_fifo_init(d, (volatile struct pscnv_fifo_init_cmd*)call_data);
        break;
    case PSCNV_CMD_FIFO_INIT_IB:
        pscnv_execute_fifo_init_ib(d, (volatile struct pscnv_fifo_init_ib_cmd*)call_data);
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
//#ifdef PSCNV_DEBUG_IO
    fprintf(stderr, "pscnv_mmio_readl addr=0x" TARGET_FMT_plx " val=0x%08x\n",
            addr, val);
//#endif
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

#ifdef PSCNV_DEBUG_CHAN_ACCESS
static void pscnv_chan_writeb(void *opaque, target_phys_addr_t addr, uint32_t val)
{
    PscnvState *d = opaque;
    fprintf(stderr, "pscnv_chan_writeb addr=0x" TARGET_FMT_plx" val=0x%02x\n",
            addr, val);
    *(uint8_t*)((char*)d->chan_bar_memory + addr) = val;
}

static uint32_t pscnv_chan_readb(void *opaque, target_phys_addr_t addr)
{
    PscnvState *d = opaque;
    uint32_t val = *(uint8_t*)((char*)d->chan_bar_memory + addr);
    fprintf(stderr, "pscnv_chan_readb addr=0x" TARGET_FMT_plx " val=0x%02x\n",
            addr, val & 0xff);
    return val;
}

static void pscnv_chan_writew(void *opaque, target_phys_addr_t addr, uint32_t val)
{
    PscnvState *d = opaque;
    fprintf(stderr, "pscnv_chan_writew addr=0x" TARGET_FMT_plx " val=0x%04x\n",
            addr, val);
    *(uint16_t*)((char*)d->chan_bar_memory + addr) = val;
}

static uint32_t pscnv_chan_readw(void *opaque, target_phys_addr_t addr)
{
    PscnvState *d = opaque;
    uint32_t val = *(uint16_t*)((char*)d->chan_bar_memory + addr);
    fprintf(stderr, "pscnv_chan_readw addr=0x" TARGET_FMT_plx" val = 0x%04x\n",
            addr, val & 0xffff);
    return val;
}

static void pscnv_chan_writel(void *opaque, target_phys_addr_t addr, uint32_t val)
{
    PscnvState *d = opaque;
    fprintf(stderr, "pscnv_chan_writel addr=0x" TARGET_FMT_plx" val=0x%08x\n",
            addr, val);
    *(uint32_t*)((char*)d->chan_bar_memory + addr) = val;
}

static uint32_t pscnv_chan_readl(void *opaque, target_phys_addr_t addr)
{
    PscnvState *d = opaque;
    uint32_t val = *(uint32_t*)((char*)d->chan_bar_memory + addr);
    fprintf(stderr, "pscnv_chan_readl addr=0x" TARGET_FMT_plx " val=0x%08x\n",
            addr, val);
    return val;
}

static const MemoryRegionOps pscnv_chan_debug_ops = {
    .old_mmio = {
        .read = { pscnv_chan_readb, pscnv_chan_readw, pscnv_chan_readl },
        .write = { pscnv_chan_writeb, pscnv_chan_writew, pscnv_chan_writel },
    },
    .endianness = DEVICE_NATIVE_ENDIAN,
};

#endif

#ifdef PSCNV_DEBUG_VRAM_ACCESS
static void pscnv_vram_writeb(void *opaque, target_phys_addr_t addr, uint32_t val)
{
    PscnvState *d = opaque;
    fprintf(stderr, "pscnv_vram_writeb addr=0x" TARGET_FMT_plx" val=0x%02x\n",
            addr, val);
    *(uint8_t*)((char*)d->vram_bar_memory + addr) = val;
}

static uint32_t pscnv_vram_readb(void *opaque, target_phys_addr_t addr)
{
    PscnvState *d = opaque;
    uint32_t val = *(uint8_t*)((char*)d->vram_bar_memory + addr);
    fprintf(stderr, "pscnv_vram_readb addr=0x" TARGET_FMT_plx " val=0x%02x\n",
            addr, val & 0xff);
    return val;
}

static void pscnv_vram_writew(void *opaque, target_phys_addr_t addr, uint32_t val)
{
    PscnvState *d = opaque;
    fprintf(stderr, "pscnv_vram_writew addr=0x" TARGET_FMT_plx " val=0x%04x\n",
            addr, val);
    *(uint16_t*)((char*)d->vram_bar_memory + addr) = val;
}

static uint32_t pscnv_vram_readw(void *opaque, target_phys_addr_t addr)
{
    PscnvState *d = opaque;
    uint32_t val = *(uint16_t*)((char*)d->vram_bar_memory + addr);
    fprintf(stderr, "pscnv_vram_readw addr=0x" TARGET_FMT_plx" val = 0x%04x\n",
            addr, val & 0xffff);
    return val;
}

static void pscnv_vram_writel(void *opaque, target_phys_addr_t addr, uint32_t val)
{
    PscnvState *d = opaque;
    fprintf(stderr, "pscnv_vram_writel addr=0x" TARGET_FMT_plx" val=0x%08x\n",
            addr, val);
    *(uint32_t*)((char*)d->vram_bar_memory + addr) = val;
}

static uint32_t pscnv_vram_readl(void *opaque, target_phys_addr_t addr)
{
    PscnvState *d = opaque;
    uint32_t val = *(uint32_t*)((char*)d->vram_bar_memory + addr);
    fprintf(stderr, "pscnv_vram_readl addr=0x" TARGET_FMT_plx " val=0x%08x\n",
            addr, val);
    return val;
}

static const MemoryRegionOps pscnv_vram_debug_ops = {
    .old_mmio = {
        .read = { pscnv_vram_readb, pscnv_vram_readw, pscnv_vram_readl },
        .write = { pscnv_vram_writeb, pscnv_vram_writew, pscnv_vram_writel },
    },
    .endianness = DEVICE_NATIVE_ENDIAN,
};

#endif

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

    munmap(d->vram_bar_memory, PSCNV_VIRT_VRAM_SIZE);
    munmap(d->chan_bar_memory, d->chan_bar_size);
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
    /* TODO: this does not work? o.O */
    /*d->gpu_info[PSCNV_INFO_GRAPH_UNITS] =
            read_gpu_info(d, PSCNV_GETPARAM_GRAPH_UNITS);*/
    /* TODO: these are not defined in libdrm_pscnv */
    d->gpu_info[PSCNV_INFO_GPC_COUNT] =
            read_gpu_info(d, /*PSCNV_GETPARAM_GPC_COUNT*/ 15);
    d->gpu_info[PSCNV_INFO_TP_COUNT_IDX] =
            read_gpu_info(d, /*PSCNV_GETPARAM_TP_COUNT_IDX*/ 16);
    d->gpu_info[PSCNV_INFO_MP_COUNT] =
            read_gpu_info(d, /*PSCNV_GETPARAM_MP_COUNT*/ 100);

    /* allocation struct freelist */
    d->alloc_data = calloc(sizeof(struct pscnv_memory_allocation), 16);
    d->alloc_count = 16;
    d->alloc_freelist = 0;
    for (i = 0; i < 16; i++) {
        d->alloc_data[i].size = -1;
        d->alloc_data[i].next = i + 1;
    }
    d->alloc_data[15].next = -1;

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

    /* allocate contiguous virtual address space for the vram bar */
    d->vram_bar_memory = mmap(NULL, PSCNV_VIRT_VRAM_SIZE, PROT_READ | PROT_WRITE,
                              MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (d->vram_bar_memory == MAP_FAILED) {
        hw_error("%s: could not allocate vram bar memory\n", __func__);
    }
    d->chan_bar_memory = mmap(NULL, d->chan_bar_size, PROT_READ | PROT_WRITE,
                              MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (d->vram_bar_memory == MAP_FAILED) {
        hw_error("%s: could not allocate chan bar memory\n", __func__);
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

#ifdef PSCNV_DEBUG_VRAM_ACCESS
    memory_region_init_io(&d->vram_bar, &pscnv_vram_debug_ops, d, "pscnv-vram",
                          PSCNV_VIRT_VRAM_SIZE);
#else
    memory_region_init_ram_ptr(&d->vram_bar, "pscnv-vram",
                               PSCNV_VIRT_VRAM_SIZE, d->vram_bar_memory);
#endif
    pci_register_bar(pci_dev, 2, 0, &d->vram_bar);
    vmstate_register_ram(&d->vram_bar, &pci_dev->qdev);

#ifdef PSCNV_DEBUG_CHAN_ACCESS
    memory_region_init_io(&d->chan_bar, &pscnv_chan_debug_ops, d, "pscnv-chan",
                          d->chan_bar_size);
#else
    memory_region_init_ram_ptr(&d->chan_bar, "pscnv-chan", d->chan_bar_size,
                               d->chan_bar_memory);
#endif
    pci_register_bar(pci_dev, 3, 0, &d->chan_bar);
    vmstate_register_ram(&d->chan_bar, &pci_dev->qdev);

    /* mark the whole bar as free */
    struct pscnv_memory_area *memory_area = malloc(sizeof(*memory_area));
    memory_area->start = 0;
    memory_area->size = PSCNV_VIRT_VRAM_SIZE;
    memory_area->next = memory_area->prev = NULL;
    memory_area->handle = (uint32_t)-1;
    d->memory_areas = memory_area;

    /*d->irq = pci_dev->irq[0];*/

    /* no channels have been allocated yet */
    memset(d->chan_handle, -1, sizeof(d->chan_handle));
    memset(d->fifo_init, -1, sizeof(d->fifo_init));

    memset(d->vspace_handle, -1, sizeof(d->vspace_handle));

    /* install the handlers needed for migration */
    register_savevm_live(&pci_dev->qdev, "pscnv_virt", -1, 1,
                         &pscnv_save_handlers, d);
    qemu_mutex_init(&d->migration_log_lock);
    d->migration_log_start = NULL;
    d->migration_log_end = NULL;
    d->migration_active = 0;

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
