
#include "pscnv_virt.h"

#include <libpscnv.h>
#include <sys/mman.h>

/**
 * Checks whether an entry in the chan memory region is associated with a
 * pscnv channel.
 */
static int chan_is_allocated(PscnvState *d, uint32_t chan) {
    return d->chan_handle[chan] != (uint32_t)-1;
}

static void pscnv_resume_channels(PscnvState *d) {
    int ret;
    int i;
    char *current_channel;
    unsigned int chsize;

    /**
     * Reallocate all channels.
     */
    chsize = d->is_nv50 ? 0x2000 : 0x1000;
    current_channel = d->channel_content;
    for (i = 0; i < PSCNV_VIRT_CHAN_COUNT; i++) {
        if (chan_is_allocated(d, i)) {
            fprintf(stderr, "pscnv_save_cancel: Allocating channel %d.\n", i);
            uint64_t map_handle;
            void *chmem;
            /* create a new channel */
            ret = pscnv_chan_new(d->drm_fd, d->chan_vspace[i],
                                 &d->chan_handle[i], &map_handle);
            if (ret) {
                fprintf(stderr, "pscnv_virt: pscnv_chan_new failed (%d)\n", ret);
            }
            if (d->chan_handle[i] >= PSCNV_VIRT_CHAN_COUNT) {
                fprintf(stderr, "pscnv_virt: Bug: invalid cid %d\n",
                        d->chan_handle[i]);
                return;
            }
            /* map the channel */
            chmem = mmap(d->chan_bar_memory + i * chsize, chsize,
                         PROT_READ | PROT_WRITE, MAP_SHARED | MAP_FIXED,
                         d->drm_fd, map_handle);
            if (chmem == MAP_FAILED) {
                fprintf(stderr, "pscnv_virt: Could not map channel %d\n",
                        d->chan_handle[i]);
            }
            /* restore the channel state */
            memcpy(d->chan_bar_memory + i * chsize, current_channel, chsize);
            if (d->fifo_init[i].command != (uint32_t)-1) {
                struct pscnv_fifo_init_ib_cmd *cmd = &d->fifo_init[i];
                ret = pscnv_fifo_init_ib(d->drm_fd, d->chan_handle[i], cmd->pb_handle,
                                         cmd->flags, cmd->slimask, cmd->ib_start,
                                         cmd->ib_order);
                if (ret) {
                    fprintf(stderr, "pscnv_virt: pscnv_fifo_init_ib failed (%d)\n", ret);
                }
            }
            current_channel += chsize;
        }
    }
}

static void pscnv_revert_migration_mappings(PscnvState *d) {
    int i;
    void *mmap_result;

    // Copy changed memory content from RAM to GPU
    for (i = 0; i < d->alloc_count; i++) {
        struct pscnv_memory_allocation *obj = &d->alloc_data[i];
        if (obj->size != (uint64_t)-1) {
            if (obj->migration_mapping != NULL && obj->mapping != NULL) {
                memcpy(d->vram_bar_memory + obj->mapping->start,
                       obj->migration_mapping, obj->size);
            }
        }
    }
    // Unmap copies made for migration
    mmap_result = mmap(d->vram_bar_memory, PSCNV_VIRT_VRAM_SIZE, PROT_NONE,
                       MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
    if (mmap_result == MAP_FAILED) {
        fprintf(stderr, "pscnv_virt: could not unmap vram\n");
    }
    // Map objects into the VRAM BAR again
    for (i = 0; i < d->alloc_count; i++) {
        struct pscnv_memory_allocation *obj = &d->alloc_data[i];
        if (obj->size != (uint64_t)-1) {
            if (obj->migration_mapping != NULL) {
                if (munmap(obj->migration_mapping, obj->size) != 0) {
                    fprintf(stderr, "pscnv_virt: could not unmap obj %d\n", i);
                }
            }
            obj->migration_mapping = NULL;
            if (obj->mapping != NULL) {
                mmap_result = mmap(d->vram_bar_memory + obj->mapping->start, obj->size,
                        PROT_READ | PROT_WRITE, MAP_SHARED | MAP_FIXED, d->drm_fd,
                        obj->map_handle);
                if (mmap_result == MAP_FAILED) {
                    fprintf(stderr, "pscnv_virt: could not map obj %d\n", i);
                }
            }
        }
    }
}

static void pscnv_save_state(QEMUFile *f, void *opaque) {
    fprintf(stderr, "pscnv_save_state\n");
    // TODO
}
static int pscnv_save_live_setup(QEMUFile *f, void *opaque) {
    int i;
    unsigned int chsize;
    PscnvState *d = opaque;
    unsigned int channel_count;
    char *current_channel;
    void *mmap_result;
    int ret;

    fprintf(stderr, "pscnv_save_live_setup\n");

    /**
     * Idle all channels.
     */
    channel_count = 0;
    chsize = d->is_nv50 ? 0x2000 : 0x1000;
    for (i = 0; i < PSCNV_VIRT_CHAN_COUNT; i++) {
        if (chan_is_allocated(d, i)) {
            uint32_t *channel = (uint32_t*)(d->chan_bar_memory + i * chsize);
            fprintf(stderr, "dma put: %08x get: %08x\n"
                            "ib put: %08x get: %08x\n",
                    channel[0x10], channel[0x11], channel[0x22], channel[0x23]);
            while (channel[0x10] != channel[0x11] || channel[0x22] != channel[0x23]) {
                // busy-loop until the channel is idle
            }
            channel_count++;
        }
    }

    /**
     * Save the channel content and unmap the channels.
     */
    d->channel_content = malloc(chsize * channel_count);
    current_channel = d->channel_content;
    for (i = 0; i < PSCNV_VIRT_CHAN_COUNT; i++) {
        if (chan_is_allocated(d, i)) {
            fprintf(stderr, "pscnv_save_cancel: Deleting channel %d.\n", i);
            memcpy(current_channel, d->chan_bar_memory + i * chsize, chsize);
            /* delete the channel */
            ret = pscnv_chan_free(d->drm_fd, d->chan_handle[i]);
            if (ret) {
                fprintf(stderr, "pscnv_virt: could not free channel (%d)\n", ret);
            }
            /* unmap the channel */
            mmap_result = mmap(d->chan_bar_memory + i * chsize, chsize,
                    PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
            if (mmap_result == MAP_FAILED) {
                fprintf(stderr, "pscnv_virt: could not unmap channel %d\n", i);
            }
            current_channel += chsize;
        }
    }
    mmap_result = mmap(d->chan_bar_memory, d->chan_bar_size,
                       PROT_READ | PROT_WRITE,
                       MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
    if (mmap_result == MAP_FAILED) {
        fprintf(stderr, "pscnv_virt: could not unmap channels\n");
        return -1;
    }

    /**
     * Map GPU memory contents.
     */
    // TODO: DMA
    /*for (i = 0; i < d->alloc_count; i++) {
        struct pscnv_memory_allocation *obj = &d->alloc_data[i];
        if (obj->size != (uint64_t)-1) {
            if (obj->mapping != NULL) {
                obj->migration_mapping = NULL;
            } else {
                obj->migration_mapping =
                        mmap(NULL, obj->size, PROT_READ | PROT_WRITE,
                             MAP_SHARED, d->drm_fd, obj->map_handle);
                if (obj->migration_mapping == MAP_FAILED) {
                    fprintf(stderr, "pscnv_virt: could not map obj %d\n", i);
                    return -1;
                }
            }
        }
    }*/
    mmap_result = mmap(d->vram_bar_memory, PSCNV_VIRT_VRAM_SIZE,
                       PROT_READ | PROT_WRITE,
                       MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
    if (mmap_result == MAP_FAILED) {
        fprintf(stderr, "pscnv_virt: could not unmap vram\n");
        return -1;
    }
    for (i = 0; i < d->alloc_count; i++) {
        struct pscnv_memory_allocation *obj = &d->alloc_data[i];
        if (obj->size != (uint64_t)-1) {
            obj->migration_mapping =
                    mmap(NULL, obj->size, PROT_READ | PROT_WRITE,
                         MAP_SHARED, d->drm_fd, obj->map_handle);
            if (obj->migration_mapping == MAP_FAILED) {
                fprintf(stderr, "pscnv_virt: could not map obj %d\n", i);
                return -1;
            }
            if (obj->mapping != NULL) {
                memcpy(d->vram_bar_memory + obj->mapping->start,
                       obj->migration_mapping, obj->size);
            }
        }
    }

    /**
     * We just let the normal RAM migration code take care of mapped buffers.
     */
    /*memory_region_set_log(&d->vram_bar, 1, DIRTY_MEMORY_PSCNV);
    memory_region_set_dirty(&d->vram_bar, 0, PSCNV_VIRT_VRAM_SIZE);
    memory_region_sync_dirty_bitmap(&d->vram_bar);*/

    // TODO

    /**
     * Start copying memory.
     */
    // TODO
    return 0;
}
static int pscnv_save_live_iterate(QEMUFile *f, void *opaque) {
    fprintf(stderr, "pscnv_save_live_iterate\n");
    // TODO
    return 1;
}
static int pscnv_save_live_complete(QEMUFile *f, void *opaque) {
    int i;
    PscnvState *d = opaque;

    fprintf(stderr, "pscnv_save_live_complete\n");

    //memory_region_sync_dirty_bitmap(&d->vram_bar);

    /**
     * Write memory into the buffer.
     */
    for (i = 0; i < d->alloc_count; i++) {
        struct pscnv_memory_allocation *obj = &d->alloc_data[i];
        void *data;
        if (obj->size != (uint64_t)-1) {
            /*if (obj->mapping != NULL) {
                data = d->vram_bar_memory + obj->mapping->start;
            } else {
                data = obj->migration_mapping;
            }*/
            data = obj->migration_mapping;
            qemu_put_be32(f, obj->size);
            qemu_put_buffer(f, data, obj->size);
        }
    }

    /**
     * Revert all changes made by the migration functions.
     */
    pscnv_revert_migration_mappings(d);
    pscnv_resume_channels(d);
    return 0;
}
static void pscnv_save_cancel(void *opaque) {
    PscnvState *d = opaque;

    fprintf(stderr, "pscnv_save_cancel\n");

    pscnv_revert_migration_mappings(d);
    pscnv_resume_channels(d);
}
static int pscnv_load_state(QEMUFile *f, void *opaque, int version_id) {
    fprintf(stderr, "pscnv_load_state\n");
    // TODO
    return -1;
}

SaveVMHandlers pscnv_save_handlers = {
    .save_state = pscnv_save_state,
    .save_live_setup = pscnv_save_live_setup,
    .save_live_iterate = pscnv_save_live_iterate,
    .save_live_complete = pscnv_save_live_complete,
    .cancel = pscnv_save_cancel,
    .load_state = pscnv_load_state,
};

int pscnv_remove_migration_log_entries(PscnvState *d, uint32_t handle,
                                        int type_mask) {
    int removed = 0;
    struct pscnv_migration_log_entry *entry = d->migration_log_start;
    while (entry != NULL) {
        if (entry->handle == handle && (entry->type & type_mask) != 0) {
            struct pscnv_migration_log_entry *next = entry->next;
            if (entry->next != NULL) {
                entry->next->prev = entry->prev;
            } else {
                d->migration_log_end = entry->prev;
            }
            if (entry->prev != NULL) {
                entry->prev->next = entry->next;
            } else {
                d->migration_log_start = entry->next;
            }
            removed |= entry->type;
            free(entry);
            entry = next;
        }
    }
    return removed;
}
void pscnv_add_migration_log_entry(PscnvState *d, uint32_t handle,
                                   enum pscnv_migration_log_type type) {
    struct pscnv_migration_log_entry *entry = malloc(sizeof(*entry));
    entry->prev = d->migration_log_end;
    entry->next = NULL;
    if (d->migration_log_end != NULL) {
        d->migration_log_end->next = entry;
    } else {
        d->migration_log_start = entry;
    }
    d->migration_log_end = entry;
    entry->type = type;
    entry->handle = handle;
}

