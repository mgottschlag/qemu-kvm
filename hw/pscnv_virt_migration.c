
#include "pscnv_virt.h"

#include "sysemu.h"

#include <libpscnv.h>
#include <sys/mman.h>

#define PSCNV_SAVE_EOS 0x1
#define PSCNV_SAVE_ALLOC 0x2
#define PSCNV_SAVE_FREE 0x3
#define PSCNV_SAVE_MAP 0x4
#define PSCNV_SAVE_UNMAP 0x5
#define PSCNV_SAVE_VSPACE 0x6
#define PSCNV_SAVE_VSPACE_MAP 0x7
#define PSCNV_SAVE_CHAN 0x8
#define PSCNV_SAVE_FINISH 0x9
#define PSCNV_SAVE_DATA 0xa

static uint64_t get_time(void) {
    uint64_t usecs;
    struct timespec time;
    clock_gettime(CLOCK_REALTIME, &time);
    usecs = time.tv_sec * 1000000;
    usecs += time.tv_nsec / 1000;
    return usecs;
}


static int add_allocation_entry_fixed(PscnvState *d, uint32_t handle,
                                      struct pscnv_memory_allocation *entry) {
    while (handle >= d->alloc_count) {
        /* allocate new entries */
        uint32_t i;
        uint32_t new_count = d->alloc_count * 2;
        d->alloc_data = realloc(d->alloc_data,
                new_count * sizeof(struct pscnv_memory_allocation));
        for (i = d->alloc_count; i < new_count; i++) {
            d->alloc_data[i].size = 0xffffffffffffffff;
            d->alloc_data[i].next = i + 1;
        }
        d->alloc_data[new_count - 1].next = d->alloc_freelist;
        d->alloc_freelist = d->alloc_count;
        d->alloc_count = new_count;
    }
    /* search for an existing free entry */
    if (d->alloc_freelist == -1) {
        return -1;
    }
    if (d->alloc_freelist == handle) {
        d->alloc_freelist = d->alloc_data[handle].next;
    } else {
        uint32_t prev = d->alloc_freelist;
        uint32_t curr = d->alloc_data[prev].next;
        while (curr != handle) {
            if (curr == -1) {
                return -1;
            }
            prev = curr;
            curr = d->alloc_data[prev].next;
        }
        d->alloc_data[prev].next = d->alloc_data[handle].next;
    }
    /* set the content of the entry */
    d->alloc_data[handle] = *entry;
    return 0;
}

static struct pscnv_memory_area *add_mapping_entry_fixed(PscnvState *d,
                                                         uint32_t start,
                                                         uint32_t size) {
    struct pscnv_memory_area *area = d->memory_areas;
    while (area != NULL) {
        if (area->start > start) {
            return NULL;
        }
        if (area->start + area->size >= start + size) {
            break;
        }
        area = area->next;
    }
    if (area == NULL) {
        return NULL;
    }
    if (area->handle != (uint32_t)-1) {
        return NULL;
    }
    if (area->start != start) {
        struct pscnv_memory_area *prev = malloc(sizeof(*prev));
        prev->prev = area->prev;
        prev->next = area;
        prev->start = area->start;
        prev->size = start - area->start;
        prev->handle = -1;
        if (area->prev != NULL) {
            area->prev->next = prev;
        }
        area->prev = prev;
        area->size -= start - area->start;
        area->start = start;
    }
    if (area->size != size) {
        struct pscnv_memory_area *next = malloc(sizeof(*next));
        next->prev = area;
        next->next = area->next;
        next->start = start + size;
        next->size = area->size - size;
        next->handle = -1;
        if (area->next != NULL) {
            area->next->prev = next;
        }
        area->next = next;
        area->size = size;
    }
    return area;
}

/**
 * Checks whether an entry in the chan memory region is associated with a
 * pscnv channel.
 */
static int chan_is_allocated(PscnvState *d, uint32_t chan) {
    return d->chan_handle[chan] != (uint32_t)-1;
}

static void init_channel(uint32_t *chan, uint32_t *ib, uint32_t *cmd,
                         uint64_t cmd_offset) {
    /* we only bind the COMPUTE and M2MF engines, the benchmarks do not need
     * anything else to resume from the saved state */
    /* TODO: implement the remaining state */
    uint64_t ib_entry;
    cmd[0] = (0x2<<28) | (1<<16) | (2<<13) | (0>>2);
    cmd[1] = 0x9039;
    cmd[2] = (0x2<<28) | (1<<16) | (1<<13) | (0>>2);
    cmd[3] = 0x90c0;
    ib_entry = cmd_offset | (16ull << 40);
    ib[0] = ib_entry;
    ib[1] = ib_entry >> 32;
    chan[0x8c / 4] = 1;
    while (chan[0x88 / 4] != 1);
}

static void restore_channel_state(PscnvState *d,
                                  uint32_t handle,
                                  uint32_t *data) {
    struct pscnv_fifo_init_ib_cmd *init_cmd = &d->fifo_init[handle];
    struct pscnv_vspace_mapping *mapping = d->vspace_mapping[d->chan_vspace[handle]];
    uint32_t ib_handle = -1;
    uint32_t *ib;
    uint32_t cmd_handle;
    uint64_t cmd_map_handle;
    uint32_t *cmd;
    uint64_t cmd_offset;
    int ret;
    /*uint32_t ib_get = data[0x88 / 4];*/
    uint32_t ib_get = 0x1;
    uint32_t ib_put = data[0x8c / 4];
    uint64_t ib_entry;
    uint32_t chsize = d->is_nv50 ? 0x2000 : 0x1000;
    uint32_t *chan = (uint32_t*)(d->chan_bar_memory + handle * chsize);
    int i;
    fprintf(stderr, "Chan state: put: %d, get: %d\n", ib_put, ib_get);
    /* find the IB */
    while (mapping != NULL) {
        if (init_cmd->ib_start == mapping->offset) {
            ib_handle = mapping->obj;
            break;
        }
        mapping = mapping->vspace_next;
    }
    if (ib_handle == (uint32_t)-1) {
        fprintf(stderr, "restore_channel_state: IB not found!\n");
        return;
    }
    ib = mmap(NULL, d->alloc_data[ib_handle].size, PROT_READ | PROT_WRITE,
              MAP_SHARED, d->drm_fd, d->alloc_data[ib_handle].map_handle);
    if (ib == MAP_FAILED) {
        fprintf(stderr, "restore_channel_state: Could not map IB!\n");
        return;
    }

    /* allocate some memory to place the command */
    ret = pscnv_gem_new(d->drm_fd, 0x0, 0x6, 0x0,
                        0x1000, NULL, &cmd_handle, &cmd_map_handle);
    if (ret != 0) {
        fprintf(stderr, "restore_channel_state: Could not create command buffer!\n");
        return;
    }
    cmd = mmap(NULL, 0x1000, PROT_READ | PROT_WRITE,
              MAP_SHARED, d->drm_fd, cmd_map_handle);
    if (cmd == MAP_FAILED) {
        fprintf(stderr, "restore_channel_state: Could not map command buffer!\n");
        return;
    }
    ret = pscnv_vspace_map(d->drm_fd, d->vspace_handle[d->chan_vspace[handle]],
                           cmd_handle, 0x20000000, 0x10000000000ull,
                           0x0, 0x0, &cmd_offset);
    if (ret != 0) {
        fprintf(stderr, "restore_channel_state: Could not map command buffer into vspace!\n");
        return;
    }
    /* reinitialize the channel (add and initialize engines) */
    init_channel(chan, ib, cmd, cmd_offset);
    /* adjust the channel GET pointer by making the GPU execute NOP commands */
    ib_entry = cmd_offset | (8ull << 40);
    for (i = 1; i < ib_get; i++) {
        cmd[0] = (0x2<<28) | (1<<16) | (1<<13) | (0x100>>2); /* 0x100 = NOP */
        cmd[1] = 0;
        ib[i * 2] = ib_entry;
        ib[i * 2 + 1] = ib_entry >> 32;
        chan[0x8c / 4] = i + 1;
        while (1) {
            uint32_t ib_get = chan[0x88 / 4];
            uint32_t ib_put = chan[0x8c / 4];
            fprintf(stderr, "put: %d, get: %d\n", ib_put, ib_get);
            if (ib_get == ib_put) {
                break;
            }
        }
    }
    /* update the PUT pointer to the value which has been set by the guest */
    chan[0x8c / 4] = ib_put;
    /* free the temporary command memory */
    ret = pscnv_vspace_unmap(d->drm_fd,
                             d->vspace_handle[d->chan_vspace[handle]],
                             cmd_offset);
    munmap(cmd, 0x1000);
    pscnv_gem_close(d->drm_fd, cmd_handle);
    munmap(ib, d->alloc_data[ib_handle].size);
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
    /*current_channel = d->channel_content;*/
    current_channel = malloc(chsize);
    for (i = 0; i < PSCNV_VIRT_CHAN_COUNT; i++) {
        if (chan_is_allocated(d, i)) {
            fprintf(stderr, "pscnv_save_cancel: Allocating channel %d.\n", i);
            uint64_t map_handle;
            void *chmem;
            /* create a new channel */
            ret = pscnv_chan_new(d->drm_fd, d->vspace_handle[d->chan_vspace[i]],
                                 &d->chan_handle[i], &map_handle);
            if (ret) {
                fprintf(stderr, "pscnv_virt: pscnv_chan_new failed (%d)\n", ret);
            }
            if (d->chan_handle[i] >= PSCNV_VIRT_CHAN_COUNT) {
                fprintf(stderr, "pscnv_virt: Bug: invalid cid %d\n",
                        d->chan_handle[i]);
                return;
            }
            /* backup the old channel content */
            memcpy(current_channel, d->chan_bar_memory + i * chsize, chsize);
            /* map the channel */
            chmem = mmap(d->chan_bar_memory + i * chsize, chsize,
                         PROT_READ | PROT_WRITE, MAP_SHARED | MAP_FIXED,
                         d->drm_fd, map_handle);
            if (chmem == MAP_FAILED) {
                fprintf(stderr, "pscnv_virt: Could not map channel %d\n",
                        d->chan_handle[i]);
            }
            if (d->fifo_init[i].command != (uint32_t)-1) {
                struct pscnv_fifo_init_ib_cmd *cmd = &d->fifo_init[i];
                ret = pscnv_fifo_init_ib(d->drm_fd, d->chan_handle[i], cmd->pb_handle,
                                           cmd->flags, cmd->slimask, cmd->ib_start,
                                           cmd->ib_order);
                if (ret) {
                    fprintf(stderr, "pscnv_virt: pscnv_fifo_init_ib failed (%d)\n", ret);
                }
                /* restore the channel state */
                /*memcpy(d->chan_bar_memory + i * chsize, current_channel, chsize);*/
                restore_channel_state(d, i, (uint32_t*)current_channel);
            }
        }
    }
    free(current_channel);
}

static void pscnv_revert_migration_mappings(PscnvState *d) {
    int i;
    void *mmap_result;

    // Copy changed memory content from RAM to GPU
    for (i = 0; i < d->alloc_count; i++) {
        struct pscnv_memory_allocation *obj = &d->alloc_data[i];
        if (obj->size != (uint64_t)-1 && obj->mapping != NULL) {
            void *data = mmap(NULL, obj->size, PROT_READ | PROT_WRITE,
                              MAP_SHARED, d->drm_fd, obj->map_handle);
            if (data == MAP_FAILED) {
                fprintf(stderr, "pscnv_virt: could not map obj %d\n", i);
                continue;
            }
            memcpy(data, d->vram_bar_memory + obj->mapping->start, obj->size);
            munmap(data, obj->size);
        }
    }
    // Unmap copies made for migration
    /*mmap_result = mmap(d->vram_bar_memory, PSCNV_VIRT_VRAM_SIZE, PROT_NONE,
                       MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
    if (mmap_result == MAP_FAILED) {
        fprintf(stderr, "pscnv_virt: could not unmap vram\n");
    }*/
    // Map objects into the VRAM BAR again
    for (i = 0; i < d->alloc_count; i++) {
        struct pscnv_memory_allocation *obj = &d->alloc_data[i];
        if (obj->size != (uint64_t)-1 && obj->mapping != NULL) {
            mmap_result = mmap(d->vram_bar_memory + obj->mapping->start, obj->size,
                    PROT_READ | PROT_WRITE, MAP_SHARED | MAP_FIXED, d->drm_fd,
                    obj->map_handle);
            if (mmap_result == MAP_FAILED) {
                fprintf(stderr, "pscnv_virt: could not map obj %d\n", i);
            }
        }
    }
}

/**
 * Returns 0 if no log entry was available.
 */
static int pscnv_save_log_entry(PscnvState *d, QEMUFile *f) {
    struct pscnv_migration_log_entry *tmp;
    struct pscnv_migration_log_entry entry;
    struct pscnv_memory_allocation obj;
    struct pscnv_memory_area mapping;
    void *buffer_data = NULL;

    /* transmit object content after LOG_ALLOC */
    if (d->current_obj != (uint32_t)-1) {
        qemu_put_byte(f, PSCNV_SAVE_DATA);
        qemu_put_be32(f, d->current_obj);
        qemu_put_be32(f, d->current_obj_pos);
        qemu_put_be32(f, 0x1000);
        qemu_put_buffer(f, (unsigned char*)d->current_obj_data + d->current_obj_pos,
                        0x1000);
        d->current_obj_pos += 0x1000;
        if (d->current_obj_pos >= d->current_obj_size) {
            d->current_obj = -1;
            munmap(d->current_obj_data, d->current_obj_size);
        }
        return 1;
    }

    qemu_mutex_lock(&d->migration_log_lock);
    /* check whether the log is empty */
    if (d->migration_log_start == NULL) {
        qemu_mutex_unlock(&d->migration_log_lock);
        return 0;
    }
    /* remove one entry from the log */
    tmp = d->migration_log_start;
    entry = *tmp;
    if (tmp->next != NULL) {
        tmp->next->prev = NULL;
    }
    d->migration_log_start = tmp->next;
    // TODO: this is not thread-safe!
    obj = d->alloc_data[entry.handle];
    if (obj.mapping != NULL) {
        mapping = *obj.mapping;
    } else {
        memset(&mapping, 0, sizeof(mapping));
    }
    /* for allocation entries we also need to map the buffer in case it is
     * deleted later */
    if (entry.type == PSCNV_MIGRATION_LOG_ALLOC && obj.mapping == NULL) {
        if (obj.flags & PSCNV_GEM_SYSRAM_SNOOP) {
            buffer_data = mmap(NULL, obj.size, PROT_READ | PROT_WRITE,
                               MAP_SHARED, d->drm_fd, obj.map_handle);
            assert(buffer_data != MAP_FAILED);
        } else {
            buffer_data = pscnv_dma_to_sysram(d->dma, obj.handle, obj.size);
            assert(buffer_data != NULL);
        }
    }
    qemu_mutex_unlock(&d->migration_log_lock);

    if (entry.type == PSCNV_MIGRATION_LOG_ALLOC) {
        qemu_put_byte(f, PSCNV_SAVE_ALLOC);
        qemu_put_be32(f, entry.handle);
        qemu_put_be64(f, obj.size);
        qemu_put_be32(f, obj.cookie);
        qemu_put_be32(f, obj.flags);
        qemu_put_be32(f, obj.tile_flags);
        qemu_put_byte(f, obj.mapping != NULL);
        fprintf(stderr, "ALLOC %x %x %x %x %"PRIx64"\n", entry.handle,
                obj.cookie, obj.flags, obj.tile_flags, obj.size);
        if (obj.mapping == NULL) {
            /*uint64_t start = get_time();
            qemu_put_buffer(f, buffer_data, obj.size);
            fprintf(stderr, "transfer: %lfms\n", (double)(get_time() - start) / 1000);*/
            d->current_obj = entry.handle;
            d->current_obj_pos = 0;
            d->current_obj_size = obj.size;
            d->current_obj_data = buffer_data;
        } else {
            qemu_put_be32(f, mapping.start);
            qemu_put_be32(f, mapping.size);
        }
    } else if (entry.type == PSCNV_MIGRATION_LOG_FREE) {
        qemu_put_byte(f, PSCNV_SAVE_FREE);
        qemu_put_be32(f, entry.handle);
    } else if (entry.type == PSCNV_MIGRATION_LOG_MAP) {
        qemu_put_byte(f, PSCNV_SAVE_MAP);
        qemu_put_be32(f, entry.handle);
        qemu_put_be32(f, mapping.start);
        qemu_put_be32(f, mapping.size);
    } else if (entry.type == PSCNV_MIGRATION_LOG_UNMAP) {
        qemu_put_byte(f, PSCNV_SAVE_UNMAP);
        qemu_put_be32(f, entry.handle);
    }

    return 1;
}

static void pscnv_save_state(QEMUFile *f, void *opaque) {
    fprintf(stderr, "pscnv_save_state\n");
    // TODO
    qemu_put_byte(f, PSCNV_SAVE_FINISH);
    qemu_put_byte(f, PSCNV_SAVE_EOS);
}
static int pscnv_save_live_setup(QEMUFile *f, void *opaque) {
    int i;
    unsigned int chsize;
    PscnvState *d = opaque;
    unsigned int channel_count;
    /*char *current_channel;*/
    void *mmap_result;
    char *channel_content;
    uint64_t start = get_time();

    int saved_vm_running = runstate_is_running();
    fprintf(stderr, "freeze (%d).\n", saved_vm_running);
    vm_stop(RUN_STATE_SAVE_VM);

    fprintf(stderr, "pscnv_save_live_setup\n");

    d->migration_active = 1;
    d->current_obj = -1;

    memcpy(d->chan_handle_tmp, d->chan_handle, sizeof(d->chan_handle));

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
    channel_content = mmap(NULL, d->chan_bar_size,
                       PROT_READ | PROT_WRITE,
                       MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    /*d->channel_content = malloc(chsize * channel_count);*/
    /*current_channel = d->channel_content;*/
    for (i = 0; i < PSCNV_VIRT_CHAN_COUNT; i++) {
        if (chan_is_allocated(d, i)) {
            fprintf(stderr, "pscnv_save_live_setup: Unmapping channel %d.\n", i);
            memcpy(channel_content + i * chsize,
                   d->chan_bar_memory + i * chsize, chsize);
            /* unmap the channel */
            mmap_result = mmap(d->chan_bar_memory + i * chsize, chsize,
                    PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
            if (mmap_result == MAP_FAILED) {
                fprintf(stderr, "pscnv_virt: could not unmap channel %d\n", i);
            }
            /*current_channel += chsize;*/
        }
    }
    /*munmap(d->chan_bar_memory, d->chan_bar_size);
    channel_content = mremap(channel_content, d->chan_bar_size,
                             d->chan_bar_size, MREMAP_FIXED,
                             d->chan_bar_memory);*/
    mmap_result = mmap(d->chan_bar_memory, d->chan_bar_size,
                       PROT_READ | PROT_WRITE,
                       MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
    if (mmap_result == MAP_FAILED) {
        fprintf(stderr, "pscnv_virt: could not unmap channels\n");
        if (saved_vm_running) {
            vm_start();
        }
        return -1;
    }
    // TODO: this can be optimized?
    memcpy(d->chan_bar_memory, channel_content, d->chan_bar_size);
    munmap(channel_content, d->chan_bar_size);

    /**
     * Add migration log entries for all existing objects so that these are
     * copied in pscnv_save_live_iterate.
     */
    for (i = 0; i < d->alloc_count; i++) {
        struct pscnv_memory_allocation *obj = &d->alloc_data[i];
        if (obj->size != (uint64_t)-1) {
            pscnv_add_migration_log_entry(d, i, PSCNV_MIGRATION_LOG_ALLOC);
        }
    }

    fprintf(stderr, "unfreeze.\n");
    if (saved_vm_running) {
        vm_start();
    }

    d->halted = 0;
    d->start_time = time(NULL);

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
    /*mmap_result = mmap(d->vram_bar_memory, PSCNV_VIRT_VRAM_SIZE,
                       PROT_READ | PROT_WRITE,
                       MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
    if (mmap_result == MAP_FAILED) {
        fprintf(stderr, "pscnv_virt: could not unmap vram\n");
        if (saved_vm_running) {
            vm_start();
        }
        return -1;
    }
    for (i = 0; i < d->alloc_count; i++) {
        struct pscnv_memory_allocation *obj = &d->alloc_data[i];
        if (obj->size != (uint64_t)-1 && obj->mapping != NULL) {
            void *data = mmap(NULL, obj->size, PROT_READ | PROT_WRITE,
                              MAP_SHARED, d->drm_fd, obj->map_handle);
            if (data == MAP_FAILED) {
                fprintf(stderr, "pscnv_virt: could not map obj %d\n", i);
                if (saved_vm_running) {
                    vm_start();
                }
                return -1;
            }
            memcpy(d->vram_bar_memory + obj->mapping->start,
                   data, obj->size);
            munmap(data, obj->size);
        }
    }*/

    /**
     * We just let the normal RAM migration code take care of mapped buffers.
     */
    /*memory_region_set_log(&d->vram_bar, 1, DIRTY_MEMORY_PSCNV);
    memory_region_set_dirty(&d->vram_bar, 0, PSCNV_VIRT_VRAM_SIZE);
    memory_region_sync_dirty_bitmap(&d->vram_bar);*/

    qemu_put_byte(f, PSCNV_SAVE_EOS);

    fprintf(stderr, "pscnv_save_live_setup done: %lfms\n",
            (double)(get_time() - start) / 1000);
    return 0;
}

static int pscnv_save_live_iterate(QEMUFile *f, void *opaque) {
    int ret;
    int i;
    PscnvState *d = opaque;
    uint64_t start = get_time();
    /*uint64_t transmit_start;*/

    fprintf(stderr, "pscnv_save_live_iterate\n");

    if (!d->halted) {
        /**
         * Delete the channels now that the GPU has been halted.
         */
        // HACK!
        if (time(NULL) - d->start_time < 4) {
            qemu_put_byte(f, PSCNV_SAVE_EOS);
            return 0;
        }

        for (i = 0; i < PSCNV_VIRT_CHAN_COUNT; i++) {
            if (d->chan_handle_tmp[i] != (uint32_t)-1) {
                fprintf(stderr, "pscnv_save_live_setup: Deleting channel %d.\n", i);
                /* delete the channel */
                ret = pscnv_chan_free(d->drm_fd, d->chan_handle_tmp[i]);
                if (ret) {
                    fprintf(stderr, "pscnv_virt: could not free channel (%d)\n", ret);
                }
            }
        }
        d->halted = 1;
    }

    /* transmit all memory buffers */
    /*transmit_start = get_time();*/
    while ((ret = qemu_file_rate_limit(f)) == 0/* && get_time() - transmit_start < 100000*/) {
        if (pscnv_save_log_entry(d, f) == 0) {
            qemu_put_byte(f, PSCNV_SAVE_EOS);
            return 1;
        }
    }
    if (ret < 0) {
        return ret;
    }

    qemu_put_byte(f, PSCNV_SAVE_EOS);

    fprintf(stderr, "pscnv_save_live_iterate done: %lfms\n",
            (double)(get_time() - start) / 1000);
    return 0;
}
static int pscnv_save_live_complete(QEMUFile *f, void *opaque) {
    PscnvState *d = opaque;
    int i;
    /*char *current_channel = d->channel_content;*/
    unsigned int chsize = d->is_nv50 ? 0x2000 : 0x1000;

    fprintf(stderr, "pscnv_save_live_complete\n");

    /* write remaining log entries */
    while (pscnv_save_log_entry(d, f) != 0);
    /* write remaining information about channels and virtual address spaces */
    for (i = 0; i < PSCNV_VIRT_VSPACE_COUNT; i++) {
        if (d->vspace_handle[i] != (uint32_t)-1) {
            struct pscnv_vspace_mapping *mapping = d->vspace_mapping[i];
            qemu_put_byte(f, PSCNV_SAVE_VSPACE);
            qemu_put_be32(f, i);
            while(mapping != NULL) {
                fprintf(stderr, "Saving mapping: %"PRIx64" - %"PRIx64"\n",
                        mapping->offset,
                        mapping->offset + d->alloc_data[mapping->obj].size);
                qemu_put_byte(f, PSCNV_SAVE_VSPACE_MAP);
                qemu_put_be32(f, mapping->vspace);
                qemu_put_be32(f, mapping->obj);
                qemu_put_be64(f, mapping->offset);
                qemu_put_be32(f, mapping->flags);
                mapping = mapping->vspace_next;
            }
        }
    }
    for (i = 0; i < PSCNV_VIRT_CHAN_COUNT; i++) {
        if (d->chan_handle[i] != (uint32_t)-1) {
            uint32_t *channel = (uint32_t*)(d->chan_bar_memory + i * chsize);
            fprintf(stderr, "dma put: %08x get: %08x\n"
                            "ib put: %08x get: %08x\n",
                    channel[0x10], channel[0x11], channel[0x22], channel[0x23]);
            qemu_put_byte(f, PSCNV_SAVE_CHAN);
            qemu_put_be32(f, i);
            qemu_put_be32(f, d->chan_vspace[i]);
            if (d->fifo_init[i].command != (uint32_t)-1) {
                struct pscnv_fifo_init_ib_cmd *cmd = &d->fifo_init[i];
                qemu_put_byte(f, 1);
                qemu_put_be32(f, cmd->pb_handle);
                qemu_put_be32(f, cmd->flags);
                qemu_put_be32(f, cmd->slimask);
                qemu_put_be64(f, cmd->ib_start);
                qemu_put_be32(f, cmd->ib_order);
            } else {
                qemu_put_byte(f, 0);
            }
            /*qemu_put_buffer(f, (void*)current_channel, chsize);
            current_channel += chsize;*/
        }
    }

    qemu_put_byte(f, PSCNV_SAVE_EOS);

    /**
     * Revert all changes made by the migration functions.
     */
    // TODO: this is not necessary!
    /*pscnv_revert_migration_mappings(d);
    pscnv_resume_channels(d);*/

    d->migration_active = 0;
    return 0;
}
static void pscnv_save_cancel(void *opaque) {
    PscnvState *d = opaque;

    fprintf(stderr, "pscnv_save_cancel\n");

    pscnv_revert_migration_mappings(d);
    pscnv_resume_channels(d);

    d->migration_active = 0;
}
static int pscnv_load_state(QEMUFile *f, void *opaque, int version_id) {
    PscnvState *d = opaque;
    int ret;

    fprintf(stderr, "pscnv_load_state\n");

    while (1) {
        int type = qemu_get_byte(f);
        fprintf(stderr, "pscnv_virt: %d\n", type);
        if (type == PSCNV_SAVE_EOS) {
            break;
        } else if (type == PSCNV_SAVE_ALLOC) {
            struct pscnv_memory_allocation result;
            uint32_t handle = qemu_get_be32(f);
            uint64_t size = qemu_get_be64(f);
            uint32_t cookie = qemu_get_be32(f);
            uint32_t flags = qemu_get_be32(f);
            uint32_t tile_flags = qemu_get_be32(f);
            int mapped = qemu_get_byte(f);
            /* allocate a gem object */
            fprintf(stderr, "pscnv_gem_new: %x %x %x %x %"PRIx64"\n", handle, cookie,
                    flags, tile_flags, size);
            ret = pscnv_gem_new(d->drm_fd, cookie, flags, tile_flags,
                                size, NULL, &result.handle, &result.map_handle);
            if (ret != 0) {
                fprintf(stderr, "pscnv_gem_new failed: %d\n", ret);
                return -EINVAL;
            }
            result.cookie = cookie;
            result.flags = flags;
            result.tile_flags = tile_flags;
            result.size = (size + 0xfff) & ~0xfff;
            result.mapping = NULL;
            result.vspace_mapping = NULL;
            /* add it at the specified position */
            if (add_allocation_entry_fixed(d, handle, &result) != 0) {
                fprintf(stderr, "Could not create allocation entry!\n");
                return -EINVAL;
            }
            /* map it and load the contents if necessary */
            if (mapped) {
                uint32_t start = qemu_get_be32(f);
                uint32_t size = qemu_get_be32(f);
                d->alloc_data[handle].mapping =
                        add_mapping_entry_fixed(d, start, size);
                if (d->alloc_data[handle].mapping == NULL) {
                    fprintf(stderr, "ALLOC: Invalid memory range.\n");
                }
                d->alloc_data[handle].mapping->handle = handle;
            } else {
                /*buffer_data = mmap(NULL, size, PROT_READ | PROT_WRITE,
                                   MAP_SHARED, d->drm_fd, result.map_handle);
                assert(buffer_data != MAP_FAILED);
                qemu_get_buffer(f, buffer_data, size);
                munmap(buffer_data, size);*/
            }
        } else if (type == PSCNV_SAVE_DATA) {
            uint32_t handle = qemu_get_be32(f);
            // TODO: this should be 64 bit
            uint32_t offset = qemu_get_be32(f);
            uint32_t size = qemu_get_be32(f);
            struct pscnv_memory_allocation *obj = &d->alloc_data[handle];
            if (handle != d->current_obj) {
                if (d->current_obj != (uint32_t)-1) {
                    munmap(d->current_obj_data, d->current_obj_size);
                }
                d->current_obj = handle;
                d->current_obj_data = mmap(NULL, obj->size, PROT_READ | PROT_WRITE,
                                           MAP_SHARED, d->drm_fd, obj->map_handle);
                d->current_obj_size = obj->size;
            }
            qemu_get_buffer(f, (unsigned char*)d->current_obj_data + offset, size);
        } else if (type == PSCNV_SAVE_FREE) {
            uint32_t handle = qemu_get_be32(f);
            struct pscnv_memory_allocation *obj = &d->alloc_data[handle];
            /* clear the mapping */
            if (obj->mapping != NULL) {
                pscnv_free_memory(d, obj->mapping);
            }
            /* invalidate the migration mapping as well */
            if (d->current_obj == handle) {
                munmap(d->current_obj_data, d->current_obj_size);
                d->current_obj = -1;
            }
            /* free the underlying gpu buffer */
            pscnv_gem_close(d->drm_fd, obj->handle);
            /* free the allocation list entry */
            obj->next = d->alloc_freelist;
            d->alloc_freelist = handle;
        } else if (type == PSCNV_SAVE_MAP) {
            uint32_t handle = qemu_get_be32(f);
            uint32_t start = qemu_get_be32(f);
            uint32_t size = qemu_get_be32(f);
            d->alloc_data[handle].mapping =
                    add_mapping_entry_fixed(d, start, size);
            d->alloc_data[handle].mapping->handle = handle;
        } else if (type == PSCNV_SAVE_UNMAP) {
            // TODO
        } else if (type == PSCNV_SAVE_VSPACE) {
            uint32_t handle = qemu_get_be32(f);
            uint32_t vid;
            int ret;
            ret = pscnv_vspace_new(d->drm_fd, &vid);
            if (ret) {
                fprintf(stderr, "pscnv_virt: pscnv_vspace_new failed (%d)\n", ret);
                return -EINVAL;
            }
            fprintf(stderr, "Created vspace %d (%d).\n", handle, vid);
            d->vspace_handle[handle] = vid;
            d->vspace_mapping[handle] = NULL;
        } else if (type == PSCNV_SAVE_VSPACE_MAP) {
            uint32_t vspace = qemu_get_be32(f);
            uint32_t obj = qemu_get_be32(f);
            uint64_t offset = qemu_get_be64(f);
            uint32_t flags = qemu_get_be32(f);
            uint64_t result;
            uint32_t vid = d->vspace_handle[vspace];

            fprintf(stderr, "Mapping: %"PRIx64" - %"PRIx64"\n", offset,
                    offset + d->alloc_data[obj].size);
            ret = pscnv_vspace_map(d->drm_fd, vid,
                                   d->alloc_data[obj].handle, offset,
                                   offset + d->alloc_data[obj].size, 0, flags,
                                   &result);
            if (ret != 0) {
                fprintf(stderr, "pscnv_vspace_map failed (%d)\n", ret);
                return -EINVAL;
            }
            if (result != offset) {
                fprintf(stderr, "pscnv_vspace_map: different resulting offset!\n");
                return -EINVAL;
            }
            // add mapping list entry
            pscnv_add_vspace_mapping(d, vspace, obj, offset, flags);
        } else if (type == PSCNV_SAVE_CHAN) {
            int initialized;
            /*int chsize = d->is_nv50 ? 0x2000 : 0x1000;*/
            uint32_t handle = qemu_get_be32(f);
            uint32_t vspace = qemu_get_be32(f);
            d->chan_handle[handle] = 0;
            d->chan_vspace[handle] = vspace;
            d->fifo_init[handle].command = -1;
            initialized = qemu_get_byte(f) != 0;
            if (initialized) {
                struct pscnv_fifo_init_ib_cmd *cmd = &d->fifo_init[handle];
                cmd->command = PSCNV_CMD_FIFO_INIT_IB;
                cmd->pb_handle = qemu_get_be32(f);
                cmd->flags = qemu_get_be32(f);
                cmd->slimask = qemu_get_be32(f);
                cmd->ib_start = qemu_get_be64(f);
                cmd->ib_order = qemu_get_be32(f);
            }
            /*qemu_get_buffer(f, (void*)d->chan_bar_memory + handle * chsize, chsize);*/
        } else if (type == PSCNV_SAVE_FINISH) {
            if (d->current_obj != (uint32_t)-1) {
                munmap(d->current_obj_data, d->current_obj_size);
                d->current_obj = -1;
            }
            fprintf(stderr, "pscnv_virt: Done!\n");
            pscnv_revert_migration_mappings(d);
            pscnv_resume_channels(d);
        }
    }
    return 0;
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

