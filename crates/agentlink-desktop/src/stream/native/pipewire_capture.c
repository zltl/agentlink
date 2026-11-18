/*
 * Portal ScreenCast consumer. Compiled only when libpipewire-0.3 headers
 * are present (see build.rs). MemFd and dma-buf buffers are mapped by
 * PipeWire (PW_STREAM_FLAG_MAP_BUFFERS) and copied once into the caller's
 * BGRA buffer. The dma-buf fd itself is not imported into an encoder.
 */
#ifdef HAVE_PIPEWIRE

#include <pipewire/pipewire.h>
#include <spa/param/video/format-utils.h>
#include <spa/param/video/raw.h>
#include <spa/buffer/meta.h>
#include <spa/pod/builder.h>
#include <spa/debug/types.h>

#include <errno.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

/* Bound matches Rust MAX_CURSOR_BITMAP_EDGE. */
#define AL_PW_CURSOR_EDGE 128
#define AL_PW_MAX_DIM 16384
#define AL_PW_MAX_FRAME_BYTES (64u * 1024u * 1024u)

int al_pw_validate_frame_copy(
    int width,
    int height,
    int chunk_stride,
    uint32_t chunk_offset,
    uint32_t chunk_size,
    uint32_t maxsize,
    size_t *out_stride,
    size_t *out_alloc_bytes,
    size_t *out_copy_bytes
) {
    uint64_t min_row;
    uint64_t stride64;
    uint64_t alloc64;
    uint64_t min_valid64;
    uint64_t copy64;

    if (width <= 0 || height <= 0 || width > AL_PW_MAX_DIM || height > AL_PW_MAX_DIM || chunk_stride < 0) {
        return 0;
    }
    min_row = (uint64_t)(uint32_t)width * 4ULL;
    stride64 = chunk_stride > 0 ? (uint64_t)(uint32_t)chunk_stride : min_row;
    if (stride64 < min_row || stride64 > (uint64_t)AL_PW_MAX_FRAME_BYTES) {
        return 0;
    }
    alloc64 = stride64 * (uint64_t)(uint32_t)height;
    if (alloc64 == 0 || alloc64 > (uint64_t)AL_PW_MAX_FRAME_BYTES) {
        return 0;
    }
    min_valid64 = (uint64_t)(uint32_t)(height - 1) * stride64 + min_row;
    if ((uint64_t)chunk_size < min_valid64) {
        return 0;
    }
    copy64 = (uint64_t)chunk_size < alloc64 ? (uint64_t)chunk_size : alloc64;
    if ((uint64_t)maxsize < copy64 || (uint64_t)chunk_offset > (uint64_t)maxsize - copy64) {
        return 0;
    }
    if (out_stride) *out_stride = (size_t)stride64;
    if (out_alloc_bytes) *out_alloc_bytes = (size_t)alloc64;
    if (out_copy_bytes) *out_copy_bytes = (size_t)copy64;
    return 1;
}

typedef struct PwCapture {
    struct pw_thread_loop *loop;
    struct pw_context *context;
    struct pw_core *core;
    struct pw_stream *stream;
    int width;
    int height;
    int stride;
    int format;
    int src_width;
    int src_height;
    int target_width;
    int dma_buf;
    int seq;
    int last_taken;
    int crop_valid;
    int crop_x;
    int crop_y;
    int crop_w;
    int crop_h;
    /* SPA_META_Cursor — updated on every process callback; readable without take(). */
    int cursor_valid;
    int cursor_visible;
    int cursor_x;
    int cursor_y;
    int cursor_hotspot_x;
    int cursor_hotspot_y;
    int cursor_w;
    int cursor_h;
    int cursor_seq;
    int cursor_has_bitmap;
    uint8_t cursor_rgba[AL_PW_CURSOR_EDGE * AL_PW_CURSOR_EDGE * 4];
    uint8_t *bgra;
    int bgra_size;
    int failed;
    pthread_mutex_t mu;
} PwCapture;

static int is_bgra(uint32_t format) {
    return format == SPA_VIDEO_FORMAT_BGRA || format == SPA_VIDEO_FORMAT_BGRx;
}

static void downsample_nn(
    const uint8_t *src,
    int src_w,
    int src_h,
    int src_stride,
    uint8_t *dst,
    int out_w,
    int out_h,
    int out_stride
) {
    int y;
    for (y = 0; y < out_h; y++) {
        int sy = (int)(((int64_t)y * (int64_t)src_h) / (int64_t)out_h);
        int x;
        const uint8_t *srow;
        uint8_t *drow;
        if (sy >= src_h) sy = src_h - 1;
        srow = src + (size_t)sy * (size_t)src_stride;
        drow = dst + (size_t)y * (size_t)out_stride;
        for (x = 0; x < out_w; x++) {
            int sx = (int)(((int64_t)x * (int64_t)src_w) / (int64_t)out_w);
            if (sx >= src_w) sx = src_w - 1;
            memcpy(drow + (size_t)x * 4u, srow + (size_t)sx * 4u, 4);
        }
    }
}


static void on_param_changed(void *userdata, uint32_t id, const struct spa_pod *param) {
    PwCapture *cap = userdata;
    struct spa_video_info info;
    if (id != SPA_PARAM_Format || param == NULL) {
        return;
    }
    if (spa_format_parse(param, &info.media_type, &info.media_subtype) < 0) {
        return;
    }
    if (info.media_type != SPA_MEDIA_TYPE_video || info.media_subtype != SPA_MEDIA_SUBTYPE_raw) {
        return;
    }
    if (spa_format_video_raw_parse(param, &info.info.raw) < 0) {
        return;
    }
    pthread_mutex_lock(&cap->mu);
    if (info.info.raw.size.width > 0 && info.info.raw.size.width <= AL_PW_MAX_DIM
        && info.info.raw.size.height > 0 && info.info.raw.size.height <= AL_PW_MAX_DIM) {
        cap->width = (int)info.info.raw.size.width;
        cap->height = (int)info.info.raw.size.height;
    } else {
        cap->width = 0;
        cap->height = 0;
    }
    cap->src_width = cap->width;
    cap->src_height = cap->height;
    cap->format = (int)info.info.raw.format;
    pthread_mutex_unlock(&cap->mu);
}

/*
 * SPA_META_Cursor / SPA_META_VideoCrop are enum members, not macros — never
 * `#ifdef` them (that compiles the parser OUT on real spa headers). Under
 * HAVE_PIPEWIRE, spa/buffer/meta.h is included and the enum values exist.
 *
 * Semantics (PipeWire docs + Mutter unset):
 * - Absent meta: keep prior cursor (not a new hide).
 * - id == 0: Mutter explicit unset → hidden / outside stream.
 * - bitmap_offset == 0: no NEW bitmap (keep sprite); position may update.
 * - format == 0: no new bitmap info.
 * - inner bitmap.offset == 0: no image pixels → invisible.
 * Mutter cursor pixels are premultiplied BGRA; we un-premultiply to straight
 * RGBA for the wire so egui ColorImage::from_rgba_unmultiplied is correct.
 */
static int cursor_format_supported(uint32_t format) {
    return format == SPA_VIDEO_FORMAT_BGRA
        || format == SPA_VIDEO_FORMAT_BGRx
        || format == SPA_VIDEO_FORMAT_RGBA
        || format == SPA_VIDEO_FORMAT_RGBx;
}

static void apply_cursor_meta(PwCapture *cap, struct spa_buffer *spa_buf) {
    struct spa_meta *meta = spa_buffer_find_meta(spa_buf, SPA_META_Cursor);
    struct spa_meta_cursor *cur;
    if (!meta || !meta->data || meta->size < sizeof(struct spa_meta_cursor)) {
        return; /* absent — do not hide */
    }
    cur = meta->data;
    if (cur->id == 0) {
        cap->cursor_valid = 1;
        cap->cursor_visible = 0;
        cap->cursor_seq++;
        return;
    }
    cap->cursor_valid = 1;
    cap->cursor_x = cur->position.x;
    cap->cursor_y = cur->position.y;
    cap->cursor_hotspot_x = cur->hotspot.x;
    cap->cursor_hotspot_y = cur->hotspot.y;
    cap->cursor_visible = 1;
    if (cur->bitmap_offset == 0) {
        /* Position-only; keep prior sprite. */
        cap->cursor_seq++;
        return;
    }
    if (cur->bitmap_offset < sizeof(struct spa_meta_cursor)) {
        cap->cursor_seq++;
        return;
    }
    if ((size_t)cur->bitmap_offset + sizeof(struct spa_meta_bitmap) > meta->size) {
        cap->cursor_seq++;
        return;
    }
    {
        struct spa_meta_bitmap *bm =
            SPA_PTROFF(cur, cur->bitmap_offset, struct spa_meta_bitmap);
        uint32_t bw_u = bm->size.width;
        uint32_t bh_u = bm->size.height;
        if (bm->format == 0) {
            cap->cursor_seq++;
            return;
        }
        if (bm->offset == 0) {
            cap->cursor_visible = 0;
            cap->cursor_has_bitmap = 0;
            cap->cursor_w = 0;
            cap->cursor_h = 0;
            cap->cursor_seq++;
            return;
        }
        if (!cursor_format_supported(bm->format)
            || bw_u == 0 || bh_u == 0
            || bw_u > (uint32_t)AL_PW_CURSOR_EDGE
            || bh_u > (uint32_t)AL_PW_CURSOR_EDGE
            || bm->stride < 0
            || (uint32_t)bm->stride < bw_u * 4u
            || bm->offset < sizeof(struct spa_meta_bitmap)) {
            /* Unsupported / bad geometry — keep prior bitmap, pos already set. */
            cap->cursor_seq++;
            return;
        }
        {
            size_t pix_base = (size_t)cur->bitmap_offset + (size_t)bm->offset;
            size_t last = pix_base
                + (size_t)(bh_u - 1u) * (size_t)bm->stride
                + (size_t)bw_u * 4u;
            if (last > meta->size || pix_base + (size_t)bw_u * 4u > meta->size) {
                cap->cursor_seq++;
                return;
            }
            {
                const uint8_t *src = SPA_PTROFF(bm, bm->offset, const uint8_t);
                int bw = (int)bw_u;
                int bh = (int)bh_u;
                int row;
                int is_bgr = bm->format == SPA_VIDEO_FORMAT_BGRA
                    || bm->format == SPA_VIDEO_FORMAT_BGRx;
                int force_opaque = bm->format == SPA_VIDEO_FORMAT_BGRx
                    || bm->format == SPA_VIDEO_FORMAT_RGBx;
                for (row = 0; row < bh; row++) {
                    const uint8_t *srow = src + (size_t)row * (size_t)bm->stride;
                    uint8_t *drow = cap->cursor_rgba + (size_t)row * (size_t)bw * 4u;
                    int col;
                    for (col = 0; col < bw; col++) {
                        const uint8_t *px = srow + (size_t)col * 4u;
                        uint8_t r = is_bgr ? px[2] : px[0];
                        uint8_t g = px[1];
                        uint8_t b = is_bgr ? px[0] : px[2];
                        uint8_t a = force_opaque ? 255 : px[3];
                        /* Un-premultiply Mutter premul → straight RGBA for wire. */
                        if (!force_opaque && a > 0 && a < 255) {
                            r = (uint8_t)(((unsigned)r * 255u) / (unsigned)a);
                            g = (uint8_t)(((unsigned)g * 255u) / (unsigned)a);
                            b = (uint8_t)(((unsigned)b * 255u) / (unsigned)a);
                        }
                        drow[col * 4 + 0] = r;
                        drow[col * 4 + 1] = g;
                        drow[col * 4 + 2] = b;
                        drow[col * 4 + 3] = a;
                    }
                }
                cap->cursor_w = bw;
                cap->cursor_h = bh;
                cap->cursor_has_bitmap = 1;
            }
        }
    }
    cap->cursor_seq++;
}

static void apply_videocrop_meta(PwCapture *cap, struct spa_buffer *spa_buf) {
    struct spa_meta *meta = spa_buffer_find_meta(spa_buf, SPA_META_VideoCrop);
    if (meta && meta->data && meta->size >= sizeof(struct spa_region)) {
        struct spa_region *region = meta->data;
        int cx = region->position.x;
        int cy = region->position.y;
        int cw = (int)region->size.width;
        int ch = (int)region->size.height;
        if (cw > 0 && ch > 0 && cx >= 0 && cy >= 0
            && cx + cw <= cap->width && cy + ch <= cap->height
            && (cw < cap->width || ch < cap->height)) {
            cap->crop_valid = 1;
            cap->crop_x = cx;
            cap->crop_y = cy;
            cap->crop_w = cw;
            cap->crop_h = ch;
        }
    }
}

static void on_process(void *userdata) {
    PwCapture *cap = userdata;
    struct pw_buffer *buffer;
    struct spa_buffer *spa_buf;
    struct spa_data *data;
    int size;
    int stride;
    int height;
    uint8_t *dst;
    int have_video = 0;

    buffer = pw_stream_dequeue_buffer(cap->stream);
    if (buffer == NULL) {
        return;
    }
    spa_buf = buffer->buffer;

    pthread_mutex_lock(&cap->mu);
    /* Cursor / crop first — metadata-only buffers must not wait on pixels. */
    apply_cursor_meta(cap, spa_buf);
    cap->crop_valid = 0;
    cap->crop_x = cap->crop_y = cap->crop_w = cap->crop_h = 0;
    apply_videocrop_meta(cap, spa_buf);

    if (spa_buf->n_datas >= 1) {
        data = &spa_buf->datas[0];
        if (data->data != NULL && data->chunk != NULL && is_bgra((uint32_t)cap->format)) {
            size_t valid_stride = 0;
            size_t alloc_bytes = 0;
            size_t copy_bytes = 0;
            if (al_pw_validate_frame_copy(
                    cap->width,
                    cap->height,
                    data->chunk->stride,
                    data->chunk->offset,
                    data->chunk->size,
                    data->maxsize,
                    &valid_stride,
                    &alloc_bytes,
                    &copy_bytes)) {
                size = (int)alloc_bytes;
                if (cap->bgra_size < size) {
                    uint8_t *grown = (uint8_t *)realloc(cap->bgra, alloc_bytes);
                    if (grown) {
                        cap->bgra = grown;
                        cap->bgra_size = size;
                    }
                }
                if (cap->bgra && (size_t)cap->bgra_size >= alloc_bytes) {
                    const void *src_ptr = SPA_PTROFF(data->data, data->chunk->offset, const void);
                    dst = cap->bgra;
                    memcpy(dst, src_ptr, copy_bytes);
                    if (alloc_bytes > copy_bytes) {
                        memset(dst + copy_bytes, 0, alloc_bytes - copy_bytes);
                    }
                    cap->stride = (int)valid_stride;
                    cap->src_width = cap->width;
                    cap->src_height = cap->height;
                    cap->dma_buf = data->type == SPA_DATA_DmaBuf;
                    have_video = 1;
                }
            }
        }
    }
    /* Only bump video seq when a real frame was copied. */
    if (have_video) {
        cap->seq++;
    }
    pthread_mutex_unlock(&cap->mu);
    pw_stream_queue_buffer(cap->stream, buffer);
}

static const struct pw_stream_events STREAM_EVENTS = {
    PW_VERSION_STREAM_EVENTS,
    .param_changed = on_param_changed,
    .process = on_process,
};

struct NodeWait {
    uint32_t target;
    volatile int found;
};

static void on_registry_global(
    void *data,
    uint32_t id,
    uint32_t permissions,
    const char *type,
    uint32_t version,
    const struct spa_dict *props
) {
    struct NodeWait *wait = data;
    (void)permissions;
    (void)type;
    (void)version;
    (void)props;
    if (id == wait->target) {
        wait->found = 1;
    }
}

static const struct pw_registry_events REGISTRY_EVENTS = {
    PW_VERSION_REGISTRY_EVENTS,
    .global = on_registry_global,
};

PwCapture *al_pw_open(int fd, unsigned int node_id) {
    PwCapture *cap;
    struct pw_properties *props;
    int argc = 0;

    static int once = 0;
    if (!once) {
        pw_init(&argc, NULL);
        once = 1;
    }
    cap = (PwCapture *)calloc(1, sizeof(*cap));
    if (!cap) {
        return NULL;
    }
    pthread_mutex_init(&cap->mu, NULL);
    cap->loop = pw_thread_loop_new("agentlink-pw", NULL);
    if (!cap->loop) {
        pthread_mutex_destroy(&cap->mu);
        free(cap);
        return NULL;
    }
    cap->context = pw_context_new(pw_thread_loop_get_loop(cap->loop), NULL, 0);
    if (!cap->context) {
        pw_thread_loop_destroy(cap->loop);
        pthread_mutex_destroy(&cap->mu);
        free(cap);
        return NULL;
    }
    if (pw_thread_loop_start(cap->loop) < 0) {
        pw_context_destroy(cap->context);
        pw_thread_loop_destroy(cap->loop);
        pthread_mutex_destroy(&cap->mu);
        free(cap);
        return NULL;
    }
    pw_thread_loop_lock(cap->loop);
    if (fd >= 0) {
        cap->core = pw_context_connect_fd(cap->context, fd, NULL, 0);
    } else {
        /* Mutter exports ScreenCast nodes on the user's default daemon. */
        cap->core = pw_context_connect(cap->context, NULL, 0);
    }
    if (!cap->core) {
        pw_thread_loop_unlock(cap->loop);
        pw_thread_loop_stop(cap->loop);
        pw_context_destroy(cap->context);
        pw_thread_loop_destroy(cap->loop);
        pthread_mutex_destroy(&cap->mu);
        free(cap);
        return NULL;
    }
    /*
     * Mutter emits PipeWireStreamAdded before the node is visible to other
     * clients. Wait for the registry to announce it, otherwise
     * pw_stream_connect fails with "no target node available".
     */
    if (fd < 0) {
        struct pw_registry *registry =
            pw_core_get_registry(cap->core, PW_VERSION_REGISTRY, 0);
        if (registry) {
            struct spa_hook hook;
            struct NodeWait wait;
            wait.target = node_id;
            wait.found = 0;
            pw_registry_add_listener(registry, &hook, &REGISTRY_EVENTS, &wait);
            pw_thread_loop_unlock(cap->loop);
            for (int i = 0; i < 300 && !wait.found; i++) {
                usleep(10000);
            }
            pw_thread_loop_lock(cap->loop);
            spa_hook_remove(&hook);
            pw_proxy_destroy((struct pw_proxy *)registry);
            if (!wait.found) {
                pw_thread_loop_unlock(cap->loop);
                pw_thread_loop_stop(cap->loop);
                pw_context_destroy(cap->context);
                pw_thread_loop_destroy(cap->loop);
                pthread_mutex_destroy(&cap->mu);
                free(cap);
                return NULL;
            }
        }
    }
    /*
     * Do not set PW_KEY_TARGET_OBJECT: a string there is matched as a node
     * name, not an id, and overrides the numeric target passed to
     * pw_stream_connect ("no target node available").
     */
    props = pw_properties_new(
        PW_KEY_MEDIA_TYPE, "Video",
        PW_KEY_MEDIA_CATEGORY, "Capture",
        PW_KEY_MEDIA_ROLE, "Screen",
        NULL);
    cap->stream = pw_stream_new_simple(
        pw_thread_loop_get_loop(cap->loop),
        "agentlink-screencast",
        props,
        &STREAM_EVENTS,
        cap);
    if (!cap->stream) {
        pw_thread_loop_unlock(cap->loop);
        pw_thread_loop_stop(cap->loop);
        pw_context_destroy(cap->context);
        pw_thread_loop_destroy(cap->loop);
        pthread_mutex_destroy(&cap->mu);
        free(cap);
        return NULL;
    }
    /*
     * Without an EnumFormat the consumer port never negotiates and
     * param_changed/process never fire. Mutter offers BGRx/BGRA on memfd or
     * dma-buf; both are copied out by on_process(). Request Cursor (+ optional
     * VideoCrop) meta so metadata-mode producers attach spa_meta_cursor.
     */
    {
        uint8_t fmt[2048];
        struct spa_pod_builder builder = SPA_POD_BUILDER_INIT(fmt, sizeof(fmt));
        const struct spa_pod *params[4];
        uint32_t n_params = 0;
        params[n_params++] = spa_pod_builder_add_object(
            &builder,
            SPA_TYPE_OBJECT_Format, SPA_PARAM_EnumFormat,
            SPA_FORMAT_mediaType, SPA_POD_Id(SPA_MEDIA_TYPE_video),
            SPA_FORMAT_mediaSubtype, SPA_POD_Id(SPA_MEDIA_SUBTYPE_raw),
            SPA_FORMAT_VIDEO_format, SPA_POD_CHOICE_ENUM_Id(
                3,
                SPA_VIDEO_FORMAT_BGRx,
                SPA_VIDEO_FORMAT_BGRx,
                SPA_VIDEO_FORMAT_BGRA),
            0);
        /* Enum values — not macros; always request when HAVE_PIPEWIRE. */
        params[n_params++] = spa_pod_builder_add_object(
            &builder,
            SPA_TYPE_OBJECT_ParamMeta, SPA_PARAM_Meta,
            SPA_PARAM_META_type, SPA_POD_Id(SPA_META_Cursor),
            SPA_PARAM_META_size, SPA_POD_Int(
                (int)sizeof(struct spa_meta_cursor) +
                (int)sizeof(struct spa_meta_bitmap) +
                AL_PW_CURSOR_EDGE * AL_PW_CURSOR_EDGE * 4),
            0);
        params[n_params++] = spa_pod_builder_add_object(
            &builder,
            SPA_TYPE_OBJECT_ParamMeta, SPA_PARAM_Meta,
            SPA_PARAM_META_type, SPA_POD_Id(SPA_META_VideoCrop),
            SPA_PARAM_META_size, SPA_POD_Int((int)sizeof(struct spa_meta_region)),
            0);
        if (pw_stream_connect(
                cap->stream,
                PW_DIRECTION_INPUT,
                node_id,
                PW_STREAM_FLAG_AUTOCONNECT | PW_STREAM_FLAG_MAP_BUFFERS,
                params,
                n_params) < 0) {
            pw_stream_destroy(cap->stream);
            pw_thread_loop_unlock(cap->loop);
            pw_thread_loop_stop(cap->loop);
            pw_context_destroy(cap->context);
            pw_thread_loop_destroy(cap->loop);
            pthread_mutex_destroy(&cap->mu);
            free(cap);
            return NULL;
        }
    }
    pw_thread_loop_unlock(cap->loop);
    return cap;
}

int al_pw_take(
    PwCapture *cap,
    unsigned char *dst,
    int dst_cap,
    int *width,
    int *height,
    int *stride,
    int *dma_buf,
    int wait_ms
) {
    int spins;
    int step_us = 5000;
    if (!cap || !dst || dst_cap < 0) {
        return -1;
    }
    spins = wait_ms <= 0 ? 1 : (wait_ms * 1000) / step_us;
    if (spins < 1) {
        spins = 1;
    }
    for (int i = 0; i < spins; i++) {
        int seq;
        pthread_mutex_lock(&cap->mu);
        seq = cap->seq;
        if (seq != cap->last_taken && cap->bgra && cap->width > 0 && cap->height > 0 && cap->stride > 0) {
            uint64_t size64 = (uint64_t)(uint32_t)cap->stride * (uint64_t)(uint32_t)cap->height;
            if (size64 > (uint64_t)AL_PW_MAX_FRAME_BYTES || (size_t)size64 > (size_t)cap->bgra_size) {
                pthread_mutex_unlock(&cap->mu);
                return -1;
            }
            if (size64 > (uint64_t)(uint32_t)dst_cap) {
                /* Report the real geometry so the caller can resize. */
                *width = cap->width;
                *height = cap->height;
                *stride = cap->stride;
                *dma_buf = cap->dma_buf;
                pthread_mutex_unlock(&cap->mu);
                return -2;
            }
            if (cap->target_width > 0 && cap->target_width < cap->width) {
                int out_w = cap->target_width;
                int out_h = (int)(((int64_t)cap->height * (int64_t)out_w + cap->width / 2) / cap->width);
                uint64_t out_stride64;
                uint64_t out_size64;
                if (out_h < 1) out_h = 1;
                out_stride64 = (uint64_t)(uint32_t)out_w * 4ULL;
                out_size64 = out_stride64 * (uint64_t)(uint32_t)out_h;
                if (out_size64 > (uint64_t)(uint32_t)dst_cap) {
                    *width = out_w;
                    *height = out_h;
                    *stride = (int)out_stride64;
                    *dma_buf = cap->dma_buf;
                    pthread_mutex_unlock(&cap->mu);
                    return -2;
                }
                downsample_nn(cap->bgra, cap->width, cap->height, cap->stride,
                              dst, out_w, out_h, (int)out_stride64);
                *width = out_w;
                *height = out_h;
                *stride = (int)out_stride64;
            } else {
                memcpy(dst, cap->bgra, (size_t)size64);
                *width = cap->width;
                *height = cap->height;
                *stride = cap->stride;
            }
            *dma_buf = cap->dma_buf;
            cap->last_taken = seq;
            pthread_mutex_unlock(&cap->mu);
            return 1;
        }
        pthread_mutex_unlock(&cap->mu);
        if (i + 1 < spins) {
            struct timespec ts;
            ts.tv_sec = 0;
            ts.tv_nsec = step_us * 1000L;
            nanosleep(&ts, NULL);
        }
    }
    return 0;
}


void al_pw_set_target_width(PwCapture *cap, int target_width) {
    if (!cap) return;
    pthread_mutex_lock(&cap->mu);
    cap->target_width = target_width > 0 ? target_width : 0;
    pthread_mutex_unlock(&cap->mu);
}

void al_pw_geometry(
    PwCapture *cap,
    int *src_width,
    int *src_height,
    int *out_width,
    int *out_height
) {
    if (!cap) return;
    pthread_mutex_lock(&cap->mu);
    if (src_width) *src_width = cap->src_width > 0 ? cap->src_width : cap->width;
    if (src_height) *src_height = cap->src_height > 0 ? cap->src_height : cap->height;
    if (out_width) {
        if (cap->target_width > 0 && cap->target_width < cap->width)
            *out_width = cap->target_width;
        else
            *out_width = cap->width;
    }
    if (out_height) {
        if (cap->target_width > 0 && cap->target_width < cap->width) {
            int oh = (int)(((int64_t)cap->height * (int64_t)cap->target_width + cap->width / 2) / cap->width);
            *out_height = oh < 1 ? 1 : oh;
        } else {
            *out_height = cap->height;
        }
    }
    pthread_mutex_unlock(&cap->mu);
}

int al_pw_videocrop(PwCapture *cap, int *x, int *y, int *w, int *h) {
    int ok = 0;
    if (!cap) return 0;
    pthread_mutex_lock(&cap->mu);
    if (cap->crop_valid && cap->crop_w > 0 && cap->crop_h > 0) {
        if (x) *x = cap->crop_x;
        if (y) *y = cap->crop_y;
        if (w) *w = cap->crop_w;
        if (h) *h = cap->crop_h;
        ok = 1;
    }
    pthread_mutex_unlock(&cap->mu);
    return ok;
}

/*
 * Latest SPA_META_Cursor without waiting on al_pw_take / encode.
 * Returns 1 when a sample is available, 0 when none yet, -1 on error.
 * rgba_out may be NULL to skip bitmap copy; *has_bitmap reports presence.
 */
int al_pw_cursor(
    PwCapture *cap,
    int *x,
    int *y,
    int *hotspot_x,
    int *hotspot_y,
    int *visible,
    int *width,
    int *height,
    int *has_bitmap,
    unsigned char *rgba_out,
    int rgba_cap
) {
    if (!cap) return -1;
    pthread_mutex_lock(&cap->mu);
    if (!cap->cursor_valid) {
        pthread_mutex_unlock(&cap->mu);
        return 0;
    }
    if (x) *x = cap->cursor_x;
    if (y) *y = cap->cursor_y;
    if (hotspot_x) *hotspot_x = cap->cursor_hotspot_x;
    if (hotspot_y) *hotspot_y = cap->cursor_hotspot_y;
    if (visible) *visible = cap->cursor_visible ? 1 : 0;
    if (width) *width = cap->cursor_w;
    if (height) *height = cap->cursor_h;
    if (has_bitmap) *has_bitmap = cap->cursor_has_bitmap ? 1 : 0;
    if (rgba_out && cap->cursor_has_bitmap && cap->cursor_w > 0 && cap->cursor_h > 0) {
        int need = cap->cursor_w * cap->cursor_h * 4;
        if (need > rgba_cap) {
            pthread_mutex_unlock(&cap->mu);
            return -2;
        }
        memcpy(rgba_out, cap->cursor_rgba, (size_t)need);
    }
    pthread_mutex_unlock(&cap->mu);
    return 1;
}

void al_pw_close(PwCapture *cap) {

    if (!cap) {
        return;
    }
    if (cap->loop) {
        pw_thread_loop_lock(cap->loop);
        if (cap->stream) {
            pw_stream_destroy(cap->stream);
        }
        pw_thread_loop_unlock(cap->loop);
        pw_thread_loop_stop(cap->loop);
    }
    if (cap->context) {
        pw_context_destroy(cap->context);
    }
    if (cap->loop) {
        pw_thread_loop_destroy(cap->loop);
    }
    free(cap->bgra);
    pthread_mutex_destroy(&cap->mu);
    free(cap);
}

#else
typedef struct PwCapture PwCapture;
#endif
