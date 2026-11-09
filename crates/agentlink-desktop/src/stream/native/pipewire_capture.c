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
#include <spa/pod/builder.h>
#include <spa/debug/types.h>

#include <errno.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

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
    cap->width = (int)info.info.raw.size.width;
    cap->height = (int)info.info.raw.size.height;
    cap->src_width = cap->width;
    cap->src_height = cap->height;
    cap->format = (int)info.info.raw.format;
    pthread_mutex_unlock(&cap->mu);
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

    buffer = pw_stream_dequeue_buffer(cap->stream);
    if (buffer == NULL) {
        return;
    }
    spa_buf = buffer->buffer;
    if (spa_buf->n_datas < 1) {
        pw_stream_queue_buffer(cap->stream, buffer);
        return;
    }
    data = &spa_buf->datas[0];
    if (data->data == NULL || data->chunk == NULL) {
        pw_stream_queue_buffer(cap->stream, buffer);
        return;
    }
    pthread_mutex_lock(&cap->mu);
    height = cap->height;
    stride = data->chunk->stride > 0 ? data->chunk->stride : cap->width * 4;
    if (height <= 0 || cap->width <= 0 || !is_bgra((uint32_t)cap->format)) {
        pthread_mutex_unlock(&cap->mu);
        pw_stream_queue_buffer(cap->stream, buffer);
        return;
    }
    size = stride * height;
    if (size <= 0 || size > 64 * 1024 * 1024) {
        pthread_mutex_unlock(&cap->mu);
        pw_stream_queue_buffer(cap->stream, buffer);
        return;
    }
    if (cap->bgra_size < size) {
        uint8_t *grown = (uint8_t *)realloc(cap->bgra, (size_t)size);
        if (!grown) {
            pthread_mutex_unlock(&cap->mu);
            pw_stream_queue_buffer(cap->stream, buffer);
            return;
        }
        cap->bgra = grown;
        cap->bgra_size = size;
    }
    dst = cap->bgra;
    if (data->chunk->size > 0 && (int)data->chunk->size < size) {
        size = (int)data->chunk->size;
    }
    memcpy(dst, data->data, (size_t)size);
    cap->stride = stride;
    cap->src_width = cap->width;
    cap->src_height = cap->height;
    cap->dma_buf = data->type == SPA_DATA_DmaBuf;
    cap->seq++;
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
        free(cap);
        return NULL;
    }
    cap->context = pw_context_new(pw_thread_loop_get_loop(cap->loop), NULL, 0);
    if (!cap->context) {
        pw_thread_loop_destroy(cap->loop);
        free(cap);
        return NULL;
    }
    if (pw_thread_loop_start(cap->loop) < 0) {
        pw_context_destroy(cap->context);
        pw_thread_loop_destroy(cap->loop);
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
        free(cap);
        return NULL;
    }
    /*
     * Without an EnumFormat the consumer port never negotiates and
     * param_changed/process never fire. Mutter offers BGRx/BGRA on memfd or
     * dma-buf; both are copied out by on_process().
     */
    {
        uint8_t fmt[1024];
        struct spa_pod_builder builder = SPA_POD_BUILDER_INIT(fmt, sizeof(fmt));
        const struct spa_pod *params[1];
        params[0] = spa_pod_builder_add_object(
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
        if (pw_stream_connect(
                cap->stream,
                PW_DIRECTION_INPUT,
                node_id,
                PW_STREAM_FLAG_AUTOCONNECT | PW_STREAM_FLAG_MAP_BUFFERS,
                params,
                1) < 0) {
            pw_stream_destroy(cap->stream);
            pw_thread_loop_unlock(cap->loop);
            pw_thread_loop_stop(cap->loop);
            pw_context_destroy(cap->context);
            pw_thread_loop_destroy(cap->loop);
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
    if (!cap || !dst) {
        return -1;
    }
    spins = wait_ms <= 0 ? 1 : (wait_ms * 1000) / step_us;
    if (spins < 1) {
        spins = 1;
    }
    for (int i = 0; i < spins; i++) {
        int seq;
        int size;
        pthread_mutex_lock(&cap->mu);
        seq = cap->seq;
        if (seq != cap->last_taken && cap->bgra && cap->width > 0 && cap->height > 0) {
            size = cap->stride * cap->height;
            if (size > dst_cap) {
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
                int out_stride;
                int out_size;
                if (out_h < 1) out_h = 1;
                out_stride = out_w * 4;
                out_size = out_stride * out_h;
                if (out_size > dst_cap) {
                    *width = out_w;
                    *height = out_h;
                    *stride = out_stride;
                    *dma_buf = cap->dma_buf;
                    pthread_mutex_unlock(&cap->mu);
                    return -2;
                }
                downsample_nn(cap->bgra, cap->width, cap->height, cap->stride,
                              dst, out_w, out_h, out_stride);
                *width = out_w;
                *height = out_h;
                *stride = out_stride;
            } else {
                memcpy(dst, cap->bgra, (size_t)size);
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
