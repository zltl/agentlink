/* Public-domain minih264 (https://github.com/lieff/minih264), CC0. */
#include <stdlib.h>
#include <string.h>

#ifndef H264E_MAX_THREADS
#define H264E_MAX_THREADS 1
#endif
/* Apple clang does not declare the old vtbl2q_u8 name. vqtbl2_u8 is the
   same 32-byte table lookup and returns uint8x8_t, which is what the
   call site passes to vreinterpret_s16_u8. */
#if defined(__APPLE__) && defined(__aarch64__)
#define vtbl2q_u8 vqtbl2_u8
#endif
#define MINIH264_IMPLEMENTATION
#include "minih264e.h"

typedef struct MiniEncoder {
    H264E_persist_t *enc;
    H264E_scratch_t *scratch;
    int sizeof_scratch;
} MiniEncoder;

MiniEncoder *mini_open(int width, int height, int gop, int vbv_bytes) {
    H264E_create_param_t par;
    int sizeof_persist = 0;
    int sizeof_scratch = 0;
    MiniEncoder *mini;

    memset(&par, 0, sizeof(par));
    par.width = width;
    par.height = height;
    par.gop = gop;
    par.vbv_size_bytes = vbv_bytes > 0 ? vbv_bytes : 0;
    par.const_input_flag = 1;
    par.fine_rate_control_flag = 1;
    par.max_long_term_reference_frames = 0;
#if H264E_MAX_THREADS
    par.max_threads = 1;
#endif
    if (H264E_sizeof(&par, &sizeof_persist, &sizeof_scratch) != H264E_STATUS_SUCCESS) {
        return NULL;
    }
    mini = (MiniEncoder *)calloc(1, sizeof(*mini));
    if (!mini) {
        return NULL;
    }
    mini->enc = (H264E_persist_t *)calloc(1, (size_t)sizeof_persist);
    mini->scratch = (H264E_scratch_t *)calloc(1, (size_t)sizeof_scratch);
    mini->sizeof_scratch = sizeof_scratch;
    if (!mini->enc || !mini->scratch || H264E_init(mini->enc, &par) != H264E_STATUS_SUCCESS) {
        free(mini->enc);
        free(mini->scratch);
        free(mini);
        return NULL;
    }
    return mini;
}

int mini_encode(
    MiniEncoder *mini,
    unsigned char *y,
    unsigned char *u,
    unsigned char *v,
    int stride_y,
    int stride_u,
    int stride_v,
    int frame_type,
    int desired_bytes,
    unsigned char *out,
    int out_cap
) {
    H264E_io_yuv_t frame;
    H264E_run_param_t run;
    unsigned char *coded = NULL;
    int coded_len = 0;
    int status;

    if (!mini || !out || out_cap <= 0) {
        return -1;
    }
    memset(&frame, 0, sizeof(frame));
    memset(&run, 0, sizeof(run));
    frame.yuv[0] = y;
    frame.yuv[1] = u;
    frame.yuv[2] = v;
    frame.stride[0] = stride_y;
    frame.stride[1] = stride_u;
    frame.stride[2] = stride_v;
    run.encode_speed = H264E_SPEED_FASTEST;
    run.frame_type = frame_type;
    run.desired_frame_bytes = desired_bytes > 0 ? desired_bytes : 4000;
    run.qp_min = 18;
    run.qp_max = 42;
    status = H264E_encode(mini->enc, mini->scratch, &run, &frame, &coded, &coded_len);
    if (status != H264E_STATUS_SUCCESS || !coded || coded_len <= 0 || coded_len > out_cap) {
        return status == H264E_STATUS_SUCCESS ? -2 : status;
    }
    memcpy(out, coded, (size_t)coded_len);
    return coded_len;
}

void mini_close(MiniEncoder *mini) {
    if (!mini) {
        return;
    }
    free(mini->enc);
    free(mini->scratch);
    free(mini);
}
