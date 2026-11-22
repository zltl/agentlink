/*
 * VideoToolbox baseline/main encoder. AllowFrameReordering is false, so the
 * session does not emit B-frames. Output is Annex-B.
 */
#include <CoreFoundation/CoreFoundation.h>
#include <CoreMedia/CoreMedia.h>
#include <CoreVideo/CoreVideo.h>
#include <VideoToolbox/VideoToolbox.h>

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

typedef struct VtEnc {
    VTCompressionSessionRef session;
    VTPixelTransferSessionRef transfer;
    CVPixelBufferRef dst_pixel;
    CVPixelBufferRef src_pixel;
    int src_pixel_w;
    int src_pixel_h;
    int width;
    int height;
    int hevc;
    uint8_t *annexb;
    size_t annexb_len;
    size_t annexb_cap;
    int keyframe;
    int failed;
    int timescale;
    int64_t next_pts;
} VtEnc;

static void append_bytes(VtEnc *enc, const uint8_t *data, size_t len) {
    if (enc->annexb_len + len > enc->annexb_cap) {
        size_t next = (enc->annexb_cap ? enc->annexb_cap * 2 : 65536);
        while (next < enc->annexb_len + len) {
            next *= 2;
        }
        uint8_t *grown = realloc(enc->annexb, next);
        if (!grown) {
            enc->failed = 1;
            return;
        }
        enc->annexb = grown;
        enc->annexb_cap = next;
    }
    memcpy(enc->annexb + enc->annexb_len, data, len);
    enc->annexb_len += len;
}

static void append_nal(VtEnc *enc, const uint8_t *nal, size_t len) {
    static const uint8_t start[4] = {0, 0, 0, 1};
    append_bytes(enc, start, 4);
    append_bytes(enc, nal, len);
}

static void avcc_to_annexb(VtEnc *enc, CMBlockBufferRef block) {
    size_t total = CMBlockBufferGetDataLength(block);
    size_t offset = 0;
    while (offset + 4 <= total) {
        uint8_t lenb[4];
        if (CMBlockBufferCopyDataBytes(block, offset, 4, lenb) != kCMBlockBufferNoErr) {
            return;
        }
        uint32_t nal_len = ((uint32_t)lenb[0] << 24) | ((uint32_t)lenb[1] << 16) |
                           ((uint32_t)lenb[2] << 8) | (uint32_t)lenb[3];
        offset += 4;
        if (nal_len == 0 || offset + nal_len > total) {
            return;
        }
        uint8_t *tmp = malloc(nal_len);
        if (!tmp) {
            return;
        }
        if (CMBlockBufferCopyDataBytes(block, offset, nal_len, tmp) == kCMBlockBufferNoErr) {
            append_nal(enc, tmp, nal_len);
        }
        free(tmp);
        offset += nal_len;
    }
}

static void output_callback(
    void *ref,
    void *source_frame,
    OSStatus status,
    VTEncodeInfoFlags flags,
    CMSampleBufferRef sample
) {
    (void)source_frame;
    (void)flags;
    VtEnc *enc = ref;
    if (status != noErr || sample == NULL || enc == NULL) {
        if (enc) {
            enc->failed = 1;
        }
        return;
    }
    enc->keyframe = 1;
    CFArrayRef attachments = CMSampleBufferGetSampleAttachmentsArray(sample, false);
    if (attachments && CFArrayGetCount(attachments) > 0) {
        CFDictionaryRef dict = CFArrayGetValueAtIndex(attachments, 0);
        CFBooleanRef not_sync = CFDictionaryGetValue(dict, kCMSampleAttachmentKey_NotSync);
        if (not_sync == kCFBooleanTrue) {
            enc->keyframe = 0;
        }
    }
    if (enc->keyframe) {
        CMFormatDescriptionRef fmt = CMSampleBufferGetFormatDescription(sample);
        size_t count = 0;
        int index;
        for (index = 0; index < 8; index++) {
            const uint8_t *set = NULL;
            size_t set_len = 0;
            OSStatus ps = enc->hevc
                ? CMVideoFormatDescriptionGetHEVCParameterSetAtIndex(
                      fmt, index, &set, &set_len, &count, NULL)
                : CMVideoFormatDescriptionGetH264ParameterSetAtIndex(
                      fmt, index, &set, &set_len, &count, NULL);
            if (ps != noErr) {
                break;
            }
            append_nal(enc, set, set_len);
        }
    }
    CMBlockBufferRef block = CMSampleBufferGetDataBuffer(sample);
    if (block) {
        avcc_to_annexb(enc, block);
    }
}

static CFDictionaryRef encoder_spec(void) {
    CFMutableDictionaryRef spec = CFDictionaryCreateMutable(
        kCFAllocatorDefault, 1, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
    if (spec) {
        CFDictionarySetValue(spec, kVTVideoEncoderSpecification_EnableHardwareAcceleratedVideoEncoder, kCFBooleanTrue);
    }
    return spec;
}

int al_vt_open(int width, int height, int fps, int bitrate, int hevc, void **out) {
    VtEnc *enc;
    OSStatus status;
    CFDictionaryRef spec;
    CFNumberRef num;
    int32_t interval;
    int32_t rate;
    int32_t avg;
    CMVideoCodecType codec;

    if (!out || width < 2 || height < 2) {
        return -1;
    }
    *out = NULL;
    enc = calloc(1, sizeof(*enc));
    if (!enc) {
        return -1;
    }
    enc->width = width;
    enc->height = height;
    enc->hevc = hevc ? 1 : 0;
    enc->timescale = fps > 0 ? fps : 30;
    codec = hevc ? kCMVideoCodecType_HEVC : kCMVideoCodecType_H264;
    spec = encoder_spec();
    status = VTCompressionSessionCreate(
        kCFAllocatorDefault,
        width,
        height,
        codec,
        spec,
        NULL,
        kCFAllocatorDefault,
        output_callback,
        enc,
        &enc->session);
    if (spec) {
        CFRelease(spec);
    }
    if (status != noErr || !enc->session) {
        free(enc);
        return (int)status;
    }
    if (VTPixelTransferSessionCreate(kCFAllocatorDefault, &enc->transfer) != noErr) {
        enc->transfer = NULL;
    }
    if (CVPixelBufferCreate(
            kCFAllocatorDefault,
            width,
            height,
            kCVPixelFormatType_32BGRA,
            NULL,
            &enc->dst_pixel) != kCVReturnSuccess) {
        enc->dst_pixel = NULL;
    }
    VTSessionSetProperty(enc->session, kVTCompressionPropertyKey_RealTime, kCFBooleanTrue);
    VTSessionSetProperty(enc->session, kVTCompressionPropertyKey_AllowFrameReordering, kCFBooleanFalse);
    if (!hevc) {
        VTSessionSetProperty(
            enc->session, kVTCompressionPropertyKey_ProfileLevel, kVTProfileLevel_H264_Baseline_AutoLevel);
    }
    avg = bitrate > 0 ? bitrate : 2000000;
    num = CFNumberCreate(kCFAllocatorDefault, kCFNumberSInt32Type, &avg);
    VTSessionSetProperty(enc->session, kVTCompressionPropertyKey_AverageBitRate, num);
    CFRelease(num);
    rate = fps > 0 ? fps : 30;
    num = CFNumberCreate(kCFAllocatorDefault, kCFNumberSInt32Type, &rate);
    VTSessionSetProperty(enc->session, kVTCompressionPropertyKey_ExpectedFrameRate, num);
    CFRelease(num);
    interval = rate * 2;
    num = CFNumberCreate(kCFAllocatorDefault, kCFNumberSInt32Type, &interval);
    VTSessionSetProperty(enc->session, kVTCompressionPropertyKey_MaxKeyFrameInterval, num);
    CFRelease(num);
    VTCompressionSessionPrepareToEncodeFrames(enc->session);
    *out = enc;
    return 0;
}

static void copy_bounded_bgra(
    CVPixelBufferRef pixel,
    const unsigned char *bgra,
    int src_w,
    int src_h,
    int src_stride,
    int dst_w,
    int dst_h
) {
    CVPixelBufferLockBaseAddress(pixel, 0);
    {
        uint8_t *base = CVPixelBufferGetBaseAddress(pixel);
        size_t row = CVPixelBufferGetBytesPerRow(pixel);
        int rows = src_h < dst_h ? src_h : dst_h;
        size_t copy_w = (size_t)(src_w < dst_w ? src_w : dst_w) * 4u;
        int y;
        if (copy_w > (size_t)src_stride) {
            copy_w = (size_t)src_stride;
        }
        if (copy_w > row) {
            copy_w = row;
        }
        memset(base, 0, row * (size_t)dst_h);
        for (y = 0; y < rows; y++) {
            memcpy(base + (size_t)y * row, bgra + (size_t)y * (size_t)src_stride, copy_w);
        }
    }
    CVPixelBufferUnlockBaseAddress(pixel, 0);
}

static void scale_bounded_bgra(
    CVPixelBufferRef pixel,
    const unsigned char *bgra,
    int src_w,
    int src_h,
    int src_stride,
    int dst_w,
    int dst_h
) {
    CVPixelBufferLockBaseAddress(pixel, 0);
    {
        uint8_t *base = CVPixelBufferGetBaseAddress(pixel);
        size_t dst_row = CVPixelBufferGetBytesPerRow(pixel);
        int y;
        memset(base, 0, dst_row * (size_t)dst_h);
        for (y = 0; y < dst_h; y++) {
            int sy = (int)(((int64_t)y * (int64_t)src_h) / (int64_t)dst_h);
            const uint8_t *srow;
            uint8_t *drow;
            int x;
            if (sy >= src_h) sy = src_h - 1;
            srow = bgra + (size_t)sy * (size_t)src_stride;
            drow = base + (size_t)y * dst_row;
            for (x = 0; x < dst_w; x++) {
                int sx = (int)(((int64_t)x * (int64_t)src_w) / (int64_t)dst_w);
                if (sx >= src_w) sx = src_w - 1;
                memcpy(drow + (size_t)x * 4u, srow + (size_t)sx * 4u, 4);
            }
        }
    }
    CVPixelBufferUnlockBaseAddress(pixel, 0);
}

static int ensure_src_pixel(VtEnc *enc, int src_w, int src_h) {
    if (enc->src_pixel && enc->src_pixel_w == src_w && enc->src_pixel_h == src_h) {
        return 1;
    }
    if (enc->src_pixel) {
        CFRelease(enc->src_pixel);
        enc->src_pixel = NULL;
        enc->src_pixel_w = 0;
        enc->src_pixel_h = 0;
    }
    if (CVPixelBufferCreate(
            kCFAllocatorDefault,
            src_w,
            src_h,
            kCVPixelFormatType_32BGRA,
            NULL,
            &enc->src_pixel) != kCVReturnSuccess || !enc->src_pixel) {
        enc->src_pixel = NULL;
        return 0;
    }
    enc->src_pixel_w = src_w;
    enc->src_pixel_h = src_h;
    return 1;
}

int al_vt_encode(
    void *raw,
    const unsigned char *bgra,
    int src_w,
    int src_h,
    int src_stride,
    int force_key,
    unsigned char *dst,
    int dst_cap,
    int *keyframe
) {
    VtEnc *enc = raw;
    CVPixelBufferRef pixel = NULL;
    int owns_pixel = 0;
    CFDictionaryRef frame_props = NULL;
    OSStatus status;
    VTEncodeInfoFlags flags = 0;
    int only_mb_pad;

    if (!enc || !bgra || !dst || dst_cap <= 0 || src_w <= 0 || src_h <= 0 || src_stride < src_w * 4) {
        return -1;
    }
    enc->annexb_len = 0;
    enc->failed = 0;
    enc->keyframe = 0;
    if (enc->dst_pixel) {
        pixel = enc->dst_pixel;
    } else {
        status = CVPixelBufferCreate(
            kCFAllocatorDefault,
            enc->width,
            enc->height,
            kCVPixelFormatType_32BGRA,
            NULL,
            &pixel);
        if (status != kCVReturnSuccess || !pixel) {
            return -2;
        }
        owns_pixel = 1;
    }
    only_mb_pad = (src_w <= enc->width && src_h <= enc->height &&
                   (enc->width - src_w) < 16 && (enc->height - src_h) < 16);
    if (only_mb_pad) {
        copy_bounded_bgra(pixel, bgra, src_w, src_h, src_stride, enc->width, enc->height);
    } else if (enc->transfer && ensure_src_pixel(enc, src_w, src_h)) {
        copy_bounded_bgra(enc->src_pixel, bgra, src_w, src_h, src_stride, src_w, src_h);
        if (VTPixelTransferSessionTransferImage(enc->transfer, enc->src_pixel, pixel) != noErr) {
            scale_bounded_bgra(pixel, bgra, src_w, src_h, src_stride, enc->width, enc->height);
        }
    } else {
        scale_bounded_bgra(pixel, bgra, src_w, src_h, src_stride, enc->width, enc->height);
    }
    if (force_key) {
        const void *keys[] = {kVTEncodeFrameOptionKey_ForceKeyFrame};
        const void *vals[] = {kCFBooleanTrue};
        frame_props = CFDictionaryCreate(
            kCFAllocatorDefault, keys, vals, 1, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
    }
    /* A repeated presentation time is dropped, which looks like an empty
     * packet. EncodeFrame is asynchronous: CompleteFrames runs the output
     * callback before we read annexb. */
    CMTime pts = CMTimeMake(enc->next_pts, enc->timescale);
    enc->next_pts += 1;
    status = VTCompressionSessionEncodeFrame(
        enc->session, pixel, pts, kCMTimeInvalid, frame_props, NULL, &flags);
    if (frame_props) {
        CFRelease(frame_props);
    }
    if (owns_pixel) {
        CFRelease(pixel);
    }
    if (status == noErr) {
        status = VTCompressionSessionCompleteFrames(enc->session, kCMTimeInvalid);
    }
    if (status != noErr || enc->failed || enc->annexb_len == 0) {
        return status != noErr ? (int)status : -3;
    }
    if ((int)enc->annexb_len > dst_cap) {
        return -4;
    }
    memcpy(dst, enc->annexb, enc->annexb_len);
    if (keyframe) {
        *keyframe = enc->keyframe;
    }
    return (int)enc->annexb_len;
}

void al_vt_set_bitrate(void *raw, int bitrate) {
    VtEnc *enc = raw;
    CFNumberRef num;
    int32_t avg;
    if (!enc || !enc->session) {
        return;
    }
    avg = bitrate > 0 ? bitrate : 200000;
    num = CFNumberCreate(kCFAllocatorDefault, kCFNumberSInt32Type, &avg);
    if (num) {
        VTSessionSetProperty(enc->session, kVTCompressionPropertyKey_AverageBitRate, num);
        CFRelease(num);
    }
}

void al_vt_close(void *raw) {
    VtEnc *enc = raw;
    if (!enc) {
        return;
    }
    if (enc->session) {
        VTCompressionSessionCompleteFrames(enc->session, kCMTimeInvalid);
        VTCompressionSessionInvalidate(enc->session);
        CFRelease(enc->session);
    }
    if (enc->transfer) {
        VTPixelTransferSessionInvalidate(enc->transfer);
        CFRelease(enc->transfer);
    }
    if (enc->dst_pixel) {
        CFRelease(enc->dst_pixel);
    }
    if (enc->src_pixel) {
        CFRelease(enc->src_pixel);
    }
    free(enc->annexb);
    free(enc);
}
