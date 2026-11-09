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
    CFMutableDictionaryRef props;
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
    status = VTCompressionSessionCreate(
        kCFAllocatorDefault,
        width,
        height,
        codec,
        encoder_spec(),
        NULL,
        kCFAllocatorDefault,
        output_callback,
        enc,
        &enc->session);
    if (status != noErr || !enc->session) {
        free(enc);
        return (int)status;
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
    (void)props;
    VTCompressionSessionPrepareToEncodeFrames(enc->session);
    *out = enc;
    return 0;
}

int al_vt_encode(
    void *raw,
    const unsigned char *bgra,
    int stride,
    int force_key,
    unsigned char *dst,
    int dst_cap,
    int *keyframe
) {
    VtEnc *enc = raw;
    CVPixelBufferRef pixel = NULL;
    CFDictionaryRef frame_props = NULL;
    OSStatus status;
    VTEncodeInfoFlags flags = 0;

    if (!enc || !bgra || !dst || dst_cap <= 0) {
        return -1;
    }
    enc->annexb_len = 0;
    enc->failed = 0;
    enc->keyframe = 0;
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
    CVPixelBufferLockBaseAddress(pixel, 0);
    {
        uint8_t *base = CVPixelBufferGetBaseAddress(pixel);
        size_t row = CVPixelBufferGetBytesPerRow(pixel);
        int y;
        int copy = stride < (int)row ? stride : (int)row;
        for (y = 0; y < enc->height; y++) {
            memcpy(base + y * row, bgra + y * stride, (size_t)copy);
        }
    }
    CVPixelBufferUnlockBaseAddress(pixel, 0);
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
    CFRelease(pixel);
    if (status == noErr) {
        status = VTCompressionSessionCompleteFrames(enc->session, kCMTimeInvalid);
    }
    if (status != noErr || enc->failed || enc->annexb_len == 0 || (int)enc->annexb_len > dst_cap) {
        return status != noErr ? (int)status : -3;
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
    free(enc->annexb);
    free(enc);
}
