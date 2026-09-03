/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "video_encoder_fuzzer.h"
#include "message_parcel.h"
#include "securec.h"
#include "camera_log.h"

namespace OHOS {
namespace CameraStandard {
using namespace OHOS::MediaAVCodec;
const int32_t CONST_2 = 2;
const int32_t MIN_SIZE_NUM = 64;
const int32_t FUZZ_BUFFER_CAPACITY = 1024;
std::shared_ptr<VideoEncoder> VideoEncoderFuzzer::fuzz_{nullptr};

static const std::vector<std::string> CODEC_MIMES = {"video/avc", "video/hevc", "video/invalid"};

static sptr<FrameRecord> CreateFrameRecord(FuzzedDataProvider& fdp, int64_t baseTimestamp)
{
    int64_t timestamp = baseTimestamp + fdp.ConsumeIntegral<int32_t>();
    GraphicTransformType formType = static_cast<GraphicTransformType>(fdp.ConsumeIntegral<uint8_t>()
        % (GraphicTransformType::GRAPHIC_ROTATE_BUTT + CONST_2));
    sptr<SurfaceBuffer> videoBuffer = SurfaceBuffer::Create();
    sptr<FrameRecord> frameRecord = new(std::nothrow) FrameRecord(videoBuffer, timestamp, formType);
    if (frameRecord != nullptr) {
        frameRecord->SetIDRProperty(fdp.ConsumeBool());
        frameRecord->SetMuxerIndex(fdp.ConsumeIntegral<int32_t>());
    }
    return frameRecord;
}

static std::shared_ptr<Media::AVBuffer> CreateFuzzAVBuffer(FuzzedDataProvider& fdp)
{
    auto allocator = Media::AVAllocatorFactory::CreateSharedAllocator(Media::MemoryFlag::MEMORY_READ_WRITE);
    if (allocator == nullptr) {
        return nullptr;
    }
    std::shared_ptr<Media::AVBuffer> buffer =
        Media::AVBuffer::CreateAVBuffer(allocator, FUZZ_BUFFER_CAPACITY);
    if (buffer != nullptr) {
        buffer->pts_ = fdp.ConsumeIntegral<int64_t>();
        buffer->flag_ = fdp.ConsumeIntegral<uint32_t>();
        buffer->dts_ = fdp.ConsumeIntegral<int64_t>();
    }
    return buffer;
}

static void InitializeLifecycleEncoder(FuzzedDataProvider& fdp)
{
    VideoCodecType mode = static_cast<VideoCodecType>(fdp.ConsumeIntegral<uint8_t>()
        % (static_cast<int32_t>(VideoCodecType::VIDEO_ENCODE_TYPE_HEVC) + CONST_2));
    ColorSpace color = static_cast<ColorSpace>(fdp.ConsumeIntegral<uint8_t>()
        % (ColorSpace::H_LOG + 1));
    bool isExtendImage = fdp.ConsumeBool();
    VideoEncoderFuzzer::fuzz_ = std::make_shared<VideoEncoder>(mode, color, isExtendImage);
    CHECK_RETURN_ELOG(!VideoEncoderFuzzer::fuzz_, "Create fuzz_ Error");
    VideoEncoderFuzzer::fuzz_->size_ = std::make_shared<Size>();
    VideoEncoderFuzzer::fuzz_->IsHdr(color);

    std::string codecMime = CODEC_MIMES[fdp.ConsumeIntegral<uint8_t>() % CODEC_MIMES.size()];
    VideoEncoderFuzzer::fuzz_->Create(codecMime);
    VideoEncoderFuzzer::fuzz_->Config();
    VideoEncoderFuzzer::fuzz_->Start();
    VideoEncoderFuzzer::fuzz_->GetSurface();
}

static void ProcessInputAndState(FuzzedDataProvider& fdp)
{
    int64_t timestamp = fdp.ConsumeIntegral<int64_t>();
    VideoEncoderFuzzer::fuzz_->TsVecInsert(timestamp);
    VideoEncoderFuzzer::fuzz_->TsVecInsert(timestamp + fdp.ConsumeIntegral<int32_t>());

    OH_AVBuffer* avBuf = OH_AVBuffer_Create(FUZZ_BUFFER_CAPACITY);
    if (avBuf != nullptr) {
        sptr<CodecAVBufferInfo> info = new CodecAVBufferInfo(fdp.ConsumeIntegral<uint32_t>(), avBuf);
        info->attr.offset = fdp.ConsumeIntegral<int32_t>();
        info->attr.size = fdp.ConsumeIntegral<int32_t>();
        info->attr.pts = fdp.ConsumeIntegral<int64_t>();
        info->attr.flags = fdp.ConsumeIntegral<uint32_t>();
        VideoEncoderFuzzer::fuzz_->PushInputData(info);
        OH_AVBuffer_Destroy(avBuf);
    }

    VideoEncoderFuzzer::fuzz_->NotifyEndOfStream();
    VideoEncoderFuzzer::fuzz_->FreeOutputData(fdp.ConsumeIntegral<uint32_t>());

    std::shared_ptr<Size> size = std::make_shared<Size>();
    int32_t rotation = fdp.ConsumeIntegral<int32_t>();
    VideoEncoderFuzzer::fuzz_->SetVideoCodec(size, rotation);
    VideoEncoderFuzzer::fuzz_->RestartVideoCodec(size, rotation);
    VideoEncoderFuzzer::fuzz_->videoCodecType_ = VideoCodecType::VIDEO_ENCODE_TYPE_AVC;
    VideoEncoderFuzzer::fuzz_->RestartVideoCodec(size, rotation);

    sptr<FrameRecord> frameRecord = CreateFrameRecord(fdp, timestamp);
    if (frameRecord != nullptr) {
        VideoEncoderFuzzer::fuzz_->TsVecInsert(frameRecord->GetTimeStamp());
        VideoEncoderFuzzer::fuzz_->isStarted_ = false;
        VideoEncoderFuzzer::fuzz_->EncodeSurfaceBuffer(frameRecord);
        VideoEncoderFuzzer::fuzz_->EncodeExtendSurfaceBuffer(frameRecord);
        sptr<VideoCodecAVBufferInfo> bufferInfo =
            new VideoCodecAVBufferInfo(fdp.ConsumeIntegral<uint32_t>(), fdp.ConsumeIntegral<int64_t>(),
                CreateFuzzAVBuffer(fdp));
        VideoEncoderFuzzer::fuzz_->overTimeMap.EnsureInsert(frameRecord->GetTimeStamp(),
            VideoEncoder::OverTimeBufferInfo{0, bufferInfo});
        VideoEncoderFuzzer::fuzz_->ProcessOverTimeFrame(frameRecord);
        VideoEncoderFuzzer::fuzz_->ReleaseSurfaceBuffer(frameRecord);
        sptr<SurfaceBuffer> detachBuf;
        VideoEncoderFuzzer::fuzz_->DetachCodecBuffer(detachBuf, frameRecord);
    }
}

void VideoEncoderFuzzer::LifecycleFuzzTest(FuzzedDataProvider& fdp)
{
    InitializeLifecycleEncoder(fdp);
    ProcessInputAndState(fdp);

    VideoEncoderFuzzer::fuzz_->GetEncoderBitrate();
    VideoEncoderFuzzer::fuzz_->CheckIfRestartNeeded();
    VideoEncoderFuzzer::fuzz_->GetBframeAbility();
    VideoEncoderFuzzer::fuzz_->Stop();
    VideoEncoderFuzzer::fuzz_->Release();
    VideoEncoderFuzzer::fuzz_ = nullptr;
}

void VideoEncoderFuzzer::NullStateFuzzTest(FuzzedDataProvider& fdp)
{
    fuzz_ = std::make_shared<VideoEncoder>();
    CHECK_RETURN_ELOG(!fuzz_, "Create fuzz_ Error");

    ColorSpace spaces[] = {COLOR_SPACE_UNKNOWN, DISPLAY_P3, SRGB, BT709, BT2020_HLG, BT2020_PQ,
        BT2020_HLG_LIMIT, BT2020_PQ_LIMIT, P3_HLG, H_LOG};
    for (auto cs : spaces) {
        fuzz_->IsHdr(cs);
    }
    fuzz_->size_ = std::make_shared<Size>();
    fuzz_->Create(CODEC_MIMES[fdp.ConsumeIntegral<uint8_t>() % CODEC_MIMES.size()]);
    fuzz_->Config();
    fuzz_->Start();
    fuzz_->GetSurface();
    fuzz_->NotifyEndOfStream();
    fuzz_->FreeOutputData(fdp.ConsumeIntegral<uint32_t>());
    fuzz_->Stop();

    sptr<FrameRecord> frameRecord = CreateFrameRecord(fdp, fdp.ConsumeIntegral<int64_t>());
    if (frameRecord != nullptr) {
        fuzz_->TsVecInsert(frameRecord->GetTimeStamp());
        fuzz_->EncodeSurfaceBuffer(frameRecord);
        fuzz_->EncodeExtendSurfaceBuffer(frameRecord);
        fuzz_->ProcessOverTimeFrame(frameRecord);
        fuzz_->ReleaseSurfaceBuffer(frameRecord);
        sptr<SurfaceBuffer> detachBuf;
        fuzz_->DetachCodecBuffer(detachBuf, frameRecord);
    }
    if (fuzz_->encoder_ == nullptr) {
        sptr<CodecAVBufferInfo> info = new CodecAVBufferInfo(fdp.ConsumeIntegral<uint32_t>(), nullptr);
        fuzz_->PushInputData(info);
    }

    fuzz_->GetEncoderBitrate();
    fuzz_->CheckIfRestartNeeded();
    fuzz_->GetBframeAbility();

    int64_t diff = fdp.ConsumeIntegral<int64_t>();
    fuzz_->IsTimestampInvalid(diff);
    fuzz_->IsTimestampInvalid(fdp.ConsumeIntegral<int64_t>());

    int64_t pts1 = fdp.ConsumeIntegral<int64_t>();
    int64_t pts2 = fdp.ConsumeIntegral<int64_t>();
    fuzz_->CheckTimestampOrder(pts1, 0);
    fuzz_->CheckTimestampOrder(pts2, 1);

    std::shared_ptr<Media::AVBuffer> buffer = CreateFuzzAVBuffer(fdp);
    if (buffer != nullptr) {
        fuzz_->ProcessFrameInfo(buffer);
    }
    fuzz_->SetXpsBuffer(CreateFuzzAVBuffer(fdp));
    fuzz_->GetXpsBuffer();
    fuzz_->Release();
    fuzz_ = nullptr;
}

void VideoEncoderFuzzer::CallbackFuzzTest(FuzzedDataProvider& fdp)
{
    VideoCodecType mode = static_cast<VideoCodecType>(fdp.ConsumeIntegral<uint8_t>()
        % (static_cast<int32_t>(VideoCodecType::VIDEO_ENCODE_TYPE_HEVC) + CONST_2));
    ColorSpace color = static_cast<ColorSpace>(fdp.ConsumeIntegral<uint8_t>()
        % (ColorSpace::H_LOG + 1));
    fuzz_ = std::make_shared<VideoEncoder>(mode, color, fdp.ConsumeBool());
    CHECK_RETURN_ELOG(!fuzz_, "Create fuzz_ Error");
    fuzz_->size_ = std::make_shared<Size>();
    fuzz_->Create(CODEC_MIMES[fdp.ConsumeIntegral<uint8_t>() % CODEC_MIMES.size()]);
    fuzz_->Config();
    fuzz_->Start();

    auto callback = std::make_shared<VideoEncoder::CallBack>(fuzz_->weak_from_this());
    callback->OnError(static_cast<AVCodecErrorType>(fdp.ConsumeIntegral<uint8_t>()),
        fdp.ConsumeIntegral<int32_t>());
    MediaAVCodec::Format format = MediaAVCodec::Format();
    callback->OnOutputFormatChanged(format);
    callback->OnInputBufferAvailable(fdp.ConsumeIntegral<uint32_t>(), CreateFuzzAVBuffer(fdp));

    std::shared_ptr<Media::AVBuffer> outBuffer = CreateFuzzAVBuffer(fdp);
    if (outBuffer != nullptr) {
        callback->OnOutputBufferAvailable(fdp.ConsumeIntegral<uint32_t>(), outBuffer);
        int64_t overtimePts = outBuffer->pts_;
        fuzz_->overTimeMap.EnsureInsert(overtimePts, VideoEncoder::OverTimeBufferInfo{0, nullptr});
        callback->OnOutputBufferAvailable(fdp.ConsumeIntegral<uint32_t>(), CreateFuzzAVBuffer(fdp));
    }

    std::shared_ptr<Media::AVBuffer> copyBuffer = CreateFuzzAVBuffer(fdp);
    if (copyBuffer != nullptr) {
        fuzz_->CopyAVBuffer(copyBuffer);
    }

    sptr<FrameRecord> frameRecord = CreateFrameRecord(fdp, fdp.ConsumeIntegral<int64_t>());
    if (frameRecord != nullptr) {
        uint32_t flags[] = {AVCODEC_BUFFER_FLAGS_SYNC_FRAME, AVCODEC_BUFFER_FLAGS_NONE,
            AVCODEC_BUFFER_FLAGS_CODEC_DATA, 0xFFFFFFFF};
        for (uint32_t flag : flags) {
            std::shared_ptr<Media::AVBuffer> buf = CreateFuzzAVBuffer(fdp);
            if (buf == nullptr) {
                continue;
            }
            buf->flag_ = flag;
            sptr<VideoCodecAVBufferInfo> bufferInfo =
                new VideoCodecAVBufferInfo(fdp.ConsumeIntegral<uint32_t>(), fdp.ConsumeIntegral<int64_t>(), buf);
            fuzz_->isStarted_ = true;
            fuzz_->ProcessEncodedBuffer(frameRecord, bufferInfo);
            fuzz_->ProcessEncodedBufferWithoutCopy(frameRecord, bufferInfo);
        }
    }

    fuzz_->SetXpsBuffer(CreateFuzzAVBuffer(fdp));
    fuzz_->GetXpsBuffer();
    fuzz_->Release();
    fuzz_ = nullptr;
}

void Test(uint8_t* data, size_t size)
{
    FuzzedDataProvider fdp(data, size);
    if (fdp.remaining_bytes() < MIN_SIZE_NUM) {
        return;
    }
    uint8_t testSelector = fdp.ConsumeIntegral<uint8_t>() % 3;
    if (testSelector == 0) {
        auto fuzzer = std::make_unique<VideoEncoderFuzzer>();
        if (fuzzer != nullptr) {
            fuzzer->LifecycleFuzzTest(fdp);
        }
    } else if (testSelector == 1) {
        auto fuzzer = std::make_unique<VideoEncoderFuzzer>();
        if (fuzzer != nullptr) {
            fuzzer->NullStateFuzzTest(fdp);
        }
    } else {
        auto fuzzer = std::make_unique<VideoEncoderFuzzer>();
        if (fuzzer != nullptr) {
            fuzzer->CallbackFuzzTest(fdp);
        }
    }
}
} // namespace CameraStandard
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(uint8_t* data, size_t size)
{
    OHOS::CameraStandard::Test(data, size);
    return 0;
}
