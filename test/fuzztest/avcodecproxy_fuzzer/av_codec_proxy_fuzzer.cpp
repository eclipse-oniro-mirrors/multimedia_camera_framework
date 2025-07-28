/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include "av_codec_proxy_fuzzer.h"
#include "camera_log.h"

using namespace OHOS::Media::Plugins;

namespace OHOS {
namespace CameraStandard {
static constexpr int32_t MIN_SIZE_NUM = 64;
static constexpr int32_t NUM_1 = 1;
static constexpr size_t MAX_LENGTH_STRING = 64;

std::shared_ptr<AVCodecProxy> AvCodecProxyFuzzer::avCodecProxyFuzz_{nullptr};

void AvCodecProxyFuzzer::AvCodecProxyFuzzerTest1(FuzzedDataProvider& fdp)
{
    if (fdp.remaining_bytes() < MIN_SIZE_NUM) {
        return;
    }
    avCodecProxyFuzz_ = AVCodecProxy::CreateAVCodecProxy();
    CHECK_RETURN_ELOG(!avCodecProxyFuzz_, "CreateAVCodecProxy Error");
    int32_t fd = fdp.ConsumeIntegral<int32_t>();
    constexpr int32_t executionModeCount = static_cast<int32_t>(OutputFormat::FLAC) + NUM_1;
    OutputFormat format = static_cast<OutputFormat>(fdp.ConsumeIntegral<uint8_t>() % executionModeCount);
    avCodecProxyFuzz_->CreateAVMuxer(fd, format);
    std::shared_ptr<Meta> param = std::make_shared<Meta>();
    avCodecProxyFuzz_->AVMuxerSetParameter(param);
    std::shared_ptr<Meta> userMeta = std::make_shared<Meta>();
    avCodecProxyFuzz_->AVMuxerSetUserMeta(userMeta);
    int32_t trackIndex = fdp.ConsumeIntegral<int32_t>();
    std::shared_ptr<Meta> trackDesc = std::make_shared<Meta>();
    avCodecProxyFuzz_->AVMuxerAddTrack(trackIndex, trackDesc);
    avCodecProxyFuzz_->AVMuxerStart();
    std::shared_ptr<AVBuffer> sample = std::make_shared<AVBuffer>();
    avCodecProxyFuzz_->AVMuxerWriteSample(trackIndex, sample);
    avCodecProxyFuzz_->AVMuxerStop();
}

void AvCodecProxyFuzzer::AvCodecProxyFuzzerTest2(FuzzedDataProvider& fdp)
{
    if (fdp.remaining_bytes() < MIN_SIZE_NUM) {
        return;
    }
    avCodecProxyFuzz_ = AVCodecProxy::CreateAVCodecProxy();
    CHECK_RETURN_ELOG(!avCodecProxyFuzz_, "CreateAVCodecProxy Error");
    std::string codecMime(fdp.ConsumeRandomLengthString(MAX_LENGTH_STRING));
    avCodecProxyFuzz_->CreateAVCodecVideoEncoder(codecMime);
    avCodecProxyFuzz_->AVCodecVideoEncoderPrepare();
    avCodecProxyFuzz_->AVCodecVideoEncoderStart();
    avCodecProxyFuzz_->AVCodecVideoEncoderStop();
    avCodecProxyFuzz_->AVCodecVideoEncoderRelease();
    avCodecProxyFuzz_->IsVideoEncoderExisted();
    avCodecProxyFuzz_->CreateInputSurface();
    uint32_t index = fdp.ConsumeIntegral<uint32_t>();
    avCodecProxyFuzz_->QueueInputBuffer(index);
    avCodecProxyFuzz_->AVCodecVideoEncoderNotifyEos();
    avCodecProxyFuzz_->ReleaseOutputBuffer(index);
    Format format;
    avCodecProxyFuzz_->AVCodecVideoEncoderSetParameter(format);
    std::shared_ptr<MediaCodecCallback> callback = std::make_shared<CoderCallback>();
    avCodecProxyFuzz_->AVCodecVideoEncoderSetCallback(callback);
    avCodecProxyFuzz_->AVCodecVideoEncoderConfigure(format);
}

void AvCodecProxyFuzzer::AvCodecProxyFuzzerTest3(FuzzedDataProvider& fdp)
{
    if (fdp.remaining_bytes() < MIN_SIZE_NUM) {
        return;
    }
    avCodecProxyFuzz_ = AVCodecProxy::CreateAVCodecProxy();
    CHECK_RETURN_ELOG(!avCodecProxyFuzz_, "CreateAVCodecProxy Error");
    int32_t fd = fdp.ConsumeIntegral<int32_t>();
    int64_t offset = fdp.ConsumeIntegral<int64_t>();
    int64_t size = fdp.ConsumeIntegral<int64_t>();
    avCodecProxyFuzz_->CreateAVSource(fd, offset, size);
    Format format;
    avCodecProxyFuzz_->AVSourceGetSourceFormat(format);
    avCodecProxyFuzz_->AVSourceGetUserMeta(format);
    uint32_t trackIndex = fdp.ConsumeIntegral<uint32_t>();
    avCodecProxyFuzz_->AVSourceGetTrackFormat(format, trackIndex);
}

void AvCodecProxyFuzzer::AvCodecProxyFuzzerTest4(FuzzedDataProvider& fdp)
{
    if (fdp.remaining_bytes() < MIN_SIZE_NUM) {
        return;
    }
    avCodecProxyFuzz_ = AVCodecProxy::CreateAVCodecProxy();
    CHECK_RETURN_ELOG(!avCodecProxyFuzz_, "CreateAVCodecProxy Error");
    std::shared_ptr<AVSource> source = std::make_shared<AVSourceTest>();
    avCodecProxyFuzz_->CreateAVDemuxer(source);
    uint32_t trackIndex = fdp.ConsumeIntegral<uint32_t>();
    std::shared_ptr<AVBuffer> sample = std::make_shared<AVBuffer>();
    avCodecProxyFuzz_->ReadSampleBuffer(trackIndex, sample);
    int64_t millisecond = fdp.ConsumeIntegral<int64_t>();
    constexpr int32_t executionModeCount = static_cast<int32_t>(SeekMode::SEEK_CLOSEST_INNER) + NUM_1;
    SeekMode mode = static_cast<SeekMode>(fdp.ConsumeIntegral<uint8_t>() % executionModeCount);
    avCodecProxyFuzz_->AVDemuxerSeekToTime(millisecond, mode);
    avCodecProxyFuzz_->AVDemuxerSelectTrackByID(trackIndex);
}

void Test(uint8_t* data, size_t size)
{
    FuzzedDataProvider fdp(data, size);
    auto avCodecProxyFuzzer = std::make_unique<AvCodecProxyFuzzer>();
    if (avCodecProxyFuzzer == nullptr) {
        MEDIA_INFO_LOG("avCodecProxyFuzzer is null");
        return;
    }
    avCodecProxyFuzzer->AvCodecProxyFuzzerTest1(fdp);
    avCodecProxyFuzzer->AvCodecProxyFuzzerTest2(fdp);
    avCodecProxyFuzzer->AvCodecProxyFuzzerTest3(fdp);
    avCodecProxyFuzzer->AvCodecProxyFuzzerTest4(fdp);
}

} // namespace CameraStandard
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(uint8_t* data, size_t size)
{
    OHOS::CameraStandard::Test(data, size);
    return 0;
}