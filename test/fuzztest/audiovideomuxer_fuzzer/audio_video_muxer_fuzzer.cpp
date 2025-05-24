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

#include "audio_video_muxer_fuzzer.h"
#include "message_parcel.h"
#include "securec.h"
#include "camera_log.h"
#include "avmuxer.h"
#include "avmuxer_impl.h"

namespace OHOS {
namespace CameraStandard {
static constexpr int32_t MIN_SIZE_NUM = 6;
static constexpr int32_t NUM_1 = 1;
std::shared_ptr<AudioVideoMuxer> AudioVideoMuxerFuzzer::fuzz_{nullptr};

/*
* describe: get data from outside untrusted data(g_data) which size is according to sizeof(T)
* tips: only support basic type
*/

void AudioVideoMuxerFuzzer::AudioVideoMuxerFuzzTest(FuzzedDataProvider& fdp)
{
    if (fdp.remaining_bytes()  < MIN_SIZE_NUM) {
        return;
    }
    fuzz_ = std::make_shared<AudioVideoMuxer>();
    CHECK_ERROR_RETURN_LOG(!fuzz_, "Create fuzz_ Error");
    uint8_t randomNum = fdp.ConsumeIntegral<uint8_t>();
    fuzz_->Create(static_cast<OH_AVOutputFormat>(randomNum), nullptr);
    std::shared_ptr<OHOS::Media::AVBuffer> sample = std::make_shared<OHOS::Media::AVBuffer>();

    constexpr int32_t executionModeCount = static_cast<int32_t>(TrackType::META_TRACK) + NUM_1;
    TrackType type = static_cast<TrackType>(fdp.ConsumeIntegral<uint8_t>() % executionModeCount);
    std::shared_ptr<AVMuxerImpl> impl = std::make_shared<AVMuxerImpl>();
    fuzz_->muxer_ = impl;
    int32_t trackId = fdp.ConsumeIntegral<int32_t>();
    fuzz_->WriteSampleBuffer(sample, type);
    std::shared_ptr<Format> format = std::make_shared<Format>();
    fuzz_->AddTrack(trackId, format, type);
}

void Test(uint8_t* data, size_t size)
{
    auto audioVideoMuxer = std::make_unique<AudioVideoMuxerFuzzer>();
    if (audioVideoMuxer == nullptr) {
        MEDIA_INFO_LOG("audioVideoMuxer is null");
        return;
    }
    FuzzedDataProvider fdp(data, size);
    audioVideoMuxer->AudioVideoMuxerFuzzTest(fdp);
}

} // namespace CameraStandard
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(uint8_t* data, size_t size)
{
    OHOS::CameraStandard::Test(data, size);
    return 0;
}