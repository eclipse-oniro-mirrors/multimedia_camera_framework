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
static constexpr int32_t MIN_SIZE_NUM = 10;
const size_t THRESHOLD = 10;

std::shared_ptr<VideoEncoder> VideoEncoderFuzzer::fuzz_{nullptr};

void VideoEncoderFuzzer::VideoEncoderFuzzTest(FuzzedDataProvider& fdp)
{
    if (fdp.remaining_bytes() < MIN_SIZE_NUM) {
        return;
    }
    fuzz_ = std::make_shared<VideoEncoder>();
    CHECK_ERROR_RETURN_LOG(!fuzz_, "Create fuzz_ Error");
    uint8_t randomNum = fdp.ConsumeIntegral<uint8_t>();
    std::vector<std::string> testStrings = {"test1", "test2"};
    std::string codecMime(testStrings[randomNum % testStrings.size()]);
    fuzz_->Create(codecMime);
    fuzz_->Config();
    fuzz_->Start();
    fuzz_->GetSurface();
    int64_t timestamp = fdp.ConsumeIntegral<int64_t>();
    std::vector<GraphicTransformType> graphicType = {
        GRAPHIC_ROTATE_NONE,
        GRAPHIC_ROTATE_90,
        GRAPHIC_ROTATE_180,
        GRAPHIC_ROTATE_270,
        GRAPHIC_FLIP_H,
        GRAPHIC_FLIP_V,
        GRAPHIC_FLIP_H_ROT90,
        GRAPHIC_FLIP_V_ROT90,
        GRAPHIC_FLIP_H_ROT180,
        GRAPHIC_FLIP_V_ROT180,
        GRAPHIC_FLIP_H_ROT270,
        GRAPHIC_FLIP_V_ROT270,
        GRAPHIC_ROTATE_BUTT,
    };

    GraphicTransformType type_ = graphicType[fdp.ConsumeIntegral<uint16_t>() % graphicType.size()];
    sptr<SurfaceBuffer> videoBuffer = SurfaceBuffer::Create();
    sptr<FrameRecord> frameRecord =
        new(std::nothrow) FrameRecord(videoBuffer, timestamp, type_);
    fuzz_->ReleaseSurfaceBuffer(frameRecord);
    fuzz_->NotifyEndOfStream();
    uint32_t bufferIndex = GetData<uint32_t>();
    fuzz_->FreeOutputData(bufferIndex);
    fuzz_->Stop();
}

void Test(uint8_t* data, size_t size)
{
    auto videoEncoder = std::make_unique<VideoEncoderFuzzer>();
    if (videoEncoder == nullptr) {
        MEDIA_INFO_LOG("videoEncoder is null");
        return;
    }
    FuzzedDataProvider fdp(data, size);
    videoEncoder->VideoEncoderFuzzTest(fdp);
}
} // namespace CameraStandard
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(uint8_t* data, size_t size)
{
    if (size < OHOS::CameraStandard::THRESHOLD) {
        return 0;
    }

    OHOS::CameraStandard::Test(data, size);
    return 0;
}