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

#include "moving_photo_proxy_fuzzer.h"

#include <cstddef>
#include <cstdint>
#include "camera_ability_const.h"
#include "camera_log.h"
#include "camera_util.h"
#include "ipc_skeleton.h"
#include "photo_asset_proxy.h"
#include "frame_record.h"

namespace OHOS {
namespace CameraStandard {
static constexpr int32_t MIN_SIZE_NUM = 64;
static constexpr int32_t NUM_1 = 1;

sptr<AvcodecTaskManagerIntf> MovingPhotoProxyFuzzer::taskManagerfuzz_ { nullptr };
sptr<AudioCapturerSessionIntf> MovingPhotoProxyFuzzer::capturerSessionfuzz_ { nullptr };

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

std::vector<ColorSpace> colorSpaceType = {
    COLOR_SPACE_UNKNOWN, // 0
    DISPLAY_P3,          // 3
    SRGB,                // 4
    BT709,               // 6
    BT2020_HLG,          // 9
    BT2020_PQ,           // 10
    P3_HLG,              // 11
    P3_PQ,               // 12
    DISPLAY_P3_LIMIT,    // 14
    SRGB_LIMIT,          // 15
    BT709_LIMIT,         // 16
    BT2020_HLG_LIMIT,    // 19
    BT2020_PQ_LIMIT,     // 20
    P3_HLG_LIMIT,        // 21
    P3_PQ_LIMIT,         // 22
};

void MyFunction()
{
    MEDIA_DEBUG_LOG("MyFunction started!");
}

void MovingPhotoProxyFuzzer::MovingPhotoProxyFuzzTest(FuzzedDataProvider& fdp)
{
    if (fdp.remaining_bytes() < MIN_SIZE_NUM) {
        return;
    }
    CHECK_EXECUTE(
        taskManagerfuzz_ == nullptr, taskManagerfuzz_ = AvcodecTaskManagerProxy::CreateAvcodecTaskManagerProxy());
    CHECK_RETURN_ELOG(!taskManagerfuzz_, "CreateAvcodecTaskManagerProxy Error");
    CHECK_EXECUTE(capturerSessionfuzz_ == nullptr,
        capturerSessionfuzz_ = AudioCapturerSessionProxy::CreateAudioCapturerSessionProxy());
    CHECK_RETURN_ELOG(!capturerSessionfuzz_, "CreateAudioCapturerSessionProxy Error");

    capturerSessionfuzz_->CreateAudioSession();
    capturerSessionfuzz_->StartAudioCapture();
    capturerSessionfuzz_->StopAudioCapture();

    int32_t videoCodecTypeCount1 =
        static_cast<int32_t>(OHOS::CameraStandard::VideoCodecType::VIDEO_ENCODE_TYPE_AVC) + NUM_1;
    VideoCodecType videoCodecType = static_cast<VideoCodecType>(fdp.ConsumeIntegral<uint8_t>() % videoCodecTypeCount1);
    int32_t colorSpace = static_cast<int32_t>(colorSpaceType[fdp.ConsumeIntegral<int32_t>() % colorSpaceType.size()]);
    taskManagerfuzz_->CreateAvcodecTaskManager(capturerSessionfuzz_, videoCodecType, colorSpace);
    taskManagerfuzz_->SubmitTask(MyFunction);
    uint32_t preBufferCount = fdp.ConsumeIntegral<uint32_t>();
    uint32_t postBufferCount = fdp.ConsumeIntegral<uint32_t>();
    taskManagerfuzz_->SetVideoBufferDuration(preBufferCount, postBufferCount);
    int32_t timestamp = fdp.ConsumeIntegral<int32_t>();
    int32_t captureId = fdp.ConsumeIntegral<int32_t>();
    taskManagerfuzz_->SetVideoFd(timestamp, nullptr, captureId);

    GraphicTransformType type_ = graphicType[fdp.ConsumeIntegral<uint16_t>() % graphicType.size()];
    sptr<SurfaceBuffer> videoBuffer = SurfaceBuffer::Create();
    sptr<FrameRecord> frameRecord = new (std::nothrow) FrameRecord(videoBuffer, timestamp, type_);
    std::vector<sptr<FrameRecord>> frameRecords;
    frameRecords.push_back(frameRecord);
    taskManagerfuzz_->isEmptyVideoFdMap();
    int64_t startTimeStamp = fdp.ConsumeIntegral<int64_t>();
    taskManagerfuzz_->TaskManagerInsertStartTime(captureId, startTimeStamp);
    int64_t endTimeStamp = fdp.ConsumeIntegral<int64_t>();
    taskManagerfuzz_->TaskManagerInsertEndTime(captureId, endTimeStamp);

    std::this_thread::sleep_for(std::chrono::seconds(1));
}

void MovingPhotoProxyFuzzer::SetVideoIdFuzzTest(FuzzedDataProvider& fdp)
{
    if (fdp.remaining_bytes() < MIN_SIZE_NUM) {
        return;
    }
    CHECK_EXECUTE(
        taskManagerfuzz_ == nullptr, taskManagerfuzz_ = AvcodecTaskManagerProxy::CreateAvcodecTaskManagerProxy());
    CHECK_RETURN_ELOG(!taskManagerfuzz_, "CreateAvcodecTaskManagerProxy Error");
    CHECK_EXECUTE(capturerSessionfuzz_ == nullptr,
        capturerSessionfuzz_ = AudioCapturerSessionProxy::CreateAudioCapturerSessionProxy());
    CHECK_RETURN_ELOG(!capturerSessionfuzz_, "CreateAudioCapturerSessionProxy Error");

    int32_t videoCodecTypeCount1 =
        static_cast<int32_t>(OHOS::CameraStandard::VideoCodecType::VIDEO_ENCODE_TYPE_AVC) + NUM_1;
    VideoCodecType videoCodecType = static_cast<VideoCodecType>(fdp.ConsumeIntegral<uint8_t>() % videoCodecTypeCount1);
    int32_t colorSpace = static_cast<int32_t>(colorSpaceType[fdp.ConsumeIntegral<int32_t>() % colorSpaceType.size()]);
    taskManagerfuzz_->CreateAvcodecTaskManager(capturerSessionfuzz_, videoCodecType, colorSpace);
    int32_t captureId = fdp.ConsumeIntegral<int32_t>();
    string videoId = fdp.ConsumeRandomLengthString();
    taskManagerfuzz_->SetVideoId(captureId, videoId);
}

void MovingPhotoProxyFuzzer::SetDeferredVideoEnhanceFlagFuzzTest(FuzzedDataProvider& fdp)
{
    if (fdp.remaining_bytes() < MIN_SIZE_NUM) {
        return;
    }
    CHECK_EXECUTE(
        taskManagerfuzz_ == nullptr, taskManagerfuzz_ = AvcodecTaskManagerProxy::CreateAvcodecTaskManagerProxy());
    CHECK_RETURN_ELOG(!taskManagerfuzz_, "CreateAvcodecTaskManagerProxy Error");
    CHECK_EXECUTE(capturerSessionfuzz_ == nullptr,
        capturerSessionfuzz_ = AudioCapturerSessionProxy::CreateAudioCapturerSessionProxy());
    CHECK_RETURN_ELOG(!capturerSessionfuzz_, "CreateAudioCapturerSessionProxy Error");

    int32_t videoCodecTypeCount1 =
        static_cast<int32_t>(OHOS::CameraStandard::VideoCodecType::VIDEO_ENCODE_TYPE_AVC) + NUM_1;
    VideoCodecType videoCodecType = static_cast<VideoCodecType>(fdp.ConsumeIntegral<uint8_t>() % videoCodecTypeCount1);
    int32_t colorSpace = static_cast<int32_t>(colorSpaceType[fdp.ConsumeIntegral<int32_t>() % colorSpaceType.size()]);
    taskManagerfuzz_->CreateAvcodecTaskManager(capturerSessionfuzz_, videoCodecType, colorSpace);
    int32_t captureId = fdp.ConsumeIntegral<int32_t>();
    uint32_t deferredVideoEnhanceFlag = fdp.ConsumeIntegral<uint32_t>();
    taskManagerfuzz_->SetDeferredVideoEnhanceFlag(captureId,  deferredVideoEnhanceFlag);
    taskManagerfuzz_->GetDeferredVideoEnhanceFlag(captureId);
}

void MovingPhotoProxyFuzzer::RecordVideoTypeFuzzTest(FuzzedDataProvider& fdp)
{
    if (fdp.remaining_bytes() < MIN_SIZE_NUM) {
        return;
    }
    CHECK_EXECUTE(
        taskManagerfuzz_ == nullptr, taskManagerfuzz_ = AvcodecTaskManagerProxy::CreateAvcodecTaskManagerProxy());
    CHECK_RETURN_ELOG(!taskManagerfuzz_, "CreateAvcodecTaskManagerProxy Error");
    CHECK_EXECUTE(capturerSessionfuzz_ == nullptr,
        capturerSessionfuzz_ = AudioCapturerSessionProxy::CreateAudioCapturerSessionProxy());
    CHECK_RETURN_ELOG(!capturerSessionfuzz_, "CreateAudioCapturerSessionProxy Error");

    int32_t videoCodecTypeCount1 =
        static_cast<int32_t>(OHOS::CameraStandard::VideoCodecType::VIDEO_ENCODE_TYPE_AVC) + NUM_1;
    VideoCodecType videoCodecType = static_cast<VideoCodecType>(fdp.ConsumeIntegral<uint8_t>() % videoCodecTypeCount1);
    int32_t colorSpace = static_cast<int32_t>(colorSpaceType[fdp.ConsumeIntegral<int32_t>() % colorSpaceType.size()]);
    taskManagerfuzz_->CreateAvcodecTaskManager(capturerSessionfuzz_, videoCodecType, colorSpace);
    int32_t captureId = fdp.ConsumeIntegral<int32_t>();
    VideoType videoType = static_cast<VideoType>(XT_ORIGIN_VIDEO);
    taskManagerfuzz_->RecordVideoType(captureId,videoType);
}

void Test(uint8_t* data, size_t size)
{
    FuzzedDataProvider fdp(data, size);
    auto MovingPhotoProxy = std::make_unique<MovingPhotoProxyFuzzer>();
    if (MovingPhotoProxy == nullptr) {
        MEDIA_INFO_LOG("MovingPhotoProxy is null");
        return;
    }
    MovingPhotoProxy->MovingPhotoProxyFuzzTest(fdp);
    MovingPhotoProxy->SetVideoIdFuzzTest(fdp);
    MovingPhotoProxy->SetDeferredVideoEnhanceFlagFuzzTest(fdp);
    MovingPhotoProxy->RecordVideoTypeFuzzTest(fdp);
}

} // namespace CameraStandard
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(uint8_t* data, size_t size)
{
    OHOS::CameraStandard::Test(data, size);
    return 0;
}