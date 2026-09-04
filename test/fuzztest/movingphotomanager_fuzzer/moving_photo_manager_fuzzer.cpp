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

#include "moving_photo_manager_fuzzer.h"
#include "camera_log.h"
#include "ability/camera_ability_enum.h"
#include "photo_asset_interface.h"
#include <cstddef>
#include <cstdint>
#include <memory>
#include <string>

namespace OHOS {
namespace CameraStandard {

static constexpr int32_t STR_LEN_32 = 32;
static constexpr uint8_t FUZZ_TEST_COUNT = 3;
static constexpr uint8_t COLOR_STYLE_PHOTO_TYPE_COUNT = 3;

// covers: ReleaseStreamStruct (ORIGIN/XT_ORIGIN VideoType branches),
// ChangeListenerSetXtStyleType (true/false branches), SetBufferDuration (0 / non-0 branches),
// SetClearFlag + SetBrotherListener (null listener branches), Release
void MovingPhotoManagerFuzzer::FuzzTest1(FuzzedDataProvider& fdp)
{
    sptr<MovingPhotoManager> manager = new MovingPhotoManager();
    CHECK_RETURN_ELOG(!manager, "Create manager Error");
    manager->ReleaseStreamStruct(VideoType::ORIGIN_VIDEO);
    manager->ReleaseStreamStruct(VideoType::XT_ORIGIN_VIDEO);
    manager->ChangeListenerSetXtStyleType(true);
    manager->ChangeListenerSetXtStyleType(false);
    manager->SetBufferDuration(0, 0);
    manager->SetBufferDuration(fdp.ConsumeIntegral<uint32_t>() | 1, fdp.ConsumeIntegral<uint32_t>() | 1);
    manager->SetClearFlag();
    manager->SetBrotherListener();
    manager->Release();
}

// covers: StartAudioCapture / SetVideoFd / StartRecord / InsertStartTime / InsertEndTime /
// SetDeferredVideoEnhanceFlag (null proxy early-return branches with default-constructed manager)
void MovingPhotoManagerFuzzer::FuzzTest2(FuzzedDataProvider& fdp)
{
    sptr<MovingPhotoManager> manager = new MovingPhotoManager();
    CHECK_RETURN_ELOG(!manager, "Create manager Error");
    manager->StartAudioCapture();
    int64_t timestamp = fdp.ConsumeIntegral<int64_t>();
    int32_t captureId = fdp.ConsumeIntegral<int32_t>();
    manager->SetVideoFd(timestamp, nullptr, captureId);
    manager->StartRecord(static_cast<uint64_t>(timestamp), fdp.ConsumeIntegral<int32_t>(), captureId,
        static_cast<ColorStylePhotoType>(fdp.ConsumeIntegral<uint8_t>() % COLOR_STYLE_PHOTO_TYPE_COUNT), fdp.ConsumeBool());
    manager->InsertStartTime(captureId, timestamp);
    manager->InsertEndTime(captureId, timestamp);
    manager->SetDeferredVideoEnhanceFlag(captureId, fdp.ConsumeIntegral<uint32_t>(),
        fdp.ConsumeRandomLengthString(STR_LEN_32),
        static_cast<ColorStylePhotoType>(fdp.ConsumeIntegral<uint8_t>() % COLOR_STYLE_PHOTO_TYPE_COUNT),
        fdp.ConsumeBool());
}

// covers: StartOnceRecord (ORIGIN/XT_ORIGIN VideoType + null listener), StartProcessAudioTask (null proxy),
// StopMovingPhoto (type == ORIGIN -> xtStyle.StopDrainOut true branch / XT_EFFECT -> false branch)
void MovingPhotoManagerFuzzer::FuzzTest3(FuzzedDataProvider& fdp)
{
    sptr<MovingPhotoManager> manager = new MovingPhotoManager();
    CHECK_RETURN_ELOG(!manager, "Create manager Error");
    uint64_t timestamp = static_cast<uint64_t>(fdp.ConsumeIntegral<int64_t>());
    int32_t rotation = fdp.ConsumeIntegral<int32_t>();
    int32_t captureId = fdp.ConsumeIntegral<int32_t>();
    manager->StartOnceRecord(timestamp, rotation, captureId, VideoType::ORIGIN_VIDEO);
    manager->StartOnceRecord(timestamp, rotation, captureId, VideoType::XT_ORIGIN_VIDEO);
    manager->StartProcessAudioTask(captureId, fdp.ConsumeIntegral<int64_t>());
    manager->StopMovingPhoto(VideoType::ORIGIN_VIDEO);
    manager->StopMovingPhoto(VideoType::XT_EFFECT_VIDEO);
    sleep(1);
}

void Test(uint8_t* data, size_t size)
{
    FuzzedDataProvider fdp(data, size);
    auto fuzzer = std::make_unique<MovingPhotoManagerFuzzer>();
    if (fuzzer == nullptr) {
        MEDIA_INFO_LOG("fuzzer is null");
        return;
    }
    switch (fdp.ConsumeIntegral<uint8_t>() % FUZZ_TEST_COUNT) {
        case 0:
            fuzzer->FuzzTest1(fdp);
            break;
        case 1:
            fuzzer->FuzzTest2(fdp);
            break;
        default:
            fuzzer->FuzzTest3(fdp);
            break;
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
