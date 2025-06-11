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

#include "moving_photo_surface_wrapper_fuzzer.h"
#include "camera_input.h"
#include "camera_log.h"
#include "camera_photo_proxy.h"
#include "capture_input.h"
#include "capture_output.h"
#include "capture_scene_const.h"
#include "input/camera_manager.h"
#include "message_parcel.h"
#include "refbase.h"
#include <cstddef>
#include <cstdint>
#include <memory>
#include "token_setproc.h"
#include "nativetoken_kit.h"
#include "accesstoken_kit.h"
#include "securec.h"
#include <mutex>

namespace OHOS {
namespace CameraStandard {
static constexpr int32_t MIN_SIZE_NUM = 16;

std::shared_ptr<MovingPhotoSurfaceWrapper> MovingPhotoSurfaceWrapperFuzzer::fuzz_{nullptr};
std::shared_ptr<MovingPhotoSurfaceWrapper::BufferConsumerListener>
    MovingPhotoSurfaceWrapperFuzzer::listener_{nullptr};

void MovingPhotoSurfaceWrapperFuzzer::MovingPhotoSurfaceWrapperFuzzTest(FuzzedDataProvider& fdp)
{
    if (fdp.remaining_bytes() < MIN_SIZE_NUM) {
        return;
    }
    fuzz_ = std::make_shared<MovingPhotoSurfaceWrapper>();
    CHECK_ERROR_RETURN_LOG(!fuzz_, "Create fuzz_ Error");
    fuzz_->GetProducer();
    int32_t width = fdp.ConsumeIntegral<int32_t>();
    int32_t height = fdp.ConsumeIntegral<int32_t>();
    fuzz_->CreateMovingPhotoSurfaceWrapper(width, height);
    fuzz_->OnBufferArrival();
    if (listener_ == nullptr) {
        sptr<MovingPhotoSurfaceWrapper> surfaceWrapper = nullptr;
        listener_ = std::make_shared<MovingPhotoSurfaceWrapper::BufferConsumerListener>(surfaceWrapper);
    }
    listener_->OnBufferAvailable();
}

void Test(uint8_t* data, size_t size)
{
    FuzzedDataProvider fdp(data, size);
    auto movingPhotoSurfaceWrapper = std::make_unique<MovingPhotoSurfaceWrapperFuzzer>();
    if (movingPhotoSurfaceWrapper == nullptr) {
        MEDIA_INFO_LOG("movingPhotoSurfaceWrapper is null");
        return;
    }
    movingPhotoSurfaceWrapper->MovingPhotoSurfaceWrapperFuzzTest(fdp);
}

} // namespace CameraStandard
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(uint8_t* data, size_t size)
{
    OHOS::CameraStandard::Test(data, size);
    return 0;
}