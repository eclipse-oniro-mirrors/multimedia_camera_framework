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

#ifndef CAMERA_INPUT_FUZZER_H
#define CAMERA_INPUT_FUZZER_H

#include "stream_capture_stub.h"
#include <fuzzer/FuzzedDataProvider.h>

namespace OHOS {
namespace CameraStandard {
class HStreamCaptureStubFuzz : public StreamCaptureStub {
public:
    int32_t Capture(const std::shared_ptr<OHOS::Camera::CameraMetadata> &captureSettings) override
    {
        return 0;
    }
    int32_t CancelCapture() override
    {
        return 0;
    }
    int32_t ConfirmCapture() override
    {
        return 0;
    }
    int32_t SetCallback(const sptr<IStreamCaptureCallback> &callback) override
    {
        return 0;
    }
    int32_t SetPhotoAvailableCallback(const sptr<IStreamCapturePhotoCallback> &callback) override
    {
        return 0;
    }
    int32_t SetPhotoAssetAvailableCallback(const sptr<IStreamCapturePhotoAssetCallback> &callback) override
    {
        return 0;
    }
    int32_t SetThumbnailCallback(const sptr<IStreamCaptureThumbnailCallback> &callback) override
    {
        return 0;
    }
    int32_t UnSetCallback() override
    {
        return 0;
    }
    int32_t Release() override
    {
        return 0;
    }
    int32_t SetThumbnail(bool isEnabled) override
    {
        return 0;
    }
    int32_t EnableRawDelivery(bool enabled) override
    {
        return 0;
    }
    int32_t EnableMovingPhoto(bool enabled) override
    {
        return 0;
    }
    int32_t SetBufferProducerInfo(const std::string &bufName, const sptr<OHOS::IBufferProducer> &producer) override
    {
        return 0;
    }
    int32_t DeferImageDeliveryFor(int32_t type) override
    {
        return 0;
    }
    int32_t IsDeferredPhotoEnabled() override
    {
        return 0;
    }
    int32_t IsDeferredVideoEnabled() override
    {
        return 0;
    }
    int32_t SetMovingPhotoVideoCodecType(int32_t videoCodecType) override
    {
        return 0;
    }
    int32_t SetCameraPhotoRotation(bool isEnable) override
    {
        return 0;
    }
    int32_t EnableOfflinePhoto(bool isEnable) override
    {
        return 0;
    }
    int32_t CallbackEnter([[maybe_unused]] uint32_t code) override
    {
        return 0;
    }
    int32_t CallbackExit([[maybe_unused]] uint32_t code, [[maybe_unused]] int32_t result) override
    {
        return 0;
    }
    int32_t UnSetPhotoAvailableCallback() override
    {
        return 0;
    }
    int32_t UnSetPhotoAssetAvailableCallback() override
    {
        return 0;
    }
    int32_t UnSetThumbnailCallback() override
    {
        return 0;
    }
    ErrCode CreateMediaLibrary(const sptr<CameraPhotoProxy>& photoProxy, std::string& uri, int32_t& cameraShotType,
        std::string& burstKey, int64_t timestamp) override
    {
        return 0;
    }
};
class HStreamCaptureStubFuzzer {
public:
    static std::shared_ptr<HStreamCaptureStubFuzz> fuzz_;
    static void HStreamCaptureStubFuzzTest1(FuzzedDataProvider &fdp);
    static void HStreamCaptureStubFuzzTest2(FuzzedDataProvider &fdp);
    static void HStreamCaptureStubFuzzTest3();
    static void HStreamCaptureStubFuzzTest4(FuzzedDataProvider &fdp);
    static void HStreamCaptureStubFuzzTest5(FuzzedDataProvider &fdp);
    static void HStreamCaptureStubFuzzTest6(FuzzedDataProvider &fdp);
    static void HStreamCaptureStubFuzzTest7(FuzzedDataProvider &fdp);
    static void HStreamCaptureStubFuzzTest8(FuzzedDataProvider &fdp);
    static void HStreamCaptureStubFuzzTest9(FuzzedDataProvider &fdp);
    static void HStreamCaptureStubFuzzTest10(FuzzedDataProvider &fdp);
    static void HStreamCaptureStubFuzzTest11();
    static void HStreamCaptureStubFuzzTest12();
    static void HStreamCaptureStubFuzzTest13();
    static void HStreamCaptureStubFuzzTest14();
    static void HStreamCaptureStubFuzzTest15();
    static void HStreamCaptureStubFuzzTest16();
    static void HStreamCaptureStubFuzzTest17();
    static void HStreamCaptureStubFuzzTest18();
    static void HStreamCaptureStubFuzzTest19();
    static void HStreamCaptureStubFuzzTest20();
    static void HStreamCaptureStubFuzzTest21();
    static void HStreamCaptureStubFuzzTest22(FuzzedDataProvider &fdp);
};
}  // namespace CameraStandard
}  // namespace OHOS
#endif  // CAMERA_INPUT_FUZZER_H