/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#include <fuzzer/FuzzedDataProvider.h>
#include <memory>
#include <functional>
#include "camera_log.h"
#include "fuzz_util.h"
#include "test_token.h"
#include "features/smart_capture_preview_feature.h"
#include "capture_session.h"

using namespace OHOS;
using namespace OHOS::CameraStandard;

static constexpr uint32_t TOKEN_ID_BIT_WIDTH = 32;

class MockColorStylePreviewImageChangeCallback : public ColorStylePreviewImageChangeCallback {
public:
    void OnColorStylePreviewImageChange(const std::vector<std::shared_ptr<Media::PixelMap>>& pixelMaps) override
    {
    }
};

static void TestEnableSmartCapturePreview(FuzzedDataProvider& fdp)
{
    auto smartCapturePreviewFeature = std::make_shared<SmartCapturePreviewFeature>(nullptr);
    if (!smartCapturePreviewFeature) {
        return;
    }
    bool isEnable = fdp.ConsumeBool();
    (void)smartCapturePreviewFeature->EnableSmartCapturePreview(isEnable);
}

static void TestSetSmartCapturePreviewReceiveCallback(FuzzedDataProvider& fdp)
{
    auto smartCapturePreviewFeature = std::make_shared<SmartCapturePreviewFeature>(nullptr);
    if (!smartCapturePreviewFeature) {
        return;
    }
    if (fdp.ConsumeBool()) {
        std::shared_ptr<ColorStylePreviewImageChangeCallback> callback =
            std::make_shared<MockColorStylePreviewImageChangeCallback>();
        (void)smartCapturePreviewFeature->SetSmartCapturePreviewReceiveCallback(callback);
    } else {
        std::shared_ptr<ColorStylePreviewImageChangeCallback> callback = nullptr;
        (void)smartCapturePreviewFeature->SetSmartCapturePreviewReceiveCallback(callback);
    }
}

static void TestSetSmartCapturePreviewReceiveCallbackTaihe(FuzzedDataProvider& fdp)
{
    auto smartCapturePreviewFeature = std::make_shared<SmartCapturePreviewFeature>(nullptr);
    if (!smartCapturePreviewFeature) {
        return;
    }
    if (fdp.ConsumeBool()) {
        auto callback = std::make_shared<ColorStylePreviewImageChangeCallbackListenerTaihe>(
            [](std::vector<std::shared_ptr<Media::PixelMap>>) {});
        (void)smartCapturePreviewFeature->SetSmartCapturePreviewReceiveCallbackTaihe(callback);
    } else {
        std::shared_ptr<ColorStylePreviewImageChangeCallbackListenerTaihe> callback = nullptr;
        (void)smartCapturePreviewFeature->SetSmartCapturePreviewReceiveCallbackTaihe(callback);
    }
}

static void TestSetBufferSize(FuzzedDataProvider& fdp)
{
    auto smartCapturePreviewFeature = std::make_shared<SmartCapturePreviewFeature>(nullptr);
    if (!smartCapturePreviewFeature) {
        return;
    }
    int32_t bufferSize = fdp.ConsumeIntegralInRange<int32_t>(0, 100);
    smartCapturePreviewFeature->SetBufferSize(bufferSize);
}

static void Init()
{
    CHECK_RETURN_ELOG(!TestToken().GetAllCameraPermission(), "Get permission fail");
}

static void Test(FuzzedDataProvider& fdp)
{
    auto func = fdp.PickValueInArray({
        TestEnableSmartCapturePreview,
        TestSetSmartCapturePreviewReceiveCallback,
        TestSetSmartCapturePreviewReceiveCallbackTaihe,
        TestSetBufferSize,
    });
    func(fdp);
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    FuzzedDataProvider fdp(data, size);
    Test(fdp);
    return 0;
}

extern "C" int LLVMFuzzerInitialize(int* argc, char*** argv)
{
    if (SetSelfTokenID(718336240uLL | (1uLL << TOKEN_ID_BIT_WIDTH)) < 0) {
        return -1;
    }
    Init();
    return 0;
}
