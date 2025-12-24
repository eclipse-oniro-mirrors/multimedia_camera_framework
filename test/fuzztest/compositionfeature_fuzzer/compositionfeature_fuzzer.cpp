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

#include "fuzzer/FuzzedDataProvider.h"
#include "native_info_callback.h"
#include "features/composition_feature.h"
#include "capture_session.h"
#include "camera_manager.h"
#include "camera_log.h"
#include "test_token.h"
#include "pixel_map.h"

using namespace std;

namespace OHOS {
namespace CameraStandard {
constexpr uint32_t MAX_STR_LEN = 64;
static constexpr CameraFormat PREVIEW_FORMAT = CAMERA_FORMAT_YUV_420_SP;
static constexpr Size PREVIEW_SIZE { .width = 1920, .height = 1440 };
class MockCompositionEffectInfoCallback : public NativeInfoCallback<CompositionEffectInfo> {
public:
    MockCompositionEffectInfoCallback() {};
    virtual ~MockCompositionEffectInfoCallback() = default;
    void OnInfoChanged(CompositionEffectInfo) override {};
};

void CompositionFeatureUnitTest(FuzzedDataProvider& fdp)
{
    auto cameraManager = CameraManager::GetInstance();
    std::vector<sptr<CameraDevice>> cameras = cameraManager->GetSupportedCameras();
    CHECK_RETURN_ELOG(cameras.empty(), "cameras is empty");
    auto camDevice = cameras.front();
    auto camInput = cameraManager->CreateCameraInput(camDevice);
    std::string cameraSettings = camInput->GetCameraSettings();
    camInput->SetCameraSettings(cameraSettings);
    camInput->GetCameraDevice()->Open();

    sptr<CaptureSession> captureSession = cameraManager->CreateCaptureSession(SceneMode::CAPTURE);

    sptr<Surface> previewSurface = Surface::CreateSurfaceAsConsumer();
    Profile previewProfile = Profile(PREVIEW_FORMAT, PREVIEW_SIZE);
    auto previewOutput = cameraManager->CreatePreviewOutput(previewProfile, previewSurface);

    int32_t intResult = captureSession->BeginConfig();

    intResult = captureSession->AddInput((sptr<CaptureInput>&)camInput);

    intResult = captureSession->AddOutput((sptr<CaptureOutput>&)previewOutput);

    intResult = captureSession->CommitConfig();
    captureSession->Start();
    captureSession->IsCompositionSuggestionSupported();
    captureSession->EnableCompositionSuggestion(fdp.ConsumeBool());
    bool isSupport;
    captureSession->IsCompositionEffectPreviewSupported(isSupport);
    captureSession->EnableCompositionEffectPreview(fdp.ConsumeBool());
    std::vector<std::string> supportedLanguages;
    captureSession->GetSupportedRecommendedInfoLanguage(supportedLanguages);
    captureSession->SetRecommendedInfoLanguage(fdp.ConsumeRandomLengthString(MAX_STR_LEN));
    auto callback = std::make_shared<MockCompositionEffectInfoCallback>();
    captureSession->SetCompositionEffectReceiveCallback(callback);
    captureSession->SetCompositionEffectReceiveCallback(nullptr);
    captureSession->Stop();
}

void CompositionEffectListenerTest(FuzzedDataProvider& fdp)
{
    auto feature = std::make_shared<CompositionFeature>(nullptr);
    auto surface = IConsumerSurface::Create();
    auto listener = sptr<CompositionEffectListener>::MakeSptr(feature, surface);
    auto callback = std::make_shared<MockCompositionEffectInfoCallback>();
    feature->SetCompositionEffectReceiveCallback(callback);
    sptr<SurfaceBuffer> buffer = SurfaceBuffer::Create();

    BufferRequestConfig requestConfig = {
        .width = fdp.ConsumeIntegral<int32_t>() & 0x0FF0,
        .height = fdp.ConsumeIntegral<int32_t>() & 0x0FFF,
        .strideAlignment = 0x8,
        .format = GraphicPixelFormat::GRAPHIC_PIXEL_FMT_YCRCB_420_SP,
        .usage = BUFFER_USAGE_CAMERA_WRITE | BUFFER_USAGE_CPU_READ | BUFFER_USAGE_CPU_WRITE | BUFFER_USAGE_MEM_DMA |
            BUFFER_USAGE_MEM_MMZ_CACHE,
        .timeout = 0,
    };
    GSError allocErrorCode = buffer->Alloc(requestConfig);
    CHECK_RETURN_ELOG(allocErrorCode != 0, "Alloc fail");
    CompositionEffectListener::Buffer2PixelMap(buffer);

}

void Test(uint8_t* data, size_t size)
{
    FuzzedDataProvider fdp(data, size);
    CHECK_RETURN_ELOG(!TestToken().GetAllCameraPermission(), "GetPermission error");
    CompositionFeatureUnitTest(fdp);
    CompositionEffectListenerTest(fdp);
}

} // namespace CameraStandard
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(uint8_t* data, size_t size)
{
    OHOS::CameraStandard::Test(data, size);
    return 0;
}