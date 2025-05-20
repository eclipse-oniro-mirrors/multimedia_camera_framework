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

#include "metadata_output_fuzzer.h"
#include "message_parcel.h"
#include "securec.h"
#include "camera_log.h"
#include "camera_manager.h"
#include "camera_device.h"
#include "capture_input.h"
#include "picture_proxy.h"
namespace OHOS {
namespace CameraStandard {
using namespace DeferredProcessing;
static constexpr int32_t MIN_SIZE_NUM = 64;
static constexpr int32_t streamId = 0;
const size_t THRESHOLD = 10;
static pid_t pid = 0;
std::vector<MetadataObjectType> metadataObjectTypes = {
    MetadataObjectType::BAR_CODE_DETECTION,
    MetadataObjectType::BASE_FACE_DETECTION,
    MetadataObjectType::CAT_BODY,
    MetadataObjectType::CAT_FACE,
    MetadataObjectType::FACE,
};
std::vector<MetadataObjectType> typeAdded = {
    MetadataObjectType::CAT_BODY,
    MetadataObjectType::CAT_FACE,
    MetadataObjectType::FACE,
};
std::vector<MetadataObjectType> supportedType = {
    MetadataObjectType::CAT_BODY,
    MetadataObjectType::CAT_FACE,
    MetadataObjectType::FACE,
    MetadataObjectType::HUMAN_BODY,
};

std::shared_ptr<MetadataOutput> MetadataOutputFuzzer::fuzz_{nullptr};
sptr<CameraManager> cameraManager_ = nullptr;

void MetadataOutputFuzzer::MetadataOutputFuzzTest(FuzzedDataProvider& fdp)
{
    if (fdp.remaining_bytes() < MIN_SIZE_NUM) {
        return;
    }
    cameraManager_ = CameraManager::GetInstance();
    std::vector<sptr<CameraDevice>> cameras = cameraManager_->GetCameraDeviceListFromServer();
    CHECK_ERROR_RETURN_LOG(cameras.empty(), "MetadataOutputFuzzer: GetCameraDeviceListFromServer Error");
    sptr<CaptureInput> input = cameraManager_->CreateCameraInput(cameras[0]);
    CHECK_ERROR_RETURN_LOG(!input, "CreateCameraInput Error");
    sptr<CaptureOutput> metadata = cameraManager_->CreateMetadataOutput();
    sptr<CaptureSession> session = cameraManager_->CreateCaptureSession();
    session->BeginConfig();
    session->AddInput(input);
    session->AddOutput(metadata);
    session->CommitConfig();
    session->Start();
    session->innerInputDevice_ = nullptr;
    sptr<MetadataOutput> metadatOutput = (sptr<MetadataOutput>&)metadata;
    fuzz_->SetSession(session);
    fuzz_->CreateStream();
    fuzz_->GetAppObjectCallback();
    fuzz_->GetAppStateCallback();
    fuzz_->GetSupportedMetadataObjectTypes();
    std::shared_ptr<MetadataObjectCallback> metadataObjectCallback = std::make_shared<AppMetadataCallback>();
    fuzz_->checkValidType(typeAdded, supportedType);
    std::vector<MetadataObjectType> typesOfMetadata;
    typesOfMetadata.push_back(MetadataObjectType::FACE);
    fuzz_->convert(typesOfMetadata);
    std::shared_ptr<MetadataObjectCallback> appObjectCallback = std::make_shared<AppMetadataCallback>();
    fuzz_->appObjectCallback_ = appObjectCallback;
    sptr<IStreamMetadataCallback> cameraMetadataCallback = new HStreamMetadataCallbackImpl(metadatOutput);
    fuzz_->cameraMetadataCallback_ = cameraMetadataCallback;
    fuzz_->SetCallback(appObjectCallback);
    std::shared_ptr<OHOS::Camera::CameraMetadata> result = session->GetMetadata();
    std::shared_ptr<HStreamMetadataCallbackImpl> hstreamMetadataCallbackImpl =
        std::make_shared<HStreamMetadataCallbackImpl>(metadatOutput);
    hstreamMetadataCallbackImpl->OnMetadataResult(streamId, result);
    fuzz_->Release();
    fuzz_->appStateCallback_ = nullptr;
    fuzz_->CameraServerDied(pid);
}

void MetadataOutputFuzzer::MetadataOutputFuzzTest1(FuzzedDataProvider& fdp)
{
    if (fdp.remaining_bytes() < MIN_SIZE_NUM) {
        return;
    }
    std::shared_ptr<MetadataObjectFactory> factory = std::make_shared<MetadataObjectFactory>();
    factory->ResetParameters();
    MetadataObjectType type = MetadataObjectType::HUMAN_BODY;
    sptr<MetadataObject> ret = factory->createMetadataObject(type);
    IDeferredPhotoProcessingSessionCallbackFuzz callback;
    auto object = callback.AsObject();
    sptr<IStreamMetadata> streamMetadata = iface_cast<IStreamMetadata>(object);
    sptr<IConsumerSurface> surface = IConsumerSurface::Create();
    sptr<MetadataObjectFactory> factoryPtr = MetadataObjectFactory::GetInstance();
    sptr<MetadataObjectFactory> factoryPtr_2 = MetadataObjectFactory::GetInstance();
    std::shared_ptr<OHOS::Camera::CameraMetadata> result = nullptr;
    std::vector<sptr<MetadataObject>> metaObjects = {};
    bool isNeedMirror = fdp.ConsumeBool();
    bool isNeedFlip = fdp.ConsumeBool();
    fuzz_->ProcessMetadata(streamId, result, metaObjects, isNeedMirror, isNeedFlip);
    camera_metadata_item_t metadataItem;
    fuzz_->reportFaceResults_ = fdp.ConsumeBool();
    fuzz_->GenerateObjects(metadataItem, type, metaObjects, isNeedMirror, isNeedFlip);
    fuzz_->ProcessRectBox(fdp.ConsumeIntegral<int32_t>(), fdp.ConsumeIntegral<int32_t>(),
        fdp.ConsumeIntegral<int32_t>(), fdp.ConsumeIntegral<int32_t>(), isNeedMirror, isNeedFlip);
    int32_t index = fdp.ConsumeIntegral<int32_t>();
    fuzz_->ProcessExternInfo(factoryPtr, metadataItem, index, type, isNeedMirror, isNeedFlip);
    fuzz_->GetSurface();
    fuzz_->surface_ = nullptr;
    fuzz_->ReleaseSurface();
    fuzz_->SetCapturingMetadataObjectTypes(metadataObjectTypes);
    fuzz_->AddMetadataObjectTypes(metadataObjectTypes);
    fuzz_->RemoveMetadataObjectTypes(metadataObjectTypes);
}

void Test(uint8_t* data, size_t size)
{
    FuzzedDataProvider fdp(data, size);
    auto metadataOutput = std::make_unique<MetadataOutputFuzzer>();
    if (metadataOutput == nullptr) {
        MEDIA_INFO_LOG("metadataOutput is null");
        return;
    }
    IDeferredPhotoProcessingSessionCallbackFuzz callback;
    auto object = callback.AsObject();
    sptr<IStreamMetadata> streamMetadata = iface_cast<IStreamMetadata>(object);
    sptr<IConsumerSurface> surface = IConsumerSurface::Create();
    MetadataOutputFuzzer::fuzz_ = std::make_shared<MetadataOutput>(surface, streamMetadata);
    CHECK_ERROR_RETURN_LOG(!MetadataOutputFuzzer::fuzz_, "Create fuzz_ Error");
    metadataOutput->MetadataOutputFuzzTest(fdp);
    metadataOutput->MetadataOutputFuzzTest1(fdp);
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