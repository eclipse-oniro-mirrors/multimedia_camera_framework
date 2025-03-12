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

namespace OHOS {
namespace CameraStandard {
using namespace DeferredProcessing;
static constexpr int32_t MAX_CODE_LEN  = 512;
static constexpr int32_t MIN_SIZE_NUM = 4;
static constexpr int32_t streamId = 0;
static const uint8_t* RAW_DATA = nullptr;
const size_t THRESHOLD = 10;
static size_t g_dataSize = 0;
static size_t g_pos;
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

/*
* describe: get data from outside untrusted data(g_data) which size is according to sizeof(T)
* tips: only support basic type
*/
template<class T>
T GetData()
{
    T object {};
    size_t objectSize = sizeof(object);
    if (RAW_DATA == nullptr || objectSize > g_dataSize - g_pos) {
        return object;
    }
    errno_t ret = memcpy_s(&object, objectSize, RAW_DATA + g_pos, objectSize);
    if (ret != EOK) {
        return {};
    }
    g_pos += objectSize;
    return object;
}

template<class T>
uint32_t GetArrLength(T& arr)
{
    if (arr == nullptr) {
        MEDIA_INFO_LOG("%{public}s: The array length is equal to 0", __func__);
        return 0;
    }
    return sizeof(arr) / sizeof(arr[0]);
}

void MetadataOutputFuzzer::MetadataOutputFuzzTest()
{
    if ((RAW_DATA == nullptr) || (g_dataSize > MAX_CODE_LEN) || (g_dataSize < MIN_SIZE_NUM)) {
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

void MetadataOutputFuzzer::MetadataOutputFuzzTest1()
{
    if ((RAW_DATA == nullptr) || (g_dataSize > MAX_CODE_LEN) || (g_dataSize < MIN_SIZE_NUM)) {
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
    bool isNeedMirror = GetData<bool>();
    bool isNeedFlip = GetData<bool>();
    fuzz_->ProcessMetadata(streamId, result, metaObjects, isNeedMirror, isNeedFlip);
    camera_metadata_item_t metadataItem;
    fuzz_->reportFaceResults_ = GetData<bool>();
    fuzz_->GenerateObjects(metadataItem, type, metaObjects, isNeedMirror, isNeedFlip);
    fuzz_->ProcessRectBox(GetData<int32_t>(), GetData<int32_t>(), GetData<int32_t>(),
        GetData<int32_t>(), isNeedMirror, isNeedFlip);
    int32_t index = GetData<int32_t>();
    fuzz_->ProcessExternInfo(factoryPtr, metadataItem, index, type, isNeedMirror, isNeedFlip);
    fuzz_->GetSurface();
    fuzz_->surface_ = nullptr;
    fuzz_->ReleaseSurface();
    fuzz_->SetCapturingMetadataObjectTypes(metadataObjectTypes);
    fuzz_->AddMetadataObjectTypes(metadataObjectTypes);
    fuzz_->RemoveMetadataObjectTypes(metadataObjectTypes);
}

void Test()
{
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
    metadataOutput->MetadataOutputFuzzTest();
    metadataOutput->MetadataOutputFuzzTest1();
}

typedef void (*TestFuncs[1])();

TestFuncs g_testFuncs = {
    Test,
};

bool FuzzTest(const uint8_t* rawData, size_t size)
{
    // initialize data
    RAW_DATA = rawData;
    g_dataSize = size;
    g_pos = 0;

    uint32_t code = GetData<uint32_t>();
    uint32_t len = GetArrLength(g_testFuncs);
    if (len > 0) {
        g_testFuncs[code % len]();
    } else {
        MEDIA_INFO_LOG("%{public}s: The len length is equal to 0", __func__);
    }

    return true;
}
} // namespace CameraStandard
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(uint8_t* data, size_t size)
{
    if (size < OHOS::CameraStandard::THRESHOLD) {
        return 0;
    }

    OHOS::CameraStandard::FuzzTest(data, size);
    return 0;
}