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

#include "hstream_repeat_fuzzer.h"
#include "foundation/multimedia/camera_framework/common/utils/camera_log.h"
#include "message_parcel.h"
#include "iservice_registry.h"
#include <cstddef>
#include <cstdint>
#include <memory>
#include "token_setproc.h"
#include "iconsumer_surface.h"
#include "nativetoken_kit.h"
#include "accesstoken_kit.h"
#include "camera_metadata_info.h"
#include "metadata_utils.h"
#include "camera_service_ipc_interface_code.h"
#include "camera_device.h"
#include "camera_manager.h"
#include "ipc_skeleton.h"
#include "securec.h"

namespace OHOS {
namespace CameraStandard {
using namespace OHOS::HDI::Camera::V1_0;
static constexpr int32_t MAX_CODE_LEN = 512;
static constexpr int32_t MIN_SIZE_NUM = 4;
static const uint8_t* RAW_DATA = nullptr;
const size_t THRESHOLD = 10;
static size_t g_dataSize = 0;
static size_t g_pos;
const int32_t ITEMCOUNT = 10;
const int32_t DATASIZE = 100;
const int32_t PHOTO_WIDTH = 1280;
const int32_t PHOTO_HEIGHT = 960;
const int32_t PHOTO_FORMAT = 2000;

HStreamRepeat *HStreamRepeatFuzzer::fuzz_ = nullptr;

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

void HStreamRepeatFuzzer::HStreamRepeatFuzzTest1()
{
    if ((RAW_DATA == nullptr) || (g_dataSize > MAX_CODE_LEN) || (g_dataSize < MIN_SIZE_NUM)) {
        return;
    }
    sptr<Surface> photoSurface;
    photoSurface = Surface::CreateSurfaceAsConsumer("hstreamrepeat");
    if (fuzz_ == nullptr) {
        fuzz_ = new (std::nothrow) HStreamRepeat(nullptr,
            PHOTO_FORMAT, PHOTO_WIDTH, PHOTO_HEIGHT, RepeatStreamType::PREVIEW);
    }
    std::shared_ptr<OHOS::Camera::CameraMetadata> cameraAbility;
    sptr<OHOS::HDI::Camera::V1_0::IStreamOperator> streamOperator;
    fuzz_->LinkInput(streamOperator, cameraAbility);
    StreamInfo_V1_1 streamInfo;
    fuzz_->SetVideoStreamInfo(streamInfo);
    fuzz_->SetStreamInfo(streamInfo);
    sptr<OHOS::IBufferProducer> metaProducer;
    fuzz_->SetMetaProducer(metaProducer);
    SketchStatus status = SketchStatus::STOPED;
    fuzz_->UpdateSketchStatus(status);
    std::shared_ptr<OHOS::Camera::CameraMetadata> settings;
    settings = std::make_shared<OHOS::Camera::CameraMetadata>(ITEMCOUNT, DATASIZE);
    fuzz_->StartSketchStream(settings);
    camera_position_enum_t cameraPosition = OHOS_CAMERA_POSITION_FRONT;
    fuzz_->SetUsedAsPosition(cameraPosition);
    fuzz_->Start(settings, GetData<bool>());
    fuzz_->Start();
    fuzz_->OnFrameStarted();
    fuzz_->OnFrameEnded(GetData<int32_t>());
    CaptureEndedInfoExt captureEndedInfo = {1, 100, true, "video123"};
    fuzz_->OnDeferredVideoEnhancementInfo(captureEndedInfo);
    fuzz_->OnFrameError(GetData<int32_t>());
    fuzz_->OnSketchStatusChanged(status);
    fuzz_->Stop();
    fuzz_->Release();
    fuzz_->ReleaseStream(GetData<bool>());
}

void HStreamRepeatFuzzer::HStreamRepeatFuzzTest2()
{
    if ((RAW_DATA == nullptr) || (g_dataSize > MAX_CODE_LEN) || (g_dataSize < MIN_SIZE_NUM)) {
        return;
    }
    sptr<Surface> photoSurface;
    photoSurface = Surface::CreateSurfaceAsConsumer("hstreamrepeat");
    if (fuzz_ == nullptr) {
        fuzz_ = new (std::nothrow) HStreamRepeat(nullptr,
            PHOTO_FORMAT, PHOTO_WIDTH, PHOTO_HEIGHT, RepeatStreamType::PREVIEW);
    }
    sptr<IBufferProducer> producer = photoSurface->GetProducer();
    fuzz_->AddDeferredSurface(producer);
    fuzz_->SetFrameRate(GetData<int32_t>(), GetData<int32_t>());
    fuzz_->SetMirror(GetData<bool>());
    fuzz_->SetMirrorForLivePhoto(GetData<bool>(), GetData<int32_t>());
    fuzz_->SetCameraRotation(GetData<bool>(), GetData<int32_t>());
    fuzz_->SetCameraApi(GetData<uint32_t>());
    std::string deviceClass;
    fuzz_->SetPreviewRotation(deviceClass);
    fuzz_->UpdateSketchRatio(GetData<float>());
    fuzz_->GetSketchStream();
    fuzz_->GetRepeatStreamType();
    fuzz_->SyncTransformToSketch();
    fuzz_->SetStreamTransform(GetData<int>());
    camera_position_enum_t cameraPosition = OHOS_CAMERA_POSITION_FRONT;
    int32_t sensorOrientation = GetData<int32_t>();
    fuzz_->ProcessVerticalCameraPosition(sensorOrientation, cameraPosition);
    int32_t streamRotation = GetData<int32_t>();
    fuzz_->ProcessCameraPosition(streamRotation, cameraPosition);
    fuzz_->ProcessFixedTransform(sensorOrientation, cameraPosition);
    fuzz_->ProcessFixedDiffDeviceTransform(cameraPosition);
    fuzz_->ProcessCameraSetRotation(sensorOrientation, cameraPosition);
    camera_position_enum_t cameraPosition1 = OHOS_CAMERA_POSITION_BACK;
    int32_t sensorOrientation1 = GetData<int32_t>();
    fuzz_->ProcessVerticalCameraPosition(sensorOrientation1, cameraPosition1);
    int32_t streamRotation1 = GetData<int32_t>();
    fuzz_->ProcessCameraPosition(streamRotation1, cameraPosition1);
    fuzz_->ProcessFixedTransform(sensorOrientation1, cameraPosition1);
    fuzz_->ProcessFixedDiffDeviceTransform(cameraPosition1);
    fuzz_->ProcessCameraSetRotation(sensorOrientation1, cameraPosition1);
}

void HStreamRepeatFuzzer::HStreamRepeatFuzzTest3()
{
    if ((RAW_DATA == nullptr) || (g_dataSize > MAX_CODE_LEN) || (g_dataSize < MIN_SIZE_NUM)) {
        return;
    }
    sptr<Surface> photoSurface;
    photoSurface = Surface::CreateSurfaceAsConsumer("hstreamrepeat");
    if (fuzz_ == nullptr) {
        fuzz_ = new (std::nothrow) HStreamRepeat(nullptr,
            PHOTO_FORMAT, PHOTO_WIDTH, PHOTO_HEIGHT, RepeatStreamType::PREVIEW);
    }
    sptr<IBufferProducer> producer = photoSurface->GetProducer();
    std::shared_ptr<OHOS::Camera::CameraMetadata> settings;
    settings = std::make_shared<OHOS::Camera::CameraMetadata>(ITEMCOUNT, DATASIZE);
    fuzz_->OperatePermissionCheck(GetData<int>());
    fuzz_->OpenVideoDfxSwitch(settings);
    fuzz_->EnableSecure(GetData<bool>());
    fuzz_->UpdateVideoSettings(settings);
    fuzz_->UpdateFrameRateSettings(settings);
    std::shared_ptr<OHOS::Camera::CameraMetadata> dynamicSetting;
    fuzz_->UpdateFrameMuteSettings(settings, dynamicSetting);
#ifdef NOTIFICATION_ENABLE
    fuzz_->UpdateBeautySettings(settings);
    fuzz_->CancelNotification();
    fuzz_->IsNeedBeautyNotification();
#endif
    sptr<IStreamCapture> photoOutput = nullptr;
    fuzz_->AttachMetaSurface(producer, GetData<int32_t>());
    fuzz_->ToggleAutoVideoFrameRate(GetData<bool>());
    fuzz_->UpdateAutoFrameRateSettings(settings);
    std::shared_ptr<HStreamRepeatCallbackStub> callback = std::make_shared<HStreamRepeatCallbackStubDemo>();
    MessageParcel data;
    callback->HandleOnDeferredVideoEnhancementInfo(data);
}

void Test()
{
    auto hstreamRepeat = std::make_unique<HStreamRepeatFuzzer>();
    if (hstreamRepeat == nullptr) {
        MEDIA_INFO_LOG("hstreamRepeat is null");
        return;
    }
    hstreamRepeat->HStreamRepeatFuzzTest1();
    hstreamRepeat->HStreamRepeatFuzzTest2();
    hstreamRepeat->HStreamRepeatFuzzTest3();
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