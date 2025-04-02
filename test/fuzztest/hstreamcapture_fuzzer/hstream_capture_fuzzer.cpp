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

#include "hstream_capture_fuzzer.h"
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

const int32_t PHOTO_WIDTH = 1280;
const int32_t PHOTO_HEIGHT = 960;
const int32_t PHOTO_FORMAT = 2000;
const int32_t ITEMCOUNT = 10;
const int32_t DATASIZE = 100;
const int32_t NUM_1 = 1;
const int32_t NUM_1024 = 1024;

std::shared_ptr<HStreamCapture> HStreamCaptureFuzzer::fuzz_{nullptr};
sptr<IBufferProducer> producer;

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

void HStreamCaptureFuzzer::HStreamCaptureFuzzTest1()
{
    if ((RAW_DATA == nullptr) || (g_dataSize > MAX_CODE_LEN) || (g_dataSize < MIN_SIZE_NUM)) {
        return;
    }
    int32_t captureId = GetData<int32_t>();
    uint8_t randomNum = GetData<uint8_t>();
    std::vector<bool> testBools = {true, false};
    bool isEnabled = (testBools[randomNum % testBools.size()]);
    bool enabled = (testBools[randomNum % testBools.size()]);
    fuzz_->CreateMediaLibraryPhotoAssetProxy(captureId);
    fuzz_->GetPhotoAssetInstance(captureId);
    fuzz_->GetAddPhotoProxyEnabled();
    fuzz_->AcquireBufferToPrepareProxy(captureId);
    StreamInfo_V1_1 streamInfo;
    fuzz_->SetStreamInfo(streamInfo);
    fuzz_->FillingPictureExtendStreamInfos(streamInfo, GetData<int32_t>());
    fuzz_->SetThumbnail(isEnabled, producer);
    fuzz_->EnableRawDelivery(enabled);
    std::vector<std::string> bufferNames = {"rawImage",
        "gainmapImage", "deepImage", "exifImage", "debugImage"};
    for (const auto& bufName : bufferNames) {
        fuzz_->SetBufferProducerInfo(bufName, producer);
    }
    int32_t type = GetData<int32_t>();
    fuzz_->DeferImageDeliveryFor(type);
    fuzz_->PrepareBurst(captureId);
    fuzz_->ResetBurst();
    fuzz_->ResetBurstKey(captureId);
    fuzz_->GetBurstKey(captureId);
    fuzz_->IsBurstCapture(captureId);
    fuzz_->IsBurstCover(captureId);
    fuzz_->GetCurBurstSeq(captureId);
    fuzz_->IsDeferredPhotoEnabled();
    fuzz_->IsDeferredVideoEnabled();
    auto videoCodecType = GetData<int32_t>();
    fuzz_->SetMovingPhotoVideoCodecType(videoCodecType);
    fuzz_->GetMovingPhotoVideoCodecType();
    fuzz_->SetCameraPhotoRotation(GetData<bool>());
}

void HStreamCaptureFuzzer::HStreamCaptureFuzzTest2()
{
    if ((RAW_DATA == nullptr) || (g_dataSize > MAX_CODE_LEN) || (g_dataSize < MIN_SIZE_NUM)) {
        return;
    }
    auto captureId = GetData<int32_t>();
    auto interfaceCode = GetData<int32_t>();
    auto timestamp = GetData<uint64_t>();
    auto isDelay = GetData<bool>();
    uint8_t randomNum = GetData<uint8_t>();
    std::vector<std::string> testStrings = {"test1", "test2"};
    std::string imageId(testStrings[randomNum % testStrings.size()]);
    fuzz_->SetBurstImages(captureId, imageId);
    fuzz_->CheckResetBurstKey(captureId);
    std::shared_ptr<OHOS::Camera::CameraMetadata> captureSettings;
    captureSettings = std::make_shared<OHOS::Camera::CameraMetadata>(ITEMCOUNT, DATASIZE);
    fuzz_->CheckBurstCapture(captureSettings, GetData<int32_t>());
    sptr<HCameraHostManager> cameraHostManager = new HCameraHostManager(nullptr);
    std::string cameraId;
    uint32_t callingTokenId = GetData<uint32_t>();
    sptr<HCameraDevice> camDevice = new (std::nothrow)
        HCameraDevice(cameraHostManager, cameraId, callingTokenId);
    camDevice->OpenDevice(true);
    fuzz_->OnCaptureReady(captureId, timestamp);
    fuzz_->Capture(captureSettings);
    fuzz_->CancelCapture();
    fuzz_->SetMode(GetData<int32_t>());
    fuzz_->GetMode();
    fuzz_->ConfirmCapture();
    fuzz_->EndBurstCapture(captureSettings);
    fuzz_->Release();
    fuzz_->ReleaseStream(isDelay);
    fuzz_->OnCaptureStarted(captureId);
    fuzz_->OnCaptureStarted(captureId, GetData<int32_t>());
    fuzz_->OnCaptureEnded(captureId, GetData<int32_t>());
    auto errorCode = GetData<int32_t>();
    fuzz_->OnCaptureError(captureId, errorCode);
    fuzz_->OnFrameShutter(captureId, timestamp);
    fuzz_->OnFrameShutterEnd(captureId, timestamp);
    CameraInfoDumper infoDumper(0);
    fuzz_->DumpStreamInfo(infoDumper);
    fuzz_->OperatePermissionCheck(interfaceCode);
    CaptureInfo captureInfoPhoto;
    fuzz_->ProcessCaptureInfoPhoto(captureInfoPhoto, captureSettings, captureId);
    fuzz_->SetRotation(captureSettings, captureId);
}

void Test()
{
    auto hstreamCapture = std::make_unique<HStreamCaptureFuzzer>();
    if (hstreamCapture == nullptr) {
        MEDIA_INFO_LOG("hstreamCapture is null");
        return;
    }
    sptr<Surface> photoSurface;
    photoSurface = Surface::CreateSurfaceAsConsumer("hstreamcapture");
    producer = photoSurface->GetProducer();
    HStreamCaptureFuzzer::fuzz_ = std::make_shared
        <HStreamCapture>(producer, PHOTO_FORMAT, PHOTO_WIDTH, PHOTO_HEIGHT);
    CHECK_ERROR_RETURN_LOG(!HStreamCaptureFuzzer::fuzz_, "Create fuzz_ Error");
    sptr<HDI::Camera::V1_0::IStreamOperator> streamOperator;
    std::shared_ptr<OHOS::Camera::CameraMetadata> cameraAbility =
        std::make_shared<OHOS::Camera::CameraMetadata>(NUM_1, NUM_1024);
    HStreamCaptureFuzzer::fuzz_->LinkInput(streamOperator, cameraAbility);
    HStreamCaptureFuzzer::fuzz_->cameraAbility_ = cameraAbility;
    hstreamCapture->HStreamCaptureFuzzTest1();
    hstreamCapture->HStreamCaptureFuzzTest2();
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