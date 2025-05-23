/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#include "stream_capture_stub_fuzzer.h"
#include "foundation/multimedia/camera_framework/common/utils/camera_log.h"
#include "hstream_capture.h"
#include "iservice_registry.h"
#include "message_parcel.h"
#include "nativetoken_kit.h"
#include "token_setproc.h"
#include "accesstoken_kit.h"
#include "camera_metadata_info.h"
#include "metadata_utils.h"
#include "iconsumer_surface.h"
#include "camera_service_ipc_interface_code.h"
#include <fuzzer/FuzzedDataProvider.h>

namespace OHOS {
namespace CameraStandard {
namespace StreamCaptureStubFuzzer {

const size_t LIMITCOUNT = 4;
static constexpr int32_t MIN_SIZE_NUM = 100;
const int32_t PHOTO_WIDTH = 1280;
const int32_t PHOTO_HEIGHT = 960;
const int32_t PHOTO_FORMAT = 2000;
const uint32_t INVALID_CODE = 9999;
const std::u16string FORMMGR_INTERFACE_TOKEN = u"IStreamCapture";
const int32_t DATA_ZERO = 0;
const int32_t ITEM_CAP = 10;
const int32_t DATA_CAP = 100;

bool g_hasPermission = false;
std::shared_ptr<HStreamCaptureStub> fuzz_{nullptr};

std::shared_ptr<OHOS::Camera::CameraMetadata> MakeMetadata(FuzzedDataProvider& fdp)
{
    int32_t itemCount = ITEM_CAP;
    int32_t dataSize = DATA_CAP;

    std::vector<uint8_t> streams = fdp.ConsumeBytes<uint8_t>(dataSize);
    std::shared_ptr<OHOS::Camera::CameraMetadata> ability;
    ability = std::make_shared<OHOS::Camera::CameraMetadata>(itemCount, dataSize);
    ability->addEntry(OHOS_ABILITY_STREAM_AVAILABLE_EXTEND_CONFIGURATIONS, streams.data(), streams.size() / LIMITCOUNT);
    int32_t compensationRange[2] = {fdp.ConsumeIntegral<int32_t>(), fdp.ConsumeIntegral<int32_t>()};
    ability->addEntry(OHOS_CONTROL_AE_COMPENSATION_RANGE, compensationRange,
                      sizeof(compensationRange) / sizeof(compensationRange[0]));
    float focalLength = fdp.ConsumeFloatingPoint<float>();
    ability->addEntry(OHOS_ABILITY_FOCAL_LENGTH, &focalLength, 1);

    int32_t sensorOrientation = fdp.ConsumeIntegral<int32_t>();
    ability->addEntry(OHOS_SENSOR_ORIENTATION, &sensorOrientation, 1);

    int32_t cameraPosition = fdp.ConsumeIntegral<int32_t>();
    ability->addEntry(OHOS_ABILITY_CAMERA_POSITION, &cameraPosition, 1);

    const camera_rational_t aeCompensationStep[] = {{fdp.ConsumeIntegral<int32_t>(), fdp.ConsumeIntegral<int32_t>()}};
    ability->addEntry(OHOS_CONTROL_AE_COMPENSATION_STEP, &aeCompensationStep,
                      sizeof(aeCompensationStep) / sizeof(aeCompensationStep[0]));
    return ability;
}

void CheckPermission()
{
    if (!g_hasPermission) {
        uint64_t tokenId;
        const char *perms[0];
        perms[0] = "ohos.permission.CAMERA";
        NativeTokenInfoParams infoInstance = { .dcapsNum = 0, .permsNum = 1, .aclsNum = 0, .dcaps = NULL,
            .perms = perms, .acls = NULL, .processName = "camera_capture", .aplStr = "system_basic",
        };
        tokenId = GetAccessTokenId(&infoInstance);
        SetSelfTokenID(tokenId);
        OHOS::Security::AccessToken::AccessTokenKit::ReloadNativeTokenInfo();
        g_hasPermission = true;
    }
}

void Test(uint8_t *data, size_t size)
{
    FuzzedDataProvider fdp(data, size);
    if (fdp.remaining_bytes() < MIN_SIZE_NUM) {
        return;
    }
    CheckPermission();
    sptr<IConsumerSurface> photoSurface = IConsumerSurface::Create();
    CHECK_ERROR_RETURN_LOG(!photoSurface, "StreamCaptureStubFuzzer: Create photoSurface Error");
    sptr<IBufferProducer> producer = photoSurface->GetProducer();
    fuzz_ = std::make_shared<HStreamCapture>(producer, PHOTO_FORMAT, PHOTO_WIDTH, PHOTO_HEIGHT);
    CHECK_ERROR_RETURN_LOG(!fuzz_, "Create fuzz_ Error");

    Test_OnRemoteRequest(fdp);
    Test_HandleCapture(fdp);
    Test_HandleSetThumbnail(fdp);
    Test_HandleSetBufferProducerInfo(fdp);
    Test_HandleEnableDeferredType(fdp);
    Test_HandleSetCallback(fdp);
    fuzz_->Release();
}

void Request(MessageParcel &data, MessageParcel &reply, MessageOption &option, StreamCaptureInterfaceCode scic)
{
    uint32_t code = static_cast<uint32_t>(scic);
    data.RewindRead(0);
    fuzz_->OnRemoteRequest(code, data, reply, option);
}

void Test_OnRemoteRequest(FuzzedDataProvider& fdp)
{
    MessageParcel data;
    int32_t dataSize = fdp.ConsumeIntegralInRange(DATA_ZERO, DATA_CAP);
    data.RewindWrite(dataSize);
    data.WriteInterfaceToken(FORMMGR_INTERFACE_TOKEN);
    auto metadata = MakeMetadata(fdp);
    CHECK_ERROR_RETURN_LOG(!(OHOS::Camera::MetadataUtils::EncodeCameraMetadata(metadata, data)),
        "StreamCaptureStubFuzzer: EncodeCameraMetadata Error");
    MessageParcel reply;
    MessageOption option;
    Request(data, reply, option, StreamCaptureInterfaceCode::CAMERA_STREAM_CAPTURE_START);
    Request(data, reply, option, StreamCaptureInterfaceCode::CAMERA_STREAM_CAPTURE_CANCEL);
    Request(data, reply, option, StreamCaptureInterfaceCode::CAMERA_STREAM_CAPTURE_CONFIRM);
    Request(data, reply, option, StreamCaptureInterfaceCode::CAMERA_STREAM_CAPTURE_SET_CALLBACK);
    Request(data, reply, option, StreamCaptureInterfaceCode::CAMERA_STREAM_CAPTURE_RELEASE);
    Request(data, reply, option, StreamCaptureInterfaceCode::CAMERA_SERVICE_SET_THUMBNAIL);
    Request(data, reply, option, StreamCaptureInterfaceCode::CAMERA_SERVICE_ENABLE_DEFERREDTYPE);
    Request(data, reply, option, StreamCaptureInterfaceCode::CAMERA_STREAM_GET_DEFERRED_PHOTO);
    Request(data, reply, option, StreamCaptureInterfaceCode::CAMERA_STREAM_GET_DEFERRED_VIDEO);
    Request(data, reply, option, StreamCaptureInterfaceCode::CAMERA_STREAM_SET_BUFFER_PRODUCER_INFO);
    uint32_t code = INVALID_CODE;
    data.RewindRead(0);
    fuzz_->OnRemoteRequest(code, data, reply, option);
}

void Test_HandleCapture(FuzzedDataProvider& fdp)
{
    MessageParcel data;
    int32_t dataSize = fdp.ConsumeIntegralInRange(DATA_ZERO, DATA_CAP);
    // tagCount
    data.WriteUint32(1);
    // itemCapacity
    data.WriteUint32(ITEM_CAP);
    // dataCapacity
    data.WriteUint32(DATA_CAP);
    // item.index
    data.WriteUint32(0);
    // item.item
    data.WriteUint32(1);
    // item.data_type
    data.WriteUint32(0);
    // item.count
    data.WriteUint32(1);
    data.WriteInt32(1);
    std::vector<uint8_t> streams = fdp.ConsumeBytes<uint8_t>(dataSize);
    data.WriteRawData(streams.data(), streams.size());
    data.RewindRead(0);
    fuzz_->HandleCapture(data);
}

void Test_HandleSetThumbnail(FuzzedDataProvider& fdp)
{
    MessageParcel data;
    int32_t dataSize = fdp.ConsumeIntegralInRange(DATA_ZERO, DATA_CAP);
    sptr<IConsumerSurface> photoSurface = IConsumerSurface::Create();
    CHECK_ERROR_RETURN_LOG(!photoSurface, "StreamCaptureStubFuzzer: Create photoSurface Error");
    sptr<IRemoteObject> producer = photoSurface->GetProducer()->AsObject();
    data.WriteRemoteObject(producer);
    std::vector<uint8_t> streams = fdp.ConsumeBytes<uint8_t>(dataSize);
    data.WriteRawData(streams.data(), streams.size());
    data.RewindRead(0);
    fuzz_->HandleSetThumbnail(data);
}

void Test_HandleSetBufferProducerInfo(FuzzedDataProvider& fdp)
{
    MessageParcel data;
    int32_t dataSize = fdp.ConsumeIntegralInRange(DATA_ZERO, DATA_CAP);
    sptr<IConsumerSurface> photoSurface = IConsumerSurface::Create();
    CHECK_ERROR_RETURN_LOG(!photoSurface, "StreamCaptureStubFuzzer: Create photoSurface Error");
    sptr<IRemoteObject> producer = photoSurface->GetProducer()->AsObject();
    data.WriteRemoteObject(producer);
    std::vector<uint8_t> streams = fdp.ConsumeBytes<uint8_t>(dataSize);
    data.WriteRawData(streams.data(), streams.size());
    data.RewindRead(0);
    fuzz_->HandleSetBufferProducerInfo(data);
}

void Test_HandleEnableDeferredType(FuzzedDataProvider& fdp)
{
    MessageParcel data;
    int32_t dataSize = fdp.ConsumeIntegralInRange(DATA_ZERO, DATA_CAP);
    std::vector<uint8_t> streams = fdp.ConsumeBytes<uint8_t>(dataSize);
    data.WriteRawData(streams.data(), streams.size());
    data.RewindRead(0);
    fuzz_->HandleEnableDeferredType(data);
}

void Test_HandleSetCallback(FuzzedDataProvider& fdp)
{
    MessageParcel data;
    int32_t dataSize = fdp.ConsumeIntegralInRange(DATA_ZERO, DATA_CAP);
    auto samgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    static const int32_t AUDIO_POLICY_SERVICE_ID = 3009;
    auto object = samgr->GetSystemAbility(AUDIO_POLICY_SERVICE_ID);
    data.WriteRemoteObject(object);
    std::vector<uint8_t> streams = fdp.ConsumeBytes<uint8_t>(dataSize);
    data.WriteRawData(streams.data(), streams.size());
    data.RewindRead(0);
    fuzz_->HandleSetCallback(data);
}

} // namespace StreamCaptureStubFuzzer
} // namespace CameraStandard
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(uint8_t *data, size_t size)
{
    /* Run your code on data */
    OHOS::CameraStandard::StreamCaptureStubFuzzer::Test(data, size);
    return 0;
}