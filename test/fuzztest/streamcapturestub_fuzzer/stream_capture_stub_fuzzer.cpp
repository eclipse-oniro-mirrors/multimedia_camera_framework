/*
 * Copyright (c) 2023-2025 Huawei Device Co., Ltd.
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
#include <fuzzer/FuzzedDataProvider.h>
#include "test_token.h"

namespace OHOS {
namespace CameraStandard {
namespace StreamCaptureStubFuzzer {

const int32_t LIMITSIZE = 2;
const size_t LIMITCOUNT = 4;
const int32_t PHOTO_WIDTH = 1280;
const int32_t PHOTO_HEIGHT = 960;
const int32_t PHOTO_FORMAT = 2000;
const uint32_t INVALID_CODE = 9999;
const std::u16string FORMMGR_INTERFACE_TOKEN = u"IStreamCapture";
const int32_t ITEM_CAP = 10;
const int32_t DATA_CAP = 100;

std::shared_ptr<StreamCaptureStub> fuzz_{nullptr};

std::shared_ptr<OHOS::Camera::CameraMetadata> MakeMetadata(uint8_t *rawData, size_t size)
{
    int32_t itemCount = ITEM_CAP;
    int32_t dataSize = DATA_CAP;
    FuzzedDataProvider fdp(rawData, size);

    int32_t *streams = reinterpret_cast<int32_t *>(rawData);
    std::shared_ptr<OHOS::Camera::CameraMetadata> ability;
    ability = std::make_shared<OHOS::Camera::CameraMetadata>(itemCount, dataSize);
    ability->addEntry(OHOS_ABILITY_STREAM_AVAILABLE_EXTEND_CONFIGURATIONS, streams, size / LIMITCOUNT);
    int32_t compensationRange[2] = {rawData[0], rawData[1]};
    ability->addEntry(OHOS_CONTROL_AE_COMPENSATION_RANGE, compensationRange,
                      sizeof(compensationRange) / sizeof(compensationRange[0]));
    float focalLength = fdp.ConsumeFloatingPoint<float>();
    ability->addEntry(OHOS_ABILITY_FOCAL_LENGTH, &focalLength, 1);

    int32_t sensorOrientation = fdp.ConsumeIntegral<int32_t>();
    ability->addEntry(OHOS_SENSOR_ORIENTATION, &sensorOrientation, 1);

    int32_t cameraPosition = fdp.ConsumeIntegral<int32_t>();
    ability->addEntry(OHOS_ABILITY_CAMERA_POSITION, &cameraPosition, 1);

    const camera_rational_t aeCompensationStep[] = {{rawData[0], rawData[1]}};
    ability->addEntry(OHOS_CONTROL_AE_COMPENSATION_STEP, &aeCompensationStep,
                      sizeof(aeCompensationStep) / sizeof(aeCompensationStep[0]));
    return ability;
}

void Test(uint8_t *rawData, size_t size)
{
    if (rawData == nullptr || size < LIMITSIZE) {
        return;
    }
    CHECK_RETURN_ELOG(!TestToken().GetAllCameraPermission(), "GetAllCameraPermission fail");

    sptr<IConsumerSurface> photoSurface = IConsumerSurface::Create();
    CHECK_RETURN_ELOG(!photoSurface, "StreamCaptureStubFuzzer: Create photoSurface Error");
    sptr<IBufferProducer> producer = photoSurface->GetProducer();
    fuzz_ = std::make_shared<HStreamCapture>(producer, PHOTO_FORMAT, PHOTO_WIDTH, PHOTO_HEIGHT);
    CHECK_RETURN_ELOG(!fuzz_, "Create fuzz_ Error");

    Test_OnRemoteRequest(rawData, size);
    Test_HandleCapture(rawData, size);
    Test_HandleSetThumbnail(rawData, size);
    Test_HandleSetBufferProducerInfo(rawData, size);
    Test_HandleEnableDeferredType(rawData, size);
    Test_HandleSetCallback(rawData, size);
    fuzz_->Release();
}

void Request(MessageParcel &data, MessageParcel &reply, MessageOption &option, IStreamCaptureIpcCode scic)
{
    uint32_t code = static_cast<uint32_t>(scic);
    data.RewindRead(0);
    fuzz_->OnRemoteRequest(code, data, reply, option);
}

void Test_OnRemoteRequest(uint8_t *rawData, size_t size)
{
    MessageParcel data;
    data.RewindWrite(0);
    data.WriteInterfaceToken(FORMMGR_INTERFACE_TOKEN);
    auto metadata = MakeMetadata(rawData, size);
    CHECK_RETURN_ELOG(!(OHOS::Camera::MetadataUtils::EncodeCameraMetadata(metadata, data)),
        "StreamCaptureStubFuzzer: EncodeCameraMetadata Error");
    MessageParcel reply;
    MessageOption option;
    Request(data, reply, option, IStreamCaptureIpcCode::COMMAND_CANCEL_CAPTURE);
    Request(data, reply, option, IStreamCaptureIpcCode::COMMAND_CAPTURE);
    Request(data, reply, option, IStreamCaptureIpcCode::COMMAND_SET_CALLBACK);
    Request(data, reply, option, IStreamCaptureIpcCode::COMMAND_RELEASE);
    Request(data, reply, option, IStreamCaptureIpcCode::COMMAND_SET_THUMBNAIL);
    Request(data, reply, option, IStreamCaptureIpcCode::COMMAND_DEFER_IMAGE_DELIVERY_FOR);
    Request(data, reply, option, IStreamCaptureIpcCode::COMMAND_IS_DEFERRED_PHOTO_ENABLED);
    Request(data, reply, option, IStreamCaptureIpcCode::COMMAND_IS_DEFERRED_VIDEO_ENABLED);
    Request(data, reply, option, IStreamCaptureIpcCode::COMMAND_SET_BUFFER_PRODUCER_INFO);
    uint32_t code = INVALID_CODE;
    data.RewindRead(0);
    fuzz_->OnRemoteRequest(code, data, reply, option);
}

void Test_HandleCapture(uint8_t *rawData, size_t size)
{
    MessageParcel data;
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
    data.WriteRawData(rawData, size);
    data.RewindRead(0);
}

void Test_HandleSetThumbnail(uint8_t *rawData, size_t size)
{
    MessageParcel data;
    sptr<IConsumerSurface> photoSurface = IConsumerSurface::Create();
    CHECK_RETURN_ELOG(!photoSurface, "StreamCaptureStubFuzzer: Create photoSurface Error");
    sptr<IRemoteObject> producer = photoSurface->GetProducer()->AsObject();
    data.WriteRemoteObject(producer);
    data.WriteRawData(rawData, size);
    data.RewindRead(0);
}

void Test_HandleSetBufferProducerInfo(uint8_t *rawData, size_t size)
{
    MessageParcel data;
    sptr<IConsumerSurface> photoSurface = IConsumerSurface::Create();
    CHECK_RETURN_ELOG(!photoSurface, "StreamCaptureStubFuzzer: Create photoSurface Error");
    sptr<IRemoteObject> producer = photoSurface->GetProducer()->AsObject();
    data.WriteRemoteObject(producer);
    data.WriteRawData(rawData, size);
    data.RewindRead(0);
}

void Test_HandleEnableDeferredType(uint8_t *rawData, size_t size)
{
    MessageParcel data;
    data.WriteRawData(rawData, size);
    data.RewindRead(0);
}

void Test_HandleSetCallback(uint8_t *rawData, size_t size)
{
    MessageParcel data;
    auto samgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    static const int32_t AUDIO_POLICY_SERVICE_ID = 3009;
    auto object = samgr->GetSystemAbility(AUDIO_POLICY_SERVICE_ID);
    data.WriteRemoteObject(object);
    data.WriteRawData(rawData, size);
    data.RewindRead(0);

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