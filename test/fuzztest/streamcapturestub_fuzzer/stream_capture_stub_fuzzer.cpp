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
#include "hstream_capture.h"
#include "message_parcel.h"
#include "nativetoken_kit.h"
#include "token_setproc.h"
#include "accesstoken_kit.h"
#include "camera_metadata_info.h"
#include "metadata_utils.h"
#include "iconsumer_surface.h"

namespace {

const int32_t LIMITSIZE = 2;
const size_t LIMITCOUNT = 4;
const int32_t PHOTO_WIDTH = 1280;
const int32_t PHOTO_HEIGHT = 960;
const int32_t PHOTO_FORMAT = 2000;
const std::u16string FORMMGR_INTERFACE_TOKEN = u"IStreamCapture";

std::shared_ptr<OHOS::Camera::CameraMetadata> MakeMetadata(uint8_t *rawData, size_t size)
{
    int32_t itemCount = 10;
    int32_t dataSize = 100;
    int32_t *streams = reinterpret_cast<int32_t *>(rawData);
    std::shared_ptr<OHOS::Camera::CameraMetadata> ability;
    ability = std::make_shared<OHOS::Camera::CameraMetadata>(itemCount, dataSize);
    ability->addEntry(OHOS_ABILITY_STREAM_AVAILABLE_EXTEND_CONFIGURATIONS, streams, size / LIMITCOUNT);
    int32_t compensationRange[2] = {rawData[0], rawData[1]};
    ability->addEntry(OHOS_CONTROL_AE_COMPENSATION_RANGE, compensationRange,
                      sizeof(compensationRange) / sizeof(compensationRange[0]));
    float focalLength = rawData[0];
    ability->addEntry(OHOS_ABILITY_FOCAL_LENGTH, &focalLength, 1);

    int32_t sensorOrientation = rawData[0];
    ability->addEntry(OHOS_SENSOR_ORIENTATION, &sensorOrientation, 1);

    int32_t cameraPosition = rawData[0];
    ability->addEntry(OHOS_ABILITY_CAMERA_POSITION, &cameraPosition, 1);

    const camera_rational_t aeCompensationStep[] = {{rawData[0], rawData[1]}};
    ability->addEntry(OHOS_CONTROL_AE_COMPENSATION_STEP, &aeCompensationStep,
                      sizeof(aeCompensationStep) / sizeof(aeCompensationStep[0]));
    return ability;
}

}

namespace OHOS {
namespace CameraStandard {

bool StreamCaptureStubFuzzer::hasPermission = false;
HStreamCaptureStub *StreamCaptureStubFuzzer::fuzz = nullptr;

void StreamCaptureStubFuzzer::CheckPermission()
{
    if (!hasPermission) {
        uint64_t tokenId;
        const char *perms[0];
        perms[0] = "ohos.permission.CAMERA";
        NativeTokenInfoParams infoInstance = { .dcapsNum = 0, .permsNum = 1, .aclsNum = 0, .dcaps = NULL,
            .perms = perms, .acls = NULL, .processName = "camera_capture", .aplStr = "system_basic",
        };
        tokenId = GetAccessTokenId(&infoInstance);
        SetSelfTokenID(tokenId);
        OHOS::Security::AccessToken::AccessTokenKit::ReloadNativeTokenInfo();
        hasPermission = true;
    }
}

void TestPart2(MessageParcel &data, HStreamCaptureStub *fuzz)
{
    data.RewindRead(0);
    uint32_t code = 0;
    MessageParcel reply;
    MessageOption option;
    fuzz->OnRemoteRequest(code, data, reply, option);

    data.RewindRead(0);
    fuzz->AddAuthInfo(data, reply, code);

    data.RewindRead(0);
    fuzz->InvokerDataBusThread(data, reply);

    data.RewindRead(0);
    fuzz->InvokerThread(code, data, reply, option);

    data.RewindRead(0);
    fuzz->Marshalling(data);

    data.RewindRead(0);
    fuzz->NoticeServiceDie(data, reply, option);

    data.RewindRead(0);
    fuzz->SendRequest(code, data, reply, option);

    data.RewindRead(0);
    fuzz->ProcessProto(code, data, reply, option);

    data.RewindRead(0);
    fuzz->OnRemoteDump(code, data, reply, option);
}

void StreamCaptureStubFuzzer::Test(uint8_t *rawData, size_t size)
{
    if (rawData == nullptr || size < LIMITSIZE) {
        return;
    }
    CheckPermission();

    if (fuzz == nullptr) {
        sptr<IConsumerSurface> photoSurface = IConsumerSurface::Create();
        if (photoSurface == nullptr) {
            return;
        }
        sptr<IBufferProducer> producer = photoSurface->GetProducer();
        fuzz = new HStreamCapture(producer, PHOTO_FORMAT, PHOTO_WIDTH, PHOTO_HEIGHT);
    }
    
    MessageParcel data;
    data.WriteRawData(rawData, size);

    data.RewindRead(0);
    fuzz->HandleCapture(data);

    data.RewindRead(0);
    fuzz->HandleEnableDeferredType(data);

    data.RewindRead(0);
    fuzz->HandleSetCallback(data);

    data.RewindRead(0);
    fuzz->HandleSetThumbnail(data);

    data.RewindWrite(0);
    data.WriteInterfaceToken(FORMMGR_INTERFACE_TOKEN);
    auto metadata = MakeMetadata(rawData, size);
    if (!(OHOS::Camera::MetadataUtils::EncodeCameraMetadata(metadata, data))) {
        return;
    }

    TestPart2(data, fuzz);
}

} // namespace CameraStandard
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(uint8_t *data, size_t size)
{
    /* Run your code on data */
    OHOS::CameraStandard::StreamCaptureStubFuzzer::Test(data, size);
    return 0;
}