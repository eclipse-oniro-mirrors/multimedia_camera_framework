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

#include "stream_repeat_stub_fuzzer.h"
#include "nativetoken_kit.h"
#include "token_setproc.h"
#include "accesstoken_kit.h"
#include "hstream_repeat.h"
#include "iconsumer_surface.h"
#include "metadata_utils.h"
#include "camera_service_ipc_interface_code.h"
#include <cstdint>

namespace {

const int32_t LIMITSIZE = 2;
const size_t LIMITCOUNT = 4;
const int32_t PHOTO_WIDTH = 1280;
const int32_t PHOTO_HEIGHT = 960;
const int32_t PHOTO_FORMAT = 2000;
const uint32_t INVALID_CODE = 9999;
const uint32_t CAMERA_ADD_DEFERRED = 4;
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
namespace StreamRepeatStubFuzzer {

bool g_hasPermission = false;
HStreamRepeatStub *fuzz = nullptr;

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

void Test(uint8_t *rawData, size_t size)
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
        fuzz = new HStreamRepeat(producer, PHOTO_FORMAT,
            PHOTO_WIDTH, PHOTO_HEIGHT, RepeatStreamType::PREVIEW);
    }

    Test_OnRemoteRequest(rawData, size);
}

void RunCase(MessageParcel &data, StreamRepeatInterfaceCode sric)
{
    MessageParcel reply;
    MessageOption option;
    data.RewindRead(0);
    fuzz->OnRemoteRequest(static_cast<uint32_t>(sric), data, reply, option);
}

void Test_OnRemoteRequest(uint8_t *rawData, size_t size)
{
    MessageParcel data;
    data.WriteInterfaceToken(FORMMGR_INTERFACE_TOKEN);
    auto metadata = MakeMetadata(rawData, size);
    if (!(OHOS::Camera::MetadataUtils::EncodeCameraMetadata(metadata, data))) {
        return;
    }
    RunCase(data, StreamRepeatInterfaceCode::CAMERA_START_VIDEO_RECORDING);
    RunCase(data, StreamRepeatInterfaceCode::CAMERA_STOP_VIDEO_RECORDING);
    RunCase(data, StreamRepeatInterfaceCode::CAMERA_STREAM_REPEAT_RELEASE);
    RunCase(data, StreamRepeatInterfaceCode::CAMERA_REMOVE_SKETCH_STREAM_REPEAT);
    RunCase(data, StreamRepeatInterfaceCode::CAMERA_UPDATE_SKETCH_RATIO);
    RunCase(data, StreamRepeatInterfaceCode::STREAM_FRAME_RANGE_SET);

    uint32_t code;
    MessageParcel reply;
    MessageOption option;

    code = static_cast<uint32_t>(StreamRepeatInterfaceCode::CAMERA_STREAM_REPEAT_SET_CALLBACK);
    data.RewindWrite(0);
    data.WriteInterfaceToken(FORMMGR_INTERFACE_TOKEN);
    data.WriteRawData(rawData, size);
    data.RewindRead(0);
    fuzz->OnRemoteRequest(code, data, reply, option);

    code = static_cast<uint32_t>(StreamRepeatInterfaceCode::CAMERA_FORK_SKETCH_STREAM_REPEAT);
    data.RewindWrite(0);
    data.WriteInterfaceToken(FORMMGR_INTERFACE_TOKEN);
    data.WriteInt32(PHOTO_WIDTH);
    data.WriteInt32(PHOTO_HEIGHT);
    data.WriteFloat(1.0f);
    data.WriteRawData(rawData, size);
    data.RewindRead(0);
    fuzz->OnRemoteRequest(code, data, reply, option);

    code = CAMERA_ADD_DEFERRED;
    data.RewindWrite(0);
    data.WriteInterfaceToken(FORMMGR_INTERFACE_TOKEN);
    data.WriteRawData(rawData, size);
    data.RewindRead(0);
    fuzz->OnRemoteRequest(code, data, reply, option);

    code = INVALID_CODE;
    data.RewindRead(0);
    fuzz->OnRemoteRequest(code, data, reply, option);
}

} // namespace StreamRepeatStubFuzzer
} // namespace CameraStandard
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(uint8_t *data, size_t size)
{
    /* Run your code on data */
    OHOS::CameraStandard::StreamRepeatStubFuzzer::Test(data, size);
    return 0;
}