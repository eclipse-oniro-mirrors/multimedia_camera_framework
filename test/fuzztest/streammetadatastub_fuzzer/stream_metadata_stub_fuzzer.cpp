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

#include "stream_metadata_stub_fuzzer.h"
#include "foundation/multimedia/camera_framework/common/utils/camera_log.h"
#include "hstream_metadata.h"
#include "nativetoken_kit.h"
#include "token_setproc.h"
#include "accesstoken_kit.h"
#include "camera_metadata_info.h"
#include "iconsumer_surface.h"
#include "metadata_utils.h"
#include "camera_service_ipc_interface_code.h"
#include <fuzzer/FuzzedDataProvider.h>

namespace {

const size_t LIMITCOUNT = 4;
const int32_t PHOTO_FORMAT = 2000;
const uint32_t INVALID_CODE = 9999;
const std::u16string FORMMGR_INTERFACE_TOKEN = u"IStreamCapture";
static constexpr int32_t MIN_SIZE_NUM = 150;

std::shared_ptr<OHOS::Camera::CameraMetadata> MakeMetadata(FuzzedDataProvider& fdp)
{
    int32_t itemCount = 10;
    int32_t dataSize = 100;

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

}

namespace OHOS {
namespace CameraStandard {
namespace StreamMetadataStubFuzzer {

bool g_hasPermission = false;
sptr<HStreamMetadataStub> fuzz_{nullptr};

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
    CHECK_ERROR_RETURN_LOG(!photoSurface, "StreamMetadataStubFuzzer: Create photoSurface Error");
    sptr<IBufferProducer> producer = photoSurface->GetProducer();
    const int32_t face = 0;
    std::vector<int32_t> type = {face};
    fuzz_ = new HStreamMetadata(producer, PHOTO_FORMAT, type);
    CHECK_ERROR_RETURN_LOG(!fuzz_, "Create fuzz_ Error");

    Test_OnRemoteRequest(fdp);
}

void Test_OnRemoteRequest(FuzzedDataProvider& fdp)
{
    MessageParcel data;
    data.WriteInterfaceToken(fuzz_->GetDescriptor());
    auto metadata = MakeMetadata(fdp);
    CHECK_ERROR_RETURN_LOG(!(OHOS::Camera::MetadataUtils::EncodeCameraMetadata(metadata, data)),
        "StreamMetadataStubFuzzer: EncodeCameraMetadata Error");
    uint32_t code;
    MessageParcel reply;
    MessageOption option;
    std::vector<StreamMetadataInterfaceCode> streamMetadataInfo = {
        CAMERA_STREAM_META_START,
        CAMERA_STREAM_META_STOP,
        CAMERA_STREAM_META_RELEASE,
        CAMERA_STREAM_META_SET_CALLBACK,
        CAMERA_STREAM_META_ENABLE_RESULTS,
        CAMERA_STREAM_META_DISABLE_RESULTS,
        CAMERA_STREAM_META_UNSET_CALLBACK,
    };

    code  = static_cast<uint32_t>(streamMetadataInfo[fdp.ConsumeIntegral<uint32_t>() % streamMetadataInfo.size()]);
    data.RewindRead(0);
    fuzz_->OnRemoteRequest(code, data, reply, option);

    code = static_cast<uint32_t>(streamMetadataInfo[fdp.ConsumeIntegral<uint32_t>() % streamMetadataInfo.size()]);
    data.RewindRead(0);
    fuzz_->OnRemoteRequest(code, data, reply, option);

    code = static_cast<uint32_t>(streamMetadataInfo[fdp.ConsumeIntegral<uint32_t>() % streamMetadataInfo.size()]);
    data.RewindRead(0);
    fuzz_->OnRemoteRequest(code, data, reply, option);

    code = INVALID_CODE;
    data.RewindRead(0);
    fuzz_->OnRemoteRequest(code, data, reply, option);
}

} // namespace StreamMetadataStubFuzzer
} // namespace CameraStandard
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(uint8_t *data, size_t size)
{
    /* Run your code on data */
    OHOS::CameraStandard::StreamMetadataStubFuzzer::Test(data, size);
    return 0;
}