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

#include "stream_depth_data_stub_fuzzer.h"
#include "foundation/multimedia/camera_framework/common/utils/camera_log.h"
#include "hstream_depth_data.h"
#include "iservice_registry.h"
#include "message_parcel.h"
#include "nativetoken_kit.h"
#include "token_setproc.h"
#include "accesstoken_kit.h"
#include "iconsumer_surface.h"
#include <fuzzer/FuzzedDataProvider.h>
#include "test_token.h"

using namespace OHOS::CameraStandard;
namespace OHOS {
namespace CameraStandard {
namespace StreamDepthDataStubFuzzer {

const int32_t LIMITSIZE = 2;
const int32_t PHOTO_WIDTH = 1280;
const int32_t PHOTO_HEIGHT = 960;
const int32_t PHOTO_FORMAT = 2000;
const uint32_t INVALID_CODE = 9999;
const std::u16string FORMMGR_INTERFACE_TOKEN = u"IStreamDepthData";

sptr<IBufferProducer> g_producer;

HStreamDepthData& GetHStreamDepthData(){
    static HStreamDepthData hstreamDepthData(g_producer, PHOTO_FORMAT, PHOTO_WIDTH, PHOTO_HEIGHT);
    return hstreamDepthData;
}

void Test(uint8_t *rawData, size_t size)
{
    if (rawData == nullptr || size < LIMITSIZE) {
        return;
    }
    sptr<IConsumerSurface> photoSurface = IConsumerSurface::Create();
    CHECK_RETURN_ELOG(!photoSurface, "StreamDepthDataStubFuzzer: Create photoSurface Error");
    g_producer = photoSurface->GetProducer();

    Test_OnRemoteRequest(rawData, size);
    Test_UncoveredCommands(rawData, size);
    Test_ErrorBranches(rawData, size);
    GetHStreamDepthData().Release();
}

void Request(MessageParcel &data, MessageParcel &reply, MessageOption &option, IStreamDepthDataIpcCode sdic)
{
    uint32_t code = static_cast<uint32_t>(sdic);
    data.RewindRead(0);
    GetHStreamDepthData().OnRemoteRequest(code, data, reply, option);
}

void Test_OnRemoteRequest(uint8_t *rawData, size_t size)
{
    FuzzedDataProvider fdp(rawData, size);

    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    data.WriteInterfaceToken(FORMMGR_INTERFACE_TOKEN);

    Request(data, reply, option, IStreamDepthDataIpcCode::COMMAND_START);

    data.RewindWrite(0);
    data.WriteInterfaceToken(FORMMGR_INTERFACE_TOKEN);
    Request(data, reply, option, IStreamDepthDataIpcCode::COMMAND_STOP);

    data.RewindWrite(0);
    data.WriteInterfaceToken(FORMMGR_INTERFACE_TOKEN);
    Request(data, reply, option, IStreamDepthDataIpcCode::COMMAND_SET_CALLBACK);

    data.RewindWrite(0);
    data.WriteInterfaceToken(FORMMGR_INTERFACE_TOKEN);
    data.WriteInt32(fdp.ConsumeIntegral<int32_t>());
    Request(data, reply, option, IStreamDepthDataIpcCode::COMMAND_SET_DATA_ACCURACY);

    data.RewindWrite(0);
    data.WriteInterfaceToken(FORMMGR_INTERFACE_TOKEN);
    Request(data, reply, option, IStreamDepthDataIpcCode::COMMAND_RELEASE);

    uint32_t code = INVALID_CODE;
    data.RewindRead(0);
    GetHStreamDepthData().OnRemoteRequest(code, data, reply, option);
}

void Test_UncoveredCommands(uint8_t *rawData, size_t size)
{
    if (rawData == nullptr || size < LIMITSIZE) {
        return;
    }

    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    data.WriteInterfaceToken(FORMMGR_INTERFACE_TOKEN);

    Request(data, reply, option, IStreamDepthDataIpcCode::COMMAND_UN_SET_CALLBACK);
}

void Test_ErrorBranches(uint8_t *rawData, size_t size)
{
    if (rawData == nullptr || size < LIMITSIZE) {
        return;
    }

    FuzzedDataProvider fdp(rawData, size);

    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    data.WriteInterfaceToken(FORMMGR_INTERFACE_TOKEN);

    Request(data, reply, option, IStreamDepthDataIpcCode::COMMAND_START);

    data.RewindWrite(0);
    data.WriteInterfaceToken(FORMMGR_INTERFACE_TOKEN);
    Request(data, reply, option, IStreamDepthDataIpcCode::COMMAND_STOP);

    data.RewindWrite(0);
    data.WriteInterfaceToken(FORMMGR_INTERFACE_TOKEN);
    Request(data, reply, option, IStreamDepthDataIpcCode::COMMAND_SET_CALLBACK);

    data.RewindWrite(0);
    data.WriteInterfaceToken(FORMMGR_INTERFACE_TOKEN);
    data.WriteInt32(0);
    Request(data, reply, option, IStreamDepthDataIpcCode::COMMAND_SET_DATA_ACCURACY);

    data.RewindWrite(0);
    data.WriteInterfaceToken(FORMMGR_INTERFACE_TOKEN);
    Request(data, reply, option, IStreamDepthDataIpcCode::COMMAND_RELEASE);

    data.RewindWrite(0);
    data.WriteInterfaceToken(FORMMGR_INTERFACE_TOKEN);
    Request(data, reply, option, IStreamDepthDataIpcCode::COMMAND_UN_SET_CALLBACK);

    data.RewindWrite(0);
    data.WriteInterfaceToken(FORMMGR_INTERFACE_TOKEN);
    uint32_t invalidCode = INVALID_CODE;
    GetHStreamDepthData().OnRemoteRequest(invalidCode, data, reply, option);
}

} // namespace StreamDepthDataStubFuzzer
} // namespace CameraStandard
} // namespace OHOS

void Init()
{
    CHECK_RETURN_ELOG(!TestToken().GetAllCameraPermission(), "GetAllCameraPermission fail");
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(uint8_t *data, size_t size)
{
    /* Run your code on data */
    OHOS::CameraStandard::StreamDepthDataStubFuzzer::Test(data, size);
    return 0;
}

extern "C" int LLVMFuzzerInitialize(int* argc, char*** argv)
{
    Init();
    return 0;
}
