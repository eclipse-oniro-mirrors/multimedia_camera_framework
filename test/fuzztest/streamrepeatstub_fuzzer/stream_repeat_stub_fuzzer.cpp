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
#include "foundation/multimedia/camera_framework/common/utils/camera_log.h"
#include "hstream_repeat.h"
#include "iservice_registry.h"
#include "nativetoken_kit.h"
#include "system_ability_definition.h"
#include "token_setproc.h"
#include "accesstoken_kit.h"
#include "iconsumer_surface.h"
#include "metadata_utils.h"
#include "test_token.h"
#include <fuzzer/FuzzedDataProvider.h>

using namespace OHOS;
using namespace OHOS::CameraStandard;
const int32_t LIMITSIZE = 2;
const int32_t PHOTO_WIDTH = 1280;
const int32_t PHOTO_HEIGHT = 960;
const int32_t PHOTO_FORMAT = 2000;
const RepeatStreamType REPEAT_STREAM_TYPE = RepeatStreamType::PREVIEW;
sptr<IBufferProducer> g_producer;

HStreamRepeat& GetHStreamRepeat()
{
    static HStreamRepeat hstreamRepeat(g_producer, PHOTO_FORMAT, PHOTO_WIDTH, PHOTO_HEIGHT, REPEAT_STREAM_TYPE);
    return hstreamRepeat;
}

namespace OHOS {
namespace CameraStandard {
namespace StreamRepeatStubFuzzer {

sptr<StreamRepeatStub> fuzz_{nullptr};

void TestHandleAddDeferredSurface(uint8_t *rawData, size_t size)
{
    MessageParcel data;
    data.WriteInterfaceToken(u"IStreamRepeat");
    data.RewindRead(0);
    MessageParcel reply;
    MessageOption option;

    data.WriteRemoteObject(g_producer->AsObject());
    data.WriteRawData(rawData, size);
    uint32_t code = static_cast<uint32_t>(IStreamRepeatIpcCode::COMMAND_ADD_DEFERRED_SURFACE);
    GetHStreamRepeat().OnRemoteRequest(code, data, reply, option);
}

void TestHandleAttachMetaSurface(uint8_t *rawData, size_t size)
{
    MessageParcel data;
    data.WriteInterfaceToken(u"IStreamRepeat");
    data.RewindRead(0);
    MessageParcel reply;
    MessageOption option;

    data.WriteRemoteObject(g_producer->AsObject());
    data.WriteRawData(rawData, size);
    uint32_t code = static_cast<uint32_t>(IStreamRepeatIpcCode::COMMAND_ATTACH_META_SURFACE);
    GetHStreamRepeat().OnRemoteRequest(code, data, reply, option);
}

void TestHandleSetCallback(uint8_t *rawData, size_t size)
{
    MessageParcel data;
    data.WriteInterfaceToken(u"IStreamRepeat");
    data.RewindRead(0);
    MessageParcel reply;
    MessageOption option;

    sptr<IRemoteObject> object = nullptr;
    auto samgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    CHECK_RETURN(!samgr);
    object = samgr->GetSystemAbility(AUDIO_POLICY_SERVICE_ID);
    sptr<IStreamRepeatCallback> repeatCallback = iface_cast<IStreamRepeatCallback>(object);
    CHECK_RETURN(!repeatCallback);
    data.WriteRemoteObject(repeatCallback->AsObject());
    data.WriteRawData(rawData, size);
    uint32_t code = static_cast<uint32_t>(IStreamRepeatIpcCode::COMMAND_SET_CALLBACK);
    GetHStreamRepeat().OnRemoteRequest(code, data, reply, option);
}

void Test(uint8_t *rawData, size_t size)
{
    if (rawData == nullptr || size < LIMITSIZE) {
        return;
    }
    CHECK_RETURN_ELOG(!TestToken().GetAllCameraPermission(), "GetAllCameraPermission fail");
    Test_OnRemoteRequest(rawData, size);
    TestHandleSetCallback(rawData, size);
    TestHandleAddDeferredSurface(rawData, size);
    TestHandleAttachMetaSurface(rawData, size);
    Test_UncoveredCommands(rawData, size);
    Test_ErrorBranches(rawData, size);
}

void RunCase(MessageParcel &data, uint32_t code)
{
    MessageParcel reply;
    MessageOption option;

    GetHStreamRepeat().OnRemoteRequest(code, data, reply, option);
}

void Test_OnRemoteRequest(uint8_t *rawData, size_t size)
{
    static const int32_t MAX_CODE = 20;
    for (int32_t i = 0; i < MAX_CODE; i++) {
        MessageParcel data;
        data.WriteInterfaceToken(u"IStreamRepeat");
        data.WriteRawData(rawData, size);
        data.RewindRead(0);
        RunCase(data, i);
    }
}

void Test_UncoveredCommands(uint8_t *rawData, size_t size)
{
    if (rawData == nullptr || size < LIMITSIZE) {
        return;
    }
    
    FuzzedDataProvider fdp(rawData, size);
    
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    
    data.WriteInterfaceToken(u"IStreamRepeat");
    data.WriteInt32(fdp.ConsumeBool() ? 1 : 0);
    RunCase(data, static_cast<uint32_t>(IStreamRepeatIpcCode::COMMAND_ENABLE_STITCHING));
    
    data.RewindWrite(0);
    data.WriteInterfaceToken(u"IStreamRepeat");
    RunCase(data, static_cast<uint32_t>(IStreamRepeatIpcCode::COMMAND_SET_OUTPUT_SETTINGS));
    
    data.RewindWrite(0);
    data.WriteInterfaceToken(u"IStreamRepeat");
    RunCase(data, static_cast<uint32_t>(IStreamRepeatIpcCode::COMMAND_GET_SUPPORTED_VIDEO_CODEC_TYPES));
    
    data.RewindWrite(0);
    data.WriteInterfaceToken(u"IStreamRepeat");
    data.WriteInt32(fdp.ConsumeBool() ? 1 : 0);
    RunCase(data, static_cast<uint32_t>(IStreamRepeatIpcCode::COMMAND_SET_BANDWIDTH_COMPRESSION));
    
    data.RewindWrite(0);
    data.WriteInterfaceToken(u"IStreamRepeat");
    RunCase(data, static_cast<uint32_t>(IStreamRepeatIpcCode::COMMAND_REMOVE_DEFERRED_SURFACE));
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
    
    data.WriteInterfaceToken(u"IStreamRepeat");
    data.WriteInt32(1);
    RunCase(data, static_cast<uint32_t>(IStreamRepeatIpcCode::COMMAND_ENABLE_STITCHING));
    
    data.RewindWrite(0);
    data.WriteInterfaceToken(u"IStreamRepeat");
    RunCase(data, static_cast<uint32_t>(IStreamRepeatIpcCode::COMMAND_SET_OUTPUT_SETTINGS));
    
    data.RewindWrite(0);
    data.WriteInterfaceToken(u"IStreamRepeat");
    RunCase(data, static_cast<uint32_t>(IStreamRepeatIpcCode::COMMAND_GET_SUPPORTED_VIDEO_CODEC_TYPES));
    
    data.RewindWrite(0);
    data.WriteInterfaceToken(u"IStreamRepeat");
    data.WriteInt32(0);
    RunCase(data, static_cast<uint32_t>(IStreamRepeatIpcCode::COMMAND_SET_BANDWIDTH_COMPRESSION));
    
    data.RewindWrite(0);
    data.WriteInterfaceToken(u"IStreamRepeat");
    RunCase(data, static_cast<uint32_t>(IStreamRepeatIpcCode::COMMAND_REMOVE_DEFERRED_SURFACE));
    
    data.RewindWrite(0);
    data.WriteInterfaceToken(u"IStreamRepeat");
    uint32_t invalidCode = 9999;
    RunCase(data, invalidCode);
}

} // namespace StreamRepeatStubFuzzer
} // namespace CameraStandard
} // namespace OHOS

void Init()
{
    CHECK_RETURN_ELOG(!TestToken().GetAllCameraPermission(), "GetAllCameraPermission fail");
    sptr<IConsumerSurface> photoSurface = IConsumerSurface::Create();
    CHECK_RETURN_ELOG(!photoSurface, "Create photoSurface Error");
    g_producer = photoSurface->GetProducer();
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(uint8_t *data, size_t size)
{
    /* Run your code on data */
    OHOS::CameraStandard::StreamRepeatStubFuzzer::Test(data, size);
    return 0;
}

extern "C" int LLVMFuzzerInitialize(int* argc, char*** argv)
{
    Init();
    return 0;
}