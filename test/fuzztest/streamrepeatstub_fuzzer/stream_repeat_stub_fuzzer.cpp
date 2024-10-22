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
#include "camera_service_ipc_interface_code.h"

namespace OHOS {
namespace CameraStandard {
namespace StreamRepeatStubFuzzer {
const int32_t LIMITSIZE = 2;
const int32_t PHOTO_WIDTH = 1280;
const int32_t PHOTO_HEIGHT = 960;
const int32_t PHOTO_FORMAT = 2000;
const RepeatStreamType REPEAT_STREAM_TYPE = RepeatStreamType::PREVIEW;

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

void TestHandleAddDeferredSurface(uint8_t *rawData, size_t size)
{
    MessageParcel data;
    data.WriteInterfaceToken(u"IStreamRepeat");
    data.RewindRead(0);
    MessageParcel reply;
    MessageOption option;
    sptr<IConsumerSurface> photoSurface = IConsumerSurface::Create();
    CHECK_ERROR_RETURN(photoSurface == nullptr);
    sptr<IBufferProducer> producer = photoSurface->GetProducer();
    sptr<HStreamRepeat> hstreamRepeat = new HStreamRepeat(producer, PHOTO_FORMAT, PHOTO_WIDTH,
        PHOTO_HEIGHT, REPEAT_STREAM_TYPE);
    data.WriteRemoteObject(producer->AsObject());
    data.WriteRawData(rawData, size);
    uint32_t code = StreamRepeatInterfaceCode::CAMERA_ADD_DEFERRED_SURFACE;
    hstreamRepeat->OnRemoteRequest(code, data, reply, option);
}

void TestHandleAttachMetaSurface(uint8_t *rawData, size_t size)
{
    MessageParcel data;
    data.WriteInterfaceToken(u"IStreamRepeat");
    data.RewindRead(0);
    MessageParcel reply;
    MessageOption option;
    sptr<IConsumerSurface> photoSurface = IConsumerSurface::Create();
    CHECK_ERROR_RETURN(photoSurface == nullptr);
    sptr<IBufferProducer> producer = photoSurface->GetProducer();
    sptr<HStreamRepeat> hstreamRepeat = new HStreamRepeat(producer, PHOTO_FORMAT, PHOTO_WIDTH,
        PHOTO_HEIGHT, REPEAT_STREAM_TYPE);
    data.WriteRemoteObject(producer->AsObject());
    data.WriteRawData(rawData, size);
    uint32_t code = StreamRepeatInterfaceCode::CAMERA_ATTACH_META_SURFACE;
    hstreamRepeat->OnRemoteRequest(code, data, reply, option);
}

void TestHandleSetCallback(uint8_t *rawData, size_t size)
{
    MessageParcel data;
    data.WriteInterfaceToken(u"IStreamRepeat");
    data.RewindRead(0);
    MessageParcel reply;
    MessageOption option;
    sptr<IConsumerSurface> photoSurface = IConsumerSurface::Create();
    CHECK_ERROR_RETURN(photoSurface == nullptr);
    sptr<IBufferProducer> producer = photoSurface->GetProducer();
    sptr<HStreamRepeat> hstreamRepeat = new HStreamRepeat(producer, PHOTO_FORMAT, PHOTO_WIDTH,
        PHOTO_HEIGHT, REPEAT_STREAM_TYPE);

    sptr<IRemoteObject> object = nullptr;
    auto samgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    CHECK_ERROR_RETURN(!samgr);
    object = samgr->GetSystemAbility(AUDIO_POLICY_SERVICE_ID);
    sptr<IStreamRepeatCallback> repeatCallback = iface_cast<IStreamRepeatCallback>(object);
    CHECK_ERROR_RETURN(!repeatCallback);
    data.WriteRemoteObject(repeatCallback->AsObject());
    data.WriteRawData(rawData, size);
    uint32_t code = StreamRepeatInterfaceCode::CAMERA_STREAM_REPEAT_SET_CALLBACK;
    CHECK_ERROR_RETURN(!hstreamRepeat);
    hstreamRepeat->OnRemoteRequest(code, data, reply, option);
}

void Test(uint8_t *rawData, size_t size)
{
    if (rawData == nullptr || size < LIMITSIZE) {
        return;
    }
    CheckPermission();
    Test_OnRemoteRequest(rawData, size);
    TestHandleSetCallback(rawData, size);
    TestHandleAddDeferredSurface(rawData, size);
    TestHandleAttachMetaSurface(rawData, size);
}

void RunCase(MessageParcel &data, uint32_t code)
{
    MessageParcel reply;
    MessageOption option;
    sptr<IConsumerSurface> photoSurface = IConsumerSurface::Create();
    if (photoSurface == nullptr) {
        return;
    }
    sptr<IBufferProducer> producer = photoSurface->GetProducer();
    sptr<HStreamRepeat> hstreamRepeat = new HStreamRepeat(producer, PHOTO_FORMAT, PHOTO_WIDTH,
        PHOTO_HEIGHT, REPEAT_STREAM_TYPE);
    hstreamRepeat->OnRemoteRequest(code, data, reply, option);
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