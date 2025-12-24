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

#include "hstream_capture_stub_fuzzer.h"
#include "camera_log.h"
#include "hstream_capture.h"
#include "iservice_registry.h"
#include "message_parcel.h"
#include "nativetoken_kit.h"
#include "string_ex.h"
#include "token_setproc.h"
#include "accesstoken_kit.h"
#include "camera_metadata_info.h"
#include "metadata_utils.h"
#include "iconsumer_surface.h"
#include "securec.h"
#include "stream_capture_callback_proxy.h"
#include "stream_capture_photo_asset_callback_proxy.h"
#include "system_ability_definition.h"
#include "iservice_registry.h"

using namespace OHOS::CameraStandard;
static const size_t MAX_LENGTH = 64;
static const int32_t NUM_10 = 10;
static const int32_t NUM_100 = 100;
static const std::u16string INTERFACE_TOKEN = u"OHOS.CameraStandard.IStreamCapture";
static std::shared_ptr<HStreamCaptureStubFuzz> g_hStreamCaptureStubFuzz;

void HStreamCaptureStubFuzzTest1(FuzzedDataProvider& fdp)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    sptr<IConsumerSurface> photoSurface = IConsumerSurface::Create();
    CHECK_RETURN(photoSurface == nullptr);
    sptr<IBufferProducer> producer = photoSurface->GetProducer();
    CHECK_RETURN_ELOG(!producer, "producer is nullptr");
    data.WriteInterfaceToken(INTERFACE_TOKEN);
    data.WriteString16(Str8ToStr16(fdp.ConsumeRandomLengthString(MAX_LENGTH)));
    data.WriteRemoteObject(producer->AsObject());
    g_hStreamCaptureStubFuzz->OnRemoteRequestInner(
        static_cast<uint32_t>(IStreamCaptureIpcCode::COMMAND_SET_BUFFER_PRODUCER_INFO), data, reply, option);
}

void HStreamCaptureStubFuzzTest2(FuzzedDataProvider& fdp)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    sptr<IConsumerSurface> photoSurface = IConsumerSurface::Create();
    CHECK_RETURN(photoSurface == nullptr);
    sptr<IBufferProducer> producer = photoSurface->GetProducer();
    CHECK_RETURN_ELOG(!producer, "producer is nullptr");
    auto value = fdp.ConsumeBool();
    data.WriteInterfaceToken(INTERFACE_TOKEN);
    data.WriteInt32(value);
    data.WriteRemoteObject(producer->AsObject());
    g_hStreamCaptureStubFuzz->OnRemoteRequestInner(
        static_cast<uint32_t>(IStreamCaptureIpcCode::COMMAND_SET_THUMBNAIL), data, reply, option);
}

void HStreamCaptureStubFuzzTest4(FuzzedDataProvider& fdp)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    auto value = fdp.ConsumeIntegral<int32_t>();
    data.WriteInterfaceToken(INTERFACE_TOKEN);
    data.WriteInt32(value);
    g_hStreamCaptureStubFuzz->OnRemoteRequestInner(
        static_cast<uint32_t>(IStreamCaptureIpcCode::COMMAND_DEFER_IMAGE_DELIVERY_FOR), data, reply, option);
}

void HStreamCaptureStubFuzzTest5(FuzzedDataProvider& fdp)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    auto value = fdp.ConsumeIntegral<int32_t>();
    data.WriteInterfaceToken(INTERFACE_TOKEN);
    data.WriteInt32(value);
    g_hStreamCaptureStubFuzz->OnRemoteRequestInner(
        static_cast<uint32_t>(IStreamCaptureIpcCode::COMMAND_SET_MOVING_PHOTO_VIDEO_CODEC_TYPE), data, reply, option);
}

void HStreamCaptureStubFuzzTest6(FuzzedDataProvider& fdp)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    auto value = fdp.ConsumeIntegral<int32_t>();
    data.WriteInterfaceToken(INTERFACE_TOKEN);
    data.WriteInt32(value);
    g_hStreamCaptureStubFuzz->OnRemoteRequestInner(
        static_cast<uint32_t>(IStreamCaptureIpcCode::COMMAND_CONFIRM_CAPTURE), data, reply, option);
}

void HStreamCaptureStubFuzzTest7(FuzzedDataProvider& fdp)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    auto value = fdp.ConsumeBool();
    data.WriteInterfaceToken(INTERFACE_TOKEN);
    data.WriteInt32(value);
    g_hStreamCaptureStubFuzz->OnRemoteRequestInner(
        static_cast<uint32_t>(IStreamCaptureIpcCode::COMMAND_ENABLE_RAW_DELIVERY), data, reply, option);
}

void HStreamCaptureStubFuzzTest8(FuzzedDataProvider& fdp)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    auto value = fdp.ConsumeBool();
    data.WriteInterfaceToken(INTERFACE_TOKEN);
    data.WriteInt32(value);
    g_hStreamCaptureStubFuzz->OnRemoteRequestInner(
        static_cast<uint32_t>(IStreamCaptureIpcCode::COMMAND_ENABLE_MOVING_PHOTO), data, reply, option);
}

void HStreamCaptureStubFuzzTest9(FuzzedDataProvider& fdp)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    auto value = fdp.ConsumeBool();
    data.WriteInterfaceToken(INTERFACE_TOKEN);
    data.WriteInt32(value);
    g_hStreamCaptureStubFuzz->OnRemoteRequestInner(
        static_cast<uint32_t>(IStreamCaptureIpcCode::COMMAND_SET_CAMERA_PHOTO_ROTATION), data, reply, option);
}

void HStreamCaptureStubFuzzTest10(FuzzedDataProvider& fdp)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    auto value = fdp.ConsumeBool();
    data.WriteInterfaceToken(INTERFACE_TOKEN);
    data.WriteInt32(value);
    g_hStreamCaptureStubFuzz->OnRemoteRequestInner(
        static_cast<uint32_t>(IStreamCaptureIpcCode::COMMAND_ENABLE_OFFLINE_PHOTO), data, reply, option);
}

void HStreamCaptureStubFuzzTest11(FuzzedDataProvider&)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    std::shared_ptr<OHOS::Camera::CameraMetadata> captureSettings =
        std::make_shared<OHOS::Camera::CameraMetadata>(NUM_10, NUM_100);
    CHECK_RETURN_ELOG(!captureSettings, "captureSettings is nullptr");
    data.WriteInterfaceToken(INTERFACE_TOKEN);
    data.WriteParcelable(captureSettings.get());
    g_hStreamCaptureStubFuzz->OnRemoteRequestInner(
        static_cast<uint32_t>(IStreamCaptureIpcCode::COMMAND_CAPTURE), data, reply, option);
}

void HStreamCaptureStubFuzzTest12(FuzzedDataProvider&)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    data.WriteInterfaceToken(INTERFACE_TOKEN);
    g_hStreamCaptureStubFuzz->OnRemoteRequestInner(
        static_cast<uint32_t>(IStreamCaptureIpcCode::COMMAND_CANCEL_CAPTURE), data, reply, option);
}

void HStreamCaptureStubFuzzTest13(FuzzedDataProvider&)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    auto samgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    CHECK_RETURN_ELOG(!samgr, "samgr is nullptr");
    auto object = samgr->GetSystemAbility(CAMERA_SERVICE_ID);
    CHECK_RETURN_ELOG(!object, "object is nullptr");
    auto proxy = std::make_shared<StreamCaptureCallbackProxy>(object);
    CHECK_RETURN_ELOG(!proxy, "proxy is nullptr");
    data.WriteInterfaceToken(INTERFACE_TOKEN);
    data.WriteRemoteObject(proxy->AsObject());
    g_hStreamCaptureStubFuzz->OnRemoteRequestInner(
        static_cast<uint32_t>(IStreamCaptureIpcCode::COMMAND_SET_CALLBACK), data, reply, option);
}

void HStreamCaptureStubFuzzTest14(FuzzedDataProvider&)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    data.WriteInterfaceToken(INTERFACE_TOKEN);
    g_hStreamCaptureStubFuzz->OnRemoteRequestInner(
        static_cast<uint32_t>(IStreamCaptureIpcCode::COMMAND_RELEASE), data, reply, option);
}

void HStreamCaptureStubFuzzTest15(FuzzedDataProvider&)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    data.WriteInterfaceToken(INTERFACE_TOKEN);
    g_hStreamCaptureStubFuzz->OnRemoteRequestInner(
        static_cast<uint32_t>(IStreamCaptureIpcCode::COMMAND_IS_DEFERRED_PHOTO_ENABLED), data, reply, option);
}

void HStreamCaptureStubFuzzTest16(FuzzedDataProvider&)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    data.WriteInterfaceToken(INTERFACE_TOKEN);
    g_hStreamCaptureStubFuzz->OnRemoteRequestInner(
        static_cast<uint32_t>(IStreamCaptureIpcCode::COMMAND_IS_DEFERRED_VIDEO_ENABLED), data, reply, option);
}

void HStreamCaptureStubFuzzTest17(FuzzedDataProvider&)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    data.WriteInterfaceToken(INTERFACE_TOKEN);
    g_hStreamCaptureStubFuzz->OnRemoteRequestInner(
        static_cast<uint32_t>(IStreamCaptureIpcCode::COMMAND_UN_SET_CALLBACK), data, reply, option);
}

void HStreamCaptureStubFuzzTest18(FuzzedDataProvider&)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    auto samgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    CHECK_RETURN_ELOG(!samgr, "samgr is nullptr");
    auto object = samgr->GetSystemAbility(CAMERA_SERVICE_ID);
    CHECK_RETURN_ELOG(!object, "object is nullptr");
    auto proxy = std::make_shared<StreamCapturePhotoAssetCallbackProxy>(object);
    CHECK_RETURN_ELOG(!proxy, "proxy is nullptr");
    data.WriteInterfaceToken(INTERFACE_TOKEN);
    data.WriteRemoteObject(proxy->AsObject());
    g_hStreamCaptureStubFuzz->OnRemoteRequestInner(
        static_cast<uint32_t>(IStreamCaptureIpcCode::COMMAND_SET_PHOTO_ASSET_AVAILABLE_CALLBACK), data, reply, option);
}

void HStreamCaptureStubFuzzTest19(FuzzedDataProvider&)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    data.WriteInterfaceToken(INTERFACE_TOKEN);
    g_hStreamCaptureStubFuzz->OnRemoteRequestInner(
        static_cast<uint32_t>(IStreamCaptureIpcCode::COMMAND_UN_SET_PHOTO_AVAILABLE_CALLBACK), data, reply, option);
}

void HStreamCaptureStubFuzzTest20(FuzzedDataProvider&)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    data.WriteInterfaceToken(INTERFACE_TOKEN);
    g_hStreamCaptureStubFuzz->OnRemoteRequestInner(
        static_cast<uint32_t>(IStreamCaptureIpcCode::COMMAND_UN_SET_PHOTO_ASSET_AVAILABLE_CALLBACK), data, reply,
        option);
}

void HStreamCaptureStubFuzzTest21(FuzzedDataProvider&)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    data.WriteInterfaceToken(INTERFACE_TOKEN);
    g_hStreamCaptureStubFuzz->OnRemoteRequestInner(
        static_cast<uint32_t>(IStreamCaptureIpcCode::COMMAND_UN_SET_THUMBNAIL_CALLBACK), data, reply, option);
}

void HStreamCaptureStubFuzzTest22(FuzzedDataProvider& fdp)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    data.WriteInterfaceToken(INTERFACE_TOKEN);
    sptr<CameraPhotoProxy> photoProxy = new (std::nothrow) CameraPhotoProxy();
    CHECK_RETURN_ELOG(!photoProxy, "photoProxy is nullptr");
    data.WriteParcelable(photoProxy);
    int64_t timestamp = fdp.ConsumeIntegral<int64_t>();
    data.WriteInt64(timestamp);
    g_hStreamCaptureStubFuzz->OnRemoteRequestInner(
        static_cast<uint32_t>(IStreamCaptureIpcCode::COMMAND_CREATE_MEDIA_LIBRARY), data, reply, option);
}

void Init()
{
    g_hStreamCaptureStubFuzz = std::make_shared<HStreamCaptureStubFuzz>();
}

void Test(FuzzedDataProvider& fdp)
{
    auto func =
        fdp.PickValueInArray({ HStreamCaptureStubFuzzTest1, HStreamCaptureStubFuzzTest2, HStreamCaptureStubFuzzTest4,
            HStreamCaptureStubFuzzTest5, HStreamCaptureStubFuzzTest6, HStreamCaptureStubFuzzTest7,
            HStreamCaptureStubFuzzTest8, HStreamCaptureStubFuzzTest9, HStreamCaptureStubFuzzTest10,
            HStreamCaptureStubFuzzTest11, HStreamCaptureStubFuzzTest12, HStreamCaptureStubFuzzTest13,
            HStreamCaptureStubFuzzTest14, HStreamCaptureStubFuzzTest15, HStreamCaptureStubFuzzTest16,
            HStreamCaptureStubFuzzTest17, HStreamCaptureStubFuzzTest18, HStreamCaptureStubFuzzTest19,
            HStreamCaptureStubFuzzTest20, HStreamCaptureStubFuzzTest21, HStreamCaptureStubFuzzTest22 });
    func(fdp);
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    FuzzedDataProvider fdp(data, size);
    Test(fdp);
    return 0;
}

extern "C" int LLVMFuzzerInitialize(int* argc, char*** argv)
{
    if (SetSelfTokenID(718336240ull | (1ull << 32)) < 0) {
        return -1;
    }
    Init();
    return 0;
}