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

namespace OHOS {
namespace CameraStandard {
static const uint8_t *RAW_DATA = nullptr;
const size_t THRESHOLD = 10;
static size_t g_dataSize = 0;
size_t max_length = 64;
static const std::u16string g_interfaceToken = u"OHOS.CameraStandard.IStreamCapture";
static size_t g_pos;
const int32_t NUM_10 = 10;
const int32_t NUM_100 = 100;
std::shared_ptr<HStreamCaptureStubFuzz> HStreamCaptureStubFuzzer::fuzz_{nullptr};

/*
 * describe: get data from outside untrusted data(g_data) which size is according to sizeof(T)
 * tips: only support basic type
 */
template <class T>
T GetData()
{
    T object{};
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

template <class T>
uint32_t GetArrLength(T &arr)
{
    if (arr == nullptr) {
        MEDIA_INFO_LOG("%{public}s: The array length is equal to 0", __func__);
        return 0;
    }
    return sizeof(arr) / sizeof(arr[0]);
}

void HStreamCaptureStubFuzzer::HStreamCaptureStubFuzzTest1(FuzzedDataProvider &fdp)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    sptr<IConsumerSurface> photoSurface = IConsumerSurface::Create();
    CHECK_RETURN(photoSurface == nullptr);
    sptr<IBufferProducer> producer = photoSurface->GetProducer();
    data.WriteInterfaceToken(g_interfaceToken);
    data.WriteString16(Str8ToStr16(fdp.ConsumeRandomLengthString(max_length)));
    data.WriteRemoteObject(producer->AsObject());
    fuzz_->OnRemoteRequestInner(
        static_cast<uint32_t>(IStreamCaptureIpcCode::COMMAND_SET_BUFFER_PRODUCER_INFO), data, reply, option);
}

void HStreamCaptureStubFuzzer::HStreamCaptureStubFuzzTest2(FuzzedDataProvider &fdp)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    sptr<IConsumerSurface> photoSurface = IConsumerSurface::Create();
    CHECK_RETURN(photoSurface == nullptr);
    sptr<IBufferProducer> producer = photoSurface->GetProducer();
    auto value = fdp.ConsumeBool();
    data.WriteInterfaceToken(g_interfaceToken);
    data.WriteInt32(value);
    data.WriteRemoteObject(producer->AsObject());
    fuzz_->OnRemoteRequestInner(
        static_cast<uint32_t>(IStreamCaptureIpcCode::COMMAND_SET_THUMBNAIL), data, reply, option);
}

void HStreamCaptureStubFuzzer::HStreamCaptureStubFuzzTest3()
{
    MessageParcel data;
    auto value = GetData<int32_t>();
    data.WriteInt32(value);
}

void HStreamCaptureStubFuzzer::HStreamCaptureStubFuzzTest4(FuzzedDataProvider &fdp)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    auto value = fdp.ConsumeIntegral<int32_t>();
    data.WriteInterfaceToken(g_interfaceToken);
    data.WriteInt32(value);
    fuzz_->OnRemoteRequestInner(
        static_cast<uint32_t>(IStreamCaptureIpcCode::COMMAND_DEFER_IMAGE_DELIVERY_FOR), data, reply, option);
}

void HStreamCaptureStubFuzzer::HStreamCaptureStubFuzzTest5(FuzzedDataProvider &fdp)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    auto value = fdp.ConsumeIntegral<int32_t>();
    data.WriteInterfaceToken(g_interfaceToken);
    data.WriteInt32(value);
    fuzz_->OnRemoteRequestInner(
        static_cast<uint32_t>(IStreamCaptureIpcCode::COMMAND_SET_MOVING_PHOTO_VIDEO_CODEC_TYPE), data, reply, option);
}

void HStreamCaptureStubFuzzer::HStreamCaptureStubFuzzTest6(FuzzedDataProvider &fdp)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    auto value = fdp.ConsumeIntegral<int32_t>();
    data.WriteInterfaceToken(g_interfaceToken);
    data.WriteInt32(value);
    fuzz_->OnRemoteRequestInner(
        static_cast<uint32_t>(IStreamCaptureIpcCode::COMMAND_CONFIRM_CAPTURE), data, reply, option);
}

void HStreamCaptureStubFuzzer::HStreamCaptureStubFuzzTest7(FuzzedDataProvider &fdp)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    auto value = fdp.ConsumeBool();
    data.WriteInterfaceToken(g_interfaceToken);
    data.WriteInt32(value);
    fuzz_->OnRemoteRequestInner(
        static_cast<uint32_t>(IStreamCaptureIpcCode::COMMAND_ENABLE_RAW_DELIVERY), data, reply, option);
}

void HStreamCaptureStubFuzzer::HStreamCaptureStubFuzzTest8(FuzzedDataProvider &fdp)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    auto value = fdp.ConsumeBool();
    data.WriteInterfaceToken(g_interfaceToken);
    data.WriteInt32(value);
    fuzz_->OnRemoteRequestInner(
        static_cast<uint32_t>(IStreamCaptureIpcCode::COMMAND_ENABLE_MOVING_PHOTO), data, reply, option);
}

void HStreamCaptureStubFuzzer::HStreamCaptureStubFuzzTest9(FuzzedDataProvider &fdp)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    auto value = fdp.ConsumeBool();
    data.WriteInterfaceToken(g_interfaceToken);
    data.WriteInt32(value);
    fuzz_->OnRemoteRequestInner(
        static_cast<uint32_t>(IStreamCaptureIpcCode::COMMAND_SET_CAMERA_PHOTO_ROTATION), data, reply, option);
}

void HStreamCaptureStubFuzzer::HStreamCaptureStubFuzzTest10(FuzzedDataProvider &fdp)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    auto value = fdp.ConsumeBool();
    data.WriteInterfaceToken(g_interfaceToken);
    data.WriteInt32(value);
    fuzz_->OnRemoteRequestInner(
        static_cast<uint32_t>(IStreamCaptureIpcCode::COMMAND_ENABLE_OFFLINE_PHOTO), data, reply, option);
}

void HStreamCaptureStubFuzzer::HStreamCaptureStubFuzzTest11()
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    std::shared_ptr<OHOS::Camera::CameraMetadata> captureSettings =
        std::make_shared<OHOS::Camera::CameraMetadata>(NUM_10, NUM_100);
    data.WriteInterfaceToken(g_interfaceToken);
    data.WriteParcelable(captureSettings.get());
    fuzz_->OnRemoteRequestInner(
        static_cast<uint32_t>(IStreamCaptureIpcCode::COMMAND_CAPTURE), data, reply, option);
}

void HStreamCaptureStubFuzzer::HStreamCaptureStubFuzzTest12()
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    data.WriteInterfaceToken(g_interfaceToken);
    fuzz_->OnRemoteRequestInner(
        static_cast<uint32_t>(IStreamCaptureIpcCode::COMMAND_CANCEL_CAPTURE), data, reply, option);
}

void HStreamCaptureStubFuzzer::HStreamCaptureStubFuzzTest13()
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    auto samgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    auto object = samgr->GetSystemAbility(CAMERA_SERVICE_ID);
    auto proxy = std::make_shared<StreamCaptureCallbackProxy>(object);
    data.WriteInterfaceToken(g_interfaceToken);
    data.WriteRemoteObject(proxy->AsObject());
    fuzz_->OnRemoteRequestInner(
        static_cast<uint32_t>(IStreamCaptureIpcCode::COMMAND_SET_CALLBACK), data, reply, option);
}

void HStreamCaptureStubFuzzer::HStreamCaptureStubFuzzTest14()
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    data.WriteInterfaceToken(g_interfaceToken);
    fuzz_->OnRemoteRequestInner(
        static_cast<uint32_t>(IStreamCaptureIpcCode::COMMAND_RELEASE), data, reply, option);
}

void HStreamCaptureStubFuzzer::HStreamCaptureStubFuzzTest15()
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    data.WriteInterfaceToken(g_interfaceToken);
    fuzz_->OnRemoteRequestInner(
        static_cast<uint32_t>(IStreamCaptureIpcCode::COMMAND_IS_DEFERRED_PHOTO_ENABLED), data, reply, option);
}

void HStreamCaptureStubFuzzer::HStreamCaptureStubFuzzTest16()
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    data.WriteInterfaceToken(g_interfaceToken);
    fuzz_->OnRemoteRequestInner(
        static_cast<uint32_t>(IStreamCaptureIpcCode::COMMAND_IS_DEFERRED_VIDEO_ENABLED), data, reply, option);
}

void HStreamCaptureStubFuzzer::HStreamCaptureStubFuzzTest17()
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    data.WriteInterfaceToken(g_interfaceToken);
    fuzz_->OnRemoteRequestInner(
        static_cast<uint32_t>(IStreamCaptureIpcCode::COMMAND_UN_SET_CALLBACK), data, reply, option);
}

void HStreamCaptureStubFuzzer::HStreamCaptureStubFuzzTest18()
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    auto samgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    auto object = samgr->GetSystemAbility(CAMERA_SERVICE_ID);
    auto proxy = std::make_shared<StreamCapturePhotoAssetCallbackProxy>(object);
    data.WriteInterfaceToken(g_interfaceToken);
    data.WriteRemoteObject(proxy->AsObject());
    fuzz_->OnRemoteRequestInner(
        static_cast<uint32_t>(IStreamCaptureIpcCode::COMMAND_SET_PHOTO_ASSET_AVAILABLE_CALLBACK), data, reply, option);
}

void HStreamCaptureStubFuzzer::HStreamCaptureStubFuzzTest19()
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    data.WriteInterfaceToken(g_interfaceToken);
    fuzz_->OnRemoteRequestInner(
        static_cast<uint32_t>(IStreamCaptureIpcCode::COMMAND_UN_SET_PHOTO_AVAILABLE_CALLBACK), data, reply, option);
}

void HStreamCaptureStubFuzzer::HStreamCaptureStubFuzzTest20()
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    data.WriteInterfaceToken(g_interfaceToken);
    fuzz_->OnRemoteRequestInner(
        static_cast<uint32_t>(IStreamCaptureIpcCode::COMMAND_UN_SET_PHOTO_ASSET_AVAILABLE_CALLBACK),
        data, reply, option);
}

void HStreamCaptureStubFuzzer::HStreamCaptureStubFuzzTest21()
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    data.WriteInterfaceToken(g_interfaceToken);
    fuzz_->OnRemoteRequestInner(
        static_cast<uint32_t>(IStreamCaptureIpcCode::COMMAND_UN_SET_THUMBNAIL_CALLBACK), data, reply, option);
}

void FuzzTest(const uint8_t *rawData, size_t size)
{
    FuzzedDataProvider fdp(rawData, size);
    auto hstreamCaptureStub = std::make_unique<HStreamCaptureStubFuzzer>();
    if (hstreamCaptureStub == nullptr) {
        MEDIA_INFO_LOG("hstreamCaptureStub is null");
        return;
    }
    HStreamCaptureStubFuzzer::fuzz_ = std::make_shared<HStreamCaptureStubFuzz>();
    hstreamCaptureStub->HStreamCaptureStubFuzzTest1(fdp);
    hstreamCaptureStub->HStreamCaptureStubFuzzTest2(fdp);
    hstreamCaptureStub->HStreamCaptureStubFuzzTest3();
    hstreamCaptureStub->HStreamCaptureStubFuzzTest4(fdp);
    hstreamCaptureStub->HStreamCaptureStubFuzzTest5(fdp);
    hstreamCaptureStub->HStreamCaptureStubFuzzTest6(fdp);
    hstreamCaptureStub->HStreamCaptureStubFuzzTest7(fdp);
    hstreamCaptureStub->HStreamCaptureStubFuzzTest8(fdp);
    hstreamCaptureStub->HStreamCaptureStubFuzzTest9(fdp);
    hstreamCaptureStub->HStreamCaptureStubFuzzTest10(fdp);
    hstreamCaptureStub->HStreamCaptureStubFuzzTest11();
    hstreamCaptureStub->HStreamCaptureStubFuzzTest12();
    hstreamCaptureStub->HStreamCaptureStubFuzzTest13();
    hstreamCaptureStub->HStreamCaptureStubFuzzTest14();
    hstreamCaptureStub->HStreamCaptureStubFuzzTest15();
    hstreamCaptureStub->HStreamCaptureStubFuzzTest16();
    hstreamCaptureStub->HStreamCaptureStubFuzzTest17();
    hstreamCaptureStub->HStreamCaptureStubFuzzTest18();
    hstreamCaptureStub->HStreamCaptureStubFuzzTest19();
    hstreamCaptureStub->HStreamCaptureStubFuzzTest20();
    hstreamCaptureStub->HStreamCaptureStubFuzzTest21();
}
}  // namespace CameraStandard
}  // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(uint8_t *data, size_t size)
{
    if (size < OHOS::CameraStandard::THRESHOLD) {
        return 0;
    }

    OHOS::CameraStandard::FuzzTest(data, size);
    return 0;
}