/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include "camera_device_service_stub_fuzzer.h"
#include "camera_log.h"
#include "message_parcel.h"
#include "camera_device_service_proxy.h"
#include "system_ability_definition.h"
#include "iservice_registry.h"

namespace OHOS {
namespace CameraStandard {
const size_t THRESHOLD = 10;
const int32_t MAX_BUFFER_SIZE = 16;
static const std::u16string g_interfaceToken = u"OHOS.CameraStandard.ICameraDeviceService";
const int32_t NUM_10 = 10;
const int32_t NUM_100 = 100;
std::shared_ptr<CameraDeviceServiceStubFuzz> CameraDeviceServiceStubFuzzer::fuzz_{nullptr};

void CameraDeviceServiceStubFuzzer::CameraDeviceServiceStubFuzzTest1()
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    data.WriteInterfaceToken(g_interfaceToken);
    fuzz_->OnRemoteRequestInner(
        static_cast<uint32_t>(ICameraDeviceServiceIpcCode::COMMAND_OPEN), data, reply, option);
}

void CameraDeviceServiceStubFuzzer::CameraDeviceServiceStubFuzzTest2()
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    data.WriteInterfaceToken(g_interfaceToken);
    fuzz_->OnRemoteRequestInner(
        static_cast<uint32_t>(ICameraDeviceServiceIpcCode::COMMAND_CLOSE), data, reply, option);
}

void CameraDeviceServiceStubFuzzer::CameraDeviceServiceStubFuzzTest3()
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    data.WriteInterfaceToken(g_interfaceToken);
    fuzz_->OnRemoteRequestInner(
        static_cast<uint32_t>(ICameraDeviceServiceIpcCode::COMMAND_RELEASE), data, reply, option);
}

void CameraDeviceServiceStubFuzzer::CameraDeviceServiceStubFuzzTest4()
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    data.WriteInterfaceToken(g_interfaceToken);
    auto samgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    CHECK_RETURN_ELOG(!samgr, "samgr is nullptr");
    auto object = samgr->GetSystemAbility(CAMERA_SERVICE_ID);
    CHECK_RETURN_ELOG(!object, "object is nullptr");
    auto proxy = std::make_shared<CameraDeviceServiceProxy>(object);
    CHECK_RETURN_ELOG(!proxy, "proxy is nullptr");
    data.WriteRemoteObject(proxy->AsObject());
    fuzz_->OnRemoteRequestInner(
        static_cast<uint32_t>(ICameraDeviceServiceIpcCode::COMMAND_SET_CALLBACK), data, reply, option);
}

void CameraDeviceServiceStubFuzzer::CameraDeviceServiceStubFuzzTest5()
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    data.WriteInterfaceToken(g_interfaceToken);
    std::shared_ptr<OHOS::Camera::CameraMetadata> metadata =
        std::make_shared<OHOS::Camera::CameraMetadata>(NUM_10, NUM_100);
    CHECK_RETURN_ELOG(!metadata, "metadata is nullptr");
    data.WriteParcelable(metadata.get());
    fuzz_->OnRemoteRequestInner(
        static_cast<uint32_t>(ICameraDeviceServiceIpcCode::COMMAND_UPDATE_SETTING), data, reply, option);
}

void CameraDeviceServiceStubFuzzer::CameraDeviceServiceStubFuzzTest6(FuzzedDataProvider &fdp)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    data.WriteInterfaceToken(g_interfaceToken);
    uint8_t vectorSize = fdp.ConsumeIntegralInRange<uint8_t>(0, MAX_BUFFER_SIZE);
    std::vector<int32_t> results;
    for (int i = 0; i < vectorSize; ++i) {
        results.push_back(fdp.ConsumeIntegral<int32_t>());
    }
    data.WriteInt32(results.size());
    for (auto it2 = results.begin(); it2 != results.end(); ++it2) {
        if (!data.WriteInt32((*it2))) {
            return;
        }
    }
    fuzz_->OnRemoteRequestInner(
        static_cast<uint32_t>(ICameraDeviceServiceIpcCode::COMMAND_ENABLE_RESULT), data, reply, option);
}

void CameraDeviceServiceStubFuzzer::CameraDeviceServiceStubFuzzTest7()
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    data.WriteInterfaceToken(g_interfaceToken);
    fuzz_->OnRemoteRequestInner(
        static_cast<uint32_t>(ICameraDeviceServiceIpcCode::COMMAND_GET_ENABLED_RESULTS), data, reply, option);
}

void CameraDeviceServiceStubFuzzer::CameraDeviceServiceStubFuzzTest8(FuzzedDataProvider &fdp)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    data.WriteInterfaceToken(g_interfaceToken);
    uint8_t vectorSize = fdp.ConsumeIntegralInRange<uint8_t>(0, MAX_BUFFER_SIZE);
    std::vector<int32_t> results;
    for (int i = 0; i < vectorSize; ++i) {
        results.push_back(fdp.ConsumeIntegral<int32_t>());
    }
    data.WriteInt32(results.size());
    for (auto it2 = results.begin(); it2 != results.end(); ++it2) {
        if (!data.WriteInt32((*it2))) {
            return;
        }
    }
    fuzz_->OnRemoteRequestInner(
        static_cast<uint32_t>(ICameraDeviceServiceIpcCode::COMMAND_DISABLE_RESULT), data, reply, option);
}

void CameraDeviceServiceStubFuzzer::CameraDeviceServiceStubFuzzTest9()
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    data.WriteInterfaceToken(g_interfaceToken);
    std::shared_ptr<OHOS::Camera::CameraMetadata> metadata =
        std::make_shared<OHOS::Camera::CameraMetadata>(NUM_10, NUM_100);
    CHECK_RETURN_ELOG(!metadata, "metadata is nullptr");
    data.WriteParcelable(metadata.get());
    fuzz_->OnRemoteRequestInner(
        static_cast<uint32_t>(ICameraDeviceServiceIpcCode::COMMAND_GET_STATUS), data, reply, option);
}

void CameraDeviceServiceStubFuzzer::CameraDeviceServiceStubFuzzTest10(FuzzedDataProvider &fdp)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    auto value = fdp.ConsumeIntegral<uint8_t>();
    data.WriteInterfaceToken(g_interfaceToken);
    data.WriteUint8(value);
    fuzz_->OnRemoteRequestInner(
        static_cast<uint32_t>(ICameraDeviceServiceIpcCode::COMMAND_SET_USED_AS_POSITION), data, reply, option);
}

void CameraDeviceServiceStubFuzzer::CameraDeviceServiceStubFuzzTest11()
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    data.WriteInterfaceToken(g_interfaceToken);
    fuzz_->OnRemoteRequestInner(
        static_cast<uint32_t>(ICameraDeviceServiceIpcCode::COMMAND_CLOSE_DELAYED), data, reply, option);
}

void CameraDeviceServiceStubFuzzer::CameraDeviceServiceStubFuzzTest12()
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    data.WriteInterfaceToken(g_interfaceToken);
    fuzz_->OnRemoteRequestInner(
        static_cast<uint32_t>(ICameraDeviceServiceIpcCode::COMMAND_UN_SET_CALLBACK), data, reply, option);
}

void CameraDeviceServiceStubFuzzer::CameraDeviceServiceStubFuzzTest13(FuzzedDataProvider &fdp)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    int32_t concurrentTypeofcamera = fdp.ConsumeIntegral<int32_t>();
    data.WriteInterfaceToken(g_interfaceToken);
    data.WriteInt32(concurrentTypeofcamera);
    fuzz_->OnRemoteRequestInner(
        static_cast<uint32_t>(ICameraDeviceServiceIpcCode::COMMAND_OPEN_IN_INT), data, reply, option);
}

void CameraDeviceServiceStubFuzzer::CameraDeviceServiceStubFuzzTest14()
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    data.WriteInterfaceToken(g_interfaceToken);
    fuzz_->OnRemoteRequestInner(
        static_cast<uint32_t>(ICameraDeviceServiceIpcCode::COMMAND_SET_DEVICE_RETRY_TIME), data, reply, option);
}

void CameraDeviceServiceStubFuzzer::CameraDeviceServiceStubFuzzTest15()
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    data.WriteInterfaceToken(g_interfaceToken);
    fuzz_->OnRemoteRequestInner(
        static_cast<uint32_t>(ICameraDeviceServiceIpcCode::COMMAND_OPEN_SECURE_CAMERA), data, reply, option);
}

void FuzzTest(const uint8_t *rawData, size_t size)
{
    FuzzedDataProvider fdp(rawData, size);
    auto cameraDeviceServiceStub = std::make_unique<CameraDeviceServiceStubFuzzer>();
    if (cameraDeviceServiceStub == nullptr) {
        MEDIA_INFO_LOG("cameraDeviceServiceStub is null");
        return;
    }
    CameraDeviceServiceStubFuzzer::fuzz_ = std::make_shared<CameraDeviceServiceStubFuzz>();
    cameraDeviceServiceStub->CameraDeviceServiceStubFuzzTest1();
    cameraDeviceServiceStub->CameraDeviceServiceStubFuzzTest2();
    cameraDeviceServiceStub->CameraDeviceServiceStubFuzzTest3();
    cameraDeviceServiceStub->CameraDeviceServiceStubFuzzTest4();
    cameraDeviceServiceStub->CameraDeviceServiceStubFuzzTest5();
    cameraDeviceServiceStub->CameraDeviceServiceStubFuzzTest6(fdp);
    cameraDeviceServiceStub->CameraDeviceServiceStubFuzzTest7();
    cameraDeviceServiceStub->CameraDeviceServiceStubFuzzTest8(fdp);
    cameraDeviceServiceStub->CameraDeviceServiceStubFuzzTest9();
    cameraDeviceServiceStub->CameraDeviceServiceStubFuzzTest10(fdp);
    cameraDeviceServiceStub->CameraDeviceServiceStubFuzzTest11();
    cameraDeviceServiceStub->CameraDeviceServiceStubFuzzTest12();
    cameraDeviceServiceStub->CameraDeviceServiceStubFuzzTest13(fdp);
    cameraDeviceServiceStub->CameraDeviceServiceStubFuzzTest14();
    cameraDeviceServiceStub->CameraDeviceServiceStubFuzzTest15();
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