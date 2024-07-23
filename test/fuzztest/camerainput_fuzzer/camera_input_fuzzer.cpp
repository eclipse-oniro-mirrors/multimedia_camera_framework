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

#include "camera_input_fuzzer.h"
#include "camera_input.h"
#include "input/camera_device.h"
#include "input/camera_manager.h"
#include "message_parcel.h"
#include <cstddef>
#include <cstdint>
#include <memory>

namespace OHOS {
namespace CameraStandard {
namespace CameraInputFuzzer {
const int32_t LIMITSIZE = 4;
const size_t ITEM_CAP = 10;
const size_t DATA_CAP = 1000;
void Test(uint8_t *rawData, size_t size)
{
    if (rawData == nullptr || size < LIMITSIZE) {
        return;
    }
    auto manager = CameraManager::GetInstance();
    auto cameras = manager->GetSupportedCameras();
    auto input = manager->CreateCameraInput(cameras[*rawData % cameras.size()]);
    if (input == nullptr) {
        return;
    }
    TestInput(input, rawData, size);
}

class ErrorCallbackMock : public ErrorCallback {
public:
    void OnError(const int32_t errorType, const int32_t errorMsg) const override {}
};

class ResultCallbackMock : public ResultCallback {
public:
    void OnResult(const uint64_t timestamp,
    const std::shared_ptr<OHOS::Camera::CameraMetadata> &result) const override {}
};

class CameraOcclusionDetectCallbackMock : public CameraOcclusionDetectCallback {
public:
    void OnCameraOcclusionDetected(const uint8_t isCameraOcclusionDetect) const override {}
};

void TestInput(sptr<CameraInput> input, uint8_t *rawData, size_t size)
{
    MessageParcel data;
    data.WriteRawData(rawData, size);
    input->Open();
    input->Close();
    uint64_t secureSeqId;
    data.RewindRead(0);
    input->Open(data.ReadBool(), &secureSeqId);
    input->SetErrorCallback(make_shared<ErrorCallbackMock>());
    input->SetResultCallback(make_shared<ResultCallbackMock>());
    input->SetOcclusionDetectCallback(make_shared<CameraOcclusionDetectCallbackMock>());
    input->GetCameraId();
    input->GetCameraDevice();
    input->GetErrorCallback();
    input->GetResultCallback();
    input->GetOcclusionDetectCallback();
    auto cameraObj = input->GetCameraDeviceInfo();
    input->SetCameraDeviceInfo(cameraObj);
    shared_ptr<OHOS::Camera::CameraMetadata> result;
    data.RewindRead(0);
    input->ProcessCallbackUpdates(data.ReadUint64(), result);
    input->GetCameraSettings();
    data.RewindRead(0);
    input->SetCameraSettings(data.ReadString());
    data.RewindRead(0);
    input->GetMetaSetting(data.ReadUint32());
    std::vector<vendorTag_t> infos;
    input->GetCameraAllVendorTags(infos);
    auto srcMetadata = make_shared<OHOS::Camera::CameraMetadata>(ITEM_CAP, DATA_CAP);
    data.RewindRead(0);
    for (size_t i = 0; i < ITEM_CAP; i++) {
        if (data.GetReadableBytes() >= sizeof(uint32_t)) {
            srcMetadata->addEntry(data.ReadUint32(), rawData, 1);
        }
    }
    auto dstMetadata = make_shared<OHOS::Camera::CameraMetadata>(ITEM_CAP, DATA_CAP);
    input->MergeMetadata(srcMetadata, dstMetadata);
    input->Release();
}

} // namespace StreamRepeatStubFuzzer
} // namespace CameraStandard
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(uint8_t *data, size_t size)
{
    /* Run your code on data */
    OHOS::CameraStandard::CameraInputFuzzer::Test(data, size);
    return 0;
}