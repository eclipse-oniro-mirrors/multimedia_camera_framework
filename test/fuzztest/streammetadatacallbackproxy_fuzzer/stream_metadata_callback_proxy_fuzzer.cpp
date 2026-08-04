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

#include "stream_metadata_callback_proxy_fuzzer.h"
#include "camera_log.h"
#include "camera_metadata_info.h"
#include "metadata_utils.h"
#include "message_parcel.h"

namespace OHOS {
namespace CameraStandard {
const size_t THRESHOLD = 10;
const int32_t ITEM_CAP = 10;
const int32_t DATA_CAP = 100;
std::shared_ptr<StreamMetadataCallbackProxy> StreamMetadataCallbackProxyFuzz::fuzz_{nullptr};

std::shared_ptr<OHOS::Camera::CameraMetadata> MakeMetadata(FuzzedDataProvider &fdp)
{
    int32_t itemCount = ITEM_CAP;
    int32_t dataSize = DATA_CAP;
    
    std::shared_ptr<OHOS::Camera::CameraMetadata> ability;
    ability = std::make_shared<OHOS::Camera::CameraMetadata>(itemCount, dataSize);
    
    int32_t sensorOrientation = fdp.ConsumeIntegral<int32_t>();
    ability->addEntry(OHOS_SENSOR_ORIENTATION, &sensorOrientation, 1);
    
    int32_t cameraPosition = fdp.ConsumeIntegral<int32_t>();
    ability->addEntry(OHOS_ABILITY_CAMERA_POSITION, &cameraPosition, 1);
    
    return ability;
}

void StreamMetadataCallbackProxyFuzz::StreamMetadataCallbackProxyTestWithMock(FuzzedDataProvider &fdp)
{
    auto mockRemote = sptr<IRemoteObject>(new MockIRemoteObject());
    CHECK_RETURN_ELOG(!mockRemote, "mockRemote is nullptr");
    fuzz_ = std::make_shared<StreamMetadataCallbackProxy>(mockRemote);
    CHECK_RETURN_ELOG(!fuzz_, "fuzz_ is nullptr");
    
    int32_t streamId = fdp.ConsumeIntegral<int32_t>();
    auto metadata = MakeMetadata(fdp);
    fuzz_->OnMetadataResult(streamId, metadata);
}

void StreamMetadataCallbackProxyFuzz::StreamMetadataCallbackProxyTestErrorBranches(FuzzedDataProvider &fdp)
{
    auto mockFailRemote = sptr<MockIRemoteObject>(new MockIRemoteObject());
    mockFailRemote->shouldFail = true;
    mockFailRemote->errorCode = -1;
    
    fuzz_ = std::make_shared<StreamMetadataCallbackProxy>(mockFailRemote);
    CHECK_RETURN_ELOG(!fuzz_, "fuzz_ is nullptr");
    
    int32_t streamId = fdp.ConsumeIntegral<int32_t>();
    auto metadata = MakeMetadata(fdp);
    fuzz_->OnMetadataResult(streamId, metadata);
    
    metadata = nullptr;
    fuzz_->OnMetadataResult(streamId, metadata);
}

void FuzzTest(const uint8_t *rawData, size_t size)
{
    FuzzedDataProvider fdp(rawData, size);
    auto streamMetadataCallbackProxy = std::make_unique<StreamMetadataCallbackProxyFuzz>();
    if (streamMetadataCallbackProxy == nullptr) {
        MEDIA_INFO_LOG("streamMetadataCallbackProxy is null");
        return;
    }
    streamMetadataCallbackProxy->StreamMetadataCallbackProxyTestWithMock(fdp);
    streamMetadataCallbackProxy->StreamMetadataCallbackProxyTestErrorBranches(fdp);
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
