/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#ifndef OHOS_CAMERA_H_STREAM_METADATA_H
#define OHOS_CAMERA_H_STREAM_METADATA_H
#define EXPORT_API __attribute__((visibility("default")))

#include "camera_metadata_info.h"
#include "hstream_metadata_stub.h"
#include "hstream_common.h"
#include "v1_0/istream_operator.h"

#include <refbase.h>
#include <iostream>

namespace OHOS {
namespace CameraStandard {
class EXPORT_API HStreamMetadata : public HStreamMetadataStub, public HStreamCommon {
public:
    HStreamMetadata(sptr<OHOS::IBufferProducer> producer, int32_t format, std::vector<int32_t> metadataTypes);
    ~HStreamMetadata();

    int32_t LinkInput(sptr<OHOS::HDI::Camera::V1_0::IStreamOperator> streamOperator,
        std::shared_ptr<OHOS::Camera::CameraMetadata> cameraAbility) override;
    void SetStreamInfo(StreamInfo_V1_1& streamInfo) override;
    int32_t ReleaseStream(bool isDelay) override;
    int32_t Release() override;
    int32_t Start() override;
    int32_t Stop() override;
    int32_t SetCallback(sptr<IStreamMetadataCallback>& callback) override;
    int32_t UnSetCallback() override;
    int32_t EnableMetadataType(std::vector<int32_t> metadataTypes) override;
    int32_t DisableMetadataType(std::vector<int32_t> metadataTypes) override;
    void DumpStreamInfo(CameraInfoDumper& infoDumper) override;
    int32_t OperatePermissionCheck(uint32_t interfaceCode) override;
    int32_t OnMetaResult(int32_t streamId, const std::vector<uint8_t>& result);

private:
    int32_t EnableOrDisableMetadataType(const std::vector<int32_t>& metadataTypes, const bool enable);
    void removeMetadataType(std::vector<int32_t>& vec1, std::vector<int32_t>& vec2);
    std::vector<int32_t> metadataObjectTypes_;
    std::mutex metadataTypeMutex_;
    std::atomic<bool> isStarted_ { false };
    sptr<IStreamMetadataCallback> streamMetadataCallback_;
    std::mutex callbackLock_;
    uint32_t majorVer_ = 0;
    uint32_t minorVer_ = 0;
};
} // namespace CameraStandard
} // namespace OHOS
#endif // OHOS_CAMERA_H_STREAM_METADATA_H
