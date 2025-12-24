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
#include <set>
#define EXPORT_API __attribute__((visibility("default")))

#include "camera_metadata_info.h"
#include "stream_metadata_stub.h"
#include "hstream_common.h"
#include "v1_0/istream_operator.h"
#include "icamera_ipc_checker.h"

#include <refbase.h>
#include <iostream>

namespace OHOS {
namespace CameraStandard {
static const std::unordered_map<MetadataObjectType, uint8_t> g_FwkToHALResultCameraMetaDetect_ = {
    {MetadataObjectType::FACE, 0},
    {MetadataObjectType::HUMAN_BODY, 1},
    {MetadataObjectType::CAT_FACE, 2},
    {MetadataObjectType::CAT_BODY, 3},
    {MetadataObjectType::DOG_FACE, 4},
    {MetadataObjectType::DOG_BODY, 5},
    {MetadataObjectType::SALIENT_DETECTION, 6},
    {MetadataObjectType::BAR_CODE_DETECTION, 7},
    {MetadataObjectType::BASE_FACE_DETECTION, 8},
    {MetadataObjectType::BASE_TRACKING_REGION, 9},
    {MetadataObjectType::HUMAN_HEAD, 10},
    {MetadataObjectType::TRACKING_MODE, 11},
    {MetadataObjectType::TRACKING_OBJECT_ID, 12},
    {MetadataObjectType::TIMESTAMP, 13},
};

struct DetectedObject {
    int32_t type;
    int32_t objectId;
    int64_t timestamp;
};

class EXPORT_API HStreamMetadata : public StreamMetadataStub, public HStreamCommon, public ICameraIpcChecker {
public:
    HStreamMetadata(sptr<OHOS::IBufferProducer> producer, int32_t format, std::vector<int32_t> metadataTypes);
    ~HStreamMetadata();

    int32_t LinkInput(wptr<OHOS::HDI::Camera::V1_0::IStreamOperator> streamOperator,
        std::shared_ptr<OHOS::Camera::CameraMetadata> cameraAbility) override;
    void SetStreamInfo(StreamInfo_V1_5& streamInfo) override;
    int32_t ReleaseStream(bool isDelay) override;
    int32_t Release() override;
    int32_t Start() override;
    int32_t Stop() override;
    int32_t SetCallback(const sptr<IStreamMetadataCallback>& callback) override;
    int32_t UnSetCallback() override;
    int32_t EnableMetadataType(const std::vector<int32_t>& metadataTypes) override;
    int32_t DisableMetadataType(const std::vector<int32_t>& metadataTypes) override;
    int32_t AddMetadataType(const std::vector<int32_t>& metadataTypes) override;
    int32_t RemoveMetadataType(const std::vector<int32_t>& metadataTypes) override;
    void DumpStreamInfo(CameraInfoDumper& infoDumper) override;
    int32_t OperatePermissionCheck(uint32_t interfaceCode) override;
    int32_t OnMetaResult(int32_t streamId, std::shared_ptr<OHOS::Camera::CameraMetadata> result);
    int32_t CallbackEnter([[maybe_unused]] uint32_t code) override;
    int32_t CallbackExit([[maybe_unused]] uint32_t code, [[maybe_unused]] int32_t result) override;
    std::vector<int32_t> GetMetadataObjectTypes();
    int32_t EnableDetectedObjectLifecycleReport(bool isEnabled, int64_t timestamp);
    void ProcessDetectedObjectLifecycle(const std::vector<uint8_t>& result);
    void SetFirstFrameTimestamp(int64_t timestamp);
    int32_t GetDetectedObjectLifecycleBuffer(std::vector<uint8_t>& buffer);

private:
    int32_t EnableOrDisableMetadataType(const std::vector<int32_t>& metadataTypes, const bool enable);
    void removeMetadataType(const std::vector<int32_t>& vec1, std::vector<int32_t>& vec2);
    void GetFrameTimestamp(common_metadata_header_t *metadata, int64_t &timestamp);
    void GetDetectedObject(common_metadata_header_t *metadata, std::set<int32_t> &detectedObjects,
                           int32_t &trackingObjectId);
    void FillLifecycleBuffer(std::vector<uint8_t>& lifecycleBuffer, int32_t objectId, int64_t startPts, int64_t stopPts,
                             int32_t nextTrackingObjectId);
    void UpdateDetectedObjectLifecycle(int64_t &timestamp, std::set<int32_t> &detectedObjects,
                                       int32_t trackingObjectId);
    std::vector<int32_t> metadataObjectTypes_;
    std::mutex metadataTypeMutex_;
    std::atomic<bool> isStarted_ { false };
    sptr<IStreamMetadataCallback> streamMetadataCallback_;
    std::mutex callbackLock_;
    uint32_t majorVer_ = 0;
    uint32_t minorVer_ = 0;
    int64_t firstFrameTimestamp_ {-1};
    int64_t stopTime_ {-1};
    std::atomic<bool> isDetectedObjectLifecycleReportEnabled_ {false};
    std::mutex objectLifecycleMutex_;
    std::map<int32_t, std::pair<int64_t, int64_t>> objectLifecycleMap_;
    std::map<int32_t, int32_t> objectTrackingMap_;
    std::set<int32_t> prevIds_;
    int64_t prevTs_ {-1};
    int64_t lastFrameDuration_ {-1};
};
} // namespace CameraStandard
} // namespace OHOS
#endif // OHOS_CAMERA_H_STREAM_METADATA_H
