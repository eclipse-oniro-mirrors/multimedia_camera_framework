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

#ifndef OHOS_CAMERA_H_STREAM_COMMON_H
#define OHOS_CAMERA_H_STREAM_COMMON_H

#include <atomic>
#include <cstdint>
#include <iostream>
#include <mutex>
#include <refbase.h>

#include "camera/v1_2/types.h"
#include "camera/v1_3/types.h"
#include "camera_info_dumper.h"
#include "camera_metadata_info.h"
#include "icapture_session.h"
#include "istream_common.h"
#include "v1_0/istream_operator.h"
#include "v1_1/istream_operator.h"
#include "v1_2/istream_operator.h"
#include "v1_3/istream_operator.h"
#include "v1_5/istream_operator.h"
#include "ability/camera_ability_const.h"

namespace OHOS {
namespace HDI::Display::Graphic::Common::V2_1 {
enum CM_ColorSpaceType : int32_t {
    CM_COLORSPACE_NONE,
    CM_BT601_EBU_FULL = 2 | (1 << 8) | (2 << 16) | (1 << 21),
    CM_BT601_SMPTE_C_FULL = 3 | (1 << 8) | (3 << 16) | (1 << 21),
    CM_BT709_FULL = 1 | (1 << 8) | (1 << 16) | (1 << 21),
    CM_BT2020_HLG_FULL = 4 | (5 << 8) | (4 << 16) | (1 << 21),
    CM_BT2020_PQ_FULL = 4 | (4 << 8) | (4 << 16) | (1 << 21),
    CM_BT601_EBU_LIMIT = 2 | (1 << 8) | (2 << 16) | (2 << 21),
    CM_BT601_SMPTE_C_LIMIT = 3 | (1 << 8) | (3 << 16) | (2 << 21),
    CM_BT709_LIMIT = 1 | (1 << 8) | (1 << 16) | (2 << 21),
    CM_BT2020_HLG_LIMIT = 4 | (5 << 8) | (4 << 16) | (2 << 21),
    CM_BT2020_PQ_LIMIT = 4 | (4 << 8) | (4 << 16) | (2 << 21),
    CM_SRGB_FULL = 1 | (2 << 8) | (3 << 16) | (1 << 21),
    CM_P3_FULL = 6 | (2 << 8) | (3 << 16) | (1 << 21),
    CM_P3_HLG_FULL = 6 | (5 << 8) | (3 << 16) | (1 << 21),
    CM_P3_PQ_FULL = 6 | (4 << 8) | (3 << 16) | (1 << 21),
    CM_ADOBERGB_FULL = 23 | (6 << 8) | (0 << 16) | (1 << 21),
    CM_SRGB_LIMIT = 1 | (2 << 8) | (3 << 16) | (2 << 21),
    CM_P3_LIMIT = 6 | (2 << 8) | (3 << 16) | (2 << 21),
    CM_P3_HLG_LIMIT = 6 | (5 << 8) | (3 << 16) | (2 << 21),
    CM_P3_PQ_LIMIT = 6 | (4 << 8) | (3 << 16) | (2 << 21),
    CM_ADOBERGB_LIMIT = 23 | (6 << 8) | (0 << 16) | (2 << 21),
    CM_LINEAR_SRGB = 1 | (3 << 8),
    CM_LINEAR_BT709 = 1 | (3 << 8),
    CM_LINEAR_P3 = 6 | (3 << 8),
    CM_LINEAR_BT2020 = 4 | (3 << 8),
    CM_DISPLAY_SRGB = 1 | (2 << 8) | (3 << 16) | (1 << 21),
    CM_DISPLAY_P3_SRGB = 6 | (2 << 8) | (3 << 16) | (1 << 21),
    CM_DISPLAY_P3_HLG = 6 | (5 << 8) | (3 << 16) | (1 << 21),
    CM_DISPLAY_P3_PQ = 6 | (4 << 8) | (3 << 16) | (1 << 21),
    CM_DISPLAY_BT2020_SRGB = 4 | (2 << 8) | (4 << 16) | (1 << 21),
    CM_DISPLAY_BT2020_HLG = 4 | (5 << 8) | (4 << 16) | (1 << 21),
    CM_DISPLAY_BT2020_PQ = 4 | (4 << 8) | (4 << 16) | (1 << 21),
    CM_BT2020_LOG_FULL = 4 | (9 << 8) | (4 << 16) | (1 << 21),
    CM_BT2020_LOG_LIMIT = 4 | (9 << 8) | (4 << 16) | (2 << 21),
};
} // namespace HDI::Display::Graphic::Common::V2_1
namespace CameraStandard {
using OHOS::HDI::Camera::V1_0::IStreamOperator;
using OHOS::HDI::Camera::V1_5::StreamInfo_V1_5;
constexpr int32_t CAPTURE_ID_UNSET = 0;
constexpr int32_t STREAM_ID_UNSET = 0;
class HStreamCommon : virtual public RefBase {
public:
    explicit HStreamCommon(
        StreamType streamType, sptr<OHOS::IBufferProducer> producer, int32_t format, int32_t width, int32_t height);
    explicit HStreamCommon(
        StreamType streamType, int32_t format, int32_t width, int32_t height);
    virtual ~HStreamCommon();
    virtual int32_t LinkInput(wptr<OHOS::HDI::Camera::V1_0::IStreamOperator> streamOperator,
        std::shared_ptr<OHOS::Camera::CameraMetadata> cameraAbility);
    virtual int32_t UnlinkInput();
    virtual void SetStreamInfo(StreamInfo_V1_5& streamInfo) = 0;
    virtual int32_t ReleaseStream(bool isDelay) = 0;
    virtual void DumpStreamInfo(CameraInfoDumper& infoDumper) = 0;

    virtual void SetColorSpace(ColorSpace colorSpace) final;
    virtual ColorSpace GetColorSpace() final;
    virtual int32_t StopStream() final;

    virtual int32_t GetPreparedCaptureId() final;

    void PrintCaptureDebugLog(const std::shared_ptr<OHOS::Camera::CameraMetadata> &captureMetadataSetting_);
    void SetBasicInfo(std::map<int32_t, std::string> basicParam);

    inline int32_t GetFwkStreamId()
    {
        return fwkStreamId_;
    }

    inline StreamType GetStreamType()
    {
        return streamType_;
    }

    inline void SetHdiStreamId(int32_t hdiStreamId)
    {
        hdiStreamId_ = hdiStreamId;
    }

    inline std::map<int32_t, std::string> GetBasicInfo()
    {
        std::lock_guard<std::mutex> lock(basicInfoLock_);
        return param;
    }

    inline sptr<OHOS::IBufferProducer> GetStreamProducer()
    {
        std::lock_guard<std::mutex> lock(producerLock_);
        return producer_;
    }

    inline int32_t GetHdiStreamId()
    {
        return hdiStreamId_;
    }

    int32_t SetUsePhysicalCameraOrientation(bool isUsed);
    bool GetUsePhysicalCameraOrientation();

    int32_t format_;
    int32_t width_;
    int32_t height_;
    int32_t dataSpace_ = 0;
    std::map<int32_t, std::string> param;
    sptr<OHOS::IBufferProducer> producer_;
    std::string surfaceId_= "";
    sptr<Surface> surface_;
    std::shared_ptr<OHOS::Camera::CameraMetadata> cameraAbility_ = nullptr;
    std::shared_ptr<OHOS::Camera::CameraMetadata> streamSettingsMeta_ =
        std::make_shared<OHOS::Camera::CameraMetadata>(1, 1);
    std::string videoId_;

protected:
    /*
     * Prepare a capture id, return CAMERA_OK or CAMERA_CAPTURE_LIMIT_EXCEED
     */
    virtual int32_t PrepareCaptureId() final;
    virtual void ResetCaptureId() final;

    inline sptr<OHOS::HDI::Camera::V1_0::IStreamOperator> GetStreamOperator()
    {
        std::lock_guard<std::mutex> lock(streamOperatorLock_);
        if (streamOperatorOffline_ != nullptr) {
            return streamOperatorOffline_;
        }
        return streamOperator_.promote();
    }

    inline void SetStreamOperator(wptr<OHOS::HDI::Camera::V1_0::IStreamOperator> streamOperator)
    {
        std::lock_guard<std::mutex> lock(streamOperatorLock_);
        streamOperator_ = streamOperator;
    }

    std::mutex producerLock_;
    std::mutex cameraAbilityLock_;
    uint32_t callerToken_;

    std::mutex streamOperatorLock_;
    wptr<OHOS::HDI::Camera::V1_0::IStreamOperator> streamOperator_ = nullptr;
    sptr<OHOS::HDI::Camera::V1_0::IStreamOperator> streamOperatorOffline_ = nullptr;

    int32_t captureIdForConfirmCapture_ = CAPTURE_ID_UNSET;
    bool usePhysicalCameraOrientation_ = false;
    std::mutex usePhysicalCameraOrientationMutex_;

private:
    StreamType streamType_;
    int32_t fwkStreamId_ = STREAM_ID_UNSET;
    int32_t hdiStreamId_ = STREAM_ID_UNSET;
    int32_t curCaptureID_ = CAPTURE_ID_UNSET;
    std::mutex basicInfoLock_;
};
} // namespace CameraStandard
} // namespace OHOS
#endif // OHOS_CAMERA_H_STREAM_COMMON_H
