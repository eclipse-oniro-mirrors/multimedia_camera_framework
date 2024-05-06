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
#include "camera_metadata_info.h"
#include "icapture_session.h"
#include "istream_common.h"
#include "v1_0/istream_operator.h"
#include "v1_1/istream_operator.h"
#include "v1_2/istream_operator.h"

namespace OHOS {
namespace CameraStandard {
using OHOS::HDI::Camera::V1_0::IStreamOperator;
using OHOS::HDI::Camera::V1_1::StreamInfo_V1_1;
constexpr int32_t CAPTURE_ID_UNSET = 0;
constexpr int32_t STREAM_ID_UNSET = 0;

class HStreamCommon : virtual public RefBase {
public:
    explicit HStreamCommon(
        StreamType streamType, sptr<OHOS::IBufferProducer> producer, int32_t format, int32_t width, int32_t height);
    virtual ~HStreamCommon();
    virtual int32_t LinkInput(sptr<OHOS::HDI::Camera::V1_0::IStreamOperator> streamOperator,
        std::shared_ptr<OHOS::Camera::CameraMetadata> cameraAbility);
    virtual int32_t UnlinkInput();
    virtual void SetStreamInfo(StreamInfo_V1_1& streamInfo) = 0;
    virtual int32_t ReleaseStream(bool isDelay) = 0;
    virtual void DumpStreamInfo(std::string& dumpString) = 0;

    virtual void SetColorSpace(ColorSpace colorSpace) final;
    virtual int32_t StopStream() final;

    virtual int32_t GetPreparedCaptureId() final;

    void PrintCaptureDebugLog(const std::shared_ptr<OHOS::Camera::CameraMetadata> &captureMetadataSetting_);

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

    inline int32_t GetHdiStreamId()
    {
        return hdiStreamId_;
    }

    int32_t format_;
    int32_t width_;
    int32_t height_;
    int32_t dataSpace_ = 0;
    sptr<OHOS::IBufferProducer> producer_;

    std::shared_ptr<OHOS::Camera::CameraMetadata> cameraAbility_ = nullptr;

protected:
    /*
     * Prepare a capture id, return CAMERA_OK or CAMERA_CAPTURE_LIMIT_EXCEED
     */
    virtual int32_t PrepareCaptureId() final;
    virtual void ResetCaptureId() final;

    inline sptr<OHOS::HDI::Camera::V1_0::IStreamOperator> GetStreamOperator()
    {
        std::lock_guard<std::mutex> lock(streamOperatorLock_);
        return streamOperator_;
    }

    inline void SetStreamOperator(sptr<OHOS::HDI::Camera::V1_0::IStreamOperator> streamOperator)
    {
        std::lock_guard<std::mutex> lock(streamOperatorLock_);
        streamOperator_ = streamOperator;
    }

    std::mutex producerLock_;
    std::mutex cameraAbilityLock_;
    uint32_t callerToken_;

    std::mutex streamOperatorLock_;
    sptr<OHOS::HDI::Camera::V1_0::IStreamOperator> streamOperator_ = nullptr;

private:
    StreamType streamType_;
    int32_t fwkStreamId_ = STREAM_ID_UNSET;
    int32_t hdiStreamId_ = STREAM_ID_UNSET;
    int32_t curCaptureID_ = CAPTURE_ID_UNSET;
};
} // namespace CameraStandard
} // namespace OHOS
#endif // OHOS_CAMERA_H_STREAM_COMMON_H
