/*
 * Copyright (c) 2021-2022 Huawei Device Co., Ltd.
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

#ifndef OHOS_CAMERA_NIGHT_SESSION_H
#define OHOS_CAMERA_NIGHT_SESSION_H

#include <iostream>
#include <set>
#include <vector>
#include "camera_error_code.h"
#include "input/capture_input.h"
#include "output/capture_output.h"
#include "icamera_util.h"
#include "icapture_session.h"
#include "icapture_session_callback.h"
#include "capture_session.h"

namespace OHOS {
namespace CameraStandard {
class CaptureOutput;
class NightSession : public CaptureSession {
public:
    class NightSessionMetadataResultProcessor : public MetadataResultProcessor {
    public:
        explicit NightSessionMetadataResultProcessor(wptr<NightSession> session) : session_(session) {}
        void ProcessCallbacks(
            const uint64_t timestamp, const std::shared_ptr<OHOS::Camera::CameraMetadata>& result) override;

    private:
        wptr<NightSession> session_;
    };

    explicit NightSession(sptr<ICaptureSession>& nightSession) : CaptureSession(nightSession)
    {
        metadataResultProcessor_ = std::make_shared<NightSessionMetadataResultProcessor>(this);
    }
    ~NightSession();

    /**
    * @brief Get exposure compensation range.
    * @param vector of exposure bias range.
    * @return errCode.
    */
    int32_t GetExposureRange(std::vector<uint32_t> &exposureRange);

    /**
    * @brief Set exposure compensation value.
    * @param exposure compensation value to be set.
    * @return errCode.
    */
    int32_t SetExposure(uint32_t exposureValue);

    /**
    * @brief Get exposure compensation value.
    * @param exposure current exposure compensation value .
    * @return Returns errCode.
    */
    int32_t GetExposure(uint32_t &exposureValue);

    /**
     * @brief Determine if the given Ouput can be added to session.
     *
     * @param CaptureOutput to be added to session.
     */
    bool CanAddOutput(sptr<CaptureOutput>& output) override;
};
} // namespace CameraStandard
} // namespace OHOS
#endif // OHOS_CAMERA_NIGHT_SESSION_H
