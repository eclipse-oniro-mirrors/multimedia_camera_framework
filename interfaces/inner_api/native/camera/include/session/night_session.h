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
class LongExposureCallback {
public:
    LongExposureCallback() = default;
    virtual ~LongExposureCallback() = default;
    virtual void OnLongExposure(const uint32_t longExposureTime) = 0;
};
class CaptureOutput;
class NightSession : public CaptureSession {
public:
    explicit NightSession(sptr<ICaptureSession> &nightSession): CaptureSession(nightSession)
    {
        isExposuring_ = true;
    }
    NightSession() {};
    ~NightSession();

    /**
     * @brief start long exposure
     *
     */
    void DoTryAE(bool isTryAe, uint32_t millisecond = 0);

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
    * @brief Set the exposure callback.
    * which will be called when there is exposure state change.
    *
    * @param The LongExposureCallback pointer.
    */
    void SetLongExposureCallback(std::shared_ptr<LongExposureCallback> longExposureCallback);
    void ProcessCallbacks(const uint64_t timestamp,
        const std::shared_ptr<OHOS::Camera::CameraMetadata> &result) override;
    void SetLongExposureingState(bool isExposuring);
    bool IsLongExposureingState();
private:
    void ProcessLongExposureOnce(const std::shared_ptr<OHOS::Camera::CameraMetadata> &result);
    bool isExposuring_;
    std::shared_ptr<LongExposureCallback> longExposureCallback_;
};
} // namespace CameraStandard
} // namespace OHOS
#endif // OHOS_CAMERA_NIGHT_SESSION_H
