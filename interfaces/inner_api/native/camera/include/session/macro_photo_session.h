/*
 * Copyright (c) 2024-2024 Huawei Device Co., Ltd.
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

#ifndef OHOS_CAMERA_MACRO_PHOTO_SESSION_H
#define OHOS_CAMERA_MACRO_PHOTO_SESSION_H

#include "capture_session.h"

namespace OHOS {
namespace CameraStandard {
class MacroPhotoSession : public CaptureSession {
public:
    explicit MacroPhotoSession(sptr<ICaptureSession>& captureSession);
    ~MacroPhotoSession() = default;

    /**
     * @brief Determine if the given Ouput can be added to session.
     *
     * @param CaptureOutput to be added to session.
     */
    bool CanAddOutput(sptr<CaptureOutput>& output) override;

    /**
     * @brief Commit the capture session config.
     */
    virtual int32_t CommitConfig() override;
};
} // namespace CameraStandard
} // namespace OHOS
#endif // OHOS_CAMERA_MACRO_PHOTO_SESSION_H