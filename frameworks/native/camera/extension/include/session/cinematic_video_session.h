/*
 * Copyright (c) 2025-2025 Huawei Device Co., Ltd.
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
#ifndef CINEMATIC_VIDEO_SESSION_H
#define CINEMATIC_VIDEO_SESSION_H

#include "capture_session_for_sys.h"

namespace OHOS {
namespace CameraStandard {

class CinematicVideoSession : public CaptureSessionForSys {
public:
    class CinematicVideoSessionMetadataResultProcessor : public MetadataResultProcessor {
    public:
        explicit CinematicVideoSessionMetadataResultProcessor(wptr<CinematicVideoSession> session) :
            cinematicVideoSession_(session) {}
        void ProcessCallbacks(const uint64_t timestamp,
            const std::shared_ptr<OHOS::Camera::CameraMetadata>& result) override;

    private:
        wptr<CinematicVideoSession> cinematicVideoSession_;
    };
    explicit CinematicVideoSession(sptr<ICaptureSession>& session);
    ~CinematicVideoSession();

    int32_t AddOutput(sptr<CaptureOutput>& output) override;
    int32_t RemoveOutput(sptr<CaptureOutput>& output);
private:
    sptr<ICameraRecorder> recorder_ {nullptr};
};

} // namespace CameraStandard
} // namespace OHOS
#endif // OHOS_CAMERA_CINEMATIC_VIDEO_SESSION_H