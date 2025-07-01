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

#include "input/camera_manager_for_sys.h"

#include "camera_log.h"
#include "camera_util.h"
#include "input/camera_manager.h"
#include "session/aperture_video_session.h"
#include "session/light_painting_session.h"
#include "session/quick_shot_photo_session.h"
#include "session/capture_session.h"
#include "session/fluorescence_photo_session.h"
#include "session/high_res_photo_session.h"
#include "session/macro_photo_session.h"
#include "session/macro_video_session.h"
#include "session/night_session.h"
#include "session/panorama_session.h"
#include "session/photo_session_for_sys.h"
#include "session/portrait_session.h"
#include "session/profession_session.h"
#include "session/secure_camera_session_for_sys.h"
#include "session/slow_motion_session.h"
#include "session/time_lapse_photo_session.h"
#include "session/video_session_for_sys.h"

using namespace std;
namespace OHOS {
namespace CameraStandard {
sptr<CameraManagerForSys> CameraManagerForSys::g_cameraManagerForSys = nullptr;
std::mutex CameraManagerForSys::g_sysInstanceMutex;

CameraManagerForSys::CameraManagerForSys()
{
    MEDIA_INFO_LOG("CameraManagerForSys::CameraManagerForSys construct enter");
}

CameraManagerForSys::~CameraManagerForSys()
{
    MEDIA_INFO_LOG("CameraManagerForSys::~CameraManagerForSys() called");
}

sptr<CameraManagerForSys>& CameraManagerForSys::GetInstance()
{
    std::lock_guard<std::mutex> lock(g_sysInstanceMutex);
    if (CameraManagerForSys::g_cameraManagerForSys == nullptr) {
        MEDIA_INFO_LOG("Initializing camera manager for first time!");
        CameraManagerForSys::g_cameraManagerForSys = new CameraManagerForSys();
    }
    return CameraManagerForSys::g_cameraManagerForSys;
}

sptr<CaptureSessionForSys> CameraManagerForSys::CreateCaptureSessionForSysImpl(SceneMode mode,
    sptr<ICaptureSession> session)
{
    switch (mode) {
        case SceneMode::VIDEO:
            return new (std::nothrow) VideoSessionForSys(session);
        case SceneMode::CAPTURE:
            return new (std::nothrow) PhotoSessionForSys(session);
        case SceneMode::PORTRAIT:
            return new (std::nothrow) PortraitSession(session);
        case SceneMode::PROFESSIONAL_VIDEO:
        case SceneMode::PROFESSIONAL_PHOTO:
            return new (std::nothrow) ProfessionSession(session, CameraManager::GetInstance()->GetCameraDeviceList());
        case SceneMode::NIGHT:
            return new (std::nothrow) NightSession(session);
        case SceneMode::CAPTURE_MACRO:
            return new (std::nothrow) MacroPhotoSession(session);
        case SceneMode::VIDEO_MACRO:
            return new (std::nothrow) MacroVideoSession(session);
        case SceneMode::SLOW_MOTION:
            return new (std::nothrow) SlowMotionSession(session);
        case SceneMode::HIGH_RES_PHOTO:
            return new (std::nothrow) HighResPhotoSession(session);
        case SceneMode::SECURE:
            return new (std::nothrow) SecureCameraSessionForSys(session);
        case SceneMode::QUICK_SHOT_PHOTO:
            return new (std::nothrow) QuickShotPhotoSession(session);
        case SceneMode::APERTURE_VIDEO:
            return new (std::nothrow) ApertureVideoSession(session);
        case SceneMode::PANORAMA_PHOTO:
            return new (std::nothrow) PanoramaSession(session);
        case SceneMode::LIGHT_PAINTING:
            return new (std::nothrow) LightPaintingSession(session);
        case SceneMode::TIMELAPSE_PHOTO:
            return new(std::nothrow) TimeLapsePhotoSession(session,
                CameraManager::GetInstance()->GetCameraDeviceList());
        case SceneMode::FLUORESCENCE_PHOTO:
            return new(std::nothrow) FluorescencePhotoSession(session);
        default:
            return new (std::nothrow) CaptureSessionForSys(session);
    }
}

sptr<CaptureSessionForSys> CameraManagerForSys::CreateCaptureSessionForSys(SceneMode mode)
{
    sptr<CaptureSessionForSys> session = nullptr;
    CreateCaptureSessionForSys(session, mode);
    return session;
}

int32_t CameraManagerForSys::CreateCaptureSessionForSys(sptr<CaptureSessionForSys>& pCaptureSession, SceneMode mode)
{
    MEDIA_DEBUG_LOG("CameraManagerForSys::CreateCaptureSessionForSys is called");
    CAMERA_SYNC_TRACE;
    sptr<ICaptureSession> session = nullptr;
    sptr<CaptureSessionForSys> captureSessionForSys = nullptr;
    int32_t retCode = CameraErrorCode::SUCCESS;
    retCode = CameraManager::GetInstance()->CreateCaptureSessionFromService(session, mode);
    CHECK_ERROR_RETURN_RET_LOG(retCode != CameraErrorCode::SUCCESS, retCode,
        "CreateCaptureSessionForSys failed to CreateCaptureSessionFromService with retCode is %{public}d", retCode);
    captureSessionForSys = CreateCaptureSessionForSysImpl(mode, session);
    CHECK_ERROR_RETURN_RET_LOG(captureSessionForSys == nullptr, CameraErrorCode::SERVICE_FATL_ERROR,
        "CreateCaptureSessionForSys failed to new captureSessionForSys!");
    captureSessionForSys->SetMode(mode);
    pCaptureSession = captureSessionForSys;
    return CameraErrorCode::SUCCESS;
}

int CameraManagerForSys::CreateDepthDataOutput(DepthProfile& depthProfile, sptr<IBufferProducer> &surface,
    sptr<DepthDataOutput>* pDepthDataOutput)
{
    CAMERA_SYNC_TRACE;
    sptr<IStreamDepthData> streamDepthData = nullptr;
    sptr<DepthDataOutput> depthDataOutput = nullptr;
    int32_t retCode = CameraErrorCode::SUCCESS;
    retCode = CameraManager::GetInstance()->GetStreamDepthDataFromService(depthProfile, surface, streamDepthData);
    if (retCode == CameraErrorCode::SUCCESS) {
        depthDataOutput = new(std::nothrow) DepthDataOutput(surface);
        CHECK_ERROR_RETURN_RET(depthDataOutput == nullptr, CameraErrorCode::SERVICE_FATL_ERROR);
        depthDataOutput->SetStream(streamDepthData);
    } else {
        MEDIA_ERR_LOG("GetStreamDepthDataFromService failed! retCode = %{public}d", retCode);
        return retCode;
    }
    depthDataOutput->SetDepthProfile(depthProfile);
    *pDepthDataOutput = depthDataOutput;
    return CameraErrorCode::SUCCESS;
}

} // namespace CameraStandard
} // namespace OHOS
