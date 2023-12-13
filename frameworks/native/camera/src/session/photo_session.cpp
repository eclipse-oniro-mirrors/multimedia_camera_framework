/*
 * Copyright (c) 2023-2023 Huawei Device Co., Ltd.
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
 
#include "session/photo_session.h"
#include "input/camera_input.h"
#include "input/camera_manager.h"
#include "output/camera_output_capability.h"
#include "camera_log.h"
#include "camera_error_code.h"
#include "camera_util.h"
 
namespace OHOS {
namespace CameraStandard {
PhotoSession::~PhotoSession()
{
}
 
bool PhotoSession::CanAddInput(sptr<CaptureInput> &input)
{
    // todo: get Profile passed to createOutput and compare with OutputCapability
    // if present in capability return ok.
    MEDIA_INFO_LOG("Enter Into PhotoSession::CanAddInput");
    return true;
}

bool PhotoSession::CanAddOutput(sptr<CaptureOutput> &output)
{
    // todo: get Profile passed to createOutput and compare with OutputCapability
    // if present in capability return ok.
    MEDIA_INFO_LOG("Enter Into PhotoSession::CanAddOutput");
    return true;
}
} // namespace CameraStandard
} // namespace OHOS