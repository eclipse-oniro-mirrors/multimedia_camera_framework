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

#ifndef OHOS_CAMERA_DEFERRED_TYPE_H
#define OHOS_CAMERA_DEFERRED_TYPE_H

namespace OHOS {
namespace CameraStandard {
enum DpsErrorCode {
    // session specific error code
    ERROR_SESSION_SYNC_NEEDED = 0,
    ERROR_SESSION_NOT_READY_TEMPORARILY = 1,

    // image process error code
    ERROR_IMAGE_PROC_INVALID_PHOTO_ID = 2,
    ERROR_IMAGE_PROC_FAILED = 3,
    ERROR_IMAGE_PROC_TIMEOUT = 4,
    ERROR_IMAGE_PROC_ABNORMAL = 5,
    ERROR_IMAGE_PROC_INTERRUPTED = 6,

    // video process error code
    ERROR_VIDEO_PROC_INVALID_VIDEO_ID = 7,
    ERROR_VIDEO_PROC_FAILED = 8,
    ERROR_VIDEO_PROC_TIMEOUT = 9,
    ERROR_VIDEO_PROC_INTERRUPTED = 10,
};

enum DpsStatusCode {
    SESSION_STATE_IDLE = 0,
    SESSION_STATE_RUNNALBE,
    SESSION_STATE_RUNNING,
    SESSION_STATE_SUSPENDED,
    SESSION_STATE_PREEMPTED,
};
} // namespace CameraStandard
} // namespace OHOS
#endif // OHOS_CAMERA_DEFERRED_TYPE_H