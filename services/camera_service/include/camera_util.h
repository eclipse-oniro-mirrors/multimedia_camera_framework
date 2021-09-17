/*
 * Copyright (C) 2021 Huawei Device Co., Ltd.
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

#ifndef OHOS_CAMERA_UTIL_H
#define OHOS_CAMERA_UTIL_H

#include <limits.h>
#include "types.h"

namespace OHOS {
namespace CameraStandard {
static const std::int32_t CAMERA_PREVIEW_COLOR_SPACE = 8;
static const std::int32_t CAMERA_PREVIEW_STREAM_ID = 1001;

static const std::int32_t CAMERA_PHOTO_COLOR_SPACE = 8;
static const std::int32_t CAMERA_PHOTO_STREAM_ID = 1002;

static const std::int32_t CAMERA_VIDEO_COLOR_SPACE = 8;
static const std::int32_t CAMERA_VIDEO_STREAM_ID = 1003;

static const std::int32_t CAPTURE_TYPE_COUNT = 3;

static const std::int32_t PREVIEW_CAPTURE_ID_START = 1;
static const std::int32_t PREVIEW_CAPTURE_ID_END = (INT_MAX / CAPTURE_TYPE_COUNT);

static const std::int32_t PHOTO_CAPTURE_ID_START = PREVIEW_CAPTURE_ID_END + 1;
static const std::int32_t PHOTO_CAPTURE_ID_END = (2 * (INT_MAX / CAPTURE_TYPE_COUNT));

static const std::int32_t VIDEO_CAPTURE_ID_START = PHOTO_CAPTURE_ID_END + 1;
static const std::int32_t VIDEO_CAPTURE_ID_END = INT_MAX;

enum CaptureType {
    CAPTURE_TYPE_PREVIEW = 0,
    CAPTURE_TYPE_PHOTO,
    CAPTURE_TYPE_VIDEO
};

static const std::int32_t CAMERA_PHOTO_HEIGHT = 720;
static const std::int32_t CAMERA_PHOTO_WIDTH = 1280;

static const std::int32_t CAMERA_VIDEO_HEIGHT = 720;
static const std::int32_t CAMERA_VIDEO_WIDTH = 1280;

enum CamServiceError {
    CAMERA_OK = 0,
    CAMERA_ALLOC_ERROR,
    CAMERA_INVALID_ARG,
    CAMERA_DEVICE_BUSY,
    CAMERA_DEVICE_CLOSED,
    CAMERA_DEVICE_REQUEST_TIMEOUT,
    CAMERA_STREAM_BUFFER_LOST,
    CAMERA_INVALID_OUTPUT_CFG,
    CAMERA_CAPTURE_LIMIT_EXCEED,
    CAMERA_INVALID_STATE,
    CAMERA_UNKNOWN_ERROR
};

int HdiToServiceError(Camera::CamRetCode ret);

CaptureType GetCaptureType(int32_t captureId);

bool IsValidSize(int32_t width, int32_t height, std::vector<std::pair<int32_t, int32_t>> validSizes);
} // namespace CameraStandard
} // namespace OHOS
#endif // OHOS_CAMERA_UTIL_H
