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

#include "camera_log.h"
#include "cubic_bezier.h"

namespace OHOS {
namespace CameraStandard {
namespace {
constexpr float CUBIC_BEZIER_MULTIPLE = 3.0;
constexpr float MAX_RESOLUTION = 4000.0;
constexpr float SERCH_STEP = 1.0 / MAX_RESOLUTION;

constexpr float CONTROL_POINT_X1 = 0.4;
constexpr float CONTROL_POINT_X2 = 0.2;
constexpr float CONTROL_POINT_Y1 = 0.0;
constexpr float CONTROL_POINT_Y2 = 1.0;

constexpr float DURATION_SLOP = 55.0;
constexpr float DURATION_BASE = 450.0;
constexpr float DURATION_POWER = 1.2;
constexpr int MAX_ZOOM_ARRAY_SIZE = 100;
}

float CubicBezier::mControPointX1 = CONTROL_POINT_X1;
float CubicBezier::mControPointX2 = CONTROL_POINT_X2;
float CubicBezier::mControPointY1 = CONTROL_POINT_Y1;
float CubicBezier::mControPointY2 = CONTROL_POINT_Y2;
float CubicBezier::mDurationBase = DURATION_BASE;

std::vector<float> CubicBezier::GetZoomArray(const float& currentZoom, const float& targetZoom,
    const float& frameInterval)
{
    float duration = GetDuration(currentZoom, targetZoom);
    MEDIA_INFO_LOG("CubicBezier::GetZoomArray duration is:%{public}f", duration);
    std::vector<float> result;
    CHECK_ERROR_RETURN_RET(duration == 0 || frameInterval == 0, result);
    int arraySize = static_cast<int>(duration / frameInterval);
    CHECK_ERROR_RETURN_RET_LOG(arraySize > MAX_ZOOM_ARRAY_SIZE, result,
        "Error size, duration is:%{public}f, interval is:%{public}f", duration, frameInterval);
    for (int i = 1; i <= arraySize; i++) {
        float time = frameInterval * i / duration;
        float zoom = (currentZoom + (targetZoom - currentZoom) * GetInterpolation(time));
        result.push_back(zoom);
        MEDIA_DEBUG_LOG("CubicBezier::GetZoomArray zoom is:%{public}f", zoom);
    }
    result.push_back(targetZoom);
    return result;
}

float CubicBezier::GetDuration(const float& currentZoom, const float& targetZoom)
{
    if (currentZoom == 0) {
        return 0;
    } else {
        return (DURATION_SLOP * DURATION_POWER * abs(log(targetZoom / currentZoom)) + mDurationBase);
    }
}

bool CubicBezier::SetBezierValue(const std::vector<float>& zoomBezierValue)
{
    const size_t DURATION_BASE_INDEX = 0;
    const size_t CONTROL_POINT_X1_INDEX = 1;
    const size_t CONTROL_POINT_Y1_INDEX = 2;
    const size_t CONTROL_POINT_X2_INDEX = 3;
    const size_t CONTROL_POINT_Y2_INDEX = 4;

    if (zoomBezierValue.size() < 5) {
        return false;
    }

    mDurationBase = zoomBezierValue[DURATION_BASE_INDEX];
    mControPointX1 = zoomBezierValue[CONTROL_POINT_X1_INDEX];
    mControPointY1 = zoomBezierValue[CONTROL_POINT_Y1_INDEX];
    mControPointX2 = zoomBezierValue[CONTROL_POINT_X2_INDEX];
    mControPointY2 = zoomBezierValue[CONTROL_POINT_Y2_INDEX];
    return true;
}

float CubicBezier::GetCubicBezierY(const float& time)
{
    return CUBIC_BEZIER_MULTIPLE * (1- time) * (1 - time) * time * mControPointY1 +
        CUBIC_BEZIER_MULTIPLE * (1- time) * time * time * mControPointY2 + time * time * time;
}

float CubicBezier::GetCubicBezierX(const float& time)
{
    return CUBIC_BEZIER_MULTIPLE * (1- time) * (1 - time) * time * mControPointX1 +
        CUBIC_BEZIER_MULTIPLE * (1- time) * time * time * mControPointX2 + time * time * time;
}

float CubicBezier::BinarySearch(const float& value)
{
    int low = 0;
    int high = MAX_RESOLUTION;
    int num = 0;
    while (low <= high) {
        num = num + 1;
        int middle = (low + high) / 2;
        float approximation = GetCubicBezierX(SERCH_STEP * middle);
        if (approximation < value) {
            low = middle + 1;
        } else if (approximation > value) {
            high = middle -1;
        } else {
            return middle;
        }
    }
    return low;
}

float CubicBezier::GetInterpolation(const float& input)
{
    return GetCubicBezierY(SERCH_STEP * BinarySearch(input));
}
} // namespace CameraStandard
} // namespace OHOS