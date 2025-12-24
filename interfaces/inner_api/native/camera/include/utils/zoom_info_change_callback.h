/*
 * Copyright (c) 2021-2025 Huawei Device Co., Ltd.
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
#ifndef ZOOM_INFO_CHANGE_CALLBACK
#define ZOOM_INFO_CHANGE_CALLBACK

namespace OHOS {
namespace CameraStandard {
class ZoomInfoCallback {
public:
    ZoomInfoCallback() = default;
    virtual ~ZoomInfoCallback() = default;
    virtual void OnZoomInfoChange(const std::vector<float> zoomRatioRange) = 0;
    void SetZoomRatioRange(std::vector<float> zoomRatioRange)
    {
        std::lock_guard<std::mutex> lock(mutex_);
        zoomRatioRange_ = zoomRatioRange;
    }
    std::vector<float> GetZoomRatioRange()
    {
        std::lock_guard<std::mutex> lock(mutex_);
        return zoomRatioRange_;
    }
private:
    std::vector<float> zoomRatioRange_;
    std::mutex mutex_;
};
} // namespace CameraStandard
} // namespace OHOS
#endif // ZOOM_INFO_CHANGE_CALLBACK