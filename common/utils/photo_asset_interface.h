/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#ifndef OHOS_CAMERA_FRAMEWORK_MEDIA_LIBRARY_INTERFACE_H
#define OHOS_CAMERA_FRAMEWORK_MEDIA_LIBRARY_INTERFACE_H
#include <cstdint>
#include <string>
#include "refbase.h"
namespace OHOS::Media {
    class PhotoProxy;
}
namespace OHOS::CameraStandard {
enum VideoType {
    ORIGIN_VIDEO = 0,
    XT_ORIGIN_VIDEO = 1,
    XT_EFFECT_VIDEO = 2
};
class PhotoAssetIntf {
public:
    virtual void AddPhotoProxy(sptr<Media::PhotoProxy> photoProxy);
    virtual std::string GetPhotoAssetUri();
    virtual int32_t GetVideoFd(VideoType videoType);
    virtual void NotifyVideoSaveFinished(VideoType videoType);
    virtual int32_t GetUserId();
    virtual int32_t OpenAsset();
    virtual void UpdatePhotoProxy(const sptr<Media::PhotoProxy> &photoProxy);
    virtual ~PhotoAssetIntf() = default;
#ifdef CAMERA_CAPTURE_YUV
    virtual void RegisterPhotoStateCallback(const std::function<void(int32_t)> &callback);
    virtual void UnregisterPhotoStateCallback();
#endif
};
} // namespace OHOS::CameraStandard
#endif