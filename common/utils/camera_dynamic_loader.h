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

#ifndef OHOS_CAMERA_DYNAMIC_LOADER_H
#define OHOS_CAMERA_DYNAMIC_LOADER_H

#include <string>

namespace OHOS {
namespace CameraStandard {
using namespace std;

const std::string MEDIA_LIB_SO = "libcamera_dynamic_medialibrary.z.so";
const std::string PICTURE_SO = "libcamera_dynamic_picture.z.so";
const std::string NAPI_EXT_SO = "libcamera_napi_ex.z.so";
const std::string AV_CODEC_SO = "libcamera_dynamic_avcodec.z.so";
const std::string MOVING_PHOTO_SO = "libcamera_dynamic_moving_photo.z.so";
const std::string MEDIA_MANAGER_SO = "libcamera_dynamic_media_manager.z.so";
const std::string CAMERA_NOTIFICATION_SO = "libcamera_dynamic_notification.z.so";
const std::string XCOMPONENT_CONTROLLER_SO = "libcamera_dynamic_xcomponent_controller.z.so";
const std::string IMAGE_EFFECT_SO = "libcamera_dynamic_image_effect.z.so";
const std::string MOVIE_FILE_SO = "libmovie_file.z.so";
const std::string MEDIA_STREAM_SO = "libmedia_stream.z.so";
const std::string WATERMARK_EXIF_METADATA_SO = "libcamera_dynamic_watermark_exif_metadata.z.so";

constexpr uint32_t LIB_DELAYED_UNLOAD_TIME = 30000; // 30 second

class Dynamiclib {
public:
    explicit Dynamiclib(const std::string& libName);
    ~Dynamiclib();
    bool IsLoaded();
    void* GetFunction(const std::string& functionName);

private:
    std::string libName_;
    void* libHandle_ = nullptr;
};

class CameraDynamicLoader {
public:
    static std::shared_ptr<Dynamiclib> GetDynamiclib(const std::string& libName);
    static void LoadDynamiclibAsync(const std::string& libName);
    static void FreeDynamicLibDelayed(const std::string& libName, uint32_t delayMs = LIB_DELAYED_UNLOAD_TIME);

private:
    explicit CameraDynamicLoader() = delete;
    CameraDynamicLoader(const CameraDynamicLoader&) = delete;
    CameraDynamicLoader& operator=(const CameraDynamicLoader&) = delete;

    static void FreeDynamiclibNoLock(const std::string& libName);
    static void CancelFreeDynamicLibDelayed(const std::string& libName);
    static std::shared_ptr<Dynamiclib> GetDynamiclibNoLock(const std::string& libName);
};

} // namespace CameraStandard
} // namespace OHOS
#endif // OHOS_CAMERA_DYNAMIC_LOADER_H