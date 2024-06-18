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

#ifndef CAMERA_NAPI_OBJECT_TYPES_H
#define CAMERA_NAPI_OBJECT_TYPES_H

#include <any>
#include <cstdint>
#include <memory>

#include "camera_napi_object.h"
#include "camera_output_capability.h"
#include "js_native_api_types.h"

namespace OHOS {
namespace CameraStandard {

class CameraNapiObjectTypes {
public:
    virtual ~CameraNapiObjectTypes() {};
    virtual CameraNapiObject& GetCameraNapiObject() = 0;
    virtual napi_value GenerateNapiValue(napi_env env) final;

protected:
    template<typename T, typename... Args>
    T* Hold(Args&&... args)
    {
        std::shared_ptr<T> ptr = std::make_shared<T>(std::forward<Args>(args)...);
        ptrHolder_.emplace_back(ptr);
        return ptr.get();
    }

private:
    std::list<std::shared_ptr<void>> ptrHolder_;
};

class CameraNapiObjSize : public CameraNapiObjectTypes {
public:
    explicit CameraNapiObjSize(Size& size) : size_(size) {}
    CameraNapiObject& GetCameraNapiObject() override;

private:
    Size& size_;
};

class CameraNapiObjFrameRateRange : public CameraNapiObjectTypes {
public:
    explicit CameraNapiObjFrameRateRange(std::vector<int32_t>& frameRateRange) : frameRateRange_(frameRateRange) {}
    CameraNapiObject& GetCameraNapiObject() override;

private:
    std::vector<int32_t>& frameRateRange_;
};

class CameraNapiObjProfile : public CameraNapiObjectTypes {
public:
    explicit CameraNapiObjProfile(Profile& profile) : profile_(profile) {}
    CameraNapiObject& GetCameraNapiObject() override;

private:
    Profile& profile_;
};

class CameraNapiObjVideoProfile : public CameraNapiObjectTypes {
public:
    explicit CameraNapiObjVideoProfile(VideoProfile& videoProfile) : videoProfile_(videoProfile) {}
    CameraNapiObject& GetCameraNapiObject() override;

private:
    VideoProfile& videoProfile_;
};

class CameraDevice;
class CameraNapiObjCameraDevice : public CameraNapiObjectTypes {
public:
    explicit CameraNapiObjCameraDevice(CameraDevice& cameraDevice) : cameraDevice_(cameraDevice) {}
    CameraNapiObject& GetCameraNapiObject() override;

private:
    CameraDevice& cameraDevice_;
};

struct Rect;
class CameraNapiBoundingBox : public CameraNapiObjectTypes {
public:
    explicit CameraNapiBoundingBox(Rect& rect) : rect_(rect) {}
    CameraNapiObject& GetCameraNapiObject() override;

private:
    Rect& rect_;
};

class MetadataObject;
class CameraNapiObjMetadataObject : public CameraNapiObjectTypes {
public:
    explicit CameraNapiObjMetadataObject(MetadataObject& metadataObject) : metadataObject_(metadataObject) {}
    CameraNapiObject& GetCameraNapiObject() override;

private:
    MetadataObject& metadataObject_;
};

class CameraOutputCapability;
class CameraNapiObjCameraOutputCapability : public CameraNapiObjectTypes {
public:
    explicit CameraNapiObjCameraOutputCapability(CameraOutputCapability& cameraOutputCapability)
        : cameraOutputCapability_(cameraOutputCapability)
    {}
    CameraNapiObject& GetCameraNapiObject() override;

private:
    CameraOutputCapability& cameraOutputCapability_;
};
} // namespace CameraStandard
} // namespace OHOS
#endif /* CAMERA_NAPI_OBJECT_TYPES_H */
