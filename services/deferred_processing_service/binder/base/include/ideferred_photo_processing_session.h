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

#ifndef OHOS_IDEFERRED_PHOTO_PROCESSING_SESSION_H
#define OHOS_IDEFERRED_PHOTO_PROCESSING_SESSION_H

#include "iremote_broker.h"
#include "foundation/multimedia/camera_framework/interfaces/inner_api/native/camera/include/utils/dps_metadata_info.h"

namespace OHOS {
namespace CameraStandard {
namespace DeferredProcessing {
class IDeferredPhotoProcessingSession : public IRemoteBroker {
public:
    virtual int32_t BeginSynchronize() = 0;

    virtual int32_t EndSynchronize() = 0;

    virtual int32_t AddImage(const std::string imageId, DpsMetadata& metadata, const bool discardable = false) = 0;

    virtual int32_t RemoveImage(const std::string imageId, const bool restorable = false) = 0;

    virtual int32_t RestoreImage(const std::string imageId) = 0;

    virtual int32_t ProcessImage(const std::string appName, const std::string imageId) = 0;

    virtual int32_t CancelProcessImage(const std::string imageId) = 0;

    DECLARE_INTERFACE_DESCRIPTOR(u"IDeferredPhotoProcessingSession");
};
} // namespace DeferredProcessing
} // namespace CameraStandard
} // namespace OHOS

#endif // OHOS_IDEFERRED_PHOTO_PROCESSING_SESSION_H
