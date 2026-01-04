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

#ifndef OHOS_CAMERA_ISTREAM_CAPTURE_PHOTO_CALLBACK_H
#define OHOS_CAMERA_ISTREAM_CAPTURE_PHOTO_CALLBACK_H

#include "iremote_broker.h"
#include "surface_buffer.h"
#ifdef CAMERA_CAPTURE_YUV
#include "picture_interface.h"
#endif

namespace OHOS {
namespace CameraStandard {
enum StreamCapturePhotoCallbackInterfaceCode {
    CAMERA_STREAM_CAPTURE_ON_PHOTO_AVAILABLE,
#ifdef CAMERA_CAPTURE_YUV
    CAMERA_STREAM_CAPTURE_ON_PICTURE_AVAILABLE,
#endif
};

class IStreamCapturePhotoCallback : public IRemoteBroker {
public:
    virtual int32_t OnPhotoAvailable(sptr<SurfaceBuffer> surfaceBuffer, int64_t timestamp, bool isRaw) = 0;
#ifdef CAMERA_CAPTURE_YUV
    virtual int32_t OnPhotoAvailable(std::shared_ptr<PictureIntf> picture) = 0;
#endif
    DECLARE_INTERFACE_DESCRIPTOR(u"IStreamCapturePhotoCallback");
};
} // namespace CameraStandard
} // namespace OHOS
#endif // OHOS_CAMERA_ISTREAM_CAPTURE_PHOTO_CALLBACK_H

