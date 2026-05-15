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
#include "ipc_file_descriptor.h"
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

enum ImageType : int32_t {
    ORIGINAL_IMAGE,
    EFFECTIVE_IMAGE,
};

class ImageFd : public virtual Parcelable {
public:
    ImageFd(sptr<IPCFileDescriptor> fd, ImageType imageType, int32_t bytes)
        : fd(fd), imageType(imageType), bytes(bytes) {};
    sptr<IPCFileDescriptor> fd;
    ImageType imageType;
    int32_t bytes;
    uint8_t* addr = nullptr;
    bool Marshalling(Parcel& parcel) const override
    {
        bool isSucc = true;
        isSucc &= parcel.WriteParcelable(fd);
        isSucc &= parcel.WriteInt32(static_cast<int32_t>(imageType));
        isSucc &= parcel.WriteInt32(bytes);
        return isSucc;
    }

    static ImageFd* Unmarshalling(Parcel& parcel)
    {
        sptr<IPCFileDescriptor> fd = sptr<IPCFileDescriptor>(parcel.ReadParcelable<IPCFileDescriptor>());
        ImageType imageType = static_cast<ImageType>(parcel.ReadInt32());
        int32_t bytes = parcel.ReadInt32();
        ImageFd* imageFd = new (std::nothrow) ImageFd(fd, imageType, bytes);
        return imageFd;
    }
};
} // namespace CameraStandard
} // namespace OHOS
#endif // OHOS_CAMERA_DEFERRED_TYPE_H