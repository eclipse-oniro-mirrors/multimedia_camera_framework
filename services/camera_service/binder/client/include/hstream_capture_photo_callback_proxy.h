/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#ifndef OHOS_CAMERA_HSTREAM_CAPTURE_THUMBNAIL_CALLBACK_PROXY_H
#define OHOS_CAMERA_HSTREAM_CAPTURE_THUMBNAIL_CALLBACK_PROXY_H
#define EXPORT_API __attribute__((visibility("default")))

#include "iremote_proxy.h"
#include "istream_capture_thumbnail_callback.h"

namespace OHOS {
namespace CameraStandard {
class EXPORT_API HStreamCaptureThumbnailCallbackProxy : public IRemoteProxy<IStreamCaptureThumbnailCallback> {
public:
    explicit HStreamCaptureThumbnailCallbackProxy(const sptr<IRemoteObject> &impl);

    virtual ~HStreamCaptureThumbnailCallbackProxy() = default;

    int32_t OnThumbnailAvailable(sptr<SurfaceBuffer> surfaceBuffer, int64_t timestamp) override;

private:
    static inline BrokerDelegator<HStreamCaptureThumbnailCallbackProxy> delegator_;
};
} // namespace CameraStandard
} // namespace OHOS
#endif // OHOS_CAMERA_HSTREAM_CAPTURE_THUMBNAIL_CALLBACK_PROXY_H
