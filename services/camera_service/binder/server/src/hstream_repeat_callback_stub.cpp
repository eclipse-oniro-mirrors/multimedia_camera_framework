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

#include "hstream_repeat_callback_stub.h"
#include "camera_log.h"
#include "camera_service_ipc_interface_code.h"
#include "istream_repeat_callback.h"

namespace OHOS {
namespace CameraStandard {
int HStreamRepeatCallbackStub::OnRemoteRequest(
    uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option)
{
    int errCode = -1;

    CHECK_AND_RETURN_RET(data.ReadInterfaceToken() == GetDescriptor(), errCode);
    switch (code) {
        case static_cast<uint32_t>(StreamRepeatCallbackInterfaceCode::CAMERA_STREAM_REPEAT_ON_FRAME_STARTED):
            errCode = OnFrameStarted();
            break;
        case static_cast<uint32_t>(StreamRepeatCallbackInterfaceCode::CAMERA_STREAM_REPEAT_ON_FRAME_ENDED):
            errCode = HStreamRepeatCallbackStub::HandleOnFrameEnded(data);
            break;
        case static_cast<uint32_t>(StreamRepeatCallbackInterfaceCode::CAMERA_STREAM_REPEAT_ON_ERROR):
            errCode = HStreamRepeatCallbackStub::HandleOnFrameError(data);
            break;
        case static_cast<uint32_t>(StreamRepeatCallbackInterfaceCode::CAMERA_STREAM_SKETCH_STATUS_ON_CHANGED):
            errCode = HStreamRepeatCallbackStub::HandleOnSketchStatusChanged(data);
            break;
        default:
            MEDIA_ERR_LOG("HStreamRepeatCallbackStub request code %{public}u not handled", code);
            errCode = IPCObjectStub::OnRemoteRequest(code, data, reply, option);
            break;
    }

    return errCode;
}

int HStreamRepeatCallbackStub::HandleOnFrameEnded(MessageParcel& data)
{
    int32_t frameCount = data.ReadInt32();
    return OnFrameEnded(frameCount);
}

int HStreamRepeatCallbackStub::HandleOnFrameError(MessageParcel& data)
{
    int32_t errorType = static_cast<int32_t>(data.ReadUint64());
    return OnFrameError(errorType);
}

int HStreamRepeatCallbackStub::HandleOnSketchStatusChanged(MessageParcel& data)
{
    int32_t status = data.ReadInt32();
    return OnSketchStatusChanged(static_cast<SketchStatus>(status));
}
} // namespace CameraStandard
} // namespace OHOS
