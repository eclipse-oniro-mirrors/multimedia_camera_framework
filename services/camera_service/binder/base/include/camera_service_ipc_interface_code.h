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

#ifndef OHOS_CAMERA_SERVICE_IPC_INTERFACE_CODE_H
#define OHOS_CAMERA_SERVICE_IPC_INTERFACE_CODE_H

/* SAID: 3008 */
namespace OHOS {
namespace CameraStandard {
/**
 * @brief Camera device remote request code for IPC.
 *
 * @since 1.0
 * @version 1.0
 */
enum class CameraDeviceInterfaceCode {
    CAMERA_DEVICE_OPEN = 0,
    CAMERA_DEVICE_CLOSE,
    CAMERA_DEVICE_RELEASE,
    CAMERA_DEVICE_SET_CALLBACK,
    CAMERA_DEVICE_UPDATE_SETTNGS,
    CAMERA_DEVICE_GET_ENABLED_RESULT,
    CAMERA_DEVICE_ENABLED_RESULT,
    CAMERA_DEVICE_DISABLED_RESULT,
    CAMERA_DEVICE_GET_STATUS
};

/**
 * @brief Camera service callback remote request code for IPC.
 *
 * @since 1.0
 * @version 1.0
 */
enum CameraServiceCallbackInterfaceCode {
    CAMERA_CALLBACK_STATUS_CHANGED = 0,
    CAMERA_CALLBACK_FLASHLIGHT_STATUS_CHANGED
};

/**
 * @brief Camera mute service callback remote request code for IPC.
 *
 * @since 1.0
 * @version 1.0
 */
enum CameraMuteServiceCallbackInterfaceCode {
    CAMERA_CALLBACK_MUTE_MODE = 0
};

/**
 * @brief Torch service callback remote request code for IPC.
 *
 * @since 1.0
 * @version 1.0
 */
enum TorchServiceCallbackInterfaceCode {
    TORCH_CALLBACK_TORCH_STATUS_CHANGE = 0
};

/**
 * @brief Camera service remote request code for IPC.
 *
 * @since 1.0
 * @version 1.0
 */
enum CameraServiceInterfaceCode {
    CAMERA_SERVICE_CREATE_DEVICE = 0,
    CAMERA_SERVICE_SET_CALLBACK,
    CAMERA_SERVICE_SET_MUTE_CALLBACK,
    CAMERA_SERVICE_SET_TORCH_CALLBACK,
    CAMERA_SERVICE_GET_CAMERAS,
    CAMERA_SERVICE_CREATE_CAPTURE_SESSION,
    CAMERA_SERVICE_CREATE_PHOTO_OUTPUT,
    CAMERA_SERVICE_CREATE_PREVIEW_OUTPUT,
    CAMERA_SERVICE_CREATE_DEFERRED_PREVIEW_OUTPUT,
    CAMERA_SERVICE_CREATE_VIDEO_OUTPUT,
    CAMERA_SERVICE_SET_LISTENER_OBJ,
    CAMERA_SERVICE_CREATE_METADATA_OUTPUT,
    CAMERA_SERVICE_MUTE_CAMERA,
    CAMERA_SERVICE_IS_CAMERA_MUTED,
    CAMERA_SERVICE_PRE_LAUNCH_CAMERA,
    CAMERA_SERVICE_SET_PRE_LAUNCH_CAMERA,
    CAMERA_SERVICE_SET_TORCH_LEVEL,
    CAMERA_SERVICE_PRE_SWITCH_CAMERA,
    CAMERA_SERVICE_CREATE_DEFERRED_PHOTO_PROCESSING_SESSION,
    CAMERA_SERVICE_GET_CAMERA_IDS,
    CAMERA_SERVICE_GET_CAMERA_ABILITY,
};

/**
 * @brief Camera service remote request code for DH IPC.
 *
 * @since 1.0
 * @version 1.0
 */
enum CameraServiceDHInterfaceCode {
    CAMERA_SERVICE_ALLOW_OPEN_BY_OHSIDE = 101,
    CAMERA_SERVICE_NOTIFY_CAMERA_STATE,
    CAMERA_SERVICE_NOTIFY_CLOSE_CAMERA,
    CAMERA_SERVICE_SET_PEER_CALLBACK
};

/**
 * @brief Capture session remote request code for IPC.
 *
 * @since 1.0
 * @version 1.0
 */
enum CaptureSessionInterfaceCode {
    CAMERA_CAPTURE_SESSION_BEGIN_CONFIG = 0,
    CAMERA_CAPTURE_SESSION_ADD_INPUT,
    CAMERA_CAPTURE_SESSION_CAN_ADD_INPUT,
    CAMERA_CAPTURE_SESSION_ADD_OUTPUT,
    CAMERA_CAPTURE_SESSION_REMOVE_INPUT,
    CAMERA_CAPTURE_SESSION_REMOVE_OUTPUT,
    CAMERA_CAPTURE_SESSION_COMMIT_CONFIG,
    CAMERA_CAPTURE_SESSION_START,
    CAMERA_CAPTURE_SESSION_STOP,
    CAMERA_CAPTURE_SESSION_RELEASE,
    CAMERA_CAPTURE_SESSION_SET_CALLBACK,
    CAMERA_CAPTURE_GET_SESSION_STATE,
    CAMERA_CAPTURE_GET_ACTIVE_COLOR_SPACE,
    CAMERA_CAPTURE_SET_COLOR_SPACE,
    CAMERA_CAPTURE_SESSION_SET_SMOOTH_ZOOM,
    CAMERA_CAPTURE_SESSION_SET_FEATURE_MODE
};

/**
 * @brief Stream capture remote request code for IPC.
 *
 * @since 1.0
 * @version 1.0
 */
enum StreamCaptureInterfaceCode {
    CAMERA_STREAM_CAPTURE_START = 0,
    CAMERA_STREAM_CAPTURE_CANCEL,
    CAMERA_STREAM_CAPTURE_SET_CALLBACK,
    CAMERA_STREAM_CAPTURE_RELEASE,
    CAMERA_SERVICE_SET_THUMBNAIL,
    CAMERA_STREAM_CAPTURE_CONFIRM,
    CAMERA_SERVICE_ENABLE_DEFERREDTYPE,
    CAMERA_STREAM_GET_DEFERRED_PHOTO,
    CAMERA_STREAM_GET_DEFERRED_VIDEO,
    CAMERA_STREAM_SET_RAW_PHOTO_INFO,
};

/**
 * @brief Stream repeat remote request code for IPC.
 *
 * @since 1.0
 * @version 1.0
 */
enum StreamRepeatInterfaceCode {
    CAMERA_START_VIDEO_RECORDING = 0,
    CAMERA_STOP_VIDEO_RECORDING,
    CAMERA_STREAM_REPEAT_SET_CALLBACK,
    CAMERA_STREAM_REPEAT_RELEASE,
    CAMERA_ADD_DEFERRED_SURFACE,
    CAMERA_FORK_SKETCH_STREAM_REPEAT,
    CAMERA_REMOVE_SKETCH_STREAM_REPEAT,
    CAMERA_UPDATE_SKETCH_RATIO,
    STREAM_FRAME_RANGE_SET,
    CAMERA_ENABLE_SECURE_STREAM
};

/**
 * @brief Stream metadata remote request code for IPC.
 *
 * @since 1.0
 * @version 1.0
 */
enum StreamMetadataInterfaceCode {
    CAMERA_STREAM_META_START = 0,
    CAMERA_STREAM_META_STOP,
    CAMERA_STREAM_META_RELEASE
};

/**
 * @brief Camera device callback remote request code for IPC.
 *
 * @since 1.0
 * @version 1.0
 */
enum CameraDeviceCallbackInterfaceCode {
    CAMERA_DEVICE_ON_ERROR = 0,
    CAMERA_DEVICE_ON_RESULT
};

/**
 * @brief Camera repeat stream callback remote request code for IPC.
 *
 * @since 1.0
 * @version 1.0
 */
enum StreamRepeatCallbackInterfaceCode {
    CAMERA_STREAM_REPEAT_ON_FRAME_STARTED = 0,
    CAMERA_STREAM_REPEAT_ON_FRAME_ENDED,
    CAMERA_STREAM_REPEAT_ON_ERROR,
    CAMERA_STREAM_SKETCH_STATUS_ON_CHANGED
};

/**
 * @brief Camera capture stream callback remote request code for IPC.
 *
 * @since 1.0
 * @version 1.0
 */
enum StreamCaptureCallbackInterfaceCode {
    CAMERA_STREAM_CAPTURE_ON_CAPTURE_STARTED = 0,
    CAMERA_STREAM_CAPTURE_ON_CAPTURE_ENDED,
    CAMERA_STREAM_CAPTURE_ON_CAPTURE_ERROR,
    CAMERA_STREAM_CAPTURE_ON_FRAME_SHUTTER,
    CAMERA_STREAM_CAPTURE_ON_CAPTURE_STARTED_V1_2,
    CAMERA_STREAM_CAPTURE_ON_FRAME_SHUTTER_END,
    CAMERA_STREAM_CAPTURE_ON_CAPTURE_READY
};

/**
* @brief Capture session callback remote request code for IPC.
*
* @since 1.0
* @version 1.0
*/
enum CaptureSessionCallbackInterfaceCode {
    CAMERA_CAPTURE_SESSION_ON_ERROR = 0
};
} // namespace CameraStandard
} // namespace OHOS
#endif // OHOS_CAMERA_SERVICE_IPC_INTERFACE_CODE_H
