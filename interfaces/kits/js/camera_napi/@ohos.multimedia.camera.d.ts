/*
 * Copyright (C) 2022 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

import {ErrorCallback, AsyncCallback} from './basic';
import { Context } from './app/context';

/**
 * @name camera
 * @syscap SystemCapability.Multimedia.Camera.Core
 * @import import camera from '@ohos.multimedia.camera';
 * @since 9
 */
declare namespace camera {

  /**
   * Creates a CameraManager instance.
   * @param context Current application context.
   * @param callback Callback used to return the CameraManager instance.
   * @since 9
   * @syscap SystemCapability.Multimedia.Camera.Core
   */
  function getCameraManager(context: Context, callback: AsyncCallback<CameraManager>): void;

  /**
   * Creates a CameraManager instance.
   * @param context Current application context.
   * @return Promise used to return the CameraManager instance.
   * @since 9
   * @syscap SystemCapability.Multimedia.Camera.Core
   */
  function getCameraManager(context: Context): Promise<CameraManager>;

  /**
   * Enum for camera status.
   * @since 9
   * @syscap SystemCapability.Multimedia.Camera.Core
   */
  enum CameraStatus {
    /**
     * Appear status.
     * @since 9
     * @syscap SystemCapability.Multimedia.Camera.Core
     */
    CAMERA_STATUS_APPEAR = 0,
    /**
     * Disappear status.
     * @since 9
     * @syscap SystemCapability.Multimedia.Camera.Core
     */
    CAMERA_STATUS_DISAPPEAR = 1,
    /**
     * Available status.
     * @since 9
     * @syscap SystemCapability.Multimedia.Camera.Core
     */
    CAMERA_STATUS_AVAILABLE = 2,
    /**
     * Unavailable status.
     * @since 9
     * @syscap SystemCapability.Multimedia.Camera.Core
     */
    CAMERA_STATUS_UNAVAILABLE = 3
  }

  /**
   * Profile for camera streams.
   * @since 9
   * @syscap SystemCapability.Multimedia.Camera.Core
   */
  interface Profile {
    /**
     * Camera format.
     * @since 9
     * @syscap SystemCapability.Multimedia.Camera.Core
     */
    readonly format: CameraFormat;
    /**
     * Picture size.
     * @since 9
     * @syscap SystemCapability.Multimedia.Camera.Core
     */
    readonly size: Size;
  }

  /**
   * Frame rate range.
   * @since 9
   * @syscap SystemCapability.Multimedia.Camera.Core
   */
  interface FrameRateRange {
    /**
     * Min frame rate.
     * @since 9
     * @syscap SystemCapability.Multimedia.Camera.Core
     */
    readonly min: number;
    /**
     * Max frame rate.
     * @since 9
     * @syscap SystemCapability.Multimedia.Camera.Core
     */
    readonly max: number;
  }

  /**
   * Video profile.
   * @since 9
   * @syscap SystemCapability.Multimedia.Camera.Core
   */
  interface VideoProfile extends Profile {
    /**
     * Frame rate in unit fps (frames per second).
     * @since 9
     * @syscap SystemCapability.Multimedia.Camera.Core
     */
    readonly frameRateRange: FrameRateRange;
  }

  /**
   * Camera output capability.
   * @since 9
   * @syscap SystemCapability.Multimedia.Camera.Core
   */
  interface CameraOutputCapability  {
    /**
     * Preview profiles.
     * @since 9
     * @syscap SystemCapability.Multimedia.Camera.Core
     */
    readonly previewProfiles: Array<Profile>;
    /**
     * Photo profiles.
     * @since 9
     * @syscap SystemCapability.Multimedia.Camera.Core
     */
    readonly photoProfiles: Array<Profile>;
    /**
     * Video profiles.
     * @since 9
     * @syscap SystemCapability.Multimedia.Camera.Core
     */
    readonly videoProfiles: Array<VideoProfile>;
    /**
     * All the supported metadata Object Types.
     * @since 9
     * @syscap SystemCapability.Multimedia.Camera.Core
     */
    readonly supportedMetadataObjectTypes: Array<MetadataObjectType>;
  }

  /**
   * Camera manager object.
   * @since 9
   * @syscap SystemCapability.Multimedia.Camera.Core
   */
  interface CameraManager  {
    /**
     * Gets supported camera descriptions.
     * @param callback Callback used to return the array of supported cameras.
     * @since 9
     * @syscap SystemCapability.Multimedia.Camera.Core
     */
    getSupportedCameras(callback: AsyncCallback<Array<CameraDevice>>): void;

    /**
     * Gets supported camera descriptions.
     * @return Promise used to return an array of supported cameras.
     * @since 9
     * @syscap SystemCapability.Multimedia.Camera.Core
     */
    getSupportedCameras(): Promise<Array<CameraDevice>>;

    /**
     * Gets supported output capability for specific camera.
     * @param camera Camera device.
     * @param callback Callback used to return the camera output capability.
     * @since 9
     * @syscap SystemCapability.Multimedia.Camera.Core
     */
    getSupportedOutputCapability(camera: CameraDevice, callback: AsyncCallback<CameraOutputCapability>): void;

    /**
     * Gets supported output capability for specific camera.
     * @param camera Camera device.
     * @return Promise used to return the camera output capability.
     * @since 9
     * @syscap SystemCapability.Multimedia.Camera.Core
     */
    getSupportedOutputCapability(camera: CameraDevice): Promise<CameraOutputCapability>;

    /**
     * Determine whether camera is muted.
     * @return Is camera muted.
     * @since 9
     * @syscap SystemCapability.Multimedia.Camera.Core
     */
    isCameraMuted(): boolean;

    /**
     * Determine whether camera mute is supported.
     * @return Is camera mute supported.
     * @since 9
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @systemapi
     */
    isCameraMuteSupported(): boolean;

    /**
     * Mute camera.
     * @param mute Mute camera if TRUE, otherwise unmute camera.
     * @since 9
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @systemapi
     */
    muteCamera(mute: boolean): void;

    /**
     * Creates a CameraInput instance by camera.
     * @param camera Camera device used to create the instance.
     * @param callback Callback used to return the CameraInput instance.
     * @since 9
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @permission ohos.permission.CAMERA
     */
    createCameraInput(camera: CameraDevice, callback: AsyncCallback<CameraInput>): void;

    /**
     * Creates a CameraInput instance by camera.
     * @param camera Camera device used to create the instance.
     * @return Promise used to return the CameraInput instance.
     * @since 9
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @permission ohos.permission.CAMERA
     */
    createCameraInput(camera: CameraDevice): Promise<CameraInput>;

    /**
     * Creates a CameraInput instance by camera position and type.
     * @param position Target camera position.
     * @param type Target camera type.
     * @param callback Callback used to return the CameraInput instance.
     * @since 9
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @permission ohos.permission.CAMERA
     */
    createCameraInput(position: CameraPosition, type: CameraType, callback: AsyncCallback<CameraInput>): void;

    /**
     * Creates a CameraInput instance by camera position and type.
     * @param position Target camera position.
     * @param type Target camera type.
     * @return Promise used to return the CameraInput instance.
     * @since 9
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @permission ohos.permission.CAMERA
     */
    createCameraInput(position: CameraPosition, type: CameraType): Promise<CameraInput>;

    /**
     * Creates a PreviewOutput instance.
     * @param profile Preview output profile.
     * @param surfaceId Surface object id used in camera photo output.
     * @param callback Callback used to return the PreviewOutput instance.
     * @since 9
     * @syscap SystemCapability.Multimedia.Camera.Core
     */
    createPreviewOutput(profile: Profile, surfaceId: string, callback: AsyncCallback<PreviewOutput>): void;

    /**
     * Creates a PreviewOutput instance.
     * @param profile Preview output profile.
     * @param surfaceId Surface object id used in camera photo output.
     * @return Promise used to return the PreviewOutput instance.
     * @since 9
     * @syscap SystemCapability.Multimedia.Camera.Core
     */
    createPreviewOutput(profile: Profile, surfaceId: string): Promise<PreviewOutput>;

    /**
     * Creates a PhotoOutput instance.
     * @param profile Photo output profile.
     * @param surfaceId Surface object id used in camera photo output.
     * @param callback Callback used to return the PhotoOutput instance.
     * @since 9
     * @syscap SystemCapability.Multimedia.Camera.Core
     */
    createPhotoOutput(profile: Profile, surfaceId: string, callback: AsyncCallback<PhotoOutput>): void;

    /**
     * Creates a PhotoOutput instance.
     * @param profile Photo output profile.
     * @param surfaceId Surface object id used in camera photo output.
     * @return Promise used to return the PhotoOutput instance.
     * @since 9
     * @syscap SystemCapability.Multimedia.Camera.Core
     */
    createPhotoOutput(profile: Profile, surfaceId: string): Promise<PhotoOutput>;

    /**
     * Creates a VideoOutput instance.
     * @param profile Video profile.
     * @param surfaceId Surface object id used in camera video output.
     * @param callback Callback used to return the VideoOutput instance.
     * @since 9
     * @syscap SystemCapability.Multimedia.Camera.Core
     */
    createVideoOutput(profile: VideoProfile, surfaceId: string, callback: AsyncCallback<VideoOutput>): void;

    /**
     * Creates a VideoOutput instance.
     * @param profile Video profile.
     * @param surfaceId Surface object id used in camera video output.
     * @return Promise used to return the VideoOutput instance.
     * @since 9
     * @syscap SystemCapability.Multimedia.Camera.Core
     */
    createVideoOutput(profile: VideoProfile, surfaceId: string): Promise<VideoOutput>;

    /**
     * Creates a MetadataOutput instance.
     * @param metadataObjectTypes Array of MetadataObjectType.
     * @param callback Callback used to return the MetadataOutput instance.
     * @since 9
     * @syscap SystemCapability.Multimedia.Camera.Core
     */
    createMetadataOutput(metadataObjectTypes: Array<MetadataObjectType>, callback: AsyncCallback<MetadataOutput>): void;

    /**
     * Creates a MetadataOutput instance.
     * @param metadataObjectTypes Array of MetadataObjectType.
     * @return Promise used to return the MetadataOutput instance.
     * @since 9
     * @syscap SystemCapability.Multimedia.Camera.Core
     */
    createMetadataOutput(metadataObjectTypes: Array<MetadataObjectType>): Promise<MetadataOutput>;

    /**
     * Gets a CaptureSession instance.
     * @param callback Callback used to return the CaptureSession instance.
     * @since 9
     * @syscap SystemCapability.Multimedia.Camera.Core
     */
    createCaptureSession(callback: AsyncCallback<CaptureSession>): void;

    /**
     * Gets a CaptureSession instance.
     * @return Promise used to return the CaptureSession instance.
     * @since 9
     * @syscap SystemCapability.Multimedia.Camera.Core
     */
    createCaptureSession(): Promise<CaptureSession>;

    /**
     * Subscribes camera status change event callback.
     * @param type Event type.
     * @param callback Callback used to get the camera status change.
     * @since 9
     * @syscap SystemCapability.Multimedia.Camera.Core
     */
    on(type: 'cameraStatus', callback: AsyncCallback<CameraStatusInfo>): void;

    /**
     * Subscribes camera mute change event callback.
     * @param type Event type.
     * @param callback Callback used to get the camera mute change.
     * @since 9
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @systemapi
     */
    on(type: 'cameraMute', callback: AsyncCallback<boolean>): void;
  }

  /**
   * Camera status info.
   * @since 9
   * @syscap SystemCapability.Multimedia.Camera.Core
   */
  interface CameraStatusInfo {
    /**
     * Camera instance.
     * @since 9
     * @syscap SystemCapability.Multimedia.Camera.Core
     */
    camera: CameraDevice;
    /**
     * Current camera status.
     * @since 9
     * @syscap SystemCapability.Multimedia.Camera.Core
     */
    status: CameraStatus;
  }

  /**
   * Enum for camera position.
   * @since 9
   * @syscap SystemCapability.Multimedia.Camera.Core
   */
  enum CameraPosition {
    /**
     * Unspecified position.
     * @since 9
     * @syscap SystemCapability.Multimedia.Camera.Core
     */
    CAMERA_POSITION_UNSPECIFIED = 0,
    /**
     * Back position.
     * @since 9
     * @syscap SystemCapability.Multimedia.Camera.Core
     */
    CAMERA_POSITION_BACK = 1,
    /**
     * Front position.
     * @since 9
     * @syscap SystemCapability.Multimedia.Camera.Core
     */
    CAMERA_POSITION_FRONT = 2
  }

  /**
   * Enum for camera type.
   * @since 9
   * @syscap SystemCapability.Multimedia.Camera.Core
   */
  enum CameraType {
    /**
     * Unspecified camera type
     * @since 9
     * @syscap SystemCapability.Multimedia.Camera.Core
     */
    CAMERA_TYPE_UNSPECIFIED = 0,

    /**
     * Wide camera
     * @since 9
     * @syscap SystemCapability.Multimedia.Camera.Core
     */
    CAMERA_TYPE_WIDE_ANGLE = 1,

    /**
     * Ultra wide camera
     * @since 9
     * @syscap SystemCapability.Multimedia.Camera.Core
     */
    CAMERA_TYPE_ULTRA_WIDE = 2,

    /**
     * Telephoto camera
     * @since 9
     * @syscap SystemCapability.Multimedia.Camera.Core
     */
    CAMERA_TYPE_TELEPHOTO = 3,

    /**
     * True depth camera
     * @since 9
     * @syscap SystemCapability.Multimedia.Camera.Core
     */
    CAMERA_TYPE_TRUE_DEPTH = 4
  }

  /**
   * Enum for camera connection type.
   * @since 9
   * @syscap SystemCapability.Multimedia.Camera.Core
   */
  enum ConnectionType {
    /**
     * Built-in camera.
     * @since 9
     * @syscap SystemCapability.Multimedia.Camera.Core
     */
    CAMERA_CONNECTION_BUILT_IN = 0,

    /**
     * Camera connected using USB
     * @since 9
     * @syscap SystemCapability.Multimedia.Camera.Core
     */
    CAMERA_CONNECTION_USB_PLUGIN = 1,

    /**
     * Remote camera
     * @since 9
     * @syscap SystemCapability.Multimedia.Camera.Core
     */
    CAMERA_CONNECTION_REMOTE = 2
  }

  /**
   * Camera device object.
   * @since 9
   * @syscap SystemCapability.Multimedia.Camera.Core
   */
  interface CameraDevice {
    /**
     * Camera id attribute.
     * @since 9
     * @syscap SystemCapability.Multimedia.Camera.Core
     */
    readonly cameraId: string;
    /**
     * Camera position attribute.
     * @since 9
     * @syscap SystemCapability.Multimedia.Camera.Core
     */
    readonly cameraPosition: CameraPosition;
    /**
     * Camera type attribute.
     * @since 9
     * @syscap SystemCapability.Multimedia.Camera.Core
     */
    readonly cameraType: CameraType;
    /**
     * Camera connection type attribute.
     * @since 9
     * @syscap SystemCapability.Multimedia.Camera.Core
     */
    readonly connectionType: ConnectionType;
  }

  /**
   * Size parameter.
   * @since 9
   * @syscap SystemCapability.Multimedia.Camera.Core
   */
  interface Size {
    /**
     * Height.
     * @since 9
     * @syscap SystemCapability.Multimedia.Camera.Core
     */
    height: number;
    /**
     * Width.
     * @since 9
     * @syscap SystemCapability.Multimedia.Camera.Core
     */
    width: number;
  }

  /**
   * Point parameter.
   * @since 9
   * @syscap SystemCapability.Multimedia.Camera.Core
   */
  interface Point {
    /**
     * x co-ordinate
     * @since 9
     * @syscap SystemCapability.Multimedia.Camera.Core
     */
    x: number;
    /**
     * y co-ordinate
     * @since 9
     * @syscap SystemCapability.Multimedia.Camera.Core
     */
    y: number;
  }

  /**
   * Camera input object.
   * @since 9
   * @syscap SystemCapability.Multimedia.Camera.Core
   */
  interface CameraInput {
    /**
     * Open camera.
     * @param callback Callback used to return the result.
     * @since 9
     * @syscap SystemCapability.Multimedia.Camera.Core
     */
    open(callback: AsyncCallback<void>): void;

    /**
     * Open camera.
     * @return Promise used to return the result.
     * @since 9
     * @syscap SystemCapability.Multimedia.Camera.Core
     */
    open(): Promise<void>;

    /**
     * Close camera.
     * @param callback Callback used to return the result.
     * @since 9
     * @syscap SystemCapability.Multimedia.Camera.Core
     */
    close(callback: AsyncCallback<void>): void;

    /**
     * Close camera.
     * @return Promise used to return the result.
     * @since 9
     * @syscap SystemCapability.Multimedia.Camera.Core
     */
    close(): Promise<void>;

    /**
     * Releases instance.
     * @param callback Callback used to return the result.
     * @since 9
     * @syscap SystemCapability.Multimedia.Camera.Core
     */
    release(callback: AsyncCallback<void>): void;

    /**
     * Releases instance.
     * @return Promise used to return the result.
     * @since 9
     * @syscap SystemCapability.Multimedia.Camera.Core
     */
    release(): Promise<void>;

    /**
     * Subscribes error event callback.
     * @param type Event type.
     * @param camera Camera device.
     * @param callback Callback used to get the camera input errors.
     * @since 9
     * @syscap SystemCapability.Multimedia.Camera.Core
     */
    on(type: 'error', camera: CameraDevice, callback: ErrorCallback<CameraInputError>): void;
  }

  /**
   * Enum for CameraInput error code.
   * @since 9
   * @syscap SystemCapability.Multimedia.Camera.Core
   */
  enum CameraInputErrorCode {
    /**
     * Unknown error.
     * @since 9
     */
    ERROR_UNKNOWN = -1,
    /**
     * No permission.
     * @since 9
     */
    ERROR_NO_PERMISSION = 0,
    /**
     * Camera device preempted.
     * @since 9
     */
    ERROR_DEVICE_PREEMPTED = 1,
    /**
     * Camera device disconnected.
     * @since 9
     */
    ERROR_DEVICE_DISCONNECTED = 2,
    /**
     * Camera device in use.
     * @since 9
     */
    ERROR_DEVICE_IN_USE = 3,
    /**
     * Driver error.
     * @since 9
     */
    ERROR_DRIVER_ERROR = 4,
  }

  /**
   * Camera input error object.
   * @since 9
   * @syscap SystemCapability.Multimedia.Camera.Core
   */
  interface CameraInputError extends Error {
    code: CameraInputErrorCode;
  }

  /**
   * Enum for camera format type.
   * @since 9
   * @syscap SystemCapability.Multimedia.Camera.Core
   */
   enum CameraFormat {
    /**
     * RGBA 8888 Format.
     * @since 9
     * @syscap SystemCapability.Multimedia.Camera.Core
     */
     CAMERA_FORMAT_RGBA_8888 = 3,

    /**
     * YUV 420 Format.
     * @since 9
     * @syscap SystemCapability.Multimedia.Camera.Core
     */
    CAMERA_FORMAT_YUV_420_SP = 1003,

    /**
     * JPEG Format.
     * @since 9
     * @syscap SystemCapability.Multimedia.Camera.Core
     */
    CAMERA_FORMAT_JPEG = 2000
  }

  /**
   * Enum for flash mode.
   * @since 9
   * @syscap SystemCapability.Multimedia.Camera.Core
   */
  enum FlashMode {
    /**
     * Close mode.
     * @since 9
     * @syscap SystemCapability.Multimedia.Camera.Core
     */
    FLASH_MODE_CLOSE = 0,
    /**
     * Open mode.
     * @since 9
     * @syscap SystemCapability.Multimedia.Camera.Core
     */
    FLASH_MODE_OPEN = 1,
    /**
     * Auto mode.
     * @since 9
     * @syscap SystemCapability.Multimedia.Camera.Core
     */
    FLASH_MODE_AUTO = 2,
    /**
     * Always open mode.
     * @since 9
     * @syscap SystemCapability.Multimedia.Camera.Core
     */
    FLASH_MODE_ALWAYS_OPEN = 3
  }

  /**
   * Enum for exposure mode.
   * @since 9
   */
  enum ExposureMode {
    /**
     * Lock exposure mode.
     * @since 9
     */
    EXPOSURE_MODE_LOCKED = 0,
    /**
     * Auto exposure mode.
     * @since 9
     */
     EXPOSURE_MODE_AUTO = 1,
     /**
     * Continuous automatic exposure.
     * @since 9
     */
    EXPOSURE_MODE_CONTINUOUS_AUTO = 2
  }

  /**
   * Enum for focus mode.
   * @since 9
   * @syscap SystemCapability.Multimedia.Camera.Core
   */
  enum FocusMode {
    /**
     * Manual mode.
     * @since 9
     * @syscap SystemCapability.Multimedia.Camera.Core
     */
    FOCUS_MODE_MANUAL = 0,
    /**
     * Continuous auto mode.
     * @since 9
     * @syscap SystemCapability.Multimedia.Camera.Core
     */
    FOCUS_MODE_CONTINUOUS_AUTO = 1,
    /**
     * Auto mode.
     * @since 9
     * @syscap SystemCapability.Multimedia.Camera.Core
     */
    FOCUS_MODE_AUTO = 2,
    /**
     * Locked mode.
     * @since 9
     * @syscap SystemCapability.Multimedia.Camera.Core
     */
    FOCUS_MODE_LOCKED = 3
  }

  /**
   * Enum for focus state.
   * @since 9
   * @syscap SystemCapability.Multimedia.Camera.Core
   */
  enum FocusState {
    /**
     * Scan state.
     * @since 9
     * @syscap SystemCapability.Multimedia.Camera.Core
     */
    FOCUS_STATE_SCAN = 0,
    /**
     * Focused state.
     * @since 9
     * @syscap SystemCapability.Multimedia.Camera.Core
     */
    FOCUS_STATE_FOCUSED = 1,
    /**
     * Unfocused state.
     * @since 9
     * @syscap SystemCapability.Multimedia.Camera.Core
     */
    FOCUS_STATE_UNFOCUSED = 2
  }

  /**
   * Enum for video stabilization mode.
   * @since 9
   * @syscap SystemCapability.Multimedia.Camera.Core
   */
   enum VideoStabilizationMode {
    /**
     * Turn off video stablization.
     * @since 9
     * @syscap SystemCapability.Multimedia.Camera.Core
     */
    OFF = 0,
    /**
     * LOW mode provides basic stabilization effect.
     * @since 9
     * @syscap SystemCapability.Multimedia.Camera.Core
     */
    LOW = 1,
    /**
     * MIDDLE mode means algorithms can achieve better effects than LOW mode.
     * @since 9
     * @syscap SystemCapability.Multimedia.Camera.Core
     */
    MIDDLE = 2,
    /**
     * HIGH mode means algorithms can achieve better effects than MIDDLE mode.
     * @since 9
     * @syscap SystemCapability.Multimedia.Camera.Core
     */
    HIGH = 3,
    /**
     * Camera HDF can select mode automatically.
     * @since 9
     * @syscap SystemCapability.Multimedia.Camera.Core
     */
    AUTO = 4
  }

  /**
   * Capture session object.
   * @since 9
   * @syscap SystemCapability.Multimedia.Camera.Core
   */
  interface CaptureSession {
    /**
     * Begin capture session config.
     * @param callback Callback used to return the result.
     * @since 9
     * @syscap SystemCapability.Multimedia.Camera.Core
     */
    beginConfig(callback: AsyncCallback<void>): void;

    /**
     * Begin capture session config.
     * @return Promise used to return the result.
     * @since 9
     * @syscap SystemCapability.Multimedia.Camera.Core
     */
    beginConfig(): Promise<void>;

    /**
     * Commit capture session config.
     * @param callback Callback used to return the result.
     * @since 9
     * @syscap SystemCapability.Multimedia.Camera.Core
     */
    commitConfig(callback: AsyncCallback<void>): void;

    /**
     * Commit capture session config.
     * @return Promise used to return the result.
     * @since 9
     * @syscap SystemCapability.Multimedia.Camera.Core
     */
    commitConfig(): Promise<void>;

    /**
     * Adds a camera input.
     * @param cameraInput Target camera input to add.
     * @param callback Callback used to return the result.
     * @since 9
     * @syscap SystemCapability.Multimedia.Camera.Core
     */
    addInput(cameraInput: CameraInput, callback: AsyncCallback<void>): void;

    /**
     * Adds a camera input.
     * @param cameraInput Target camera input to add.
     * @return Promise used to return the result.
     * @since 9
     * @syscap SystemCapability.Multimedia.Camera.Core
     */
    addInput(cameraInput: CameraInput): Promise<void>;

    /**
     * Removes a camera input.
     * @param cameraInput Target camera input to remove.
     * @param callback Callback used to return the result.
     * @since 9
     * @syscap SystemCapability.Multimedia.Camera.Core
     */
    removeInput(cameraInput: CameraInput, callback: AsyncCallback<void>): void;

    /**
     * Removes a camera input.
     * @param cameraInput Target camera input to remove.
     * @return Promise used to return the result.
     * @since 9
     * @syscap SystemCapability.Multimedia.Camera.Core
     */
    removeInput(cameraInput: CameraInput): Promise<void>;

    /**
     * Adds a camera output.
     * @param cameraOutput Target camera output to add.
     * @param callback Callback used to return the result.
     * @since 9
     * @syscap SystemCapability.Multimedia.Camera.Core
     */
    addOutput(cameraOutput: CameraOutput, callback: AsyncCallback<void>): void;

    /**
     * Adds a camera output.
     * @param cameraOutput Target camera output to add.
     * @return Promise used to return the result.
     * @since 9
     * @syscap SystemCapability.Multimedia.Camera.Core
     */
    addOutput(cameraOutput: CameraOutput): Promise<void>;

    /**
     * Removes a camera output.
     * @param previewOutput Target camera output to remove.
     * @param callback Callback used to return the result.
     * @since 9
     * @syscap SystemCapability.Multimedia.Camera.Core
     */
    removeOutput(cameraOutput: CameraOutput, callback: AsyncCallback<void>): void;

    /**
     * Removes a camera output.
     * @param previewOutput Target camera output to remove.
     * @return Promise used to return the result.
     * @since 9
     * @syscap SystemCapability.Multimedia.Camera.Core
     */
    removeOutput(cameraOutput: CameraOutput): Promise<void>;

    /**
     * Starts capture session.
     * @param callback Callback used to return the result.
     * @since 9
     * @syscap SystemCapability.Multimedia.Camera.Core
     */
    start(callback: AsyncCallback<void>): void;

    /**
     * Starts capture session.
     * @return Promise used to return the result.
     * @since 9
     * @syscap SystemCapability.Multimedia.Camera.Core
     */
    start(): Promise<void>;

    /**
     * Stops capture session.
     * @param callback Callback used to return the result.
     * @since 9
     * @syscap SystemCapability.Multimedia.Camera.Core
     */
    stop(callback: AsyncCallback<void>): void;

    /**
     * Stops capture session.
     * @return Promise used to return the result.
     * @since 9
     * @syscap SystemCapability.Multimedia.Camera.Core
     */
    stop(): Promise<void>;

    /**
     * Release capture session instance.
     * @param callback Callback used to return the result.
     * @since 9
     * @syscap SystemCapability.Multimedia.Camera.Core
     */
    release(callback: AsyncCallback<void>): void;

    /**
     * Release capture session instance.
     * @return Promise used to return the result.
     * @since 9
     * @syscap SystemCapability.Multimedia.Camera.Core
     */
    release(): Promise<void>;

    /**
     * Check if device has flash light.
     * @param callback Callback used to return the flash light support status.
     * @since 9
     * @syscap SystemCapability.Multimedia.Camera.Core
     */
    hasFlash(callback: AsyncCallback<boolean>): void;

    /**
     * Check if device has flash light.
     * @return Promise used to return the flash light support status.
     * @since 9
     * @syscap SystemCapability.Multimedia.Camera.Core
     */
    hasFlash(): Promise<boolean>;

    /**
     * Checks whether a specified flash mode is supported.
     * @param flashMode Flash mode.
     * @param callback Callback used to return the flash light support status.
     * @since 9
     * @syscap SystemCapability.Multimedia.Camera.Core
     */
    isFlashModeSupported(flashMode: FlashMode, callback: AsyncCallback<boolean>): void;

    /**
     * Checks whether a specified flash mode is supported.
     * @param flashMode Flash mode
     * @return Promise used to return flash mode support status.
     * @since 9
     * @syscap SystemCapability.Multimedia.Camera.Core
     */
    isFlashModeSupported(flashMode: FlashMode): Promise<boolean>;

    /**
     * Gets current flash mode.
     * @param callback Callback used to return the current flash mode.
     * @since 9
     * @syscap SystemCapability.Multimedia.Camera.Core
     */
    getFlashMode(callback: AsyncCallback<FlashMode>): void;

    /**
     * Gets current flash mode.
     * @return Promise used to return the flash mode.
     * @since 9
     * @syscap SystemCapability.Multimedia.Camera.Core
     */
    getFlashMode(): Promise<FlashMode>;

    /**
     * Sets flash mode.
     * @param flashMode Target flash mode.
     * @param callback Callback used to return the result.
     * @since 9
     * @syscap SystemCapability.Multimedia.Camera.Core
     */
    setFlashMode(flashMode: FlashMode, callback: AsyncCallback<void>): void;

    /**
     * Sets flash mode.
     * @param flashMode Target flash mode.
     * @return Promise used to return the result.
     * @since 9
     * @syscap SystemCapability.Multimedia.Camera.Core
     */
    setFlashMode(flashMode: FlashMode): Promise<void>;

    /**
     * Checks whether a specified exposure mode is supported.
     * @param aeMode Exposure mode.
     * @param callback Callback used to return the exposure mode support status.
     * @since 9
     * @syscap SystemCapability.Multimedia.Camera.Core
     */
    isExposureModeSupported(aeMode: ExposureMode, callback: AsyncCallback<boolean>): void;

    /**
     * Checks whether a specified exposure mode is supported.
     * @param aeMode Exposure mode
     * @return Promise used to return exposure mode support status.
     * @since 9
     * @syscap SystemCapability.Multimedia.Camera.Core
     */
    isExposureModeSupported(aeMode: ExposureMode): Promise<boolean>;
 
    /**
     * Gets current exposure mode.
     * @param callback Callback used to return the current exposure mode.
     * @since 9
     * @syscap SystemCapability.Multimedia.Camera.Core
     */
    getExposureMode(callback: AsyncCallback<ExposureMode>): void;

    /**
     * Gets current exposure mode.
     * @return Promise used to return the current exposure mode.
     * @since 9
     * @syscap SystemCapability.Multimedia.Camera.Core
     */
    getExposureMode(): Promise<ExposureMode>;

    /**
     * Sets exposure mode.
     * @param aeMode Exposure mode
     * @param callback Callback used to return the result.
     * @since 9
     * @syscap SystemCapability.Multimedia.Camera.Core
     */
    setExposureMode(aeMode: ExposureMode, callback: AsyncCallback<void>): void;

     /**
      * Sets Exposure mode.
      * @param aeMode Exposure mode
      * @return Promise used to return the result.
      * @since 9
      * @syscap SystemCapability.Multimedia.Camera.Core
      */
    setExposureMode(aeMode: ExposureMode): Promise<void>;

    /**
     * Gets current metering point.
     * @param callback Callback used to return the current metering point.
     * @since 9
     * @syscap SystemCapability.Multimedia.Camera.Core
     */
    getMeteringPoint(callback: AsyncCallback<Point>): void;

    /**
     * Gets current metering point.
     * @return Promise used to return the current metering point.
     * @since 9
     * @syscap SystemCapability.Multimedia.Camera.Core
     */
    getMeteringPoint(): Promise<Point>;

    /**
     * Set the center point of the metering area.
     * @param point Metering point
     * @param callback Callback used to return the result.
     * @since 9
     * @syscap SystemCapability.Multimedia.Camera.Core
     */
    setMeteringPoint(point: Point, callback: AsyncCallback<void>): void;

     /**
      * Set the center point of the metering area.
      * @param point metering point
      * @return Promise used to return the result.
      * @since 9
      * @syscap SystemCapability.Multimedia.Camera.Core
      */
    setMeteringPoint(point: Point): Promise<void>;

    /**
     * Query the exposure compensation range.
     * @param callback Callback used to return the array of compenstation range.
     * @since 9
     * @syscap SystemCapability.Multimedia.Camera.Core
     */
    getExposureBiasRange(callback: AsyncCallback<Array<number>>): void;

    /**
     * Query the exposure compensation range.
     * @return Promise used to return the array of compenstation range.
     * @since 9
     * @syscap SystemCapability.Multimedia.Camera.Core
     */
    getExposureBiasRange(): Promise<Array<number>>;

    /**
     * Set exposure compensation.
     * @param exposureBias Exposure compensation
     * @param callback Callback used to return the result.
     * @since 9
     * @syscap SystemCapability.Multimedia.Camera.Core
     */
    setExposureBias(exposureBias: number, callback: AsyncCallback<void>): void;

    /**
     * Set exposure compensation.
     * @param exposureBias Exposure compensation
     * @return Promise used to return the result.
     * @since 9
     * @syscap SystemCapability.Multimedia.Camera.Core
     */
    setExposureBias(exposureBias: number): Promise<void>;

    /**
     * Query the exposure value.
     * @param callback Callback used to return the exposure value.
     * @since 9
     * @syscap SystemCapability.Multimedia.Camera.Core
     */
    getExposureValue(callback: AsyncCallback<number>): void;

    /**
     * Query the exposure value.
     * @return Promise used to return the exposure value.
     * @since 9
     * @syscap SystemCapability.Multimedia.Camera.Core
     */
    getExposureValue(): Promise<number>;
  
      /**
     * Checks whether a specified focus mode is supported.
     * @param afMode Focus mode.
     * @param callback Callback used to return the device focus support status.
     * @since 9
     * @syscap SystemCapability.Multimedia.Camera.Core
     */
    isFocusModeSupported(afMode: FocusMode, callback: AsyncCallback<boolean>): void;

    /**
     * Checks whether a specified focus mode is supported.
     * @param afMode Focus mode.
     * @return Promise used to return the focus mode support status.
     * @since 9
     * @syscap SystemCapability.Multimedia.Camera.Core
     */
    isFocusModeSupported(afMode: FocusMode): Promise<boolean>;

    /**
     * Gets current focus mode.
     * @param callback Callback used to return the current focus mode.
     * @since 9
     * @syscap SystemCapability.Multimedia.Camera.Core
     */
    getFocusMode(callback: AsyncCallback<FocusMode>): void;

    /**
     * Gets current focus mode.
     * @return Promise used to return the focus mode.
     * @since 9
     * @syscap SystemCapability.Multimedia.Camera.Core
     */
    getFocusMode(): Promise<FocusMode>;

    /**
     * Sets focus mode.
     * @param afMode Target focus mode.
     * @param callback Callback used to return the result.
     * @since 9
     * @syscap SystemCapability.Multimedia.Camera.Core
     */
    setFocusMode(afMode: FocusMode, callback: AsyncCallback<void>): void;

    /**
     * Sets focus mode.
     * @param afMode Target focus mode.
     * @return Promise used to return the result.
     * @since 9
     * @syscap SystemCapability.Multimedia.Camera.Core
     */
    setFocusMode(afMode: FocusMode): Promise<void>;

    /**
     * Sets focus point.
     * @param point Target focus point.
     * @param callback Callback used to return the result.
     * @since 9
     * @syscap SystemCapability.Multimedia.Camera.Core
     */
    setFocusPoint(point: Point, callback: AsyncCallback<void>): void;

    /**
     * Sets focus point.
     * @param afMode Target focus point.
     * @return Promise used to return the result.
     * @since 9
     * @syscap SystemCapability.Multimedia.Camera.Core
     */
    setFocusPoint(point: Point): Promise<void>;

    /**
     * Gets current focus point.
     * @param callback Callback used to return the current focus point.
     * @since 9
     * @syscap SystemCapability.Multimedia.Camera.Core
     */
    getFocusPoint(callback: AsyncCallback<Point>): void;

    /**
     * Gets current focus point.
     * @return Promise used to return the current focus point.
     * @since 9
     * @syscap SystemCapability.Multimedia.Camera.Core
     */
    getFocusPoint(): Promise<Point>;

    /**
     * Gets current focal length.
     * @param callback Callback used to return the current focal point.
     * @since 9
     * @syscap SystemCapability.Multimedia.Camera.Core
     */
    getFocalLength(callback: AsyncCallback<number>): void;

    /**
     * Gets current focal length.
     * @return Promise used to return the current focal point.
     * @since 9
     * @syscap SystemCapability.Multimedia.Camera.Core
     */
    getFocalLength(): Promise<number>;
 
    /**
     * Gets all supported zoom ratio range.
     * @param callback Callback used to return the zoom ratio range.
     * @since 9
     * @syscap SystemCapability.Multimedia.Camera.Core
     */
    getZoomRatioRange(callback: AsyncCallback<Array<number>>): void;

    /**
     * Gets all supported zoom ratio range.
     * @return Promise used to return the zoom ratio range.
     * @since 9
     * @syscap SystemCapability.Multimedia.Camera.Core
     */
    getZoomRatioRange(): Promise<Array<number>>;

    /**
     * Gets zoom ratio.
     * @param callback Callback used to return the current zoom ratio value.
     * @since 9
     * @syscap SystemCapability.Multimedia.Camera.Core
     */
    getZoomRatio(callback: AsyncCallback<number>): void;

    /**
     * Gets zoom ratio.
     * @return Promise used to return the zoom ratio value.
     * @since 9
     * @syscap SystemCapability.Multimedia.Camera.Core
     */
    getZoomRatio(): Promise<number>;

    /**
     * Sets zoom ratio.
     * @param zoomRatio Target zoom ratio.
     * @param callback Callback used to return the result.
     * @since 9
     * @syscap SystemCapability.Multimedia.Camera.Core
     */
    setZoomRatio(zoomRatio: number, callback: AsyncCallback<void>): void;

    /**
     * Sets zoom ratio.
     * @param zoomRatio Target zoom ratio.
     * @return Promise used to return the result.
     * @since 9
     * @syscap SystemCapability.Multimedia.Camera.Core
     */
    setZoomRatio(zoomRatio: number): Promise<void>;

    /**
     * Check whether the specified video stabilization mode is supported.
     * @param vsMode Video Stabilization mode.
     * @param callback Callback used to return if video stablization mode is supported.
     * @since 9
     * @syscap SystemCapability.Multimedia.Camera.Core
     */
    isVideoStabilizationModeSupported(vsMode: VideoStabilizationMode, callback: AsyncCallback<boolean>): void;

    /**
     * Check whether the specified video stabilization mode is supported.
     * @param callback Callback used to return if video stablization mode is supported.
     * @return Promise used to return flash mode support status.
     * @since 9
     * @syscap SystemCapability.Multimedia.Camera.Core
     */
    isVideoStabilizationModeSupported(vsMode: VideoStabilizationMode): Promise<boolean>;

    /**
     * Query the video stabilization mode currently in use.
     * @param callback Callback used to return the current video stabilization mode.
     * @since 9
     * @syscap SystemCapability.Multimedia.Camera.Core
     */
    getActiveVideoStabilizationMode(callback: AsyncCallback<VideoStabilizationMode>): void;

    /**
     * Query the video stabilization mode currently in use.
     * @return Promise used to return the current video stabilization mode.
     * @since 9
     * @syscap SystemCapability.Multimedia.Camera.Core
     */
    getActiveVideoStabilizationMode(): Promise<VideoStabilizationMode>;
 
    /**
     * Set video stabilization mode.
     * @param mode video stabilization mode to set.
     * @param callback Callback used to return the result.
     * @since 9
     * @syscap SystemCapability.Multimedia.Camera.Core
     */
    setVideoStabilizationMode(mode: VideoStabilizationMode, callback: AsyncCallback<void>): void;

    /**
     * Set video stabilization mode.
     * @param mode video stabilization mode to set.
     * @return Promise used to return the result.
     * @since 9
     * @syscap SystemCapability.Multimedia.Camera.Core
     */
    setVideoStabilizationMode(mode: VideoStabilizationMode): Promise<void>;

    /**
     * Subscribes focus status change event callback.
     * @param type Event type.
     * @param callback Callback used to get the focus state change.
     * @since 9
     * @syscap SystemCapability.Multimedia.Camera.Core
     */
    on(type: 'focusStateChange', callback: AsyncCallback<FocusState>): void;

    /**
     * Subscribes error event callback.
     * @param type Event type.
     * @param callback Callback used to get the capture session errors.
     * @since 9
     * @syscap SystemCapability.Multimedia.Camera.Core
     */
    on(type: 'error', callback: ErrorCallback<CaptureSessionError>): void;
  }

  /**
   * Enum for CaptureSession error code.
   * @since 9
   * @syscap SystemCapability.Multimedia.Camera.Core
   */
  enum CaptureSessionErrorCode {
    /**
     * Unknown error.
     * @since 9
     */
    ERROR_UNKNOWN = -1,
    /**
     * Insufficient resources.
     * @since 9
     */
    ERROR_INSUFFICIENT_RESOURCES = 0,
    /**
     * Timeout error.
     * @since 9
     */
    ERROR_TIMEOUT = 1,
  }

  /**
   * Capture session error object.
   * @since 9
   * @syscap SystemCapability.Multimedia.Camera.Core
   */
  interface CaptureSessionError extends Error {
    code: CaptureSessionErrorCode;
  }

  /**
   * Camera output object.
   * @since 9
   * @syscap SystemCapability.Multimedia.Camera.Core
   */
  interface CameraOutput {
    /**
     * Release output instance.
     * @param callback Callback used to return the result.
     * @since 9
     * @syscap SystemCapability.Multimedia.Camera.Core
     */
    release(callback: AsyncCallback<void>): void;

    /**
     * Release output instance.
     * @return Promise used to return the result.
     * @since 9
     * @syscap SystemCapability.Multimedia.Camera.Core
     */
    release(): Promise<void>;
  }

  /**
   * Preview output object.
   * @since 9
   * @syscap SystemCapability.Multimedia.Camera.Core
   */
  interface PreviewOutput extends CameraOutput {
    /**
     * Start output instance.
     * @param callback Callback used to return the result.
     * @since 9
     * @syscap SystemCapability.Multimedia.Camera.Core
     */
    start(callback: AsyncCallback<void>): void;

    /**
     * Start output instance.
     * @return Promise used to return the result.
     * @since 9
     * @syscap SystemCapability.Multimedia.Camera.Core
     */
    start(): Promise<void>;

    /**
     * Stop output instance.
     * @param callback Callback used to return the result.
     * @since 9
     * @syscap SystemCapability.Multimedia.Camera.Core
     */
    stop(callback: AsyncCallback<void>): void;

    /**
     * Stop output instance.
     * @return Promise used to return the result.
     * @since 9
     * @syscap SystemCapability.Multimedia.Camera.Core
     */
    stop(): Promise<void>;

    /**
     * Subscribes frame start event callback.
     * @param type Event type.
     * @param callback Callback used to return the result.
     * @since 9
     * @syscap SystemCapability.Multimedia.Camera.Core
     */
    on(type: 'frameStart', callback: AsyncCallback<void>): void;

    /**
     * Subscribes frame end event callback.
     * @param type Event type.
     * @param callback Callback used to return the result.
     * @since 9
     * @syscap SystemCapability.Multimedia.Camera.Core
     */
    on(type: 'frameEnd', callback: AsyncCallback<void>): void;

    /**
     * Subscribes error event callback.
     * @param type Event type.
     * @param callback Callback used to get the preview output errors.
     * @since 9
     * @syscap SystemCapability.Multimedia.Camera.Core
     */
    on(type: 'error', callback: ErrorCallback<PreviewOutputError>): void;
  }

  /**
   * Enum for preview output error code.
   * @since 9
   * @syscap SystemCapability.Multimedia.Camera.Core
   */
  enum PreviewOutputErrorCode {
    /**
     * Unknown error.
     * @since 9
     */
    ERROR_UNKNOWN = -1,
  }

  /**
   * Preview output error object.
   * @since 9
   * @syscap SystemCapability.Multimedia.Camera.Core
   */
  interface PreviewOutputError extends Error {
    code: PreviewOutputErrorCode;
  }

  /**
   * Enumerates the image rotation angles.
   * @since 9
   * @syscap SystemCapability.Multimedia.Camera.Core
   */
  enum ImageRotation {
    /**
     * The capture image rotates 0 degrees.
     * @since 9
     * @syscap SystemCapability.Multimedia.Camera.Core
     */
    ROTATION_0 = 0,

    /**
     * The capture image rotates 90 degrees.
     * @since 9
     * @syscap SystemCapability.Multimedia.Camera.Core
     */
    ROTATION_90 = 90,

    /**
     * The capture image rotates 180 degrees.
     * @since 9
     * @syscap SystemCapability.Multimedia.Camera.Core
     */
    ROTATION_180 = 180,

    /**
     * The capture image rotates 270 degrees.
     * @since 9
     * @syscap SystemCapability.Multimedia.Camera.Core
     */
    ROTATION_270 = 270
  }

  interface Location {
    /**
     * Latitude.
     * @since 9
     */
    latitude: number;

    /**
     * Longitude.
     * @since 9
     */
    longitude: number;

    /**
     * Altitude.
     * @since 9
     */
    altitude: number;
  }

  /**
   * Enumerates the image quality levels.
   * @since 9
   * @syscap SystemCapability.Multimedia.Camera.Core
   */
  enum QualityLevel {
    /**
     * High image quality.
     * @since 9
     * @syscap SystemCapability.Multimedia.Camera.Core
     */
    QUALITY_LEVEL_HIGH = 0,

    /**
     * Medium image quality.
     * @since 9
     * @syscap SystemCapability.Multimedia.Camera.Core
     */
    QUALITY_LEVEL_MEDIUM = 1,

    /**
     * Low image quality.
     * @since 9
     * @syscap SystemCapability.Multimedia.Camera.Core
     */
    QUALITY_LEVEL_LOW = 2
  }

  /**
   * Photo capture options to set.
   * @since 9
   */
  interface PhotoCaptureSetting {
    /**
     * Photo image quality.
     * @since 9
     * @syscap SystemCapability.Multimedia.Camera.Core
     */
    quality?: QualityLevel;

    /**
     * Photo rotation.
     * @since 9
     * @syscap SystemCapability.Multimedia.Camera.Core
     */
    rotation?: ImageRotation;

    /**
     * Photo location.
     * @since 9
     * @syscap SystemCapability.Multimedia.Camera.Core
     */
    location?: Location;

    /**
     * Set the mirror photo function switch, default to false.
     * @since 9
     * @syscap SystemCapability.Multimedia.Camera.Core
     */
    mirror?: boolean;
  }

  /**
   * Photo output object.
   * @since 9
   * @syscap SystemCapability.Multimedia.Camera.Core
   */
  interface PhotoOutput extends CameraOutput {
    /**
     * Start capture output.
     * @param callback Callback used to return the result.
     * @since 9
     * @syscap SystemCapability.Multimedia.Camera.Core
     */
    capture(callback: AsyncCallback<void>): void;

    /**
     * Start capture output.
     * @param setting Photo capture settings.
     * @param callback Callback used to return the result.
     * @since 9
     * @syscap SystemCapability.Multimedia.Camera.Core
     */
    capture(setting: PhotoCaptureSetting, callback: AsyncCallback<void>): void;

    /**
     * Start capture output.
     * @param setting Photo capture settings.
     * @return Promise used to return the result.
     * @since 9
     * @syscap SystemCapability.Multimedia.Camera.Core
     */
    capture(setting?: PhotoCaptureSetting): Promise<void>;

    /**
     * Check whether to support mirror photo.
     * @param callback Callback used to return the mirror support status.
     * @since 9
     * @syscap SystemCapability.Multimedia.Camera.Core
     */
    isMirrorSupported(callback: AsyncCallback<boolean>): void;

    /**
     * Check whether to support mirror photo.
     * @return Promise used to return the mirror support status.
     * @since 9
     * @syscap SystemCapability.Multimedia.Camera.Core
     */
    isMirrorSupported(): Promise<boolean>;

    /**
     * Subscribes capture start event callback.
     * @param type Event type.
     * @param callback Callback used to get the capture ID.
     * @since 9
     * @syscap SystemCapability.Multimedia.Camera.Core
     */
    on(type: 'captureStart', callback: AsyncCallback<number>): void;

    /**
     * Subscribes frame shutter event callback.
     * @param type Event type.
     * @param callback Callback used to get the frame shutter information.
     * @since 9
     * @syscap SystemCapability.Multimedia.Camera.Core
     */
    on(type: 'frameShutter', callback: AsyncCallback<FrameShutterInfo>): void;

    /**
     * Subscribes capture end event callback.
     * @param type Event type.
     * @param callback Callback used to get the capture end information.
     * @since 9
     * @syscap SystemCapability.Multimedia.Camera.Core
     */
    on(type: 'captureEnd', callback: AsyncCallback<CaptureEndInfo>): void;

    /**
     * Subscribes error event callback.
     * @param type Event type.
     * @param callback Callback used to get the photo output errors.
     * @since 9
     * @syscap SystemCapability.Multimedia.Camera.Core
     */
    on(type: 'error', callback: ErrorCallback<PhotoOutputError>): void;
  }

  /**
   * Frame shutter callback info.
   * @since 9
   * @syscap SystemCapability.Multimedia.Camera.Core
   */
  interface FrameShutterInfo {
    /**
     * Capture id.
     * @since 9
     * @syscap SystemCapability.Multimedia.Camera.Core
     */
    captureId: number;
    /**
     * Timestamp for frame.
     * @since 9
     * @syscap SystemCapability.Multimedia.Camera.Core
     */
    timestamp: number;
  }

  /**
   * Capture end info.
   * @since 9
   * @syscap SystemCapability.Multimedia.Camera.Core
   */
  interface CaptureEndInfo {
    /**
     * Capture id.
     * @since 9
     * @syscap SystemCapability.Multimedia.Camera.Core
     */
    captureId: number;
    /**
     * Frame count.
     * @since 9
     * @syscap SystemCapability.Multimedia.Camera.Core
     */
    frameCount: number;
  }

  /**
   * Enum for photo output error code.
   * @since 9
   * @syscap SystemCapability.Multimedia.Camera.Core
   */
  enum PhotoOutputErrorCode {
    /**
     * Unknown error.
     * @since 9
     */
    ERROR_UNKNOWN = -1,
    /**
     * Driver error.
     * @since 9
     */
    ERROR_DRIVER_ERROR = 0,
    /**
     * Insufficient resources.
     * @since 9
     */
    ERROR_INSUFFICIENT_RESOURCES = 1,
    /**
     * Timeout error.
     * @since 9
     */
    ERROR_TIMEOUT = 2
  }

  /**
   * Photo output error object.
   * @since 9
   * @syscap SystemCapability.Multimedia.Camera.Core
   */
  interface PhotoOutputError extends Error {
    code: PhotoOutputErrorCode;
  }

  /**
   * Video output object.
   * @since 9
   * @syscap SystemCapability.Multimedia.Camera.Core
   */
  interface VideoOutput extends CameraOutput {
    /**
     * Start video output.
     * @param callback Callback used to return the result.
     * @since 9
     * @syscap SystemCapability.Multimedia.Camera.Core
     */
    start(callback: AsyncCallback<void>): void;

    /**
     * Start video output.
     * @return Promise used to return the result.
     * @since 9
     * @syscap SystemCapability.Multimedia.Camera.Core
     */
    start(): Promise<void>;

    /**
     * Stop video output.
     * @param callback Callback used to return the result.
     * @since 9
     * @syscap SystemCapability.Multimedia.Camera.Core
     */
    stop(callback: AsyncCallback<void>): void;

    /**
     * Stop video output.
     * @return Promise used to return the result.
     * @since 9
     * @syscap SystemCapability.Multimedia.Camera.Core
     */
    stop(): Promise<void>;

    /**
     * Subscribes frame start event callback.
     * @param type Event type.
     * @param callback Callback used to return the result.
     * @since 9
     * @syscap SystemCapability.Multimedia.Camera.Core
     */
    on(type: 'frameStart', callback: AsyncCallback<void>): void;

    /**
     * Subscribes frame end event callback.
     * @param type Event type.
     * @param callback Callback used to return the result.
     * @since 9
     * @syscap SystemCapability.Multimedia.Camera.Core
     */
    on(type: 'frameEnd', callback: AsyncCallback<void>): void;

    /**
     * Subscribes error event callback.
     * @param type Event type.
     * @param callback Callback used to get the video output errors.
     * @since 9
     * @syscap SystemCapability.Multimedia.Camera.Core
     */
    on(type: 'error', callback: ErrorCallback<VideoOutputError>): void;
  }

  /**
   * Enum for video output error code.
   * @since 9
   * @syscap SystemCapability.Multimedia.Camera.Core
   */
  enum VideoOutputErrorCode {
    /**
     * Unknown error.
     * @since 9
     */
    ERROR_UNKNOWN = -1,
    /**
     * Driver error.
     * @since 9
     */
    ERROR_DRIVER_ERROR = 0
  }

  /**
   * Video output error object.
   * @since 9
   * @syscap SystemCapability.Multimedia.Camera.Core
   */
  interface VideoOutputError extends Error {
    code: VideoOutputErrorCode;
  }

  /**
   * Metadata object type.
   * @since 9
   * @syscap SystemCapability.Multimedia.Camera.Core
   */
  enum MetadataObjectType {
    FACE_DETECTION = 0
  }

  /**
   * Rectangle definition.
   * @since 9
   * @syscap SystemCapability.Multimedia.Camera.Core
   */
  interface Rect {
    /**
     * X coordinator of top left point.
     * @param Promise used to return the result.
     * @since 9
     * @syscap SystemCapability.Multimedia.Camera.Core
     */
    topLeftX: number;
    /**
     * Y coordinator of top left point.
     * @param Promise used to return the result.
     * @since 9
     * @syscap SystemCapability.Multimedia.Camera.Core
     */
    topLeftY: number;
    /**
     * Width of this rectangle.
     * @since 9
     * @syscap SystemCapability.Multimedia.Camera.Core
     */
    width: number;
    /**
     * Height of this rectangle.
     * @since 9
     * @syscap SystemCapability.Multimedia.Camera.Core
     */
    height: number;
  }

  /**
   * Metadata object basis.
   * @since 9
   * @syscap SystemCapability.Multimedia.Camera.Core
   */
  interface MetadataObject {
    /**
     * Get current metadata object type.
     * @param callback Callback used to return the result.
     * @since 9
     * @syscap SystemCapability.Multimedia.Camera.Core
     */
    getType(callback: AsyncCallback<MetadataObjectType>): void;

    /**
     * Get current metadata object type.
     * @param Promise used to return the result.
     * @since 9
     * @syscap SystemCapability.Multimedia.Camera.Core
     */
    getType(): Promise<MetadataObjectType>;

    /**
     * Get current metadata object timestamp in milliseconds.
     * @param callback Callback used to return the result.
     * @since 9
     * @syscap SystemCapability.Multimedia.Camera.Core
     */
    getTimestamp(callback: AsyncCallback<number>): void;

    /**
     * Get current metadata object timestamp in milliseconds.
     * @param Promise used to return the result.
     * @since 9
     * @syscap SystemCapability.Multimedia.Camera.Core
     */
    getTimestamp(): Promise<number>;

    /**
     * Get the axis-aligned bounding box of detected metadata object.
     * @param callback Callback used to return the result.
     * @since 9
     * @syscap SystemCapability.Multimedia.Camera.Core
     */
    getBoundingBox(callback: AsyncCallback<Rect>): void;

    /**
     * Get the axis-aligned bounding box of detected metadata object.
     * @param Promise used to return the result.
     * @since 9
     * @syscap SystemCapability.Multimedia.Camera.Core
     */
    getBoundingBox(): Promise<Rect>;
  }

  /**
   * Metadata face object.
   * @since 9
   * @syscap SystemCapability.Multimedia.Camera.Core
   */
  interface MetadataFaceObject extends MetadataObject {
  }

  /**
   * Metadata Output object
   * @since 9
   * @syscap SystemCapability.Multimedia.Camera.Core
   */
  interface MetadataOutput extends CameraOutput {
    /**
     * Start output metadata
     * @param callback Callback used to return the result.
     * @since 9
     * @syscap SystemCapability.Multimedia.Camera.Core
     */
    start(callback: AsyncCallback<void>): void;

    /**
     * Start output metadata
     * @return Promise used to return the result.
     * @since 9
     * @syscap SystemCapability.Multimedia.Camera.Core
     */
    start(): Promise<void>;

    /**
     * Stop output metadata
     * @param callback Callback used to return the result.
     * @since 9
     * @syscap SystemCapability.Multimedia.Camera.Core
     */
    stop(callback: AsyncCallback<void>): void;

    /**
     * Stop output metadata
     * @return Promise used to return the result.
     * @since 9
     * @syscap SystemCapability.Multimedia.Camera.Core
     */
    stop(): Promise<void>;

    /**
     * Subscribes to metadata objects available event callback.
     * @param type Event type.
     * @param callback Callback used to get the available metadata objects.
     * @since 9
     * @syscap SystemCapability.Multimedia.Camera.Core
     */
    on(type: 'metadataObjectsAvailable', callback: AsyncCallback<Array<MetadataObject>>): void;

    /**
     * Subscribes error event callback.
     * @param type Event type.
     * @param callback Callback used to get the video output errors.
     * @since 9
     * @syscap SystemCapability.Multimedia.Camera.Core
     */
    on(type: 'error', callback: ErrorCallback<MetadataOutputError>): void;
  }

  /**
   * Enum for metadata output error code.
   * @since 9
   * @syscap SystemCapability.Multimedia.Camera.Core
   */
  enum MetadataOutputErrorCode {
    /**
     * Unknown errors.
     * @since 9
     */
    ERROR_UNKNOWN = -1,
    /**
     * Insufficient resources.
     * @since 9
     */
    ERROR_INSUFFICIENT_RESOURCES = 0
  }

  /**
   * Metadata output error object.
   * @since 9
   * @syscap SystemCapability.Multimedia.Camera.Core
   */
  interface MetadataOutputError extends Error {
    code: MetadataOutputErrorCode;
  }
}

export default camera;
