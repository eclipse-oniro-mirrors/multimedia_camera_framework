/*
* Copyright (C) 2024 Huawei Device Co., Ltd.
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

/**
* @file
* @kit CameraKit
*/

import { ErrorCallback, AsyncCallback } from './@ohos.base';
import type Context from './application/BaseContext';
import image from './@ohos.multimedia.image';
import type colorSpaceManager from './@ohos.graphics.colorSpaceManager';
import photoAccessHelper from './@ohos.file.photoAccessHelper';

/**
* @namespace camera
* @syscap SystemCapability.Multimedia.Camera.Core
* @since 10
*/
/**
* @namespace camera
* @syscap SystemCapability.Multimedia.Camera.Core
* @atomicservice
* @since 12
*/
declare namespace camera {
/**
* Creates a CameraManager instance.
*
* @param { Context } context - Current application context.
* @returns { CameraManager } CameraManager instance.
* @throws { BusinessError } 7400101 - Parameter missing or parameter type incorrect.
* @throws { BusinessError } 7400201 - Camera service fatal error.
* @syscap SystemCapability.Multimedia.Camera.Core
* @since 10
*/
function getCameraManager(context: Context): CameraManager;

  /**
   * Enum for camera status.
   *
   * @enum { number }
   * @syscap SystemCapability.Multimedia.Camera.Core
   * @since 10
   */
  enum CameraStatus {
    /**
     * Appear status.
     *
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @since 10
     */
    CAMERA_STATUS_APPEAR = 0,

    /**
     * Disappear status.
     *
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @since 10
     */
    CAMERA_STATUS_DISAPPEAR = 1,

    /**
     * Available status.
     *
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @since 10
     */
    CAMERA_STATUS_AVAILABLE = 2,

    /**
     * Unavailable status.
     *
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @since 10
     */
    CAMERA_STATUS_UNAVAILABLE = 3
  }

  /**
   * Enum for fold status.
   *
   * @enum { number }
   * @syscap SystemCapability.Multimedia.Camera.Core
   * @since 12
   */
  enum FoldStatus {
    /**
     * Non-foldable status.
     *
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @since 12
     */
    NON_FOLDABLE = 0,

    /**
     * Expanded status.
     *
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @since 12
     */
    EXPANDED = 1,

    /**
     * Folded status.
     *
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @since 12
     */
    FOLDED = 2
  }

  /**
   * Enum for the system pressure level.
   *
   * @enum { number }
   * @syscap SystemCapability.Multimedia.Camera.Core
   * @since 20
   */
    enum SystemPressureLevel {
      /**
       * System pressure normal.
       *
       * @syscap SystemCapability.Multimedia.Camera.Core
       * @since 20
       */
      SYSTEM_PRESSURE_NORMAL = 0,
   
      /**
       * System pressure mild.
       *
       * @syscap SystemCapability.Multimedia.Camera.Core
       * @since 20
       */
      SYSTEM_PRESSURE_MILD = 1,
   
      /**
       * System pressure severe.
       *
       * @syscap SystemCapability.Multimedia.Camera.Core
       * @since 20
       */
      SYSTEM_PRESSURE_SEVERE = 2,
   
      /**
       * System pressure critical.
       *
       * @syscap SystemCapability.Multimedia.Camera.Core
       * @since 20
       */
      SYSTEM_PRESSURE_CRITICAL = 3,
   
      /**
       * System pressure shutdown.
       *
       * @syscap SystemCapability.Multimedia.Camera.Core
       * @since 20
       */
      SYSTEM_PRESSURE_SHUTDOWN = 4
    }

  /**
   * Profile for camera streams.
   *
   * @typedef Profile
   * @syscap SystemCapability.Multimedia.Camera.Core
   * @since 10
   */
  interface Profile {
    /**
     * Camera format.
     *
     * @type { CameraFormat }
     * @readonly
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @since 10
     */
    readonly format: CameraFormat;

    /**
     * Picture size.
     *
     * @type { Size }
     * @readonly
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @since 10
     */
    readonly size: Size;
  }

  /**
   * Frame rate range.
   *
   * @typedef FrameRateRange
   * @syscap SystemCapability.Multimedia.Camera.Core
   * @since 10
   */
  interface FrameRateRange {
    /**
     * Min frame rate.
     *
     * @type { number }
     * @readonly
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @since 10
     */
    readonly min: number;

    /**
     * Max frame rate.
     *
     * @type { number }
     * @readonly
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @since 10
     */
    readonly max: number;
  }

  /**
   * Video profile.
   *
   * @typedef VideoProfile
   * @syscap SystemCapability.Multimedia.Camera.Core
   * @since 10
   */
  interface VideoProfile extends Profile {
    /**
     * Frame rate in unit fps (frames per second).
     *
     * @type { FrameRateRange }
     * @readonly
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @since 10
     */
    readonly frameRateRange: FrameRateRange;
  }

  /**
   * Camera output capability.
   *
   * @typedef CameraOutputCapability
   * @syscap SystemCapability.Multimedia.Camera.Core
   * @since 10
   */
  interface CameraOutputCapability {
    /**
     * Preview profiles.
     *
     * @type { Array<Profile> }
     * @readonly
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @since 10
     */
    readonly previewProfiles: Array<Profile>;

    /**
     * Photo profiles.
     *
     * @type { Array<Profile> }
     * @readonly
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @since 10
     */
    readonly photoProfiles: Array<Profile>;

    /**
     * Video profiles.
     *
     * @type { Array<VideoProfile> }
     * @readonly
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @since 10
     */
    readonly videoProfiles: Array<VideoProfile>;

    /**
     * Depth profiles.
     *
     * @type { Array<DepthProfile> }
     * @readonly
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @systemapi
     * @since 13
     */
    readonly depthProfiles: Array<DepthProfile>;

    /**
     * All the supported metadata Object Types.
     *
     * @type { Array<MetadataObjectType> }
     * @readonly
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @since 10
     */
    readonly supportedMetadataObjectTypes: Array<MetadataObjectType>;
  }

  /**
   * Control center status info.
   *
   * @typedef ControlCenterStatusInfo
   * @syscap SystemCapability.Multimedia.Camera.Core
   * @since 20
   */
    interface ControlCenterStatusInfo {
      /**
       * Control center effect type.
       *
       * @type { ControlCenterEffectType }
       * @readonly
       * @syscap SystemCapability.Multimedia.Camera.Core
       * @since 20
       */
      readonly effectType: ControlCenterEffectType;
   
      /**
       * If effect type is active.
       *
       * @type { boolean }
       * @readonly
       * @syscap SystemCapability.Multimedia.Camera.Core
       * @since 20
       */
      readonly isActive: boolean;
    }

  /**
   * Enum for camera error code.
   *
   * @enum { number }
   * @syscap SystemCapability.Multimedia.Camera.Core
   * @since 10
   */
  enum CameraErrorCode {
    /**
     * Parameter missing or parameter type incorrect.
     *
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @since 10
     */
    INVALID_ARGUMENT = 7400101,

    /**
     * Operation not allowed.
     *
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @since 10
     */
    OPERATION_NOT_ALLOWED = 7400102,

    /**
     * Session not config.
     *
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @since 10
     */
    SESSION_NOT_CONFIG = 7400103,

    /**
     * Session not running.
     *
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @since 10
     */
    SESSION_NOT_RUNNING = 7400104,

    /**
     * Session config locked.
     *
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @since 10
     */
    SESSION_CONFIG_LOCKED = 7400105,

    /**
     * Device setting locked.
     *
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @since 10
     */
    DEVICE_SETTING_LOCKED = 7400106,

    /**
     * Can not use camera cause of conflict.
     *
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @since 10
     */
    CONFLICT_CAMERA = 7400107,

    /**
     * Camera disabled cause of security reason.
     *
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @since 10
     */
    DEVICE_DISABLED = 7400108,

    /**
     * Can not use camera cause of preempted.
     *
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @since 10
     */
    DEVICE_PREEMPTED = 7400109,

    /**
     * Unresolved conflicts with current configurations.
     *
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @since 12
     */
    UNRESOLVED_CONFLICTS_WITH_CURRENT_CONFIGURATIONS = 7400110,

    /**
     * Camera service fatal error.
     *
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @since 10
     */
    SERVICE_FATAL_ERROR = 7400201
  }

  /**
   * Enum for restore parameter.
   *
   * @enum { number }
   * @syscap SystemCapability.Multimedia.Camera.Core
   * @systemapi
   * @since 11
   */
  enum RestoreParamType {
    /**
     * No need set restore Stream Parameter, only prelaunch camera device.
     *
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @systemapi
     * @since 11
     */
    NO_NEED_RESTORE_PARAM = 0,

    /**
     * Presistent default parameter, long-lasting effect after T minutes.
     *
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @systemapi
     * @since 11
     */
    PRESISTENT_DEFAULT_PARAM = 1,

    /**
     * Transient active parameter, which has a higher priority than PRESISTENT_DEFAULT_PARAM when both exist.
     *
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @systemapi
     * @since 11
     */
    TRANSIENT_ACTIVE_PARAM = 2
  }

  /**
   * Setting parameter for stream.
   *
   * @typedef SettingParam
   * @syscap SystemCapability.Multimedia.Camera.Core
   * @systemapi
   * @since 11
   */
  interface SettingParam {
    /**
     * Skin smooth level value for restore.
     *
     * @type { number }
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @systemapi
     * @since 11
     */
    skinSmoothLevel: number;

    /**
     * Face slender value for restore.
     *
     * @type { number }
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @systemapi
     * @since 11
     */
    faceSlender: number;

    /**
     * Skin tone value for restore.
     *
     * @type { number }
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @systemapi
     * @since 11
     */
    skinTone: number;
  }

  /**
   * Prelaunch config object.
   *
   * @typedef PrelaunchConfig
   * @syscap SystemCapability.Multimedia.Camera.Core
   * @systemapi
   * @since 10
   */
  interface PrelaunchConfig {
    /**
     * Camera instance.
     *
     * @type { CameraDevice }
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @systemapi
     * @since 10
     */
    cameraDevice: CameraDevice;

    /**
     * Restore parameter type.
     *
     * @type { ?RestoreParamType }
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @systemapi
     * @since 11
     */
    restoreParamType?: RestoreParamType;

    /**
     * Begin active time.
     *
     * @type { ?number }
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @systemapi
     * @since 11
     */
    activeTime?: number;

    /**
     * Setting parameter.
     *
     * @type { ?SettingParam }
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @systemapi
     * @since 11
     */
    settingParam?: SettingParam;
  }

  /**
   * Camera manager object.
   *
   * @interface CameraManager
   * @syscap SystemCapability.Multimedia.Camera.Core
   * @since 10
   */
  interface CameraManager {
    /**
     * Gets supported camera descriptions.
     *
     * @returns { Array<CameraDevice> } An array of supported cameras.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @since 10
     */
    getSupportedCameras(): Array<CameraDevice>;

    /**
     * Gets supported output capability for specific camera.
     *
     * @param { CameraDevice } camera - Camera device.
     * @returns { CameraOutputCapability } The camera output capability.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @since 10
     * @deprecated since 11
     * @useinstead ohos.multimedia.camera.CameraManager#getSupportedOutputCapability
     */
    getSupportedOutputCapability(camera: CameraDevice): CameraOutputCapability;

    /**
     * Gets supported scene mode for specific camera.
     *
     * @param { CameraDevice } camera - Camera device.
     * @returns { Array<SceneMode> } An array of supported scene mode of camera.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @since 11
     */
    getSupportedSceneModes(camera: CameraDevice): Array<SceneMode>;

    /**
     * Gets supported output capability for specific camera.
     *
     * @param { CameraDevice } camera - Camera device.
     * @param { SceneMode } mode - Scene mode.
     * @returns { CameraOutputCapability } The camera output capability.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @since 11
     */
    getSupportedOutputCapability(camera: CameraDevice, mode: SceneMode): CameraOutputCapability;

    /**
     * Determine whether camera is muted.
     *
     * @returns { boolean } Is camera muted.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @since 10
     */
    isCameraMuted(): boolean;

    /**
     * Determine whether camera mute is supported.
     *
     * @returns { boolean } Is camera mute supported.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @systemapi
     * @since 10
     */
    /**
     * Determine whether camera mute is supported.
     *
     * @returns { boolean } Is camera mute supported.
     * @throws { BusinessError } 202 - Permission verification failed. A non-system application calls a system API.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @systemapi
     * @since 13
     */
    isCameraMuteSupported(): boolean;

    /**
     * Mute camera.
     *
     * @param { boolean } mute - Mute camera if TRUE, otherwise unmute camera.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @systemapi
     * @since 10
     * @deprecated since 12
     * @useinstead ohos.multimedia.camera.CameraManager#muteCameraPersistent
     */
    muteCamera(mute: boolean): void;

    /**
     * Mutes or unmutes camera for persistence purpose.
     *
     * @permission ohos.camera.CAMERA_CONTROL
     * @param { boolean } mute - Mute camera if TRUE, otherwise unmute camera.
     * @param { PolicyType } type - Type for indicating the calling role.
     * @throws { BusinessError } 201 - Permission denied.
     * @throws { BusinessError } 202 - Not System Application.
     * @throws { BusinessError } 7400101 - Parameter missing or parameter type incorrect.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @systemapi
     * @since 12
     */
    muteCameraPersistent(mute: boolean, type: PolicyType): void;

    /**
     * Creates a CameraInput instance by camera.
     *
     * @permission ohos.permission.CAMERA
     * @param { CameraDevice } camera - Camera device used to create the instance.
     * @returns { CameraInput } The CameraInput instance.
     * @throws { BusinessError } 7400101 - Parameter missing or parameter type incorrect.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @since 10
     */
    /**
     * Creates a CameraInput instance by camera.
     *
     * @permission ohos.permission.CAMERA
     * @param { CameraDevice } camera - Camera device used to create the instance.
     * @returns { CameraInput } The CameraInput instance.
     * @throws { BusinessError } 7400101 - Parameter missing or parameter type incorrect.
     * @throws { BusinessError } 7400102 - Operation not allowed.
     * @throws { BusinessError } 7400201 - Camera service fatal error.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @since 12
     */
    createCameraInput(camera: CameraDevice): CameraInput;

    /**
     * Creates a CameraInput instance by camera position and type.
     *
     * @permission ohos.permission.CAMERA
     * @param { CameraPosition } position - Target camera position.
     * @param { CameraType } type - Target camera type.
     * @returns { CameraInput } The CameraInput instance.
     * @throws { BusinessError } 7400101 - Parameter missing or parameter type incorrect.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @since 10
     */
    /**
     * Creates a CameraInput instance by camera position and type.
     *
     * @permission ohos.permission.CAMERA
     * @param { CameraPosition } position - Target camera position.
     * @param { CameraType } type - Target camera type.
     * @returns { CameraInput } The CameraInput instance.
     * @throws { BusinessError } 7400101 - Parameter missing or parameter type incorrect.
     * @throws { BusinessError } 7400102 - Operation not allowed.
     * @throws { BusinessError } 7400201 - Camera service fatal error.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @since 12
     */
    createCameraInput(position: CameraPosition, type: CameraType): CameraInput;

    /**
     * Creates a PreviewOutput instance.
     *
     * @param { Profile } profile - Preview output profile.
     * @param { string } surfaceId - Surface object id used in camera photo output.
     * @returns { PreviewOutput } The PreviewOutput instance.
     * @throws { BusinessError } 7400101 - Parameter missing or parameter type incorrect.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @since 10
     */
    /**
     * Creates a PreviewOutput instance.
     *
     * @param { Profile } profile - Preview output profile.
     * @param { string } surfaceId - Surface object id used in camera photo output.
     * @returns { PreviewOutput } The PreviewOutput instance.
     * @throws { BusinessError } 7400101 - Parameter missing or parameter type incorrect.
     * @throws { BusinessError } 7400201 - Camera service fatal error.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @since 12
     */
    createPreviewOutput(profile: Profile, surfaceId: string): PreviewOutput;

    /**
     * Creates a PreviewOutput instance without profile.
     * You can use this method to create a preview output instance without a profile, This instance can
     * only be used in a preconfiged session.
     *
     * @param { string } surfaceId - Surface object id used in camera preview output.
     * @returns { PreviewOutput } The PreviewOutput instance.
     * @throws { BusinessError } 7400101 - Parameter missing or parameter type incorrect.
     * @throws { BusinessError } 7400201 - Camera service fatal error.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @since 12
     */
    createPreviewOutput(surfaceId: string): PreviewOutput;

    /**
     * Creates a PhotoOutput instance.
     *
     * @param { Profile } profile - Photo output profile.
     * @param { string } surfaceId - Surface object id used in camera photo output.
     * @returns { PhotoOutput } The PhotoOutput instance.
     * @throws { BusinessError } 7400101 - Parameter missing or parameter type incorrect.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @since 10
     * @deprecated since 11
     * @useinstead ohos.multimedia.camera.CameraManager#createPhotoOutput
     */
    createPhotoOutput(profile: Profile, surfaceId: string): PhotoOutput;

    /**
     * Creates a PhotoOutput instance without surfaceId.
     * Call PhotoOutput capture interface will give a callback,
     * {@link on(type: 'photoAvailable', callback: AsyncCallback<Photo>)}
     *
     * @param { Profile } profile - Photo output profile.
     * @returns { PhotoOutput } The PhotoOutput instance.
     * @throws { BusinessError } 7400101 - Parameter missing or parameter type incorrect.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @since 11
     */
    /**
     * Creates a PhotoOutput instance without surfaceId.
     * Call PhotoOutput capture interface will give a callback,
     * {@link on(type: 'photoAvailable', callback: AsyncCallback<Photo>)}
     * You can use this method to create a photo output instance without a profile, This instance can
     * only be used in a preconfiged session.
     *
     * @param { Profile } profile - Photo output profile.
     * @returns { PhotoOutput } The PhotoOutput instance.
     * @throws { BusinessError } 7400101 - Parameter missing or parameter type incorrect.
     * @throws { BusinessError } 7400201 - Camera service fatal error.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @since 12
     */
    createPhotoOutput(profile?: Profile): PhotoOutput;

    /**
     * Creates a VideoOutput instance.
     *
     * @param { VideoProfile } profile - Video profile.
     * @param { string } surfaceId - Surface object id used in camera video output.
     * @returns { VideoOutput } The VideoOutput instance.
     * @throws { BusinessError } 7400101 - Parameter missing or parameter type incorrect.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @since 10
     */
    /**
     * Creates a VideoOutput instance.
     *
     * @param { VideoProfile } profile - Video profile.
     * @param { string } surfaceId - Surface object id used in camera video output.
     * @returns { VideoOutput } The VideoOutput instance.
     * @throws { BusinessError } 7400101 - Parameter missing or parameter type incorrect.
     * @throws { BusinessError } 7400201 - Camera service fatal error.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @since 12
     */
    createVideoOutput(profile: VideoProfile, surfaceId: string): VideoOutput;

    /**
     * Creates a VideoOutput instance without profile.
     * You can use this method to create a video output instance without a profile, This instance can
     * only be used in a preconfiged session.
     *
     * @param { string } surfaceId - Surface object id used in camera video output.
     * @returns { VideoOutput } The VideoOutput instance.
     * @throws { BusinessError } 7400101 - Parameter missing or parameter type incorrect.
     * @throws { BusinessError } 7400201 - Camera service fatal error.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @since 12
     */
    createVideoOutput(surfaceId: string): VideoOutput;

    /**
     * Creates a MetadataOutput instance.
     *
     * @param { Array<MetadataObjectType> } metadataObjectTypes - Array of MetadataObjectType.
     * @returns { MetadataOutput } The MetadataOutput instance.
     * @throws { BusinessError } 7400101 - Parameter missing or parameter type incorrect.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @since 10
     */
    /**
     * Creates a MetadataOutput instance.
     *
     * @param { Array<MetadataObjectType> } metadataObjectTypes - Array of MetadataObjectType.
     * @returns { MetadataOutput } The MetadataOutput instance.
     * @throws { BusinessError } 7400101 - Parameter missing or parameter type incorrect.
     * @throws { BusinessError } 7400201 - Camera service fatal error.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @since 12
     */
    createMetadataOutput(metadataObjectTypes: Array<MetadataObjectType>): MetadataOutput;

    /**
     * Creates a DepthDataOutput instance.
     *
     * @param { DepthProfile } profile - Depth data profile.
     * @returns { DepthDataOutput } The DepthDataOutput instance.
     * @throws { BusinessError } 202 - Not System Application.
     * @throws { BusinessError } 7400101 - Parameter missing or parameter type incorrect.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @systemapi
     * @since 13
     */
    createDepthDataOutput(profile: DepthProfile): DepthDataOutput;

    /**
     * Gets a CaptureSession instance.
     *
     * @returns { CaptureSession } The CaptureSession instance.
     * @throws { BusinessError } 7400201 - Camera service fatal error.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @since 10
     * @deprecated since 11
     * @useinstead ohos.multimedia.camera.CameraManager#createSession
     */
    createCaptureSession(): CaptureSession;

    /**
     * Gets a Session instance by specific scene mode.
     *
     * @param { SceneMode } mode - Scene mode.
     * @returns { T } The specific Session instance by specific scene mode.
     * @throws { BusinessError } 401 - Parameter error. Possible causes:
     * 1. Mandatory parameters are left unspecified; 2. Incorrect parameter types;
     * 3. Parameter verification failed.
     * @throws { BusinessError } 7400201 - Camera service fatal error.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @since 11
     */
    createSession<T extends Session>(mode: SceneMode): T;

    /**
     * Subscribes camera status change event callback.
     *
     * @param { 'cameraStatus' } type - Event type.
     * @param { AsyncCallback<CameraStatusInfo> } callback - Callback used to get the camera status change.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @since 10
     */
    on(type: 'cameraStatus', callback: AsyncCallback<CameraStatusInfo>): void;

    /**
     * Unsubscribes from camera status change event callback.
     *
     * @param { 'cameraStatus' } type - Event type.
     * @param { AsyncCallback<CameraStatusInfo> } callback - Callback used to get the camera status change.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @since 10
     */
    off(type: 'cameraStatus', callback?: AsyncCallback<CameraStatusInfo>): void;

    /**
     * Subscribes fold status change event callback.
     *
     * @param { 'foldStatusChanged' } type - Event type.
     * @param { AsyncCallback<FoldStatusInfo> } callback - Callback used to get the fold status change.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @since 12
     */
    on(type: 'foldStatusChange', callback: AsyncCallback<FoldStatusInfo>): void;

    /**
     * Unsubscribes from fold status change event callback.
     *
     * @param { 'foldStatusChanged' } type - Event type.
     * @param { AsyncCallback<FoldStatusInfo> } callback - Callback used to get the fold status change.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @since 12
     */
    off(type: 'foldStatusChange', callback?: AsyncCallback<FoldStatusInfo>): void;

    /**
     * Subscribes camera mute change event callback.
     *
     * @param { 'cameraMute' } type - Event type.
     * @param { AsyncCallback<boolean> } callback - Callback used to get the camera mute change.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @systemapi
     * @since 10
     */
    /**
     * Subscribes camera mute change event callback.
     *
     * @param { 'cameraMute' } type - Event type.
     * @param { AsyncCallback<boolean> } callback - Callback used to get the camera mute change.
     * @throws { BusinessError } 202 - Permission verification failed. A non-system application calls a system API.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @systemapi
     * @since 13
     */
    on(type: 'cameraMute', callback: AsyncCallback<boolean>): void;

    /**
     * Unsubscribes from camera mute change event callback.
     *
     * @param { 'cameraMute' } type - Event type.
     * @param { AsyncCallback<boolean> } callback - Callback used to get the camera mute change.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @systemapi
     * @since 10
     */
    /**
     * Unsubscribes from camera mute change event callback.
     *
     * @param { 'cameraMute' } type - Event type.
     * @param { AsyncCallback<boolean> } callback - Callback used to get the camera mute change.
     * @throws { BusinessError } 202 - Permission verification failed. A non-system application calls a system API.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @systemapi
     * @since 13
     */
    off(type: 'cameraMute', callback?: AsyncCallback<boolean>): void;

    /**
     * Subscribes control center status change event callback.
     *
     * @param { 'controlCenterStatusChange' } type - Event type.
     * @param { AsyncCallback<boolean> } callback - Callback used to get the control center status change.
     * @throws { BusinessError } 202 - Permission verification failed. A non-system application calls a system API.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @systemapi
     * @since 20
     */
    on(type: 'controlCenterStatusChange', callback: AsyncCallback<boolean>): void;
 
    /**
     * Unsubscribes control center status change event callback.
     *
     * @param { 'controlCenterStatusChange' } type - Event type.
     * @param { AsyncCallback<boolean> } callback - Callback used to get the control center status change.
     * @throws { BusinessError } 202 - Permission verification failed. A non-system application calls a system API.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @systemapi
     * @since 20
     */
    off(type: 'controlCenterStatusChange', callback?: AsyncCallback<boolean>): void;
 
    /**
     * Check if the control center active.
     *
     * @returns { boolean } this value that specifies whether the control center active.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @since 20
     */
    isControlCenterActive(): boolean;
 
    /**
     * Create a ControlCenterSession instance.
     * 
     * @returns { ControlCenterSession } the ControlCenterSession instance.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @since 20
     */
    createControlCenterSession(): ControlCenterSession;

    /**
     * Determines whether the camera device supports prelaunch.
     * This function must be called in prior to the setPrelaunchConfig and prelaunch functions.
     *
     * @param { CameraDevice } camera - Camera device.
     * @returns { boolean } Whether prelaunch is supported.
     * @throws { BusinessError } 7400101 - Parameter missing or parameter type incorrect.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @systemapi
     * @since 10
     */
    /**
     * Determines whether the camera device supports prelaunch.
     * This function must be called in prior to the setPrelaunchConfig and prelaunch functions.
     *
     * @param { CameraDevice } camera - Camera device.
     * @returns { boolean } Whether prelaunch is supported.
     * @throws { BusinessError } 202 - Permission verification failed. A non-system application calls a system API.
     * @throws { BusinessError } 7400101 - Parameter missing or parameter type incorrect.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @systemapi
     * @since 12
     */
    isPrelaunchSupported(camera: CameraDevice): boolean;

    /**
     * Sets the camera prelaunch configuration.
     * The configuration is sent to the camera service when you exit the camera or change the configuration next time.
     *
     * @permission ohos.permission.CAMERA
     * @param { PrelaunchConfig } prelaunchConfig - Prelaunch configuration info.
     * @throws { BusinessError } 7400101 - Parameter missing or parameter type incorrect.
     * @throws { BusinessError } 7400102 - Operation not allowed.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @systemapi
     * @since 10
     */
    /**
     * Sets the camera prelaunch configuration.
     * The configuration is sent to the camera service when you exit the camera or change the configuration next time.
     *
     * @permission ohos.permission.CAMERA
     * @param { PrelaunchConfig } prelaunchConfig - Prelaunch configuration info.
     * @throws { BusinessError } 202 - Not System Application.
     * @throws { BusinessError } 7400101 - Parameter missing or parameter type incorrect.
     * @throws { BusinessError } 7400102 - Operation not allowed.
     * @throws { BusinessError } 7400201 - Camera service fatal error.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @systemapi
     * @since 12
     */
    setPrelaunchConfig(prelaunchConfig: PrelaunchConfig): void;

    /**
     * Enable the camera to prelaunch and start.
     * This function is called when the user clicks the system camera icon to start the camera application.
     *
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @systemapi
     * @since 10
     */
    /**
     * Enable the camera to prelaunch and start.
     * This function is called when the user clicks the system camera icon to start the camera application.
     *
     * @throws { BusinessError } 202 - Not System Application.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @systemapi
     * @since 13
     */
    prelaunch(): void;

    /**
     * Prepare the camera resources.
     * This function is called when the user touch down the camera switch icon in camera application.
     *
     * @param { string } cameraId - The camera to prepare.
     * @throws { BusinessError } 202 - Not System Application.
     * @throws { BusinessError } 7400101 - Parameter missing or parameter type incorrect.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @systemapi
     * @since 11
     */
    /**
     * Prepare the camera resources.
     * This function is called when the user touch down the camera switch icon in camera application.
     *
     * @param { string } cameraId - The camera to prepare.
     * @throws { BusinessError } 202 - Not System Application.
     * @throws { BusinessError } 7400101 - Parameter missing or parameter type incorrect.
     * @throws { BusinessError } 7400201 - Camera service fatal error.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @systemapi
     * @since 12
     */
    preSwitchCamera(cameraId: string): void;

    /**
     * Creates a deferred PreviewOutput instance.
     *
     * @param { Profile } profile - Preview output profile.
     * @returns { PreviewOutput } the PreviewOutput instance.
     * @throws { BusinessError } 7400101 - Parameter missing or parameter type incorrect.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @systemapi
     * @since 10
     */
    /**
     * Creates a deferred PreviewOutput instance.
     * You can use the method to create deferred preview output without profile, then you must add this output
     * to a session which already preconfiged.
     *
     * @param { Profile } profile - Preview output profile.
     * @returns { PreviewOutput } the PreviewOutput instance.
     * @throws { BusinessError } 202 - Not System Application.
     * @throws { BusinessError } 7400101 - Parameter missing or parameter type incorrect.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @systemapi
     * @since 12
     */
    createDeferredPreviewOutput(profile?: Profile): PreviewOutput;

    /**
     * Check if the device has a torch.
     *
     * @returns { boolean } this value that specifies whether the device has a torch.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @since 11
     */
    isTorchSupported(): boolean;

    /**
     * Check if a specifies torch mode is supported.
     * @param { TorchMode } mode - torch mode.
     * @returns { boolean } is torch mode supported.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @since 11
     */
    isTorchModeSupported(mode: TorchMode): boolean;

    /**
     * Get current torch mode.
     *
     * @returns { TorchMode } torch mode.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @since 11
     */
    getTorchMode(): TorchMode;

    /**
     * Set torch mode to the device.
     *
     * @param { TorchMode } mode - torch mode.
     * @throws { BusinessError } 7400101 - Parameter missing or parameter type incorrect.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @since 11
     */
    /**
     * Set torch mode to the device.
     *
     * @param { TorchMode } mode - torch mode.
     * @throws { BusinessError } 7400101 - Parameter missing or parameter type incorrect.
     * @throws { BusinessError } 7400102 - Operation not allowed.
     * @throws { BusinessError } 7400201 - Camera service fatal error.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @since 12
     */
    setTorchMode(mode: TorchMode): void;

    /**
     * Subscribes torch status change event callback.
     *
     * @param { 'torchStatusChange' } type - Event type
     * @param { AsyncCallback<TorchStatusInfo> } callback - Callback used to return the torch status change
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @since 11
     */
    on(type: 'torchStatusChange', callback: AsyncCallback<TorchStatusInfo>): void;

    /**
     * Unsubscribes torch status change event callback.
     *
     * @param { 'torchStatusChange' } type - Event type
     * @param { AsyncCallback<TorchStatusInfo> } callback - Callback used to return the torch status change
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @since 11
     */
    off(type: 'torchStatusChange', callback?: AsyncCallback<TorchStatusInfo>): void;
  }

  /**
   * Torch status info.
   *
   * @typedef TorchStatusInfo
   * @syscap SystemCapability.Multimedia.Camera.Core
   * @since 11
   */
  interface TorchStatusInfo {
    /**
     * is torch available
     *
     * @type { boolean }
     * @readonly
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @since 11
     */
    readonly isTorchAvailable: boolean;

    /**
     * is torch active
     *
     * @type { boolean }
     * @readonly
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @since 11
     */
    readonly isTorchActive: boolean;

    /**
     * the current torch brightness level.
     *
     * @type { number }
     * @readonly
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @since 11
     */
    readonly torchLevel: number;
  }

  /**
   * Enum for torch mode.
   *
   * @enum { number }
   * @syscap SystemCapability.Multimedia.Camera.Core
   * @since 11
   */
  enum TorchMode {
    /**
     * The device torch is always off.
     *
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @since 11
     */
    OFF = 0,

    /**
     * The device torch is always on.
     *
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @since 11
     */
    ON = 1,

    /**
     * The device continuously monitors light levels and uses the torch when necessary.
     *
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @since 11
     */
    AUTO = 2
  }

  /**
   * Camera status info.
   *
   * @typedef CameraStatusInfo
   * @syscap SystemCapability.Multimedia.Camera.Core
   * @since 10
   */
  interface CameraStatusInfo {
    /**
     * Camera instance.
     *
     * @type { CameraDevice }
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @since 10
     */
    camera: CameraDevice;

    /**
     * Current camera status.
     *
     * @type { CameraStatus }
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @since 10
     */
    status: CameraStatus;
  }

  /**
   * Fold status info.
   *
   * @typedef FoldStatusInfo
   * @syscap SystemCapability.Multimedia.Camera.Core
   * @since 12
   */
  interface FoldStatusInfo {
    /**
     * Gets supported camera devices under the current fold status.
     *
     * @type { Array<CameraDevice> }
     * @readonly
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @since 12
     */
    readonly supportedCameras: Array<CameraDevice>;

    /**
     * Current fold status.
     *
     * @type { FoldStatus }
     * @readonly
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @since 12
     */
    readonly foldStatus: FoldStatus;
  }

  /**
   * Enum for camera position.
   *
   * @enum { number }
   * @syscap SystemCapability.Multimedia.Camera.Core
   * @since 10
   */
  /**
   * Enum for camera position.
   *
   * @enum { number }
   * @syscap SystemCapability.Multimedia.Camera.Core
   * @atomicservice
   * @since 12
   */
  enum CameraPosition {
    /**
     * Unspecified position.
     *
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @since 10
     */
    /**
     * Unspecified position.
     *
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @atomicservice
     * @since 12
     */
    CAMERA_POSITION_UNSPECIFIED = 0,

    /**
     * Back position.
     *
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @since 10
     */
    /**
     * Back position.
     *
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @atomicservice
     * @since 12
     */
    CAMERA_POSITION_BACK = 1,

    /**
     * Front position.
     *
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @since 10
     */
    /**
     * Front position.
     *
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @atomicservice
     * @since 12
     */
    CAMERA_POSITION_FRONT = 2,

    /**
     * Camera that is inner position when the device is folded.
     *
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @since 11
     */
    /**
     * Camera that is inner position when the device is folded.
     *
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @atomicservice
     * @since 12
     * @deprecated since 12
     */
    CAMERA_POSITION_FOLD_INNER = 3
  }

  /**
   * Enum for camera type.
   *
   * @enum { number }
   * @syscap SystemCapability.Multimedia.Camera.Core
   * @since 10
   */
  enum CameraType {
    /**
     * Default camera type
     *
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @since 10
     */
    CAMERA_TYPE_DEFAULT = 0,

    /**
     * Wide camera
     *
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @since 10
     */
    CAMERA_TYPE_WIDE_ANGLE = 1,

    /**
     * Ultra wide camera
     *
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @since 10
     */
    CAMERA_TYPE_ULTRA_WIDE = 2,

    /**
     * Telephoto camera
     *
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @since 10
     */
    CAMERA_TYPE_TELEPHOTO = 3,

    /**
     * True depth camera
     *
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @since 10
     */
    CAMERA_TYPE_TRUE_DEPTH = 4
  }

  /**
   * Enum for camera connection type.
   *
   * @enum { number }
   * @syscap SystemCapability.Multimedia.Camera.Core
   * @since 10
   */
  enum ConnectionType {
    /**
     * Built-in camera.
     *
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @since 10
     */
    CAMERA_CONNECTION_BUILT_IN = 0,

    /**
     * Camera connected using USB
     *
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @since 10
     */
    CAMERA_CONNECTION_USB_PLUGIN = 1,

    /**
     * Remote camera
     *
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @since 10
     */
    CAMERA_CONNECTION_REMOTE = 2
  }

  /**
   * Enum for remote camera device type.
   *
   * @enum { number }
   * @syscap SystemCapability.Multimedia.Camera.Core
   * @systemapi
   * @since 10
   */
    /**
   * Enum for remote camera device type.
   *
   * @enum { number }
   * @syscap SystemCapability.Multimedia.Camera.Core
   * @since 16
   */
  enum HostDeviceType {
    /**
     * Indicates an unknown device camera.
     *
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @systemapi
     * @since 10
     */
        /**
     * Indicates an unknown device camera.
     *
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @since 16
     */
    UNKNOWN_TYPE = 0,

    /**
     * Indicates a smartphone camera.
     *
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @systemapi
     * @since 10
     */
     /**
     * Indicates a smartphone camera.
     *
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @since 16
     */
    PHONE = 0x0E,

    /**
     * Indicates a tablet camera.
     *
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @systemapi
     * @since 10
     */
    /**
     * Indicates a tablet camera.
     *
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @since 16
     */
    TABLET = 0x11
  }

  /**
   * Camera device object.
   *
   * @typedef CameraDevice
   * @syscap SystemCapability.Multimedia.Camera.Core
   * @since 10
   */
  interface CameraDevice {
    /**
     * Camera id attribute.
     *
     * @type { string }
     * @readonly
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @since 10
     */
    readonly cameraId: string;

    /**
     * Camera position attribute.
     *
     * @type { CameraPosition }
     * @readonly
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @since 10
     */
    readonly cameraPosition: CameraPosition;

    /**
     * Camera type attribute.
     *
     * @type { CameraType }
     * @readonly
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @since 10
     */
    readonly cameraType: CameraType;

    /**
     * Camera connection type attribute.
     *
     * @type { ConnectionType }
     * @readonly
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @since 10
     */
    readonly connectionType: ConnectionType;

    /**
     * Camera remote camera device name attribute.
     *
     * @type { string }
     * @readonly
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @systemapi
     * @since 10
     */
    /**
     * Camera remote camera device name attribute.
     *
     * @type { string }
     * @readonly
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @since 16
     */
    readonly hostDeviceName: string;

    /**
     * Camera remote camera device type attribute.
     *
     * @type { HostDeviceType }
     * @readonly
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @systemapi
     * @since 10
     */
    /**
     * Camera remote camera device type attribute.
     *
     * @type { HostDeviceType }
     * @readonly
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @since 16
     */
    readonly hostDeviceType: HostDeviceType;

    /**
     * Camera sensor orientation attribute.
     *
     * @type { number }
     * @readonly
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @since 12
     */
    readonly cameraOrientation: number;

    /**
     * Camera lens equivalent focal length
     *
     * @type { ?Array<number> }
     * @readonly
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @systemapi
     * @since 20
     */
    readonly lensEquivalentFocalLength?: Array<number>;
  }

  /**
   * Size parameter.
   *
   * @typedef Size
   * @syscap SystemCapability.Multimedia.Camera.Core
   * @since 10
   */
  interface Size {
    /**
     * Height.
     *
     * @type { number }
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @since 10
     */
    height: number;

    /**
     * Width.
     *
     * @type { number }
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @since 10
     */
    width: number;
  }

  /**
   * Point parameter.
   *
   * @typedef Point
   * @syscap SystemCapability.Multimedia.Camera.Core
   * @since 10
   */
  interface Point {
    /**
     * x co-ordinate
     *
     * @type { number }
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @since 10
     */
    x: number;

    /**
     * y co-ordinate
     *
     * @type { number }
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @since 10
     */
    y: number;
  }

  /**
   * Camera input object.
   *
   * @interface CameraInput
   * @syscap SystemCapability.Multimedia.Camera.Core
   * @since 10
   */
  interface CameraInput {
    /**
     * Open camera.
     *
     * @param { AsyncCallback<void> } callback - Callback used to return the result.
     * @throws { BusinessError } 7400107 - Can not use camera cause of conflict.
     * @throws { BusinessError } 7400108 - Camera disabled cause of security reason.
     * @throws { BusinessError } 7400201 - Camera service fatal error.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @since 10
     */
    open(callback: AsyncCallback<void>): void;

    /**
     * Open camera.
     *
     * @returns { Promise<void> } Promise used to return the result.
     * @throws { BusinessError } 7400102 - Operation not allowed.
     * @throws { BusinessError } 7400107 - Can not use camera cause of conflict.
     * @throws { BusinessError } 7400108 - Camera disabled cause of security reason.
     * @throws { BusinessError } 7400201 - Camera service fatal error.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @since 10
     */
    open(): Promise<void>;

    /**
     * Open camera.
     *
     * @param { boolean } isSecureEnabled - Enable secure camera.
     * @returns { Promise<bigint> } Promise used to return the result.
     * @throws { BusinessError } 7400107 - Can not use camera cause of conflict.
     * @throws { BusinessError } 7400108 - Camera disabled cause of security reason.
     * @throws { BusinessError } 7400201 - Camera service fatal error.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @since 12
     */
    open(isSecureEnabled: boolean): Promise<bigint>;

    /**
     * Close camera.
     *
     * @param { AsyncCallback<void> } callback - Callback used to return the result.
     * @throws { BusinessError } 7400201 - Camera service fatal error.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @since 10
     */
    close(callback: AsyncCallback<void>): void;

    /**
     * Close camera.
     *
     * @returns { Promise<void> } Promise used to return the result.
     * @throws { BusinessError } 7400201 - Camera service fatal error.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @since 10
     */
    close(): Promise<void>;

    /**
     * Subscribes to error events.
     *
     * @param { 'error' } type - Event type.
     * @param { CameraDevice } camera - Camera device.
     * @param { ErrorCallback } callback - Callback used to get the camera input errors.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @since 10
     */
    on(type: 'error', camera: CameraDevice, callback: ErrorCallback): void;

    /**
     * Unsubscribes from error events.
     *
     * @param { 'error' } type - Event type.
     * @param { CameraDevice } camera - Camera device.
     * @param { ErrorCallback } callback - Callback used to get the camera input errors.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @since 10
     */
    off(type: 'error', camera: CameraDevice, callback?: ErrorCallback): void;

    /**
     * Subscribes to camera occlusion detection results.
     *
     * @param { 'cameraOcclusionDetection' } type - Event type.
     * @param { AsyncCallback<CameraOcclusionDetectionResult> } callback - Callback used to get detection results.
     * @throws { BusinessError } 202 - Not System Application.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @systemapi
     * @since 12
     */
    on(type: 'cameraOcclusionDetection', callback: AsyncCallback<CameraOcclusionDetectionResult>): void;

    /**
     * Unsubscribes from camera occlusion detection results.
     *
     * @param { 'cameraOcclusionDetection' } type - Event type.
     * @param { AsyncCallback<CameraOcclusionDetectionResult> } callback - Callback used to get detection results.
     * @throws { BusinessError } 202 - Not System Application.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @systemapi
     * @since 12
     */
    off(type: 'cameraOcclusionDetection', callback?: AsyncCallback<CameraOcclusionDetectionResult>): void;

    /**
     * Query whether physical sensor orientation is variable under different fold status.
     *
     * @returns { boolean } this value that specifies whether sensor orientation change with fold state.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @atomicservice
     * @since 21
     * @arkts 1.1&1.2
     */
    isPhysicalCameraOrientationVariable(): boolean;

    /**
     * Get physical camera orientation under current fold status.
     *
     * @returns { int } The sensor orientation map.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @atomicservice
     * @since 21
     * @arkts 1.1&1.2
     */
    getPhysicalCameraOrientation(): int;
  
    /**
     * Choose whether to use the physical camera orientation.
     *
     * @param { boolean } isUsed - Use Physical Camera Orientation.
     * @throws { BusinessError } 7400102 - Operation not allowed.
     * @throws { BusinessError } 7400201 - Camera service fatal error.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @atomicservice
     * @since 21
     * @arkts 1.1&1.2
     */
    usePhysicalCameraOrientation(isUsed: boolean): void;
  }

  /**
   * Enumerates the camera scene modes.
   *
   * @enum { number }
   * @syscap SystemCapability.Multimedia.Camera.Core
   * @since 11
   */
  enum SceneMode {
    /**
     * Normal photo mode.
     *
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @since 11
     */
    NORMAL_PHOTO = 1,

    /**
     * Normal video mode.
     *
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @since 11
     */
    NORMAL_VIDEO = 2,

    /**
     * Portrait photo mode.
     *
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @systemapi
     * @since 11
     */
    PORTRAIT_PHOTO = 3,

    /**
     * Night photo mode.
     *
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @systemapi
     * @since 11
     */
    NIGHT_PHOTO = 4,

    /**
     * Professional photo mode.
     *
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @systemapi
     * @since 12
     */
    PROFESSIONAL_PHOTO = 5,

    /**
     * Professional video mode.
     *
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @systemapi
     * @since 12
     */
    PROFESSIONAL_VIDEO = 6,

    /**
     * Slow motion video mode.
     *
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @systemapi
     * @since 12
     */
    SLOW_MOTION_VIDEO = 7,

    /**
     * Macro photo mode.
     *
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @systemapi
     * @since 12
     */
    MACRO_PHOTO = 8,

    /**
     * Macro video mode.
     *
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @systemapi
     * @since 12
     */
    MACRO_VIDEO = 9,

    /**
     * Light painting photo mode.
     *
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @systemapi
     * @since 12
     */
    LIGHT_PAINTING_PHOTO = 10,

    /**
     * High resolution mode.
     *
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @systemapi
     * @since 12
     */
    HIGH_RESOLUTION_PHOTO = 11,

    /**
     * Secure camera mode.
     *
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @since 12
     */
    SECURE_PHOTO = 12,

    /**
     * Quick shot mode.
     *
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @systemapi
     * @since 12
     */
    QUICK_SHOT_PHOTO = 13,

    /**
     * Aperture video mode.
     *
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @systemapi
     * @since 12
     */
    APERTURE_VIDEO = 14,

    /**
     * Panorama photo camera mode.
     *
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @systemapi
     * @since 12
     */
    PANORAMA_PHOTO = 15,

    /**
     * Timelapse photo camera mode.
     *
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @systemapi
     * @since 12
     */
    TIME_LAPSE_PHOTO = 16,

    /**
     * Fluorescence photo mode.
     *
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @systemapi
     * @since 13
     */
    FLUORESCENCE_PHOTO = 17
  }

  /**
   * Enum for camera format type.
   *
   * @enum { number }
   * @syscap SystemCapability.Multimedia.Camera.Core
   * @since 10
   */
  enum CameraFormat {
    /**
     * RGBA 8888 Format.
     *
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @since 10
     */
    CAMERA_FORMAT_RGBA_8888 = 3,

    /**
     * Digital negative Format.
     *
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @systemapi
     * @since 12
     */
    CAMERA_FORMAT_DNG = 4,

    /**
     * YUV 420 Format.
     *
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @since 10
     */
    CAMERA_FORMAT_YUV_420_SP = 1003,

    /**
     * JPEG Format.
     *
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @since 10
     */
    CAMERA_FORMAT_JPEG = 2000,

    /**
     * YCBCR P010 Format.
     *
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @since 11
     */
    CAMERA_FORMAT_YCBCR_P010,

    /**
     * YCRCB P010 Format.
     *
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @since 11
     */
    CAMERA_FORMAT_YCRCB_P010,

    /**
     * HEIC Format.
     *
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @since 13
     */
    CAMERA_FORMAT_HEIC = 2003,

    /**
     * Depth Data Format: float 16.
     *
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @systemapi
     * @since 13
     */
    CAMERA_FORMAT_DEPTH_16 = 3000,

    /**
     * Depth Data Format: float 32.
     *
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @systemapi
     * @since 13
     */
    CAMERA_FORMAT_DEPTH_32 = 3001
  }

  /**
   * Enum for flash mode.
   *
   * @enum { number }
   * @syscap SystemCapability.Multimedia.Camera.Core
   * @since 10
   */
  enum FlashMode {
    /**
     * Close mode.
     *
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @since 10
     */
    FLASH_MODE_CLOSE = 0,

    /**
     * Open mode.
     *
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @since 10
     */
    FLASH_MODE_OPEN = 1,

    /**
     * Auto mode.
     *
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @since 10
     */
    FLASH_MODE_AUTO = 2,

    /**
     * Always open mode.
     *
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @since 10
     */
    FLASH_MODE_ALWAYS_OPEN = 3
  }

  /**
   * LCD Flash Status.
   *
   * @typedef LcdFlashStatus
   * @syscap SystemCapability.Multimedia.Camera.Core
   * @systemapi
   * @since 12
   */
  interface LcdFlashStatus {
    /**
     * Check whether lcd flash is needed.
     *
     * @type { boolean }
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @systemapi
     * @since 12
     */
    readonly isLcdFlashNeeded: boolean;

    /**
     * Compensate value for lcd flash.
     *
     * @type { number }
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @systemapi
     * @since 12
     */
    readonly lcdCompensation: number;
  }

  /**
   * Flash Query object.
   *
   * @interface FlashQuery
   * @syscap SystemCapability.Multimedia.Camera.Core
   * @since 12
   */
  interface FlashQuery {
    /**
     * Check if device has flash light.
     *
     * @returns { boolean } The flash light support status.
     * @throws { BusinessError } 7400103 - Session not config.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @since 11
     */
    /**
     * Check if device has flash light.
     * Move to FlashQuery interface from Flash since 12.
     *
     * @returns { boolean } The flash light support status.
     * @throws { BusinessError } 7400103 - Session not config, only throw in session usage.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @since 12
     */
    hasFlash(): boolean;

    /**
     * Checks whether a specified flash mode is supported.
     *
     * @param { FlashMode } flashMode - Flash mode
     * @returns { boolean } Is the flash mode supported.
     * @throws { BusinessError } 7400103 - Session not config.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @since 11
     */
    /**
     * Checks whether a specified flash mode is supported.
     * Move to FlashQuery interface from Flash since 12.
     *
     * @param { FlashMode } flashMode - Flash mode
     * @returns { boolean } Is the flash mode supported.
     * @throws { BusinessError } 7400103 - Session not config, only throw in session usage.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @since 12
     */
    isFlashModeSupported(flashMode: FlashMode): boolean;

    /**
     * Checks whether lcd flash is supported.
     *
     * @returns { boolean } Is lcd flash supported.
     * @throws { BusinessError } 202 - Not System Application.
     * @throws { BusinessError } 7400103 - Session not config, only throw in session usage.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @systemapi
     * @since 12
     */
    isLcdFlashSupported(): boolean;
  }

  /**
   * Flash object.
   *
   * @interface Flash
   * @syscap SystemCapability.Multimedia.Camera.Core
   * @since 11
   */
  interface Flash extends FlashQuery {
    /**
     * Gets current flash mode.
     *
     * @returns { FlashMode } The current flash mode.
     * @throws { BusinessError } 7400103 - Session not config.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @since 11
     */
    getFlashMode(): FlashMode;

    /**
     * Sets flash mode.
     *
     * @param { FlashMode } flashMode - Target flash mode.
     * @throws { BusinessError } 7400103 - Session not config.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @since 11
     */
    setFlashMode(flashMode: FlashMode): void;

    /**
     * Enable lcd flash.
     *
     * @param { boolean } enabled - Target lcd flash status.
     * @throws { BusinessError } 202 - Not System Application.
     * @throws { BusinessError } 7400103 - Session not config.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @systemapi
     * @since 13
     */
    enableLcdFlash(enabled: boolean): void;
  }

  /**
   * Enum for exposure mode.
   *
   * @enum { number }
   * @syscap SystemCapability.Multimedia.Camera.Core
   * @since 10
   */
  enum ExposureMode {
    /**
     * Lock exposure mode.
     *
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @since 10
     */
    EXPOSURE_MODE_LOCKED = 0,

    /**
     * Auto exposure mode.
     *
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @since 10
     */
    EXPOSURE_MODE_AUTO = 1,

    /**
     * Continuous automatic exposure.
     *
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @since 10
     */
    EXPOSURE_MODE_CONTINUOUS_AUTO = 2,

    /**
     * Manual exposure mode.
     *
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @systemapi
     * @since 12
     */
    EXPOSURE_MODE_MANUAL = 3
  }

  /**
   * Enum for exposure metering mode.
   *
   * @enum { number }
   * @syscap SystemCapability.Multimedia.Camera.Core
   * @systemapi
   * @since 12
   */
  enum ExposureMeteringMode {
    /**
     * Matrix metering.
     *
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @systemapi
     * @since 12
     */
    MATRIX = 0,

    /**
     * Center metering.
     *
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @systemapi
     * @since 12
     */
    CENTER = 1,

    /**
     * Spot metering.
     *
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @systemapi
     * @since 12
     */
    SPOT = 2
  }

  /**
   * AutoExposureQuery object.
   *
   * @interface AutoExposureQuery
   * @syscap SystemCapability.Multimedia.Camera.Core
   * @since 12
   */
  interface AutoExposureQuery {
    /**
     * Checks whether a specified exposure mode is supported.
     *
     * @param { ExposureMode } aeMode - Exposure mode
     * @returns { boolean } Is the exposure mode supported.
     * @throws { BusinessError } 7400103 - Session not config.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @since 11
     */
    /**
     * Checks whether a specified exposure mode is supported.
     * Move to AutoExposureQuery interface from AutoExposure interface since 12.
     *
     * @param { ExposureMode } aeMode - Exposure mode
     * @returns { boolean } Is the exposure mode supported.
     * @throws { BusinessError } 7400103 - Session not config, only throw in session usage.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @since 12
     */
    isExposureModeSupported(aeMode: ExposureMode): boolean;

    /**
     * Query the exposure compensation range.
     *
     * @returns { Array<number> } The array of compensation range.
     * @throws { BusinessError } 7400103 - Session not config.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @since 11
     */
    /**
     * Query the exposure compensation range.
     * Move to AutoExposureQuery interface from AutoExposure interface since 12.
     *
     * @returns { Array<number> } The array of compensation range.
     * @throws { BusinessError } 7400103 - Session not config, only throw in session usage.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @since 12
     */
    getExposureBiasRange(): Array<number>;

    /**
     * Checks whether a specified exposure metering mode is supported.
     *
     * @param { ExposureMeteringMode } aeMeteringMode - Exposure metering mode
     * @returns { boolean } Is the exposure metering mode supported.
     * @throws { BusinessError } 202 - Not System Application.
     * @throws { BusinessError } 7400101 - Parameter missing or parameter type incorrect.
     * @throws { BusinessError } 7400103 - Session not config, only throw in session usage.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @systemapi
     * @since 12
     */
    isExposureMeteringModeSupported(aeMeteringMode: ExposureMeteringMode): boolean;
  }

  /**
   * AutoExposure object.
   *
   * @interface AutoExposure
   * @syscap SystemCapability.Multimedia.Camera.Core
   * @since 11
   */
  interface AutoExposure extends AutoExposureQuery {
    /**
     * Gets current exposure mode.
     *
     * @returns { ExposureMode } The current exposure mode.
     * @throws { BusinessError } 7400103 - Session not config.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @since 11
     */
    getExposureMode(): ExposureMode;

    /**
     * Sets Exposure mode.
     *
     * @param { ExposureMode } aeMode - Exposure mode
     * @throws { BusinessError } 7400103 - Session not config.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @since 11
     */
    setExposureMode(aeMode: ExposureMode): void;

    /**
     * Gets current metering point.
     *
     * @returns { Point } The current metering point.
     * @throws { BusinessError } 7400103 - Session not config.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @since 11
     */
    getMeteringPoint(): Point;

    /**
     * Set the center point of the metering area.
     *
     * @param { Point } point - metering point
     * @throws { BusinessError } 7400103 - Session not config.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @since 11
     */
    setMeteringPoint(point: Point): void;

    /**
     * Query the exposure compensation range.
     *
     * @returns { Array<number> } The array of compensation range.
     * @throws { BusinessError } 7400103 - Session not config.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @since 11
     */
    getExposureBiasRange(): Array<number>;

    /**
     * Set exposure compensation.
     *
     * @param { number } exposureBias - Exposure compensation
     * @throws { BusinessError } 7400103 - Session not config.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @since 11
     */
    /**
     * Set exposure compensation.
     *
     * @param { number } exposureBias - Exposure compensation
     * @throws { BusinessError } 7400102 - Operation not allowed.
     * @throws { BusinessError } 7400103 - Session not config.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @since 12
     */
    setExposureBias(exposureBias: number): void;

    /**
     * Query the exposure value.
     *
     * @returns { number } The exposure value.
     * @throws { BusinessError } 7400103 - Session not config.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @since 11
     */
    getExposureValue(): number;

    /**
     * Gets current exposure metering mode.
     *
     * @returns { ExposureMeteringMode } The current exposure metering mode.
     * @throws { BusinessError } 202 - Not System Application.
     * @throws { BusinessError } 7400103 - Session not config, only throw in session usage.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @systemapi
     * @since 12
     */
    getExposureMeteringMode(): ExposureMeteringMode;

    /**
     * Sets exposure metering mode.
     *
     * @param { ExposureMeteringMode } aeMeteringMode - Exposure metering mode
     * @throws { BusinessError } 202 - Not System Application.
     * @throws { BusinessError } 7400101 - Parameter missing or parameter type incorrect.
     * @throws { BusinessError } 7400103 - Session not config, only throw in session usage.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @systemapi
     * @since 12
     */
    setExposureMeteringMode(aeMeteringMode: ExposureMeteringMode): void;
  }

  /**
   * Enum for focus mode.
   *
   * @enum { number }
   * @syscap SystemCapability.Multimedia.Camera.Core
   * @since 10
   */
  enum FocusMode {
    /**
     * Manual mode.
     *
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @since 10
     */
    FOCUS_MODE_MANUAL = 0,

    /**
     * Continuous auto mode.
     *
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @since 10
     */
    FOCUS_MODE_CONTINUOUS_AUTO = 1,

    /**
     * Auto mode.
     *
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @since 10
     */
    FOCUS_MODE_AUTO = 2,

    /**
     * Locked mode.
     *
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @since 10
     */
    FOCUS_MODE_LOCKED = 3
  }

  /**
   * Enum for focus state.
   *
   * @enum { number }
   * @syscap SystemCapability.Multimedia.Camera.Core
   * @since 10
   */
  enum FocusState {
    /**
     * Scan state.
     *
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @since 10
     */
    FOCUS_STATE_SCAN = 0,

    /**
     * Focused state.
     *
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @since 10
     */
    FOCUS_STATE_FOCUSED = 1,

    /**
     * Unfocused state.
     *
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @since 10
     */
    FOCUS_STATE_UNFOCUSED = 2
  }

  /**
   * Focus Query object.
   *
   * @interface FocusQuery
   * @syscap SystemCapability.Multimedia.Camera.Core
   * @since 12
   */
  interface FocusQuery {
    /**
     * Checks whether a specified focus mode is supported.
     *
     * @param { FocusMode } afMode - Focus mode.
     * @returns { boolean } Is the focus mode supported.
     * @throws { BusinessError } 7400103 - Session not config.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @since 11
     */
    /**
     * Checks whether a specified focus mode is supported.
     * Move to FocusQuery interface from Focus interface since 12.
     *
     * @param { FocusMode } afMode - Focus mode.
     * @returns { boolean } Is the focus mode supported.
     * @throws { BusinessError } 7400103 - Session not config, only throw in session usage.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @since 12
     */
    isFocusModeSupported(afMode: FocusMode): boolean;

    /**
     * Checks whether a focus assist is supported.
     *
     * @returns { boolean } Is the focus assist supported.
     * @throws { BusinessError } 202 - Not System Application.
     * @throws { BusinessError } 7400103 - Session not config, only throw in session usage.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @systemapi
     * @since 12
     */
    isFocusAssistSupported(): boolean;
  }

  /**
   * Focus object.
   *
   * @interface Focus
   * @syscap SystemCapability.Multimedia.Camera.Core
   * @since 11
   */
  interface Focus extends FocusQuery {
    /**
     * Gets current focus mode.
     *
     * @returns { FocusMode } The current focus mode.
     * @throws { BusinessError } 7400103 - Session not config.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @since 11
     */
    getFocusMode(): FocusMode;

    /**
     * Sets focus mode.
     *
     * @param { FocusMode } afMode - Target focus mode.
     * @throws { BusinessError } 7400103 - Session not config.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @since 11
     */
    setFocusMode(afMode: FocusMode): void;

    /**
     * Sets focus point.
     *
     * @param { Point } point - Target focus point.
     * @throws { BusinessError } 7400103 - Session not config.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @since 11
     */
    setFocusPoint(point: Point): void;

    /**
     * Gets current focus point.
     *
     * @returns { Point } The current focus point.
     * @throws { BusinessError } 7400103 - Session not config.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @since 11
     */
    getFocusPoint(): Point;

    /**
     * Gets current focal length.
     *
     * @returns { number } The current focal point.
     * @throws { BusinessError } 7400103 - Session not config.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @since 11
     */
    getFocalLength(): number;

    /**
     * Gets current focus assist.
     *
     * @returns { boolean } The current focus assist.
     * @throws { BusinessError } 202 - Not System Application.
     * @throws { BusinessError } 7400103 - Session not config.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @systemapi
     * @since 12
     */
    getFocusAssist(): boolean;

    /**
     * Sets focus assist.
     *
     * @param { boolean } enabled - Enable focus assist if TRUE.
     * @throws { BusinessError } 202 - Not System Application.
     * @throws { BusinessError } 7400101 - Parameter missing or parameter type incorrect.
     * @throws { BusinessError } 7400103 - Session not config.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @systemapi
     * @since 12
     */
    setFocusAssist(enabled: boolean): void;
  }

  /**
   * ManualFocus object.
   *
   * @interface ManualFocus
   * @syscap SystemCapability.Multimedia.Camera.Core
   * @systemapi
   * @since 12
   */
  interface ManualFocus {
    /**
     * Gets current focus distance.
     *
     * @returns { number } The current focus distance.
     * @throws { BusinessError } 202 - Not System Application.
     * @throws { BusinessError } 7400103 - Session not config.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @systemapi
     * @since 12
     */
    getFocusDistance(): number;

    /**
     * Sets focus distance.
     *
     * @param { number } distance - Focus distance
     * @throws { BusinessError } 202 - Not System Application.
     * @throws { BusinessError } 7400101 - Parameter missing or parameter type incorrect.
     * @throws { BusinessError } 7400103 - Session not config.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @systemapi
     * @since 12
     */
    setFocusDistance(distance: number): void;
  }

  /**
   * Enumerates the camera white balance modes.
   *
   * @enum { number }
   * @syscap SystemCapability.Multimedia.Camera.Core
   * @systemapi
   * @since 12
   */
  enum WhiteBalanceMode {
    /**
     * Auto white balance mode.
     *
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @systemapi
     * @since 12
     */
    AUTO = 0,

    /**
     * Cloudy white balance mode.
     *
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @systemapi
     * @since 12
     */
    CLOUDY = 1,

    /**
     * Incandescent white balance mode.
     *
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @systemapi
     * @since 12
     */
    INCANDESCENT = 2,

    /**
     * Fluorescent white balance mode.
     *
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @systemapi
     * @since 12
     */
    FLUORESCENT = 3,

    /**
     * Daylight white balance mode.
     *
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @systemapi
     * @since 12
     */
    DAYLIGHT = 4,

    /**
     * Manual white balance mode.
     *
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @systemapi
     * @since 12
     */
    MANUAL = 5,

    /**
     * Lock white balance mode.
     *
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @systemapi
     * @since 12
     */
    LOCKED = 6
  }

  /**
   * White Balance Query object.
   *
   * @interface WhiteBalanceQuery
   * @syscap SystemCapability.Multimedia.Camera.Core
   * @systemapi
   * @since 12
   */
  interface WhiteBalanceQuery {
    /**
     * Checks whether a specified white balance mode is supported.
     *
     * @param { WhiteBalanceMode } mode - White balance mode.
     * @returns { boolean } Is the white balance mode supported.
     * @throws { BusinessError } 202 - Not System Application.
     * @throws { BusinessError } 7400101 - Parameter missing or parameter type incorrect.
     * @throws { BusinessError } 7400103 - Session not config, only throw in session usage.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @systemapi
     * @since 12
     */
    isWhiteBalanceModeSupported(mode: WhiteBalanceMode): boolean;

    /**
     * Query the white balance mode range.
     *
     * @returns { Array<number> } The array of white balance mode range.
     * @throws { BusinessError } 202 - Not System Application.
     * @throws { BusinessError } 7400103 - Session not config, only throw in session usage.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @systemapi
     * @since 12
     */
    getWhiteBalanceRange(): Array<number>;
  }

  /**
   * WhiteBalance object.
   *
   * @interface WhiteBalance
   * @syscap SystemCapability.Multimedia.Camera.Core
   * @systemapi
   * @since 12
   */
  interface WhiteBalance extends WhiteBalanceQuery {
    /**
     * Gets current white balance mode.
     *
     * @returns { WhiteBalanceMode } The current white balance mode.
     * @throws { BusinessError } 202 - Not System Application.
     * @throws { BusinessError } 7400103 - Session not config.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @systemapi
     * @since 12
     */
    getWhiteBalanceMode(): WhiteBalanceMode;

    /**
     * Sets white balance mode.
     *
     * @param { WhiteBalanceMode } mode - Target white balance mode.
     * @throws { BusinessError } 202 - Not System Application.
     * @throws { BusinessError } 7400101 - Parameter missing or parameter type incorrect.
     * @throws { BusinessError } 7400103 - Session not config.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @systemapi
     * @since 12
     */
    setWhiteBalanceMode(mode: WhiteBalanceMode): void;

    /**
     * Gets current white balance.
     *
     * @returns { number } The current white balance.
     * @throws { BusinessError } 202 - Not System Application.
     * @throws { BusinessError } 7400103 - Session not config.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @systemapi
     * @since 12
     */
    getWhiteBalance(): number;

    /**
     * Sets white balance.
     *
     * @param { number } whiteBalance - White balance.
     * @throws { BusinessError } 202 - Not System Application.
     * @throws { BusinessError } 7400101 - Parameter missing or parameter type incorrect.
     * @throws { BusinessError } 7400103 - Session not config.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @systemapi
     * @since 12
     */
    setWhiteBalance(whiteBalance: number): void;
  }

  /**
   * Manual ISO Query object.
   *
   * @interface ManualIsoQuery
   * @syscap SystemCapability.Multimedia.Camera.Core
   * @systemapi
   * @since 12
   */
  interface ManualIsoQuery {
    /**
     * Checks whether ISO is supported.
     *
     * @returns { boolean } Is the ISO supported.
     * @throws { BusinessError } 202 - Not System Application.
     * @throws { BusinessError } 7400103 - Session not config, only throw in session usage.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @systemapi
     * @since 12
     */
    isManualIsoSupported(): boolean;

    /**
     * Get the ISO range.
     *
     * @returns { Array<number> } The array of ISO range.
     * @throws { BusinessError } 202 - Not System Application.
     * @throws { BusinessError } 7400103 - Session not config, only throw in session usage.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @systemapi
     * @since 12
     */
    getIsoRange(): Array<number>;
  }

  /**
   * ManualIso object.
   *
   * @interface ManualIso
   * @syscap SystemCapability.Multimedia.Camera.Core
   * @systemapi
   * @since 12
   */
  interface ManualIso extends ManualIsoQuery {
    /**
     * Gets current ISO.
     *
     * @returns { number } The current ISO.
     * @throws { BusinessError } 202 - Not System Application.
     * @throws { BusinessError } 7400103 - Session not config.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @systemapi
     * @since 12
     */
    getIso(): number;

    /**
     * Sets ISO.
     *
     * @param { number } iso - ISO
     * @throws { BusinessError } 202 - Not System Application.
     * @throws { BusinessError } 7400101 - Parameter missing or parameter type incorrect.
     * @throws { BusinessError } 7400103 - Session not config.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @systemapi
     * @since 12
     */
    setIso(iso: number): void;
  }

  /**
   * Enum for smooth zoom mode.
   *
   * @enum { number }
   * @syscap SystemCapability.Multimedia.Camera.Core
   * @since 11
   */
  enum SmoothZoomMode {
    /**
     * Normal zoom mode.
     *
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @since 11
     */
    NORMAL = 0
  }

  /**
   * SmoothZoomInfo object
   *
   * @typedef SmoothZoomInfo
   * @syscap SystemCapability.Multimedia.Camera.Core
   * @since 11
   */
  interface SmoothZoomInfo {
    /**
     * The duration of smooth zoom.
     *
     * @type { number }
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @since 11
     */
    duration: number;
  }

  /**
   * ZoomPointInfo object.
   *
   * @typedef ZoomPointInfo
   * @syscap SystemCapability.Multimedia.Camera.Core
   * @systemapi
   * @since 12
   */
  interface ZoomPointInfo {
    /**
     * The zoom ratio value.
     *
     * @type { number }
     * @readonly
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @systemapi
     * @since 12
     */
    readonly zoomRatio: number;

    /**
     * The equivalent focal Length.
     *
     * @type { number }
     * @readonly
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @systemapi
     * @since 12
     */
    readonly equivalentFocalLength: number;
  }

  /**
   * Zoom query object.
   *
   * @interface ZoomQuery
   * @syscap SystemCapability.Multimedia.Camera.Core
   * @since 12
   */
  interface ZoomQuery {
    /**
     * Gets all supported zoom ratio range.
     *
     * @returns { Array<number> } The zoom ratio range.
     * @throws { BusinessError } 7400103 - Session not config.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @since 11
     */
    /**
     * Gets all supported zoom ratio range.
     * Move to ZoomQuery interface from Zoom since 12.
     *
     * @returns { Array<number> } The zoom ratio range.
     * @throws { BusinessError } 7400103 - Session not config, only throw in session usage.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @since 12
     */
    getZoomRatioRange(): Array<number>;

    /**
     * Gets all important zoom ratio infos.
     *
     * @returns { Array<ZoomPointInfo> } The zoom point infos.
     * @throws { BusinessError } 202 - Not System Application.
     * @throws { BusinessError } 7400103 - Session not config, only throw in session usage.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @systemapi
     * @since 12
     */
    getZoomPointInfos(): Array<ZoomPointInfo>;
  }

  /**
   * Zoom object.
   *
   * @interface Zoom
   * @syscap SystemCapability.Multimedia.Camera.Core
   * @since 11
   */
  interface Zoom extends ZoomQuery {
    /**
     * Gets zoom ratio.
     *
     * @returns { number } The zoom ratio value.
     * @throws { BusinessError } 7400103 - Session not config.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @since 11
     */
    /**
     * Gets zoom ratio.
     *
     * @returns { number } The zoom ratio value.
     * @throws { BusinessError } 7400103 - Session not config.
     * @throws { BusinessError } 7400201 - Camera service fatal error.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @since 12
     */
    getZoomRatio(): number;

    /**
     * Sets zoom ratio.
     *
     * @param { number } zoomRatio - Target zoom ratio.
     * @throws { BusinessError } 7400103 - Session not config.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @since 11
     */
    setZoomRatio(zoomRatio: number): void;

    /**
     * Sets target zoom ratio by smooth method.
     *
     * @param { number } targetRatio - Target zoom ratio.
     * @param { SmoothZoomMode } mode - Smooth zoom mode.
     * @throws { BusinessError } 7400103 - Session not config.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @since 11
     */
    setSmoothZoom(targetRatio: number, mode?: SmoothZoomMode): void;

    /**
     * Notify device to prepare for zoom.
     *
     * @throws { BusinessError } 202 - Not System Application.
     * @throws { BusinessError } 7400103 - Session not config.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @systemapi
     * @since 11
     */
    prepareZoom(): void;

    /**
     * Notify device of zoom completion.
     *
     * @throws { BusinessError } 202 - Not System Application.
     * @throws { BusinessError } 7400103 - Session not config.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @systemapi
     * @since 11
     */
    unprepareZoom(): void;
  }

  /**
   * Enum for video stabilization mode.
   *
   * @enum { number }
   * @syscap SystemCapability.Multimedia.Camera.Core
   * @since 10
   */
  enum VideoStabilizationMode {
    /**
     * Turn off video stablization.
     *
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @since 10
     */
    OFF = 0,

    /**
     * LOW mode provides basic stabilization effect.
     *
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @since 10
     */
    LOW = 1,

    /**
     * MIDDLE mode means algorithms can achieve better effects than LOW mode.
     *
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @since 10
     */
    MIDDLE = 2,

    /**
     * HIGH mode means algorithms can achieve better effects than MIDDLE mode.
     *
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @since 10
     */
    HIGH = 3,

    /**
     * Camera HDF can select mode automatically.
     *
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @since 10
     */
    AUTO = 4
  }

  /**
   * Stabilization Query object.
   *
   * @interface StabilizationQuery
   * @syscap SystemCapability.Multimedia.Camera.Core
   * @since 12
   */
  interface StabilizationQuery {
    /**
     * Check whether the specified video stabilization mode is supported.
     *
     * @param { VideoStabilizationMode } vsMode - Video Stabilization mode.
     * @returns { boolean } Is flash mode supported.
     * @throws { BusinessError } 7400103 - Session not config.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @since 11
     */
    /**
     * Check whether the specified video stabilization mode is supported.
     * Move to StabilizationQuery interface from Stabilization since 12.
     *
     * @param { VideoStabilizationMode } vsMode - Video Stabilization mode.
     * @returns { boolean } Is flash mode supported.
     * @throws { BusinessError } 7400103 - Session not config, only throw in session usage.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @since 12
     */
    isVideoStabilizationModeSupported(vsMode: VideoStabilizationMode): boolean;
  }

  /**
   * Stabilization object.
   *
   * @interface Stabilization
   * @syscap SystemCapability.Multimedia.Camera.Core
   * @since 11
   */
  interface Stabilization extends StabilizationQuery {
    /**
     * Query the video stabilization mode currently in use.
     *
     * @returns { VideoStabilizationMode } The current video stabilization mode.
     * @throws { BusinessError } 7400103 - Session not config.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @since 11
     */
    getActiveVideoStabilizationMode(): VideoStabilizationMode;

    /**
     * Set video stabilization mode.
     *
     * @param { VideoStabilizationMode } mode - video stabilization mode to set.
     * @throws { BusinessError } 7400103 - Session not config.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @since 11
     */
    setVideoStabilizationMode(mode: VideoStabilizationMode): void;
  }

  /**
   * Enumerates the camera beauty effect types.
   *
   * @enum { number }
   * @syscap SystemCapability.Multimedia.Camera.Core
   * @systemapi
   * @since 10
   */
  enum BeautyType {
    /**
     * Auto beauty type.
     *
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @systemapi
     * @since 10
     */
    AUTO = 0,

    /**
     * Skin smooth beauty type.
     *
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @systemapi
     * @since 10
     */
    SKIN_SMOOTH = 1,

    /**
     * Face slender beauty type.
     *
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @systemapi
     * @since 10
     */
    FACE_SLENDER = 2,

    /**
     * Skin tone beauty type.
     *
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @systemapi
     * @since 10
     */
    SKIN_TONE = 3
  }

  /**
   * Beauty Query object.
   *
   * @interface BeautyQuery
   * @syscap SystemCapability.Multimedia.Camera.Core
   * @systemapi
   * @since 12
   */
  interface BeautyQuery {
    /**
     * Gets supported beauty effect types.
     *
     * @returns { Array<BeautyType> } List of beauty effect types.
     * @throws { BusinessError } 202 - Not System Application.
     * @throws { BusinessError } 7400103 - Session not config.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @systemapi
     * @since 11
     */
    /**
     * Gets supported beauty effect types.
     * Move to BeautyQuery from Beauty since 12.
     *
     * @returns { Array<BeautyType> } List of beauty effect types.
     * @throws { BusinessError } 202 - Not System Application.
     * @throws { BusinessError } 7400103 - Session not config, only throw in session usage.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @systemapi
     * @since 12
     */
    getSupportedBeautyTypes(): Array<BeautyType>;

    /**
     * Gets the specific beauty effect type range.
     *
     * @param { BeautyType } type - The type of beauty effect.
     * @returns { Array<number> } The array of the specific beauty effect range.
     * @throws { BusinessError } 202 - Not System Application.
     * @throws { BusinessError } 7400103 - Session not config.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @systemapi
     * @since 11
     */
    /**
     * Gets the specific beauty effect type range.
     * Move to BeautyQuery from Beauty since 12.
     *
     * @param { BeautyType } type - The type of beauty effect.
     * @returns { Array<number> } The array of the specific beauty effect range.
     * @throws { BusinessError } 202 - Not System Application.
     * @throws { BusinessError } 7400103 - Session not config, only throw in session usage.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @systemapi
     * @since 12
     */
    getSupportedBeautyRange(type: BeautyType): Array<number>;
  }

  /**
   * Beauty object.
   *
   * @interface Beauty
   * @syscap SystemCapability.Multimedia.Camera.Core
   * @systemapi
   * @since 11
   */
  interface Beauty extends BeautyQuery {
    /**
     * Gets the beauty effect in use.
     *
     * @param { BeautyType } type - The type of beauty effect.
     * @returns { number } the beauty effect in use.
     * @throws { BusinessError } 202 - Not System Application.
     * @throws { BusinessError } 7400103 - Session not config.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @systemapi
     * @since 11
     */
    getBeauty(type: BeautyType): number;

    /**
     * Sets a beauty effect for a camera device.
     *
     * @param { BeautyType } type - The type of beauty effect.
     * @param { number } value The number of beauty effect.
     * @throws { BusinessError } 202 - Not System Application.
     * @throws { BusinessError } 7400103 - Session not config.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @systemapi
     * @since 11
     */
    setBeauty(type: BeautyType, value: number): void;
  }

  /**
   * EffectSuggestion object.
   *
   * @typedef EffectSuggestion
   * @syscap SystemCapability.Multimedia.Camera.Core
   * @systemapi
   * @since 12
   */
  interface EffectSuggestion {

    /**
     * Checks whether effect suggestion is supported.
     *
     * @returns { boolean } Is the effect suggestion supported.
     * @throws { BusinessError } 202 - Not System Application.
     * @throws { BusinessError } 7400103 - Session not config.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @systemapi
     * @since 12
     */
    isEffectSuggestionSupported(): boolean;

    /**
     * Enable effect suggestion for session.
     *
     * @param { boolean } enabled enable effect suggestion for session if TRUE..
     * @throws { BusinessError } 202 - Not System Application.
     * @throws { BusinessError } 7400101 - Parameter missing or parameter type incorrect.
     * @throws { BusinessError } 7400103 - Session not config.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @systemapi
     * @since 12
     */
    enableEffectSuggestion(enabled: boolean): void;

    /**
     * Gets supported effect suggestion types.
     *
     * @returns { Array<EffectSuggestionType> } The array of the effect suggestion types.
     * @throws { BusinessError } 202 - Not System Application.
     * @throws { BusinessError } 7400103 - Session not config.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @systemapi
     * @since 12
     */
    getSupportedEffectSuggestionTypes(): Array<EffectSuggestionType>;

    /**
     * Set the range of effect suggestion type and enable status.
     * The application should fully set all data when it starts up.
     *
     * @param { Array<EffectSuggestionStatus> } status - The array of the effect suggestion status.
     * @throws { BusinessError } 202 - Not System Application.
     * @throws { BusinessError } 7400101 - Parameter missing or parameter type incorrect.
     * @throws { BusinessError } 7400103 - Session not config.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @systemapi
     * @since 12
     */
    setEffectSuggestionStatus(status: Array<EffectSuggestionStatus>): void;

    /**
     * Update the enable status of the effect suggestion type.
     *
     * @param { EffectSuggestionType } type - The type of effect suggestion.
     * @param { boolean } enabled - The status of effect suggestion type.
     * @throws { BusinessError } 202 - Not System Application.
     * @throws { BusinessError } 7400101 - Parameter missing or parameter type incorrect.
     * @throws { BusinessError } 7400103 - Session not config.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @systemapi
     * @since 12
     */
    updateEffectSuggestion(type: EffectSuggestionType, enabled: boolean): void;
  }

  /**
   * Enumerates the camera color effect types.
   *
   * @enum { number }
   * @syscap SystemCapability.Multimedia.Camera.Core
   * @systemapi
   * @since 11
   */
  enum ColorEffectType {
    /**
     * Normal color effect type.
     *
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @systemapi
     * @since 11
     */
    NORMAL = 0,

    /**
     * Bright color effect type.
     *
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @systemapi
     * @since 11
     */
    BRIGHT = 1,

    /**
     * Soft color effect type.
     *
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @systemapi
     * @since 11
     */
    SOFT = 2,

    /**
     * Black white color effect type.
     *
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @systemapi
     * @since 12
     */
    BLACK_WHITE = 3
  }

  /**
   * Enumerates the control center effect types.
   *
   * @enum { number }
   * @syscap SystemCapability.Multimedia.Camera.Core
   * @since 20
   */
  enum ControlCenterEffectType {
    /**
     * Beauty type.
     *
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @since 20
     */
    BEAUTY = 0,
    /**
     * Portrait type.
     *
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @since 20
     */
    PORTRAIT
  }

  /**
   * Enum for policy type
   *
   * @enum { number }
   * @syscap SystemCapability.Multimedia.Camera.Core
   * @systemapi
   * @since 12
   */
  enum PolicyType {
    /**
     * PRIVACY type.
     *
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @systemapi
     * @since 12
     */
    PRIVACY = 1,
  }

  /**
   * Color Effect Query object.
   *
   * @interface ColorEffectQuery
   * @syscap SystemCapability.Multimedia.Camera.Core
   * @systemapi
   * @since 12
   */
  interface ColorEffectQuery {
    /**
     * Gets supported color effect types.
     *
     * @returns { Array<ColorEffectType> } List of color effect types.
     * @throws { BusinessError } 202 - Not System Application.
     * @throws { BusinessError } 7400103 - Session not config.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @systemapi
     * @since 11
     */
    /**
     * Gets supported color effect types.
     * Move to ColorEffectQuery from ColorEffect since 12.
     *
     * @returns { Array<ColorEffectType> } List of color effect types.
     * @throws { BusinessError } 202 - Not System Application.
     * @throws { BusinessError } 7400103 - Session not config, only throw in session usage.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @systemapi
     * @since 12
     */
    getSupportedColorEffects(): Array<ColorEffectType>;
  }

  /**
   * Color effect object.
   *
   * @interface ColorEffect
   * @syscap SystemCapability.Multimedia.Camera.Core
   * @systemapi
   * @since 11
   */
  interface ColorEffect extends ColorEffectQuery {
    /**
     * Gets the specific color effect type.
     *
     * @returns { ColorEffectType } The array of the specific color effect type.
     * @throws { BusinessError } 202 - Not System Application.
     * @throws { BusinessError } 7400103 - Session not config.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @systemapi
     * @since 11
     */
    getColorEffect(): ColorEffectType;

    /**
     * Sets a color effect for a camera device.
     *
     * @param { ColorEffectType } type - The type of color effect.
     * @throws { BusinessError } 202 - Not System Application.
     * @throws { BusinessError } 7400103 - Session not config.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @systemapi
     * @since 11
     */
    setColorEffect(type: ColorEffectType): void;
  }

  /**
   * Color Management Query object.
   *
   * @interface ColorManagementQuery
   * @syscap SystemCapability.Multimedia.Camera.Core
   * @since 12
   */
  interface ColorManagementQuery {
    /**
     * Gets the supported color space types.
     *
     * @returns { Array<colorSpaceManager.ColorSpace> } The array of the supported color space for the session.
     * @throws { BusinessError } 7400103 - Session not config, only throw in session usage.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @since 12
     */
    getSupportedColorSpaces(): Array<colorSpaceManager.ColorSpace>;
  }

  /**
   * Color Management object.
   *
   * @interface ColorManagement
   * @syscap SystemCapability.Multimedia.Camera.Core
   * @since 12
   */
  interface ColorManagement extends ColorManagementQuery {
    /**
     * Gets the specific color space type.
     *
     * @returns { colorSpaceManager.ColorSpace } Current color space.
     * @throws { BusinessError } 7400103 - Session not config.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @since 12
     */
    getActiveColorSpace(): colorSpaceManager.ColorSpace;

    /**
     * Sets a color space for the session.
     *
     * @param { colorSpaceManager.ColorSpace } colorSpace - The type of color space.
     * @throws { BusinessError } 7400101 - Parameter missing or parameter type incorrect.
     * @throws { BusinessError } 7400102 - The colorSpace does not match the format.
     * @throws { BusinessError } 7400103 - Session not config.
     * @throws { BusinessError } 7400201 - Camera service fatal error.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @since 12
     */
    setColorSpace(colorSpace: colorSpaceManager.ColorSpace): void;
  }

  /**
   * Control Center Query object.
   *
   * @interface ControlCenterQuery
   * @syscap SystemCapability.Multimedia.Camera.Core
   * @since 20
   */
  interface ControlCenterQuery {
 
    /**
     * Checks whether control center is supported.
     *
     * @returns { boolean } Is control center supported.
     * @throws { BusinessError } 7400103 - Session not config.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @since 20
     */
    isControlCenterSupported(): boolean;
 
    /**
     * Gets the supported effect types.
     *
     * @returns { Array<ControlCenterEffectType> } The array of the supported control center type for the session.
     * @throws { BusinessError } 7400103 - Session not config, only throw in session usage.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @since 20
     */
    getSupportedEffectTypes(): Array<ControlCenterEffectType>;
  }
 
  /**
   * Control center object.
   *
   * @interface ControlCenter
   * @syscap SystemCapability.Multimedia.Camera.Core
   * @since 20
   */
  interface ControlCenter extends ControlCenterQuery {
    /**
     * Enable control center for session.
     *
     * @param { boolean } enabled enable control center for session if TRUE..
     * @throws { BusinessError } 7400101 - Parameter missing or parameter type incorrect.
     * @throws { BusinessError } 7400103 - Session not config.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @systemapi
     * @since 20
     */
    enableControlCenter(enabled: boolean): void;
  }

  /**
   * Auto Device Switch Query object.
   *
   * @interface AutoDeviceSwitchQuery
   * @syscap SystemCapability.Multimedia.Camera.Core
   * @since 13
   */
  interface AutoDeviceSwitchQuery {
    /**
     * Check whether auto device switch is supported.
     *
     * @returns { boolean } Is auto device switch supported.
     * @throws { BusinessError } 7400103 - Session not config, only throw in session usage.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @since 13
     */
    isAutoDeviceSwitchSupported(): boolean;
  }

  /**
   * Auto Device Switch object.
   *
   * @interface AutoDeviceSwitch
   * @extends AutoDeviceSwitchQuery
   * @syscap SystemCapability.Multimedia.Camera.Core
   * @since 13
   */
  interface AutoDeviceSwitch extends AutoDeviceSwitchQuery {
    /**
     * Enable auto device switch for session.
     *
     * @param { boolean } enabled - enable auto device switch if TRUE.
     * @throws { BusinessError } 401 - Parameter error. Possible causes:
     * 1. Mandatory parameters are left unspecified; 2. Incorrect parameter types;
     * 3. Parameters verification failed.
     * @throws { BusinessError } 7400102 - Operation not allowed.
     * @throws { BusinessError } 7400103 - Session not config.
     * @throws { BusinessError } 7400201 - Camera service fatal error.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @since 13
     */
    enableAutoDeviceSwitch(enabled: boolean): void;
  }

  /**
   * Auto Device Switch Status.
   *
   * @typedef AutoDeviceSwitchStatus
   * @syscap SystemCapability.Multimedia.Camera.Core
   * @since 13
   */
  interface AutoDeviceSwitchStatus {
    /**
     * Notify whether device is switched.
     *
     * @type { boolean }
     * @readonly
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @since 13
     */
    readonly isDeviceSwitched: boolean;

    /**
     * Notify whether device capability is changed.
     *
     * @type { boolean }
     * @readonly
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @since 13
     */
    readonly isDeviceCapabilityChanged: boolean;
  }

  /**
   * Macro Query object.
   *
   * @interface MacroQuery
   * @syscap SystemCapability.Multimedia.Camera.Core
   * @systemapi
   * @since 12
   */
  interface MacroQuery {
    /**
     * Determine whether camera macro is supported.
     *
     * @returns { boolean } Is camera macro supported.
     * @throws { BusinessError } 202 - Not System Application.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @systemapi
     * @since 11
     */
    /**
     * Determine whether camera macro is supported.
     * Move to MacroQuery interface from Macro since 12.
     *
     * @returns { boolean } Is camera macro supported.
     * @throws { BusinessError } 202 - Not System Application.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @systemapi
     * @since 12
     */
    isMacroSupported(): boolean;
  }

  /**
   * Macro object.
   *
   * @interface Macro
   * @syscap SystemCapability.Multimedia.Camera.Core
   * @systemapi
   * @since 11
   */
  interface Macro extends MacroQuery {
    /**
     * Enable macro for camera.
     *
     * @param { boolean } enabled - enable macro for camera if TRUE.
     * @throws { BusinessError } 202 - Not System Application.
     * @throws { BusinessError } 7400103 - Session not config.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @systemapi
     * @since 11
     */
    /**
     * Enable macro for camera.
     *
     * @param { boolean } enabled - enable macro for camera if TRUE.
     * @throws { BusinessError } 202 - Not System Application.
     * @throws { BusinessError } 7400102 - Operation not allowed.
     * @throws { BusinessError } 7400103 - Session not config.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @systemapi
     * @since 12
     */
    enableMacro(enabled: boolean): void;
  }

  /**
   * Enum for usage type used in capture session.
   *
   * @enum { number }
   * @syscap SystemCapability.Multimedia.Camera.Core
   * @systemapi
   * @since 13
   */
  enum UsageType {
    /**
     * Bokeh usage type.
     *
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @systemapi
     * @since 13
     */
    BOKEH = 0
  }

  /**
   * Session object.
   *
   * @interface Session
   * @syscap SystemCapability.Multimedia.Camera.Core
   * @since 11
   */
  interface Session {
    /**
     * Begin capture session config.
     *
     * @throws { BusinessError } 7400105 - Session config locked.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @since 11
     */
    /**
     * Begin capture session config.
     *
     * @throws { BusinessError } 7400105 - Session config locked.
     * @throws { BusinessError } 7400201 - Camera service fatal error.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @since 12
     */
    beginConfig(): void;

    /**
     * Commit capture session config.
     *
     * @param { AsyncCallback<void> } callback - Callback used to return the result.
     * @throws { BusinessError } 7400102 - Operation not allowed.
     * @throws { BusinessError } 7400201 - Camera service fatal error.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @since 11
     */
    commitConfig(callback: AsyncCallback<void>): void;

    /**
     * Commit capture session config.
     *
     * @returns { Promise<void> } Promise used to return the result.
     * @throws { BusinessError } 7400102 - Operation not allowed.
     * @throws { BusinessError } 7400201 - Camera service fatal error.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @since 11
     */
    commitConfig(): Promise<void>;

    /**
     * Determines whether the camera input can be added into the session.
     * This method is valid between Session.beginConfig() and Session.commitConfig().
     *
     * @param { CameraInput } cameraInput - Target camera input to add.
     * @returns { boolean } You can add the input into the session.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @since 11
     */
    canAddInput(cameraInput: CameraInput): boolean;

    /**
     * Adds a camera input.
     * This method is valid between Session.beginConfig() and Session.commitConfig().
     *
     * @param { CameraInput } cameraInput - Target camera input to add.
     * @throws { BusinessError } 7400101 - Parameter missing or parameter type incorrect.
     * @throws { BusinessError } 7400102 - Operation not allowed.
     * @throws { BusinessError } 7400103 - Session not config.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @since 11
     */
    /**
     * Adds a camera input.
     * This method is valid between Session.beginConfig() and Session.commitConfig().
     *
     * @param { CameraInput } cameraInput - Target camera input to add.
     * @throws { BusinessError } 7400101 - Parameter missing or parameter type incorrect.
     * @throws { BusinessError } 7400102 - Operation not allowed.
     * @throws { BusinessError } 7400103 - Session not config.
     * @throws { BusinessError } 7400201 - Camera service fatal error.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @since 12
     */
    addInput(cameraInput: CameraInput): void;

    /**
     * Removes a camera input.
     * This method is valid between Session.beginConfig() and Session.commitConfig().
     *
     * @param { CameraInput } cameraInput - Target camera input to remove.
     * @throws { BusinessError } 7400101 - Parameter missing or parameter type incorrect.
     * @throws { BusinessError } 7400102 - Operation not allowed.
     * @throws { BusinessError } 7400103 - Session not config.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @since 11
     */
    /**
     * Removes a camera input.
     * This method is valid between Session.beginConfig() and Session.commitConfig().
     *
     * @param { CameraInput } cameraInput - Target camera input to remove.
     * @throws { BusinessError } 7400101 - Parameter missing or parameter type incorrect.
     * @throws { BusinessError } 7400102 - Operation not allowed.
     * @throws { BusinessError } 7400103 - Session not config.
     * @throws { BusinessError } 7400201 - Camera service fatal error.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @since 12
     */
    removeInput(cameraInput: CameraInput): void;

    /**
     * Determines whether the camera output can be added into the session.
     * This method is valid after Session.addInput(cameraInput) and before Session.commitConfig().
     *
     * @param { CameraOutput } cameraOutput - Target camera output to add.
     * @returns { boolean } You can add the output into the session.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @since 11
     */
    canAddOutput(cameraOutput: CameraOutput): boolean;

    /**
     * Adds a camera output.
     * This method is valid after Session.addInput(cameraInput) and before Session.commitConfig().
     *
     * @param { CameraOutput } cameraOutput - Target camera output to add.
     * @throws { BusinessError } 7400101 - Parameter missing or parameter type incorrect.
     * @throws { BusinessError } 7400102 - Operation not allowed.
     * @throws { BusinessError } 7400103 - Session not config.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @since 11
     */
    /**
     * Adds a camera output.
     * This method is valid after Session.addInput(cameraInput) and before Session.commitConfig().
     *
     * @param { CameraOutput } cameraOutput - Target camera output to add.
     * @throws { BusinessError } 7400101 - Parameter missing or parameter type incorrect.
     * @throws { BusinessError } 7400102 - Operation not allowed.
     * @throws { BusinessError } 7400103 - Session not config.
     * @throws { BusinessError } 7400201 - Camera service fatal error.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @since 12
     */
    addOutput(cameraOutput: CameraOutput): void;

    /**
     * Removes a camera output.
     * This method is valid between Session.beginConfig() and Session.commitConfig().
     *
     * @param { CameraOutput } cameraOutput - Target camera output to remove.
     * @throws { BusinessError } 7400101 - Parameter missing or parameter type incorrect.
     * @throws { BusinessError } 7400102 - Operation not allowed.
     * @throws { BusinessError } 7400103 - Session not config.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @since 11
     */
    /**
     * Removes a camera output.
     * This method is valid between Session.beginConfig() and Session.commitConfig().
     *
     * @param { CameraOutput } cameraOutput - Target camera output to remove.
     * @throws { BusinessError } 7400101 - Parameter missing or parameter type incorrect.
     * @throws { BusinessError } 7400102 - Operation not allowed.
     * @throws { BusinessError } 7400103 - Session not config.
     * @throws { BusinessError } 7400201 - Camera service fatal error.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @since 12
     */
    removeOutput(cameraOutput: CameraOutput): void;

    /**
     * Starts capture session.
     *
     * @param { AsyncCallback<void> } callback - Callback used to return the result.
     * @throws { BusinessError } 7400103 - Session not config.
     * @throws { BusinessError } 7400201 - Camera service fatal error.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @since 11
     */
    /**
     * Starts capture session.
     *
     * @param { AsyncCallback<void> } callback - Callback used to return the result.
     * @throws { BusinessError } 7400102 - Operation not allowed.
     * @throws { BusinessError } 7400103 - Session not config.
     * @throws { BusinessError } 7400201 - Camera service fatal error.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @since 12
     */
    start(callback: AsyncCallback<void>): void;

    /**
     * Starts capture session.
     *
     * @returns { Promise<void> } Promise used to return the result.
     * @throws { BusinessError } 7400103 - Session not config.
     * @throws { BusinessError } 7400201 - Camera service fatal error.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @since 11
     */
    /**
     * Starts capture session.
     *
     * @returns { Promise<void> } Promise used to return the result.
     * @throws { BusinessError } 7400102 - Operation not allowed.
     * @throws { BusinessError } 7400103 - Session not config.
     * @throws { BusinessError } 7400201 - Camera service fatal error.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @since 12
     */
    start(): Promise<void>;

    /**
     * Stops capture session.
     *
     * @param { AsyncCallback<void> } callback - Callback used to return the result.
     * @throws { BusinessError } 7400201 - Camera service fatal error.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @since 11
     */
    stop(callback: AsyncCallback<void>): void;

    /**
     * Stops capture session.
     *
     * @returns { Promise<void> } Promise used to return the result.
     * @throws { BusinessError } 7400201 - Camera service fatal error.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @since 11
     */
    stop(): Promise<void>;

    /**
     * Release capture session instance.
     *
     * @param { AsyncCallback<void> } callback - Callback used to return the result.
     * @throws { BusinessError } 7400201 - Camera service fatal error.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @since 11
     */
    release(callback: AsyncCallback<void>): void;

    /**
     * Release capture session instance.
     *
     * @returns { Promise<void> } Promise used to return the result.
     * @throws { BusinessError } 7400201 - Camera service fatal error.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @since 11
     */
    release(): Promise<void>;

    /**
     * Set usage for the capture session.
     *
     * @param { UsageType } usage - The capture session usage.
     * @param { boolean } enabled - Enable usage for session if TRUE.
     * @throws { BusinessError } 202 - Not System Application.
     * @throws { BusinessError } 7400101 - Parameter missing or parameter type incorrect.
     * @throws { BusinessError } 7400102 - Operation not allowed.
     * @throws { BusinessError } 7400103 - Session not config.
     * @throws { BusinessError } 7400201 - Camera service fatal error.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @systemapi
     * @since 13
     */
    setUsage(usage: UsageType, enabled: boolean): void;

    /**
     * Get the supported camera output capability set.
     *
     * @param { CameraDevice } camera - Camera device.
     * @returns { Array<CameraOutputCapability> } The array of the output capability.
     * @throws { BusinessError } 202 - Not System Application.
     * @throws { BusinessError } 7400101 - Parameter missing or parameter type incorrect.
     * @throws { BusinessError } 7400201 - Camera service fatal error.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @systemapi
     * @since 13
     */
    getCameraOutputCapabilities(camera: CameraDevice): Array<CameraOutputCapability>;
  }

  /**
   * Capture session object.
   *
   * @interface CaptureSession
   * @syscap SystemCapability.Multimedia.Camera.Core
   * @since 10
   * @deprecated since 11
   * @useinstead ohos.multimedia.camera.VideoSession
   */
  interface CaptureSession {
    /**
     * Begin capture session config.
     *
     * @throws { BusinessError } 7400105 - Session config locked.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @since 10
     * @deprecated since 11
     * @useinstead ohos.multimedia.camera.Session#beginConfig
     */
    beginConfig(): void;

    /**
     * Commit capture session config.
     *
     * @param { AsyncCallback<void> } callback - Callback used to return the result.
     * @throws { BusinessError } 7400102 - Operation not allowed.
     * @throws { BusinessError } 7400201 - Camera service fatal error.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @since 10
     * @deprecated since 11
     * @useinstead ohos.multimedia.camera.Session#commitConfig
     */
    commitConfig(callback: AsyncCallback<void>): void;

    /**
     * Commit capture session config.
     *
     * @returns { Promise<void> } Promise used to return the result.
     * @throws { BusinessError } 7400102 - Operation not allowed.
     * @throws { BusinessError } 7400201 - Camera service fatal error.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @since 10
     * @deprecated since 11
     * @useinstead ohos.multimedia.camera.Session#commitConfig
     */
    commitConfig(): Promise<void>;

    /**
     * Adds a camera input.
     *
     * @param { CameraInput } cameraInput - Target camera input to add.
     * @throws { BusinessError } 7400101 - Parameter missing or parameter type incorrect.
     * @throws { BusinessError } 7400102 - Operation not allowed.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @since 10
     * @deprecated since 11
     * @useinstead ohos.multimedia.camera.Session#addInput
     */
    addInput(cameraInput: CameraInput): void;

    /**
     * Removes a camera input.
     *
     * @param { CameraInput } cameraInput - Target camera input to remove.
     * @throws { BusinessError } 7400101 - Parameter missing or parameter type incorrect.
     * @throws { BusinessError } 7400102 - Operation not allowed.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @since 10
     * @deprecated since 11
     * @useinstead ohos.multimedia.camera.Session#removeInput
     */
    removeInput(cameraInput: CameraInput): void;

    /**
     * Adds a camera output.
     *
     * @param { CameraOutput } cameraOutput - Target camera output to add.
     * @throws { BusinessError } 7400101 - Parameter missing or parameter type incorrect.
     * @throws { BusinessError } 7400102 - Operation not allowed.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @since 10
     * @deprecated since 11
     * @useinstead ohos.multimedia.camera.Session#addOutput
     */
    addOutput(cameraOutput: CameraOutput): void;

    /**
     * Removes a camera output.
     *
     * @param { CameraOutput } cameraOutput - Target camera output to remove.
     * @throws { BusinessError } 7400101 - Parameter missing or parameter type incorrect.
     * @throws { BusinessError } 7400102 - Operation not allowed.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @since 10
     * @deprecated since 11
     * @useinstead ohos.multimedia.camera.Session#removeOutput
     */
    removeOutput(cameraOutput: CameraOutput): void;

    /**
     * Starts capture session.
     *
     * @param { AsyncCallback<void> } callback - Callback used to return the result.
     * @throws { BusinessError } 7400103 - Session not config.
     * @throws { BusinessError } 7400201 - Camera service fatal error.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @since 10
     * @deprecated since 11
     * @useinstead ohos.multimedia.camera.Session#start
     */
    start(callback: AsyncCallback<void>): void;

    /**
     * Starts capture session.
     *
     * @returns { Promise<void> } Promise used to return the result.
     * @throws { BusinessError } 7400103 - Session not config.
     * @throws { BusinessError } 7400201 - Camera service fatal error.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @since 10
     * @deprecated since 11
     * @useinstead ohos.multimedia.camera.Session#start
     */
    start(): Promise<void>;

    /**
     * Stops capture session.
     *
     * @param { AsyncCallback<void> } callback - Callback used to return the result.
     * @throws { BusinessError } 7400201 - Camera service fatal error.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @since 10
     * @deprecated since 11
     * @useinstead ohos.multimedia.camera.Session#stop
     */
    stop(callback: AsyncCallback<void>): void;

    /**
     * Stops capture session.
     *
     * @returns { Promise<void> } Promise used to return the result.
     * @throws { BusinessError } 7400201 - Camera service fatal error.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @since 10
     * @deprecated since 11
     * @useinstead ohos.multimedia.camera.Session#stop
     */
    stop(): Promise<void>;

    /**
     * Release capture session instance.
     *
     * @param { AsyncCallback<void> } callback - Callback used to return the result.
     * @throws { BusinessError } 7400201 - Camera service fatal error.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @since 10
     * @deprecated since 11
     * @useinstead ohos.multimedia.camera.Session#release
     */
    release(callback: AsyncCallback<void>): void;

    /**
     * Release capture session instance.
     *
     * @returns { Promise<void> } Promise used to return the result.
     * @throws { BusinessError } 7400201 - Camera service fatal error.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @since 10
     * @deprecated since 11
     * @useinstead ohos.multimedia.camera.Session#release
     */
    release(): Promise<void>;

    /**
     * Check if device has flash light.
     *
     * @returns { boolean } The flash light support status.
     * @throws { BusinessError } 7400103 - Session not config.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @since 10
     * @deprecated since 11
     * @useinstead ohos.multimedia.camera.Flash#hasFlash
     */
    hasFlash(): boolean;

    /**
     * Checks whether a specified flash mode is supported.
     *
     * @param { FlashMode } flashMode - Flash mode
     * @returns { boolean } Is the flash mode supported.
     * @throws { BusinessError } 7400103 - Session not config.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @since 10
     * @deprecated since 11
     * @useinstead ohos.multimedia.camera.Flash#isFlashModeSupported
     */
    isFlashModeSupported(flashMode: FlashMode): boolean;

    /**
     * Gets current flash mode.
     *
     * @returns { FlashMode } The current flash mode.
     * @throws { BusinessError } 7400103 - Session not config.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @since 10
     * @deprecated since 11
     * @useinstead ohos.multimedia.camera.Flash#getFlashMode
     */
    getFlashMode(): FlashMode;

    /**
     * Sets flash mode.
     *
     * @param { FlashMode } flashMode - Target flash mode.
     * @throws { BusinessError } 7400103 - Session not config.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @since 10
     * @deprecated since 11
     * @useinstead ohos.multimedia.camera.Flash#setFlashMode
     */
    setFlashMode(flashMode: FlashMode): void;

    /**
     * Checks whether a specified exposure mode is supported.
     *
     * @param { ExposureMode } aeMode - Exposure mode
     * @returns { boolean } Is the exposure mode supported.
     * @throws { BusinessError } 7400103 - Session not config.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @since 10
     * @deprecated since 11
     * @useinstead ohos.multimedia.camera.AutoExposure#isExposureModeSupported
     */
    isExposureModeSupported(aeMode: ExposureMode): boolean;

    /**
     * Gets current exposure mode.
     *
     * @returns { ExposureMode } The current exposure mode.
     * @throws { BusinessError } 7400103 - Session not config.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @since 10
     * @deprecated since 11
     * @useinstead ohos.multimedia.camera.AutoExposure#getExposureMode
     */
    getExposureMode(): ExposureMode;

    /**
     * Sets Exposure mode.
     *
     * @param { ExposureMode } aeMode - Exposure mode
     * @throws { BusinessError } 7400103 - Session not config.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @since 10
     * @deprecated since 11
     * @useinstead ohos.multimedia.camera.AutoExposure#setExposureMode
     */
    setExposureMode(aeMode: ExposureMode): void;

    /**
     * Gets current metering point.
     *
     * @returns { Point } The current metering point.
     * @throws { BusinessError } 7400103 - Session not config.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @since 10
     * @deprecated since 11
     * @useinstead ohos.multimedia.camera.AutoExposure#getMeteringPoint
     */
    getMeteringPoint(): Point;

    /**
     * Set the center point of the metering area.
     *
     * @param { Point } point - metering point
     * @throws { BusinessError } 7400103 - Session not config.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @since 10
     * @deprecated since 11
     * @useinstead ohos.multimedia.camera.AutoExposure#setMeteringPoint
     */
    setMeteringPoint(point: Point): void;

    /**
     * Query the exposure compensation range.
     *
     * @returns { Array<number> } The array of compensation range.
     * @throws { BusinessError } 7400103 - Session not config.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @since 10
     * @deprecated since 11
     * @useinstead ohos.multimedia.camera.AutoExposure#getExposureBiasRange
     */
    getExposureBiasRange(): Array<number>;

    /**
     * Set exposure compensation.
     *
     * @param { number } exposureBias - Exposure compensation
     * @throws { BusinessError } 7400103 - Session not config.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @since 10
     * @deprecated since 11
     * @useinstead ohos.multimedia.camera.AutoExposure#setExposureBias
     */
    setExposureBias(exposureBias: number): void;

    /**
     * Query the exposure value.
     *
     * @returns { number } The exposure value.
     * @throws { BusinessError } 7400103 - Session not config.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @since 10
     * @deprecated since 11
     * @useinstead ohos.multimedia.camera.AutoExposure#getExposureValue
     */
    getExposureValue(): number;

    /**
     * Checks whether a specified focus mode is supported.
     *
     * @param { FocusMode } afMode - Focus mode.
     * @returns { boolean } Is the focus mode supported.
     * @throws { BusinessError } 7400103 - Session not config.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @since 10
     * @deprecated since 11
     * @useinstead ohos.multimedia.camera.Focus#isFocusModeSupported
     */
    isFocusModeSupported(afMode: FocusMode): boolean;

    /**
     * Gets current focus mode.
     *
     * @returns { FocusMode } The current focus mode.
     * @throws { BusinessError } 7400103 - Session not config.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @since 10
     * @deprecated since 11
     * @useinstead ohos.multimedia.camera.Focus#getFocusMode
     */
    getFocusMode(): FocusMode;

    /**
     * Sets focus mode.
     *
     * @param { FocusMode } afMode - Target focus mode.
     * @throws { BusinessError } 7400103 - Session not config.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @since 10
     * @deprecated since 11
     * @useinstead ohos.multimedia.camera.Focus#setFocusMode
     */
    setFocusMode(afMode: FocusMode): void;

    /**
     * Sets focus point.
     *
     * @param { Point } point - Target focus point.
     * @throws { BusinessError } 7400103 - Session not config.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @since 10
     * @deprecated since 11
     * @useinstead ohos.multimedia.camera.Focus#setFocusPoint
     */
    setFocusPoint(point: Point): void;

    /**
     * Gets current focus point.
     *
     * @returns { Point } The current focus point.
     * @throws { BusinessError } 7400103 - Session not config.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @since 10
     * @deprecated since 11
     * @useinstead ohos.multimedia.camera.Focus#getFocusPoint
     */
    getFocusPoint(): Point;

    /**
     * Gets current focal length.
     *
     * @returns { number } The current focal point.
     * @throws { BusinessError } 7400103 - Session not config.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @since 10
     * @deprecated since 11
     * @useinstead ohos.multimedia.camera.Focus#getFocalLength
     */
    getFocalLength(): number;

    /**
     * Gets all supported zoom ratio range.
     *
     * @returns { Array<number> } The zoom ratio range.
     * @throws { BusinessError } 7400103 - Session not config.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @since 10
     * @deprecated since 11
     * @useinstead ohos.multimedia.camera.Zoom#getZoomRatioRange
     */
    getZoomRatioRange(): Array<number>;

    /**
     * Gets zoom ratio.
     *
     * @returns { number } The zoom ratio value.
     * @throws { BusinessError } 7400103 - Session not config.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @since 10
     * @deprecated since 11
     * @useinstead ohos.multimedia.camera.Zoom#getZoomRatio
     */
    getZoomRatio(): number;

    /**
     * Sets zoom ratio.
     *
     * @param { number } zoomRatio - Target zoom ratio.
     * @throws { BusinessError } 7400103 - Session not config.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @since 10
     * @deprecated since 11
     * @useinstead ohos.multimedia.camera.Zoom#setZoomRatio
     */
    setZoomRatio(zoomRatio: number): void;

    /**
     * Check whether the specified video stabilization mode is supported.
     *
     * @param { VideoStabilizationMode } vsMode - Video Stabilization mode.
     * @returns { boolean } Is flash mode supported.
     * @throws { BusinessError } 7400103 - Session not config.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @since 10
     * @deprecated since 11
     * @useinstead ohos.multimedia.camera.Stabilization#isVideoStabilizationModeSupported
     */
    isVideoStabilizationModeSupported(vsMode: VideoStabilizationMode): boolean;

    /**
     * Query the video stabilization mode currently in use.
     *
     * @returns { VideoStabilizationMode } The current video stabilization mode.
     * @throws { BusinessError } 7400103 - Session not config.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @since 10
     * @deprecated since 11
     * @useinstead ohos.multimedia.camera.Stabilization#getActiveVideoStabilizationMode
     */
    getActiveVideoStabilizationMode(): VideoStabilizationMode;

    /**
     * Set video stabilization mode.
     *
     * @param { VideoStabilizationMode } mode - video stabilization mode to set.
     * @throws { BusinessError } 7400103 - Session not config.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @since 10
     * @deprecated since 11
     * @useinstead ohos.multimedia.camera.Stabilization#setVideoStabilizationMode
     */
    setVideoStabilizationMode(mode: VideoStabilizationMode): void;

    /**
     * Subscribes focus status change event callback.
     *
     * @param { 'focusStateChange' } type - Event type.
     * @param { AsyncCallback<FocusState> } callback - Callback used to get the focus state change.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @since 10
     * @deprecated since 11
     * @useinstead ohos.multimedia.camera.VideoSession#on
     */
    on(type: 'focusStateChange', callback: AsyncCallback<FocusState>): void;

    /**
     * Unsubscribes from focus status change event callback.
     *
     * @param { 'focusStateChange' } type - Event type.
     * @param { AsyncCallback<FocusState> } callback - Callback used to get the focus state change.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @since 10
     * @deprecated since 11
     * @useinstead ohos.multimedia.camera.VideoSession#off
     */
    off(type: 'focusStateChange', callback?: AsyncCallback<FocusState>): void;

    /**
     * Subscribes to error events.
     *
     * @param { 'error' } type - Event type.
     * @param { ErrorCallback } callback - Callback used to get the capture session errors.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @since 10
     * @deprecated since 11
     * @useinstead ohos.multimedia.camera.VideoSession#on
     */
    on(type: 'error', callback: ErrorCallback): void;

    /**
     * Unsubscribes from error events.
     *
     * @param { 'error' } type - Event type.
     * @param { ErrorCallback } callback - Callback used to get the capture session errors.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @since 10
     * @deprecated since 11
     * @useinstead ohos.multimedia.camera.VideoSession#off
     */
    off(type: 'error', callback?: ErrorCallback): void;

    /**
     * Gets supported beauty effect types.
     *
     * @returns { Array<BeautyType> } List of beauty effect types.
     * @throws { BusinessError } 7400103 - Session not config.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @systemapi
     * @since 10
     * @deprecated since 11
     * @useinstead ohos.multimedia.camera.Beauty#getSupportedBeautyTypes
     */
    getSupportedBeautyTypes(): Array<BeautyType>;

    /**
     * Gets the specific beauty effect type range.
     *
     * @param { BeautyType } type - The type of beauty effect.
     * @returns { Array<number> } The array of the specific beauty effect range.
     * @throws { BusinessError } 7400103 - Session not config.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @systemapi
     * @since 10
     * @deprecated since 11
     * @useinstead ohos.multimedia.camera.Beauty#getSupportedBeautyRange
     */
    getSupportedBeautyRange(type: BeautyType): Array<number>;

    /**
     * Gets the beauty effect in use.
     *
     * @param { BeautyType } type - The type of beauty effect.
     * @returns { number } the beauty effect in use.
     * @throws { BusinessError } 7400103 - Session not config.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @systemapi
     * @since 10
     * @deprecated since 11
     * @useinstead ohos.multimedia.camera.Beauty#getBeauty
     */
    getBeauty(type: BeautyType): number;

    /**
     * Sets a beauty effect for a camera device.
     *
     * @param { BeautyType } type - The type of beauty effect.
     * @param { number } value The number of beauty effect.
     * @throws { BusinessError } 7400103 - Session not config.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @systemapi
     * @since 10
     * @deprecated since 11
     * @useinstead ohos.multimedia.camera.Beauty#setBeauty
     */
    setBeauty(type: BeautyType, value: number): void;
  }

  /**
   * Types of preconfig, which used to configure session conveniently.
   * Preconfig type contains common use cases of camera output.
   *
   * @enum { number }
   * @syscap SystemCapability.Multimedia.Camera.Core
   * @since 12
   */
  enum PreconfigType {
    /**
     * 720P output for preconfig.
     *
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @since 12
     */
    PRECONFIG_720P = 0,

    /**
     * 1080P output for preconfig.
     *
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @since 12
     */
    PRECONFIG_1080P = 1,

    /**
     * 4K output for preconfig.
     *
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @since 12
     */
    PRECONFIG_4K = 2,

    /**
     * high quality output for preconfig.
     *
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @since 12
     */
    PRECONFIG_HIGH_QUALITY = 3
  }

  /**
   * The aspect ratios of preconfig, which used to configure session conveniently.
   *
   * @enum { number }
   * @syscap SystemCapability.Multimedia.Camera.Core
   * @since 12
   */
  enum PreconfigRatio {
    /**
     * Aspect ratio 1:1 for preconfig.
     *
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @since 12
     */
    PRECONFIG_RATIO_1_1 = 0,

    /**
     * Aspect ratio 4:3 for preconfig.
     *
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @since 12
     */
    PRECONFIG_RATIO_4_3 = 1,

    /**
     * Aspect ratio 16:9 for preconfig.
     *
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @since 12
     */
    PRECONFIG_RATIO_16_9 = 2
  }

  /**
   * Enum for feature type used in scene detection.
   *
   * @enum { number }
   * @syscap SystemCapability.Multimedia.Camera.Core
   * @systemapi
   * @since 12
   */
  enum SceneFeatureType {
    /**
     * Feature for boost moon capture.
     *
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @systemapi
     * @since 12
     */
    MOON_CAPTURE_BOOST = 0,

    /**
     * Feature for tripod detection.
     *
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @systemapi
     * @since 13
     */
    TRIPOD_DETECTION = 1,

    /**
     * Feature for low light boost.
     *
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @systemapi
     * @since 13
     */
    LOW_LIGHT_BOOST = 2
  }

  /**
   * Feature Detection Result.
   *
   * @typedef SceneFeatureDetectionResult
   * @syscap SystemCapability.Multimedia.Camera.Core
   * @systemapi
   * @since 12
   */
  interface SceneFeatureDetectionResult {
    /**
     * Detected feature type.
     *
     * @type { SceneFeatureType }
     * @readonly
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @systemapi
     * @since 12
     */
    readonly featureType: SceneFeatureType;

    /**
     * Check whether feature is detected.
     *
     * @type { boolean }
     * @readonly
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @systemapi
     * @since 12
     */
    readonly detected: boolean;
  }

  /**
   * Enum for tripod status.
   *
   * @enum { number }
   * @syscap SystemCapability.Multimedia.Camera.Core
   * @systemapi
   * @since 13
   */
  enum TripodStatus {
    /**
     * Invalid tripod status.
     *
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @systemapi
     * @since 13
     */
    INVALID = 0,

    /**
     * Tripod is active.
     *
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @systemapi
     * @since 13
     */
    ACTIVE = 1,

    /**
     * Enter tripod stabilization state.
     *
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @systemapi
     * @since 13
     */
    ENTERING = 2,

    /**
     * Exit tripod stabilization state.
     *
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @systemapi
     * @since 13
     */
    EXITING = 3,
  }

   /**
   * Tripod detection result.
   *
   * @interface TripodDetectionResult
   * @extends SceneFeatureDetectionResult
   * @syscap SystemCapability.Multimedia.Camera.Core
   * @systemapi
   * @since 13
   */
  interface TripodDetectionResult extends SceneFeatureDetectionResult {
    /**
     * tripod status.
     *
     * @type { TripodStatus }
     * @readonly
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @systemapi
     * @since 13
     */
    readonly tripodStatus: TripodStatus;
  }

  /**
   * Scene detection query.
   *
   * @interface SceneDetectionQuery
   * @syscap SystemCapability.Multimedia.Camera.Core
   * @systemapi
   * @since 12
   */
  interface SceneDetectionQuery {
    /**
     * Check whether specified feature is supported.
     *
     * @param { SceneFeatureType } type - Specified feature type.
     * @returns { boolean } - Is specified feature supported.
     * @throws { BusinessError } 202 - Not System Application, only throw in session usage.
     * @throws { BusinessError } 7400101 - Parameter missing or parameter type incorrect.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @systemapi
     * @since 12
     */
    isSceneFeatureSupported(type: SceneFeatureType): boolean;
  }

  /**
   * Scene detection.
   *
   * @interface SceneDetection
   * @syscap SystemCapability.Multimedia.Camera.Core
   * @systemapi
   * @since 12
   */
  interface SceneDetection extends SceneDetectionQuery {
    /**
     * Enable specified feature.
     *
     * @param { SceneFeatureType } type - Specified feature type.
     * @param { boolean } enabled - Target feature status.
     * @throws { BusinessError } 202 - Not System Application.
     * @throws { BusinessError } 7400101 - Parameter missing or parameter type incorrect.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @systemapi
     * @since 12
     */
    enableSceneFeature(type: SceneFeatureType, enabled: boolean): void;
  }

  /**
   * Photo session object for system hap.
   *
   * @interface PhotoSessionForSys
   * @extends PhotoSession, Beauty, ColorEffect, ColorManagement, Macro, SceneDetection, EffectSuggestion
   * @syscap SystemCapability.Multimedia.Camera.Core
   * @systemapi
   * @since 11
   */
  /**
   * Photo session object for system hap.
   *
   * @interface PhotoSessionForSys
   * @extends PhotoSession, Beauty, ColorEffect, ColorManagement, Macro, SceneDetection, EffectSuggestion, DepthFusion
   * @syscap SystemCapability.Multimedia.Camera.Core
   * @systemapi
   * @since 14
   */
  interface PhotoSessionForSys extends PhotoSession, Beauty, ColorEffect, ColorManagement, Macro, SceneDetection, EffectSuggestion, DepthFusion {
  }

  /**
   * Photo session object.
   *
   * @interface PhotoSession
   * @extends Session, Flash, AutoExposure, Focus, Zoom, ColorManagement
   * @syscap SystemCapability.Multimedia.Camera.Core
   * @since 11
   */
  /**
   * Photo session object.
   *
   * @interface PhotoSession
   * @extends AutoDeviceSwitch
   * @syscap SystemCapability.Multimedia.Camera.Core
   * @since 13
   */
  interface PhotoSession extends Session, Flash, AutoExposure, Focus, Zoom, ColorManagement, AutoDeviceSwitch {
    /**
     * Gets whether the choosed preconfig type can be used to configure photo session.
     * Must choose preconfig type from {@link PreconfigType}.
     *
     * @param { PreconfigType } preconfigType - preconfig type.
     * @param { PreconfigRatio } preconfigRatio - the aspect ratio of surface for preconfig,
     *                                            default value {@link PreconfigRatio#PRECONFIG_RATIO_4_3}.
     * @returns { boolean } Whether the choosed preconfig type can be used.
     * @throws { BusinessError } 7400201 - Camera service fatal error.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @since 12
     */
    canPreconfig(preconfigType: PreconfigType, preconfigRatio?: PreconfigRatio): boolean;

    /**
     * Configure photo session with the preconfig type.
     * Must choose preconfig type from {@link PreconfigType}.
     *
     * @param { PreconfigType } preconfigType - preconfig type.
     * @param { PreconfigRatio } preconfigRatio - the aspect ratio of surface for preconfig,
     *                                            default value {@link PreconfigRatio#PRECONFIG_RATIO_4_3}
     * @throws { BusinessError } 7400201 - Camera service fatal error.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @since 12
     */
    preconfig(preconfigType: PreconfigType, preconfigRatio?: PreconfigRatio): void;

    /**
     * Subscribes to error events.
     *
     * @param { 'error' } type - Event type.
     * @param { ErrorCallback } callback - Callback used to get the capture session errors.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @since 11
     */
    on(type: 'error', callback: ErrorCallback): void;

    /**
     * Unsubscribes from error events.
     *
     * @param { 'error' } type - Event type.
     * @param { ErrorCallback } callback - Callback used to get the capture session errors.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @since 11
     */
    off(type: 'error', callback?: ErrorCallback): void;

    /**
     * Subscribes focus state change event callback.
     *
     * @param { 'focusStateChange' } type - Event type.
     * @param { AsyncCallback<FocusState> } callback - Callback used to get the focus state change.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @since 11
     */
    on(type: 'focusStateChange', callback: AsyncCallback<FocusState>): void;

    /**
     * Unsubscribes from focus state change event callback.
     *
     * @param { 'focusStateChange' } type - Event type.
     * @param { AsyncCallback<FocusState> } callback - Callback used to get the focus state change.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @since 11
     */
    off(type: 'focusStateChange', callback?: AsyncCallback<FocusState>): void;

    /**
     * Subscribes zoom info event callback.
     *
     * @param { 'smoothZoomInfoAvailable' } type - Event type.
     * @param { AsyncCallback<SmoothZoomInfo> } callback - Callback used to get the zoom info.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @since 11
     */
    on(type: 'smoothZoomInfoAvailable', callback: AsyncCallback<SmoothZoomInfo>): void;

    /**
     * Unsubscribes from zoom info event callback.
     *
     * @param { 'smoothZoomInfoAvailable' } type - Event type.
     * @param { AsyncCallback<SmoothZoomInfo> } callback - Callback used to get the zoom info.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @since 11
     */
    off(type: 'smoothZoomInfoAvailable', callback?: AsyncCallback<SmoothZoomInfo>): void;

    /**
     * Subscribes camera macro status event callback.
     *
     * @param { 'macroStatusChanged' } type - Event type.
     * @param { AsyncCallback<boolean> } callback - Callback used to return the result.
     * @throws { BusinessError } 202 - Not System Application.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @systemapi
     * @since 11
     */
    on(type: 'macroStatusChanged', callback: AsyncCallback<boolean>): void;

    /**
     * Unsubscribes camera macro status event callback.
     *
     * @param { 'macroStatusChanged' } type - Event type.
     * @param { AsyncCallback<boolean> } callback - Callback used to return the result.
     * @throws { BusinessError } 202 - Not System Application.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @systemapi
     * @since 11
     */
    off(type: 'macroStatusChanged', callback?: AsyncCallback<boolean>): void;

    /**
     * Subscribes to system pressure level callback.
     *
     * @param { 'systemPressureLevelChange' } type - Event type.
     * @param { AsyncCallback<SystemPressureLevel> } callback - Callback used to return the result.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @since 20
     */
    on(type: 'systemPressureLevelChange', callback: AsyncCallback<SystemPressureLevel>): void;
 
    /**
     * Unsubscribes to system pressure level callback.
     *
     * @param { 'systemPressureLevelChange' } type - Event type.
     * @param { AsyncCallback<SystemPressureLevel> } callback - Callback used to return the result.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @since 20
     */
    off(type: 'systemPressureLevelChange', callback?: AsyncCallback<SystemPressureLevel>): void;

    /**
     * Subscribes to feature detection results.
     *
     * @param { 'featureDetection' } type - Event type.
     * @param { SceneFeatureType } featureType - Feature type.
     * @param { AsyncCallback<SceneFeatureDetectionResult> } callback - Callback used to get the detection result.
     * @throws { BusinessError } 202 - Not System Application.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @systemapi
     * @since 12
     */
    on(type: 'featureDetection', featureType: SceneFeatureType, callback: AsyncCallback<SceneFeatureDetectionResult>): void;

    /**
     * Unsubscribes from feature detection result.
     *
     * @param { 'featureDetection' } type - Event type.
     * @param { SceneFeatureType } featureType - Feature type.
     * @param { AsyncCallback<SceneFeatureDetectionResult> } callback - Callback used to get the detection result.
     * @throws { BusinessError } 202 - Not System Application.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @systemapi
     * @since 12
     */
    off(type: 'featureDetection', featureType: SceneFeatureType, callback?: AsyncCallback<SceneFeatureDetectionResult>): void;

    /**
     * Subscribes to effect suggestion event callback.
     *
     * @param { 'effectSuggestionChange' } type - Event type.
     * @param { AsyncCallback<EffectSuggestionType> } callback - Callback used to return the result.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @systemapi
     * @since 12
     */
    on(type: 'effectSuggestionChange', callback: AsyncCallback<EffectSuggestionType>): void;

    /**
     * Unsubscribes from effect suggestion event callback.
     *
     * @param { 'effectSuggestionChange' } type - Event type.
     * @param { AsyncCallback<EffectSuggestionType> } callback - Callback used to return the result.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @systemapi
     * @since 12
     */
    off(type: 'effectSuggestionChange', callback?: AsyncCallback<EffectSuggestionType>): void;

    /**
     * Subscribes to auto device switch status event callback.
     *
     * @param { 'autoDeviceSwitchStatusChange' } type - Event type.
     * @param { AsyncCallback<AutoDeviceSwitchStatus> } callback - Callback used to return the result.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @since 13
     */
    on(type: 'autoDeviceSwitchStatusChange', callback: AsyncCallback<AutoDeviceSwitchStatus>): void;

    /**
     * Unsubscribes to auto device switch status event callback.
     *
     * @param { 'autoDeviceSwitchStatusChange' } type - Event type.
     * @param { AsyncCallback<AutoDeviceSwitchStatus> } callback - Callback used to return the result.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @since 13
     */
    off(type: 'autoDeviceSwitchStatusChange', callback?: AsyncCallback<AutoDeviceSwitchStatus>): void;

    /**
     * Subscribes to lcd flash status.
     *
     * @param { 'lcdFlashStatus' } type - Event type.
     * @param { AsyncCallback<LcdFlashStatus> } callback - Callback used to get the lcd flash status.
     * @throws { BusinessError } 202 - Not System Application.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @systemapi
     * @since 13
     */
    on(type: 'lcdFlashStatus', callback: AsyncCallback<LcdFlashStatus>): void;

    /**
     * Unsubscribes from lcd flash status.
     *
     * @param { 'lcdFlashStatus' } type - Event type.
     * @param { AsyncCallback<LcdFlashStatus> } callback - Callback used to get the lcd flash status.
     * @throws { BusinessError } 202 - Not System Application.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @systemapi
     * @since 13
     */
    off(type: 'lcdFlashStatus', callback?: AsyncCallback<LcdFlashStatus>): void;

    /**
     * Gets session functions.
     *
     * @param { CameraOutputCapability } outputCapability - CameraOutputCapability to set.
     * @returns { Array<PhotoFunctions> } List of session functions.
     * @throws { BusinessError } 202 - Not System Application.
     * @throws { BusinessError } 401 - Parameter error. Possible causes: 1.Mandatory parameters are left unspecified. 2.Incorrect parameter types.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @systemapi
     * @since 13
     */
    getSessionFunctions(outputCapability: CameraOutputCapability): Array<PhotoFunctions>;

    /**
     * Gets session conflict functions.
     *
     * @returns { Array<PhotoConflictFunctions> } List of session conflict functions.
     * @throws { BusinessError } 202 - Not System Application.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @systemapi
     * @since 13
     */
    getSessionConflictFunctions(): Array<PhotoConflictFunctions>;
  }

  /**
   * Video session object for system hap.
   *
   * @interface VideoSessionForSys
   * @syscap SystemCapability.Multimedia.Camera.Core
   * @systemapi
   * @since 11
   */
  interface VideoSessionForSys extends VideoSession, Beauty, ColorEffect, ColorManagement, Macro, EffectSuggestion {
  }

  /**
   * Video session object.
   *
   * @interface VideoSession
   * @extends Session, Flash, AutoExposure, Focus, Zoom, Stabilization, ColorManagement
   * @syscap SystemCapability.Multimedia.Camera.Core
   * @since 11
   */
  /**
   * Video session object.
   *
   * @interface VideoSession
   * @extends AutoDeviceSwitch
   * @syscap SystemCapability.Multimedia.Camera.Core
   * @since 13
   */
  interface VideoSession extends Session, Flash, AutoExposure, Focus, Zoom, Stabilization, ColorManagement, ControlCenter, AutoDeviceSwitch {
    /**
     * Gets whether the choosed preconfig type can be used to configure video session.
     * Must choose preconfig type from {@link PreconfigType}.
     *
     * @param { PreconfigType } preconfigType - preconfig type.
     * @param { PreconfigRatio } preconfigRatio - the aspect ratio of surface for preconfig,
     *                                            default value {@link PreconfigRatio#PRECONFIG_RATIO_16_9}.
     * @returns { boolean } Whether the choosed preconfig type can be used.
     * @throws { BusinessError } 7400201 - Camera service fatal error.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @since 12
     */
    canPreconfig(preconfigType: PreconfigType, preconfigRatio?: PreconfigRatio): boolean;

    /**
     * Configure video session with the preconfig type.
     * Must choose preconfig type from {@link PreconfigType}.
     *
     * @param { PreconfigType } preconfigType - preconfig type.
     * @param { PreconfigRatio } preconfigRatio - the aspect ratio of surface for preconfig,
     *                                            default value {@link PreconfigRatio#PRECONFIG_RATIO_16_9}.
     * @throws { BusinessError } 7400201 - Camera service fatal error.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @since 12
     */
    preconfig(preconfigType: PreconfigType, preconfigRatio?: PreconfigRatio): void;

    /**
     * Subscribes to error events.
     *
     * @param { 'error' } type - Event type.
     * @param { ErrorCallback } callback - Callback used to get the capture session errors.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @since 11
     */
    on(type: 'error', callback: ErrorCallback): void;

    /**
     * Unsubscribes from error events.
     *
     * @param { 'error' } type - Event type.
     * @param { ErrorCallback } callback - Callback used to get the capture session errors.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @since 11
     */
    off(type: 'error', callback?: ErrorCallback): void;

    /**
     * Subscribes focus state change event callback.
     *
     * @param { 'focusStateChange' } type - Event type.
     * @param { AsyncCallback<FocusState> } callback - Callback used to get the focus state change.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @since 11
     */
    on(type: 'focusStateChange', callback: AsyncCallback<FocusState>): void;

    /**
     * Unsubscribes from focus state change event callback.
     *
     * @param { 'focusStateChange' } type - Event type.
     * @param { AsyncCallback<FocusState> } callback - Callback used to get the focus state change.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @since 11
     */
    off(type: 'focusStateChange', callback?: AsyncCallback<FocusState>): void;

    /**
     * Subscribes zoom info event callback.
     *
     * @param { 'smoothZoomInfoAvailable' } type - Event type.
     * @param { AsyncCallback<SmoothZoomInfo> } callback - Callback used to get the zoom info.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @since 11
     */
    on(type: 'smoothZoomInfoAvailable', callback: AsyncCallback<SmoothZoomInfo>): void;

    /**
     * Unsubscribes from zoom info event callback.
     *
     * @param { 'smoothZoomInfoAvailable' } type - Event type.
     * @param { AsyncCallback<SmoothZoomInfo> } callback - Callback used to get the zoom info.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @since 11
     */
    off(type: 'smoothZoomInfoAvailable', callback?: AsyncCallback<SmoothZoomInfo>): void;

    /**
     * Subscribes camera macro status event callback.
     *
     * @param { 'macroStatusChanged' } type - Event type.
     * @param { AsyncCallback<boolean> } callback - Callback used to return the result.
     * @throws { BusinessError } 202 - Not System Application.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @systemapi
     * @since 11
     */
    on(type: 'macroStatusChanged', callback: AsyncCallback<boolean>): void;

    /**
     * Unsubscribes camera macro status event callback.
     *
     * @param { 'macroStatusChanged' } type - Event type.
     * @param { AsyncCallback<boolean> } callback - Callback used to return the result.
     * @throws { BusinessError } 202 - Not System Application.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @systemapi
     * @since 11
     */
    off(type: 'macroStatusChanged', callback?: AsyncCallback<boolean>): void;

    /**
     * Subscribes to system pressure level callback.
     *
     * @param { 'systemPressureLevelChange' } type - Event type.
     * @param { AsyncCallback<SystemPressureLevel> } callback - Callback used to return the result.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @since 20
     */
    on(type: 'systemPressureLevelChange', callback: AsyncCallback<SystemPressureLevel>): void;
 
    /**
     * Unsubscribes to system pressure level callback.
     *
     * @param { 'systemPressureLevelChange' } type - Event type.
     * @param { AsyncCallback<SystemPressureLevel> } callback - Callback used to return the result.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @since 20
     */
    off(type: 'systemPressureLevelChange', callback?: AsyncCallback<SystemPressureLevel>): void;   

    /**
     * Subscribes to system pressure level callback.
     *
     * @param { 'controlCenterEffectStatusChange' } type - Event type.
     * @param { AsyncCallback<ControlCenterStatusInfo> } callback - Callback used to return the result.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @since 20
     */
     on(type: 'controlCenterEffectStatusChange', callback: AsyncCallback<ControlCenterStatusInfo>): void;
 
     /**
      * Unsubscribes to system pressure level callback.
      *
      * @param { 'controlCenterEffectStatusChange' } type - Event type.
      * @param { AsyncCallback<ControlCenterStatusInfo> } callback - Callback used to return the result.
      * @syscap SystemCapability.Multimedia.Camera.Core
      * @since 20
      */
     off(type: 'controlCenterEffectStatusChange', callback?: AsyncCallback<ControlCenterStatusInfo>): void;

    /**
     * Subscribes to lcd flash status.
     *
     * @param { 'lcdFlashStatus' } type - Event type.
     * @param { AsyncCallback<LcdFlashStatus> } callback - Callback used to get the lcd flash status.
     * @throws { BusinessError } 202 - Not System Application.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @systemapi
     * @since 13
     */
    on(type: 'lcdFlashStatus', callback: AsyncCallback<LcdFlashStatus>): void;

    /**
     * Unsubscribes from lcd flash status.
     *
     * @param { 'lcdFlashStatus' } type - Event type.
     * @param { AsyncCallback<LcdFlashStatus> } callback - Callback used to get the lcd flash status.
     * @throws { BusinessError } 202 - Not System Application.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @systemapi
     * @since 13
     */
    off(type: 'lcdFlashStatus', callback?: AsyncCallback<LcdFlashStatus>): void;

    /**
     * Subscribes to auto device switch status event callback.
     *
     * @param { 'autoDeviceSwitchStatusChange' } type - Event type.
     * @param { AsyncCallback<AutoDeviceSwitchStatus> } callback - Callback used to return the result.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @since 13
     */
    on(type: 'autoDeviceSwitchStatusChange', callback: AsyncCallback<AutoDeviceSwitchStatus>): void;

    /**
     * Unsubscribes to auto device switch status event callback.
     *
     * @param { 'autoDeviceSwitchStatusChange' } type - Event type.
     * @param { AsyncCallback<AutoDeviceSwitchStatus> } callback - Callback used to return the result.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @since 13
     */
    off(type: 'autoDeviceSwitchStatusChange', callback?: AsyncCallback<AutoDeviceSwitchStatus>): void;

    /**
     * Subscribes to effect suggestion event callback.
     *
     * @param { 'effectSuggestionChange' } type - Event type.
     * @param { AsyncCallback<EffectSuggestionType> } callback - Callback used to get the effect suggestion change info.
     * @throws { BusinessError } 202 - Not System Application.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @systemapi
     * @since 18
     */
    on(type: 'effectSuggestionChange', callback: AsyncCallback<EffectSuggestionType>): void;

    /**
     * Unsubscribes from effect suggestion event callback.
     *
     * @param { 'effectSuggestionChange' } type - Event type.
     * @param { AsyncCallback<EffectSuggestionType> } callback - Callback used to get the effect suggestion change info.
     * @throws { BusinessError } 202 - Not System Application.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @systemapi
     * @since 18
     */
    off(type: 'effectSuggestionChange', callback?: AsyncCallback<EffectSuggestionType>): void;

    /**
     * Gets session functions.
     *
     * @param { CameraOutputCapability } outputCapability - CameraOutputCapability to set.
     * @returns { Array<VideoFunctions> } List of session functions.
     * @throws { BusinessError } 202 - Not System Application.
     * @throws { BusinessError } 401 - Parameter error. Possible causes: 1.Mandatory parameters are left unspecified. 2.Incorrect parameter types.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @systemapi
     * @since 13
     */
    getSessionFunctions(outputCapability: CameraOutputCapability): Array<VideoFunctions>;

    /**
     * Gets session conflict functions.
     *
     * @returns { Array<VideoConflictFunctions> } List of session conflict functions.
     * @throws { BusinessError } 202 - Not System Application.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @systemapi
     * @since 13
     */
    getSessionConflictFunctions(): Array<VideoConflictFunctions>;
  }

  interface ControlCenterSession extends Beauty, Aperture {
    release(): void;
  }

  /**
   * Enumerates the camera portrait effects.
   *
   * @enum { number }
   * @syscap SystemCapability.Multimedia.Camera.Core
   * @systemapi
   * @since 10
   */
  enum PortraitEffect {
    /**
     * portrait effect off.
     *
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @systemapi
     * @since 10
     */
    OFF = 0,

    /**
     * circular blurring for portrait.
     *
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @systemapi
     * @since 10
     */
    CIRCLES = 1,

    /**
     * heart blurring for portrait.
     *
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @systemapi
     * @since 11
     */
    HEART = 2,

    /**
     * rotated blurring for portrait.
     *
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @systemapi
     * @since 11
     */
    ROTATED = 3,

    /**
     * studio blurring for portrait.
     *
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @systemapi
     * @since 11
     */
    STUDIO = 4,

    /**
     * theater blurring for portrait.
     *
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @systemapi
     * @since 11
     */
    THEATER = 5
  }

  /**
   * Portrait Query object.
   *
   * @interface PortraitQuery
   * @syscap SystemCapability.Multimedia.Camera.Core
   * @systemapi
   * @since 12
   */
  interface PortraitQuery {
    /**
     * Gets supported portrait effect.
     *
     * @returns { Array<PortraitEffect> } List of portrait effect.
     * @throws { BusinessError } 7400103 - Session not config.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @systemapi
     * @since 10
     */
    /**
     * Gets supported portrait effect.
     * Move to Portrait interface from PortraitPhotoSession interface since 11.
     *
     * @returns { Array<PortraitEffect> } List of portrait effect.
     * @throws { BusinessError } 202 - Not System Application.
     * @throws { BusinessError } 7400103 - Session not config.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @systemapi
     * @since 11
     */
    /**
     * Gets supported portrait effect.
     * Move to PortraitQuery interface from Portrait interface since 12.
     *
     * @returns { Array<PortraitEffect> } List of portrait effect.
     * @throws { BusinessError } 202 - Not System Application.
     * @throws { BusinessError } 7400103 - Session not config, only throw in session usage.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @systemapi
     * @since 12
     */
    getSupportedPortraitEffects(): Array<PortraitEffect>;
  }

  /**
   * Portrait object.
   *
   * @interface Portrait
   * @syscap SystemCapability.Multimedia.Camera.Core
   * @systemapi
   * @since 11
   */
  interface Portrait extends PortraitQuery {
    /**
     * Gets the portrait effect in use.
     *
     * @returns { PortraitEffect } The portrait effect in use.
     * @throws { BusinessError } 7400103 - Session not config.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @systemapi
     * @since 10
     */
    /**
     * Gets the portrait effect in use.
     * Move to Portrait interface from PortraitPhotoSession interface since 11.
     *
     * @returns { PortraitEffect } The portrait effect in use.
     * @throws { BusinessError } 202 - Not System Application.
     * @throws { BusinessError } 7400103 - Session not config.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @systemapi
     * @since 11
     */
    getPortraitEffect(): PortraitEffect;

    /**
     * Sets a portrait effect for a camera device.
     *
     * @param { PortraitEffect } effect - Effect Portrait effect to set.
     * @throws { BusinessError } 7400103 - Session not config.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @systemapi
     * @since 10
     */
    /**
     * Sets a portrait effect for a camera device.
     * Move to Portrait interface from PortraitPhotoSession interface since 11.
     *
     * @param { PortraitEffect } effect - Effect Portrait effect to set.
     * @throws { BusinessError } 202 - Not System Application.
     * @throws { BusinessError } 7400103 - Session not config.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @systemapi
     * @since 11
     */
    setPortraitEffect(effect: PortraitEffect): void;
  }

  /**
   * Zoom range.
   *
   * @typedef ZoomRange
   * @syscap SystemCapability.Multimedia.Camera.Core
   * @systemapi
   * @since 11
   */
  interface ZoomRange {
    /**
     * Min zoom value.
     *
     * @type { number }
     * @readonly
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @systemapi
     * @since 11
     */
    readonly min: number;

    /**
     * Max zoom value.
     *
     * @type { number }
     * @readonly
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @systemapi
     * @since 11
     */
    readonly max: number;
  }

  /**
   * Physical Aperture object
   *
   * @typedef PhysicalAperture
   * @syscap SystemCapability.Multimedia.Camera.Core
   * @systemapi
   * @since 11
   */
  interface PhysicalAperture {
    /**
     * Zoom Range of the specific physical aperture.
     *
     * @type { ZoomRange }
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @systemapi
     * @since 11
     */
    zoomRange: ZoomRange;

    /**
     * The supported physical apertures.
     *
     * @type { Array<number> }
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @systemapi
     * @since 11
     */
    apertures: Array<number>;
  }

  /**
   * Aperture Query object.
   *
   * @interface ApertureQuery
   * @syscap SystemCapability.Multimedia.Camera.Core
   * @systemapi
   * @since 12
   */
  interface ApertureQuery {
    /**
     * Gets the supported virtual apertures.
     *
     * @returns { Array<number> } The array of supported virtual apertures.
     * @throws { BusinessError } 202 - Not System Application.
     * @throws { BusinessError } 7400103 - Session not config.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @systemapi
     * @since 11
     */
    /**
     * Gets the supported virtual apertures.
     * Move to ApertureQuery interface from Aperture since 12.
     *
     * @returns { Array<number> } The array of supported virtual apertures.
     * @throws { BusinessError } 202 - Not System Application.
     * @throws { BusinessError } 7400103 - Session not config, only throw in session usage.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @systemapi
     * @since 12
     */
    getSupportedVirtualApertures(): Array<number>;

    /**
     * Gets the supported physical apertures.
     *
     * @returns { Array<PhysicalAperture> } The array of supported physical apertures.
     * @throws { BusinessError } 202 - Not System Application.
     * @throws { BusinessError } 7400103 - Session not config.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @systemapi
     * @since 11
     */
     /**
     * Gets the supported physical apertures.
     * Move to ApertureQuery interface from Aperture since 12.
     *
     * @returns { Array<PhysicalAperture> } The array of supported physical apertures.
     * @throws { BusinessError } 202 - Not System Application.
     * @throws { BusinessError } 7400103 - Session not config, only throw in session usage.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @systemapi
     * @since 12
     */
    getSupportedPhysicalApertures(): Array<PhysicalAperture>;
  }

  /**
   * Aperture object.
   *
   * @interface Aperture
   * @syscap SystemCapability.Multimedia.Camera.Core
   * @systemapi
   * @since 11
   */
  interface Aperture extends ApertureQuery {
    /**
     * Gets current virtual aperture value.
     *
     * @returns { number } The current virtual aperture value.
     * @throws { BusinessError } 202 - Not System Application.
     * @throws { BusinessError } 7400103 - Session not config.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @systemapi
     * @since 11
     */
    getVirtualAperture(): number;

    /**
     * Sets virtual aperture value.
     *
     * @param { number } aperture - virtual aperture value
     * @throws { BusinessError } 202 - Not System Application.
     * @throws { BusinessError } 7400103 - Session not config.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @systemapi
     * @since 11
     */
    setVirtualAperture(aperture: number): void;

    /**
     * Gets current physical aperture value.
     *
     * @returns { number } The current physical aperture value.
     * @throws { BusinessError } 202 - Not System Application.
     * @throws { BusinessError } 7400103 - Session not config.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @systemapi
     * @since 11
     */
    getPhysicalAperture(): number;

    /**
     * Sets physical aperture value.
     *
     * @param { number } aperture - physical aperture value
     * @throws { BusinessError } 202 - Not System Application.
     * @throws { BusinessError } 7400103 - Session not config.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @systemapi
     * @since 11
     */
    setPhysicalAperture(aperture: number): void;
  }

  /**
     * Portrait Photo session object.
     *
     * @interface PortraitPhotoSession
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @systemapi
     * @since 11
     */
  interface PortraitPhotoSession extends Session, Flash, AutoExposure, Focus, Zoom, Beauty, ColorEffect, ColorManagement, Portrait, Aperture {
    /**
     * Subscribes to error events.
     *
     * @param { 'error' } type - Event type.
     * @param { ErrorCallback } callback - Callback used to get the capture session errors.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @systemapi
     * @since 11
     */
    on(type: 'error', callback: ErrorCallback): void;

    /**
     * Unsubscribes from error events.
     *
     * @param { 'error' } type - Event type.
     * @param { ErrorCallback } callback - Callback used to get the capture session errors.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @systemapi
     * @since 11
     */
    off(type: 'error', callback?: ErrorCallback): void;

    /**
     * Subscribes focus state change event callback.
     *
     * @param { 'focusStateChange' } type - Event type.
     * @param { AsyncCallback<FocusState> } callback - Callback used to get the focus state change.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @systemapi
     * @since 11
     */
    on(type: 'focusStateChange', callback: AsyncCallback<FocusState>): void;

    /**
     * Unsubscribes from focus state change event callback.
     *
     * @param { 'focusStateChange' } type - Event type.
     * @param { AsyncCallback<FocusState> } callback - Callback used to get the focus state change.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @systemapi
     * @since 11
     */
    off(type: 'focusStateChange', callback?: AsyncCallback<FocusState>): void;

    /**
     * Subscribes zoom info event callback.
     *
     * @param { 'smoothZoomInfoAvailable' } type - Event type.
     * @param { AsyncCallback<SmoothZoomInfo> } callback - Callback used to get the zoom info.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @systemapi
     * @since 11
     */
    on(type: 'smoothZoomInfoAvailable', callback: AsyncCallback<SmoothZoomInfo>): void;

    /**
     * Unsubscribes from zoom info event callback.
     *
     * @param { 'smoothZoomInfoAvailable' } type - Event type.
     * @param { AsyncCallback<SmoothZoomInfo> } callback - Callback used to get the zoom info.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @systemapi
     * @since 11
     */
    off(type: 'smoothZoomInfoAvailable', callback?: AsyncCallback<SmoothZoomInfo>): void;

    /**
     * Subscribes to lcd flash status.
     *
     * @param { 'lcdFlashStatus' } type - Event type.
     * @param { AsyncCallback<LcdFlashStatus> } callback - Callback used to get the lcd flash status.
     * @throws { BusinessError } 202 - Not System Application.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @systemapi
     * @since 13
     */
    on(type: 'lcdFlashStatus', callback: AsyncCallback<LcdFlashStatus>): void;

    /**
     * Unsubscribes from lcd flash status.
     *
     * @param { 'lcdFlashStatus' } type - Event type.
     * @param { AsyncCallback<LcdFlashStatus> } callback - Callback used to get the lcd flash status.
     * @throws { BusinessError } 202 - Not System Application.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @systemapi
     * @since 13
     */
    off(type: 'lcdFlashStatus', callback?: AsyncCallback<LcdFlashStatus>): void;

    /**
     * Gets session functions.
     *
     * @param { CameraOutputCapability } outputCapability - CameraOutputCapability to set.
     * @returns { Array<PortraitPhotoFunctions> } List of session functions.
     * @throws { BusinessError } 202 - Not System Application.
     * @throws { BusinessError } 401 - Parameter error. Possible causes: 1.Mandatory parameters are left unspecified. 2.Incorrect parameter types.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @systemapi
     * @since 13
     */
    getSessionFunctions(outputCapability: CameraOutputCapability): Array<PortraitPhotoFunctions>;

    /**
     * Gets session conflict functions.
     *
     * @returns { Array<PortraitPhotoConflictFunctions> } List of session conflict functions.
     * @throws { BusinessError } 202 - Not System Application.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @systemapi
     * @since 13
     */
    getSessionConflictFunctions(): Array<PortraitPhotoConflictFunctions>;
  }

  /**
     * Aperture video session object.
     *
     * @interface ApertureVideoSession
     * @extends Session, Flash, AutoExposure, Focus, Zoom, ColorEffect, Aperture
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @systemapi
     * @since 12
     */
  interface ApertureVideoSession extends Session, Flash, AutoExposure, Focus, Zoom, ColorEffect, Aperture {
    /**
     * Subscribes to error events.
     *
     * @param { 'error' } type - Event type.
     * @param { ErrorCallback } callback - Callback used to get the capture session errors.
     * @throws { BusinessError } 202 - Not System Application.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @systemapi
     * @since 12
     */
    on(type: 'error', callback: ErrorCallback): void;

    /**
     * Unsubscribes from error events.
     *
     * @param { 'error' } type - Event type.
     * @param { ErrorCallback } callback - Callback used to get the capture session errors.
     * @throws { BusinessError } 202 - Not System Application.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @systemapi
     * @since 12
     */
    off(type: 'error', callback?: ErrorCallback): void;

    /**
     * Subscribes focus state change event callback.
     *
     * @param { 'focusStateChange' } type - Event type.
     * @param { AsyncCallback<FocusState> } callback - Callback used to get the focus state change.
     * @throws { BusinessError } 202 - Not System Application.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @systemapi
     * @since 12
     */
    on(type: 'focusStateChange', callback: AsyncCallback<FocusState>): void;

    /**
     * Unsubscribes from focus state change event callback.
     *
     * @param { 'focusStateChange' } type - Event type.
     * @param { AsyncCallback<FocusState> } callback - Callback used to get the focus state change.
     * @throws { BusinessError } 202 - Not System Application.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @systemapi
     * @since 12
     */
    off(type: 'focusStateChange', callback?: AsyncCallback<FocusState>): void;

    /**
     * Subscribes zoom info event callback.
     *
     * @param { 'smoothZoomInfoAvailable' } type - Event type.
     * @param { AsyncCallback<SmoothZoomInfo> } callback - Callback used to get the zoom info.
     * @throws { BusinessError } 202 - Not System Application.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @systemapi
     * @since 12
     */
    on(type: 'smoothZoomInfoAvailable', callback: AsyncCallback<SmoothZoomInfo>): void;

    /**
     * Unsubscribes from zoom info event callback.
     *
     * @param { 'smoothZoomInfoAvailable' } type - Event type.
     * @param { AsyncCallback<SmoothZoomInfo> } callback - Callback used to get the zoom info.
     * @throws { BusinessError } 202 - Not System Application.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @systemapi
     * @since 12
     */
    off(type: 'smoothZoomInfoAvailable', callback?: AsyncCallback<SmoothZoomInfo>): void;
  }

  /**
   * ManualExposure Query object.
   *
   * @interface ManualExposureQuery
   * @syscap SystemCapability.Multimedia.Camera.Core
   * @systemapi
   * @since 12
   */
  interface ManualExposureQuery {
    /**
     * Gets the supported manual exposure range.
     *
     * @returns { Array<number> } The array of manual exposure range.
     * @throws { BusinessError } 202 - Not System Application.
     * @throws { BusinessError } 7400103 - Session not config.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @systemapi
     * @since 11
     */
    /**
     * Gets the supported manual exposure range.
     * Move to ManualExposureQuery from ManualExposure since 12.
     *
     * @returns { Array<number> } The array of manual exposure range.
     * @throws { BusinessError } 202 - Not System Application.
     * @throws { BusinessError } 7400101 - Parameter missing or parameter type incorrect.
     * @throws { BusinessError } 7400103 - Session not config, only throw in session usage.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @systemapi
     * @since 12
     */
    getSupportedExposureRange(): Array<number>;
  }

  /**
   * ManualExposure object.
   *
   * @interface ManualExposure
   * @syscap SystemCapability.Multimedia.Camera.Core
   * @systemapi
   * @since 11
   */
  interface ManualExposure extends ManualExposureQuery {
    /**
     * Gets current exposure value.
     *
     * @returns { number } The current exposure value.
     * @throws { BusinessError } 202 - Not System Application.
     * @throws { BusinessError } 7400103 - Session not config.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @systemapi
     * @since 11
     */
    /**
     * Gets current exposure value.
     *
     * @returns { number } The current exposure value.
     * @throws { BusinessError } 202 - Not System Application.
     * @throws { BusinessError } 7400101 - Parameter missing or parameter type incorrect.
     * @throws { BusinessError } 7400103 - Session not config.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @systemapi
     * @since 12
     */
    getExposure(): number;

    /**
     * Sets Exposure value.
     *
     * @param { number } exposure - Exposure value
     * @throws { BusinessError } 202 - Not System Application.
     * @throws { BusinessError } 7400103 - Session not config.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @systemapi
     * @since 11
     */
    /**
     * Sets Exposure value.
     *
     * @param { number } exposure - Exposure value
     * @throws { BusinessError } 202 - Not System Application.
     * @throws { BusinessError } 7400102 - Operation not allowed.
     * @throws { BusinessError } 7400103 - Session not config.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @systemapi
     * @since 12
     */
    setExposure(exposure: number): void;
  }

  /**
   * Night photo session object.
   *
   * @interface NightPhotoSession
   * @syscap SystemCapability.Multimedia.Camera.Core
   * @systemapi
   * @since 11
   */
  interface NightPhotoSession extends Session, Flash, AutoExposure, Focus, Zoom, ColorEffect, Beauty, ColorManagement, ManualExposure {
    /**
     * Subscribes to error events.
     *
     * @param { 'error' } type - Event type.
     * @param { ErrorCallback } callback - Callback used to get the capture session errors.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @systemapi
     * @since 11
     */
    on(type: 'error', callback: ErrorCallback): void;

    /**
     * Unsubscribes from error events.
     *
     * @param { 'error' } type - Event type.
     * @param { ErrorCallback } callback - Callback used to get the capture session errors.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @systemapi
     * @since 11
     */
    off(type: 'error', callback?: ErrorCallback): void;

    /**
     * Subscribes focus state change event callback.
     *
     * @param { 'focusStateChange' } type - Event type.
     * @param { AsyncCallback<FocusState> } callback - Callback used to get the focus state change.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @systemapi
     * @since 11
     */
    on(type: 'focusStateChange', callback: AsyncCallback<FocusState>): void;

    /**
     * Unsubscribes from focus state change event callback.
     *
     * @param { 'focusStateChange' } type - Event type.
     * @param { AsyncCallback<FocusState> } callback - Callback used to get the focus state change.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @systemapi
     * @since 11
     */
    off(type: 'focusStateChange', callback?: AsyncCallback<FocusState>): void;

    /**
     * Subscribes zoom info event callback.
     *
     * @param { 'smoothZoomInfoAvailable' } type - Event type.
     * @param { AsyncCallback<SmoothZoomInfo> } callback - Callback used to get the zoom info.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @systemapi
     * @since 11
     */
    on(type: 'smoothZoomInfoAvailable', callback: AsyncCallback<SmoothZoomInfo>): void;

    /**
     * Unsubscribes from zoom info event callback.
     *
     * @param { 'smoothZoomInfoAvailable' } type - Event type.
     * @param { AsyncCallback<SmoothZoomInfo> } callback - Callback used to get the zoom info.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @systemapi
     * @since 11
     */
    off(type: 'smoothZoomInfoAvailable', callback?: AsyncCallback<SmoothZoomInfo>): void;

    /**
     * Subscribes to lcd flash status.
     *
     * @param { 'lcdFlashStatus' } type - Event type.
     * @param { AsyncCallback<LcdFlashStatus> } callback - Callback used to get the lcd flash status.
     * @throws { BusinessError } 202 - Not System Application.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @systemapi
     * @since 12
     */
    on(type: 'lcdFlashStatus', callback: AsyncCallback<LcdFlashStatus>): void;

    /**
     * Unsubscribes from lcd flash status.
     *
     * @param { 'lcdFlashStatus' } type - Event type.
     * @param { AsyncCallback<LcdFlashStatus> } callback - Callback used to get the lcd flash status.
     * @throws { BusinessError } 202 - Not System Application.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @systemapi
     * @since 12
     */
    off(type: 'lcdFlashStatus', callback?: AsyncCallback<LcdFlashStatus>): void;
  }

  /**
   * ISO info object
   *
   * @typedef IsoInfo
   * @syscap SystemCapability.Multimedia.Camera.Core
   * @systemapi
   * @since 12
   */
  interface IsoInfo {
    /**
     * ISO value.
     *
     * @type { ?number }
     * @readonly
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @systemapi
     * @since 12
     */
    readonly iso?: number;
  }

  /**
   * Exposure info object
   *
   * @typedef ExposureInfo
   * @syscap SystemCapability.Multimedia.Camera.Core
   * @systemapi
   * @since 12
   */
  interface ExposureInfo {
    /**
     * Exposure time value.
     *
     * @type { ?number }
     * @readonly
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @systemapi
     * @since 12
     */
    readonly exposureTime?: number;
  }

  /**
   * Aperture info object
   *
   * @typedef ApertureInfo
   * @syscap SystemCapability.Multimedia.Camera.Core
   * @systemapi
   * @since 12
   */
  interface ApertureInfo {
    /**
     * Aperture value.
     *
     * @type { ?number }
     * @readonly
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @systemapi
     * @since 12
     */
    readonly aperture?: number;
  }

  /**
   * Lumination info object
   *
   * @typedef LuminationInfo
   * @syscap SystemCapability.Multimedia.Camera.Core
   * @systemapi
   * @since 12
   */
  interface LuminationInfo {
    /**
     * Lumination value.
     *
     * @type { ?number }
     * @readonly
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @systemapi
     * @since 12
     */
    readonly lumination?: number;
  }

  /**
   * Professional photo session object.
   *
   * @interface ProfessionalPhotoSession
   * @syscap SystemCapability.Multimedia.Camera.Core
   * @systemapi
   * @since 12
   */
  interface ProfessionalPhotoSession extends Session, AutoExposure, ManualExposure, Focus, ManualFocus, WhiteBalance, ManualIso, Flash, Zoom, ColorEffect, Aperture {
    /**
     * Subscribes to error events.
     *
     * @param { 'error' } type - Event type.
     * @param { ErrorCallback } callback - Callback used to get the capture session errors.
     * @throws { BusinessError } 202 - Not System Application.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @systemapi
     * @since 12
     */
    on(type: 'error', callback: ErrorCallback): void;

    /**
     * Unsubscribes from error events.
     *
     * @param { 'error' } type - Event type.
     * @param { ErrorCallback } callback - Callback used to get the capture session errors.
     * @throws { BusinessError } 202 - Not System Application.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @systemapi
     * @since 12
     */
    off(type: 'error', callback?: ErrorCallback): void;

    /**
     * Subscribes focus state change event callback.
     *
     * @param { 'focusStateChange' } type - Event type.
     * @param { AsyncCallback<FocusState> } callback - Callback used to get the focus state change.
     * @throws { BusinessError } 202 - Not System Application.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @systemapi
     * @since 12
     */
    on(type: 'focusStateChange', callback: AsyncCallback<FocusState>): void;

    /**
     * Unsubscribes from focus state change event callback.
     *
     * @param { 'focusStateChange' } type - Event type.
     * @param { AsyncCallback<FocusState> } callback - Callback used to get the focus state change.
     * @throws { BusinessError } 202 - Not System Application.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @systemapi
     * @since 12
     */
    off(type: 'focusStateChange', callback?: AsyncCallback<FocusState>): void;

    /**
     * Subscribes zoom info event callback.
     *
     * @param { 'smoothZoomInfoAvailable' } type - Event type.
     * @param { AsyncCallback<SmoothZoomInfo> } callback - Callback used to get the zoom info.
     * @throws { BusinessError } 202 - Not System Application.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @systemapi
     * @since 12
     */
    on(type: 'smoothZoomInfoAvailable', callback: AsyncCallback<SmoothZoomInfo>): void;

    /**
     * Unsubscribes from zoom info event callback.
     *
     * @param { 'smoothZoomInfoAvailable' } type - Event type.
     * @param { AsyncCallback<SmoothZoomInfo> } callback - Callback used to get the zoom info.
     * @throws { BusinessError } 202 - Not System Application.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @systemapi
     * @since 12
     */
    off(type: 'smoothZoomInfoAvailable', callback?: AsyncCallback<SmoothZoomInfo>): void;

    /**
     * Subscribes ISO info event callback.
     *
     * @param { 'isoInfoChange' } type - Event type.
     * @param { AsyncCallback<IsoInfo> } callback - Callback used to get the ISO info.
     * @throws { BusinessError } 202 - Not System Application.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @systemapi
     * @since 12
     */
    on(type: 'isoInfoChange', callback: AsyncCallback<IsoInfo>): void;

    /**
     * Unsubscribes from ISO info event callback.
     *
     * @param { 'isoInfoChange' } type - Event type.
     * @param { AsyncCallback<IsoInfo> } callback - Callback used to get the ISO info.
     * @throws { BusinessError } 202 - Not System Application.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @systemapi
     * @since 12
     */
    off(type: 'isoInfoChange', callback?: AsyncCallback<IsoInfo>): void;

    /**
     * Subscribes exposure info event callback.
     *
     * @param { 'exposureInfoChange' } type - Event type.
     * @param { AsyncCallback<ExposureInfo> } callback - Callback used to get the exposure info.
     * @throws { BusinessError } 202 - Not System Application.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @systemapi
     * @since 12
     */
    on(type: 'exposureInfoChange', callback: AsyncCallback<ExposureInfo>): void;

    /**
     * Unsubscribes from exposure info event callback.
     *
     * @param { 'exposureInfoChange' } type - Event type.
     * @param { AsyncCallback<ExposureInfo> } callback - Callback used to get the exposure info.
     * @throws { BusinessError } 202 - Not System Application.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @systemapi
     * @since 12
     */
    off(type: 'exposureInfoChange', callback?: AsyncCallback<ExposureInfo>): void;

    /**
     * Subscribes aperture info event callback.
     *
     * @param { 'apertureInfoChange' } type - Event type.
     * @param { AsyncCallback<ApertureInfo> } callback - Callback used to get the aperture info.
     * @throws { BusinessError } 202 - Not System Application.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @systemapi
     * @since 12
     */
    on(type: 'apertureInfoChange', callback: AsyncCallback<ApertureInfo>): void;

    /**
     * Unsubscribes from aperture info event callback.
     *
     * @param { 'apertureInfoChange' } type - Event type.
     * @param { AsyncCallback<ApertureInfo> } callback - Callback used to get the aperture info.
     * @throws { BusinessError } 202 - Not System Application.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @systemapi
     * @since 12
     */
    off(type: 'apertureInfoChange', callback?: AsyncCallback<ApertureInfo>): void;

    /**
     * Subscribes lumination info event callback.
     *
     * @param { 'luminationInfoChange' } type - Event type.
     * @param { AsyncCallback<LuminationInfo> } callback - Callback used to get the lumination info.
     * @throws { BusinessError } 202 - Not System Application.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @systemapi
     * @since 12
     */
    on(type: 'luminationInfoChange', callback: AsyncCallback<LuminationInfo>): void;

    /**
     * Unsubscribes from lumination info event callback.
     *
     * @param { 'luminationInfoChange' } type - Event type.
     * @param { AsyncCallback<LuminationInfo> } callback - Callback used to get the lumination info.
     * @throws { BusinessError } 202 - Not System Application.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @systemapi
     * @since 12
     */
    off(type: 'luminationInfoChange', callback?: AsyncCallback<LuminationInfo>): void;
  }

  /**
   * Professional video session object.
   *
   * @interface ProfessionalVideoSession
   * @syscap SystemCapability.Multimedia.Camera.Core
   * @systemapi
   * @since 12
   */
  interface ProfessionalVideoSession extends Session, AutoExposure, ManualExposure, Focus, ManualFocus, WhiteBalance, ManualIso, Flash, Zoom, ColorEffect, Aperture {
    /**
     * Subscribes to error events.
     *
     * @param { 'error' } type - Event type.
     * @param { ErrorCallback } callback - Callback used to get the capture session errors.
     * @throws { BusinessError } 202 - Not System Application.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @systemapi
     * @since 12
     */
    on(type: 'error', callback: ErrorCallback): void;

    /**
     * Unsubscribes from error events.
     *
     * @param { 'error' } type - Event type.
     * @param { ErrorCallback } callback - Callback used to get the capture session errors.
     * @throws { BusinessError } 202 - Not System Application.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @systemapi
     * @since 12
     */
    off(type: 'error', callback?: ErrorCallback): void;

    /**
     * Subscribes focus state change event callback.
     *
     * @param { 'focusStateChange' } type - Event type.
     * @param { AsyncCallback<FocusState> } callback - Callback used to get the focus state change.
     * @throws { BusinessError } 202 - Not System Application.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @systemapi
     * @since 12
     */
    on(type: 'focusStateChange', callback: AsyncCallback<FocusState>): void;

    /**
     * Unsubscribes from focus state change event callback.
     *
     * @param { 'focusStateChange' } type - Event type.
     * @param { AsyncCallback<FocusState> } callback - Callback used to get the focus state change.
     * @throws { BusinessError } 202 - Not System Application.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @systemapi
     * @since 12
     */
    off(type: 'focusStateChange', callback?: AsyncCallback<FocusState>): void;

    /**
     * Subscribes zoom info event callback.
     *
     * @param { 'smoothZoomInfoAvailable' } type - Event type.
     * @param { AsyncCallback<SmoothZoomInfo> } callback - Callback used to get the zoom info.
     * @throws { BusinessError } 202 - Not System Application.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @systemapi
     * @since 12
     */
    on(type: 'smoothZoomInfoAvailable', callback: AsyncCallback<SmoothZoomInfo>): void;

    /**
     * Unsubscribes from zoom info event callback.
     *
     * @param { 'smoothZoomInfoAvailable' } type - Event type.
     * @param { AsyncCallback<SmoothZoomInfo> } callback - Callback used to get the zoom info.
     * @throws { BusinessError } 202 - Not System Application.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @systemapi
     * @since 12
     */
    off(type: 'smoothZoomInfoAvailable', callback?: AsyncCallback<SmoothZoomInfo>): void;

    /**
     * Subscribes ISO info event callback.
     *
     * @param { 'isoInfoChange' } type - Event type.
     * @param { AsyncCallback<IsoInfo> } callback - Callback used to get the ISO info.
     * @throws { BusinessError } 202 - Not System Application.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @systemapi
     * @since 12
     */
    on(type: 'isoInfoChange', callback: AsyncCallback<IsoInfo>): void;

    /**
     * Unsubscribes from ISO info event callback.
     *
     * @param { 'isoInfoChange' } type - Event type.
     * @param { AsyncCallback<IsoInfo> } callback - Callback used to get the ISO info.
     * @throws { BusinessError } 202 - Not System Application.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @systemapi
     * @since 12
     */
    off(type: 'isoInfoChange', callback?: AsyncCallback<IsoInfo>): void;

    /**
     * Subscribes exposure info event callback.
     *
     * @param { 'exposureInfoChange' } type - Event type.
     * @param { AsyncCallback<ExposureInfo> } callback - Callback used to get the exposure info.
     * @throws { BusinessError } 202 - Not System Application.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @systemapi
     * @since 12
     */
    on(type: 'exposureInfoChange', callback: AsyncCallback<ExposureInfo>): void;

    /**
     * Unsubscribes from exposure info event callback.
     *
     * @param { 'exposureInfoChange' } type - Event type.
     * @param { AsyncCallback<ExposureInfo> } callback - Callback used to get the exposure info.
     * @throws { BusinessError } 202 - Not System Application.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @systemapi
     * @since 12
     */
    off(type: 'exposureInfoChange', callback?: AsyncCallback<ExposureInfo>): void;

    /**
     * Subscribes aperture info event callback.
     *
     * @param { 'apertureInfoChange' } type - Event type.
     * @param { AsyncCallback<ApertureInfo> } callback - Callback used to get the aperture info.
     * @throws { BusinessError } 202 - Not System Application.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @systemapi
     * @since 12
     */
    on(type: 'apertureInfoChange', callback: AsyncCallback<ApertureInfo>): void;

    /**
     * Unsubscribes from aperture info event callback.
     *
     * @param { 'apertureInfoChange' } type - Event type.
     * @param { AsyncCallback<ApertureInfo> } callback - Callback used to get the aperture info.
     * @throws { BusinessError } 202 - Not System Application.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @systemapi
     * @since 12
     */
    off(type: 'apertureInfoChange', callback?: AsyncCallback<ApertureInfo>): void;

    /**
     * Subscribes lumination info event callback.
     *
     * @param { 'luminationInfoChange' } type - Event type.
     * @param { AsyncCallback<LuminationInfo> } callback - Callback used to get the lumination info.
     * @throws { BusinessError } 202 - Not System Application.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @systemapi
     * @since 12
     */
    on(type: 'luminationInfoChange', callback: AsyncCallback<LuminationInfo>): void;

    /**
     * Unsubscribes from lumination info event callback.
     *
     * @param { 'luminationInfoChange' } type - Event type.
     * @param { AsyncCallback<LuminationInfo> } callback - Callback used to get the lumination info.
     * @throws { BusinessError } 202 - Not System Application.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @systemapi
     * @since 12
     */
    off(type: 'luminationInfoChange', callback?: AsyncCallback<LuminationInfo>): void;
  }

  /**
   * Enum for slow motion status.
   *
   * @enum { number }
   * @syscap SystemCapability.Multimedia.Camera.Core
   * @systemapi
   * @since 12
   */
  enum SlowMotionStatus {
    /**
     * Slow motion disabled.
     *
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @systemapi
     * @since 12
     */
    DISABLED = 0,

    /**
     * Slow motion ready.
     *
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @systemapi
     * @since 12
     */
    READY = 1,

    /**
     * Slow motion video start.
     *
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @systemapi
     * @since 12
     */
    VIDEO_START = 2,

    /**
     * Slow motion video done.
     *
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @systemapi
     * @since 12
     */
    VIDEO_DONE = 3,

    /**
     * Slow motion finished.
     *
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @systemapi
     * @since 12
     */
    FINISHED = 4
  }

  /**
   * Slow motion video session object.
   *
   * @interface SlowMotionVideoSession
   * @syscap SystemCapability.Multimedia.Camera.Core
   * @systemapi
   * @since 12
   */
  interface SlowMotionVideoSession extends Session, Flash, AutoExposure, Focus, Zoom, ColorEffect {
    /**
     * Subscribes to error events.
     *
     * @param { 'error' } type - Event type.
     * @param { ErrorCallback } callback - Callback used to get the capture session errors.
     * @throws { BusinessError } 202 - Not System Application.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @systemapi
     * @since 12
     */
    on(type: 'error', callback: ErrorCallback): void;

    /**
     * Unsubscribes from error events.
     *
     * @param { 'error' } type - Event type.
     * @param { ErrorCallback } callback - Callback used to get the capture session errors.
     * @throws { BusinessError } 202 - Not System Application.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @systemapi
     * @since 12
     */
    off(type: 'error', callback?: ErrorCallback): void;

    /**
     * Subscribes focus state change event callback.
     *
     * @param { 'focusStateChange' } type - Event type.
     * @param { AsyncCallback<FocusState> } callback - Callback used to get the focus state change.
     * @throws { BusinessError } 202 - Not System Application.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @systemapi
     * @since 12
     */
    on(type: 'focusStateChange', callback: AsyncCallback<FocusState>): void;

    /**
     * Unsubscribes from focus state change event callback.
     *
     * @param { 'focusStateChange' } type - Event type.
     * @param { AsyncCallback<FocusState> } callback - Callback used to get the focus state change.
     * @throws { BusinessError } 202 - Not System Application.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @systemapi
     * @since 12
     */
    off(type: 'focusStateChange', callback?: AsyncCallback<FocusState>): void;

    /**
     * Subscribes zoom info event callback.
     *
     * @param { 'smoothZoomInfoAvailable' } type - Event type.
     * @param { AsyncCallback<SmoothZoomInfo> } callback - Callback used to get the zoom info.
     * @throws { BusinessError } 202 - Not System Application.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @systemapi
     * @since 12
     */
    on(type: 'smoothZoomInfoAvailable', callback: AsyncCallback<SmoothZoomInfo>): void;

    /**
     * Unsubscribes from zoom info event callback.
     *
     * @param { 'smoothZoomInfoAvailable' } type - Event type.
     * @param { AsyncCallback<SmoothZoomInfo> } callback - Callback used to get the zoom info.
     * @throws { BusinessError } 202 - Not System Application.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @systemapi
     * @since 12
     */
    off(type: 'smoothZoomInfoAvailable', callback?: AsyncCallback<SmoothZoomInfo>): void;

    /**
     * Determine whether camera slow motion detection is supported.
     *
     * @returns { boolean } Is camera slow motion detection supported.
     * @throws { BusinessError } 202 - Not System Application.
     * @throws { BusinessError } 7400103 - Session not config.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @systemapi
     * @since 12
     */
    isSlowMotionDetectionSupported(): boolean;

    /**
     * Set slow motion detection area.
     *
     * @param { Rect } area - Detection area.
     * @throws { BusinessError } 202 - Not System Application.
     * @throws { BusinessError } 7400101 - Parameter missing or parameter type incorrect.
     * @throws { BusinessError } 7400103 - Session not config.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @systemapi
     * @since 12
     */
    setSlowMotionDetectionArea(area: Rect): void;

    /**
     * Subscribes slow motion status callback.
     *
     * @param { 'slowMotionStatus' } type - Event type.
     * @param { AsyncCallback<SlowMotionStatus> } callback - Callback used to get the slow motion status.
     * @throws { BusinessError } 202 - Not System Application.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @systemapi
     * @since 12
     */
    on(type: 'slowMotionStatus', callback: AsyncCallback<SlowMotionStatus>): void;

    /**
     * Unsubscribes slow motion status callback.
     *
     * @param { 'slowMotionStatus' } type - Event type.
     * @param { AsyncCallback<SlowMotionStatus> } callback - Callback used to get the slow motion status.
     * @throws { BusinessError } 202 - Not System Application.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @systemapi
     * @since 12
     */
    off(type: 'slowMotionStatus', callback?: AsyncCallback<SlowMotionStatus>): void;
  }

  /**
   * High resolution session object.
   *
   * @interface HighResolutionPhotoSession
   * @syscap SystemCapability.Multimedia.Camera.Core
   * @systemapi
   * @since 12
   */
  interface HighResolutionPhotoSession extends Session, AutoExposure, Focus {
    /**
     * Subscribes to error events.
     *
     * @param { 'error' } type - Event type.
     * @param { ErrorCallback } callback - Callback used to get the capture session errors.
     * @throws { BusinessError } 202 - Not System Application.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @systemapi
     * @since 12
     */
    on(type: 'error', callback: ErrorCallback): void;

    /**
     * Unsubscribes from error events.
     *
     * @param { 'error' } type - Event type.
     * @param { ErrorCallback } callback - Callback used to get the capture session errors.
     * @throws { BusinessError } 202 - Not System Application.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @systemapi
     * @since 12
     */
    off(type: 'error', callback?: ErrorCallback): void;

    /**
     * Subscribes focus state change event callback.
     *
     * @param { 'focusStateChange' } type - Event type.
     * @param { AsyncCallback<FocusState> } callback - Callback used to get the focus state change.
     * @throws { BusinessError } 202 - Not System Application.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @systemapi
     * @since 12
     */
    on(type: 'focusStateChange', callback: AsyncCallback<FocusState>): void;

    /**
     * Unsubscribes from focus state change event callback.
     *
     * @param { 'focusStateChange' } type - Event type.
     * @param { AsyncCallback<FocusState> } callback - Callback used to get the focus state change.
     * @throws { BusinessError } 202 - Not System Application.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @systemapi
     * @since 12
     */
    off(type: 'focusStateChange', callback?: AsyncCallback<FocusState>): void;
  }

  /**
   * Macro photo session object.
   *
   * @interface MacroPhotoSession
   * @extends Session, Flash, AutoExposure, Focus, Zoom, ColorEffect, ManualFocus
   * @syscap SystemCapability.Multimedia.Camera.Core
   * @systemapi
   * @since 12
   */
  /**
   * Macro photo session object.
   *
   * @interface MacroPhotoSession
   * @extends Session, Flash, AutoExposure, Focus, Zoom, ColorEffect, ManualFocus, DepthFusion
   * @syscap SystemCapability.Multimedia.Camera.Core
   * @systemapi
   * @since 14
   */
  interface MacroPhotoSession extends Session, Flash, AutoExposure, Focus, Zoom, ColorEffect, ManualFocus, DepthFusion {
    /**
     * Subscribes to error events.
     *
     * @param { 'error' } type - Event type.
     * @param { ErrorCallback } callback - Callback used to get the capture session errors.
     * @throws { BusinessError } 202 - Not System Application.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @systemapi
     * @since 12
     */
    on(type: 'error', callback: ErrorCallback): void;

    /**
     * Unsubscribes from error events.
     *
     * @param { 'error' } type - Event type.
     * @param { ErrorCallback } callback - Callback used to get the capture session errors.
     * @throws { BusinessError } 202 - Not System Application.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @systemapi
     * @since 12
     */
    off(type: 'error', callback?: ErrorCallback): void;

    /**
     * Subscribes focus state change event callback.
     *
     * @param { 'focusStateChange' } type - Event type.
     * @param { AsyncCallback<FocusState> } callback - Callback used to get the focus state change.
     * @throws { BusinessError } 202 - Not System Application.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @systemapi
     * @since 12
     */
    on(type: 'focusStateChange', callback: AsyncCallback<FocusState>): void;

    /**
     * Unsubscribes from focus state change event callback.
     *
     * @param { 'focusStateChange' } type - Event type.
     * @param { AsyncCallback<FocusState> } callback - Callback used to get the focus state change.
     * @throws { BusinessError } 202 - Not System Application.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @systemapi
     * @since 12
     */
    off(type: 'focusStateChange', callback?: AsyncCallback<FocusState>): void;

    /**
     * Subscribes zoom info event callback.
     *
     * @param { 'smoothZoomInfoAvailable' } type - Event type.
     * @param { AsyncCallback<SmoothZoomInfo> } callback - Callback used to get the zoom info.
     * @throws { BusinessError } 202 - Not System Application.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @systemapi
     * @since 12
     */
    on(type: 'smoothZoomInfoAvailable', callback: AsyncCallback<SmoothZoomInfo>): void;

    /**
     * Unsubscribes from zoom info event callback.
     *
     * @param { 'smoothZoomInfoAvailable' } type - Event type.
     * @param { AsyncCallback<SmoothZoomInfo> } callback - Callback used to get the zoom info.
     * @throws { BusinessError } 202 - Not System Application.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @systemapi
     * @since 12
     */
    off(type: 'smoothZoomInfoAvailable', callback?: AsyncCallback<SmoothZoomInfo>): void;
  }

  /**
   * Macro video session object.
   *
   * @interface MacroVideoSession
   * @syscap SystemCapability.Multimedia.Camera.Core
   * @systemapi
   * @since 12
   */
  interface MacroVideoSession extends Session, Flash, AutoExposure, Focus, Zoom, ColorEffect, ManualFocus {
    /**
     * Subscribes to error events.
     *
     * @param { 'error' } type - Event type.
     * @param { ErrorCallback } callback - Callback used to get the capture session errors.
     * @throws { BusinessError } 202 - Not System Application.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @systemapi
     * @since 12
     */
    on(type: 'error', callback: ErrorCallback): void;

    /**
     * Unsubscribes from error events.
     *
     * @param { 'error' } type - Event type.
     * @param { ErrorCallback } callback - Callback used to get the capture session errors.
     * @throws { BusinessError } 202 - Not System Application.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @systemapi
     * @since 12
     */
    off(type: 'error', callback?: ErrorCallback): void;

    /**
     * Subscribes focus state change event callback.
     *
     * @param { 'focusStateChange' } type - Event type.
     * @param { AsyncCallback<FocusState> } callback - Callback used to get the focus state change.
     * @throws { BusinessError } 202 - Not System Application.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @systemapi
     * @since 12
     */
    on(type: 'focusStateChange', callback: AsyncCallback<FocusState>): void;

    /**
     * Unsubscribes from focus state change event callback.
     *
     * @param { 'focusStateChange' } type - Event type.
     * @param { AsyncCallback<FocusState> } callback - Callback used to get the focus state change.
     * @throws { BusinessError } 202 - Not System Application.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @systemapi
     * @since 12
     */
    off(type: 'focusStateChange', callback?: AsyncCallback<FocusState>): void;

    /**
     * Subscribes zoom info event callback.
     *
     * @param { 'smoothZoomInfoAvailable' } type - Event type.
     * @param { AsyncCallback<SmoothZoomInfo> } callback - Callback used to get the zoom info.
     * @throws { BusinessError } 202 - Not System Application.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @systemapi
     * @since 12
     */
    on(type: 'smoothZoomInfoAvailable', callback: AsyncCallback<SmoothZoomInfo>): void;

    /**
     * Unsubscribes from zoom info event callback.
     *
     * @param { 'smoothZoomInfoAvailable' } type - Event type.
     * @param { AsyncCallback<SmoothZoomInfo> } callback - Callback used to get the zoom info.
     * @throws { BusinessError } 202 - Not System Application.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @systemapi
     * @since 12
     */
    off(type: 'smoothZoomInfoAvailable', callback?: AsyncCallback<SmoothZoomInfo>): void;
  }

  /**
   * Secure camera session object.
   *
   * @interface SecureSession
   * @syscap SystemCapability.Multimedia.Camera.Core
   * @since 12
   */
  interface SecureSession extends Session, Flash, AutoExposure, Focus, Zoom {
    /**
     * Add Secure output for camera.
     *
     * @param { PreviewOutput } previewOutput - Specify the output as a secure flow.
     * @throws { BusinessError } 7400101 - Parameter missing or parameter type incorrect.
     * @throws { BusinessError } 7400102 - Operation not allowed.
     * @throws { BusinessError } 7400103 - Session not config.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @since 12
     */
    addSecureOutput(previewOutput: PreviewOutput): void;

    /**
     * Subscribes to error events.
     *
     * @param { 'error' } type - Event type.
     * @param { ErrorCallback } callback - Callback used to get the capture session errors.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @since 12
     */
    on(type: 'error', callback: ErrorCallback): void;

    /**
     * Unsubscribes from error events.
     *
     * @param { 'error' } type - Event type.
     * @param { ErrorCallback } callback - Callback used to get the capture session errors.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @since 12
     */
    off(type: 'error', callback?: ErrorCallback): void;

    /**
     * Subscribes focus status change event callback.
     *
     * @param { 'focusStateChange' } type - Event type.
     * @param { AsyncCallback<FocusState> } callback - Callback used to get the focus state change.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @since 12
     */
    on(type: 'focusStateChange', callback: AsyncCallback<FocusState>): void;

    /**
     * Unsubscribes from focus status change event callback.
     *
     * @param { 'focusStateChange' } type - Event type.
     * @param { AsyncCallback<FocusState> } callback - Callback used to get the focus state change.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @since 12
     */
    off(type: 'focusStateChange', callback?: AsyncCallback<FocusState>): void;
  }

  /**
   * Light painting photo session object.
   *
   * @interface LightPaintingPhotoSession
   * @extends Session, Flash, Focus, Zoom, ColorEffect
   * @syscap SystemCapability.Multimedia.Camera.Core
   * @systemapi
   * @since 12
   */
  interface LightPaintingPhotoSession extends Session, Flash, Focus, Zoom, ColorEffect {
    /**
     * Subscribes to error events.
     *
     * @param { 'error' } type - Event type.
     * @param { ErrorCallback } callback - Callback used to get the capture session errors.
     * @throws { BusinessError } 202 - Not System Application.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @systemapi
     * @since 12
     */
    on(type: 'error', callback: ErrorCallback): void;

    /**
     * Unsubscribes from error events.
     *
     * @param { 'error' } type - Event type.
     * @param { ErrorCallback } callback - Callback used to get the capture session errors.
     * @throws { BusinessError } 202 - Not System Application.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @systemapi
     * @since 12
     */
    off(type: 'error', callback?: ErrorCallback): void;

    /**
     * Subscribes focus state change event callback.
     *
     * @param { 'focusStateChange' } type - Event type.
     * @param { AsyncCallback<FocusState> } callback - Callback used to get the focus state change.
     * @throws { BusinessError } 202 - Not System Application.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @systemapi
     * @since 12
     */
    on(type: 'focusStateChange', callback: AsyncCallback<FocusState>): void;

    /**
     * Unsubscribes from focus state change event callback.
     *
     * @param { 'focusStateChange' } type - Event type.
     * @param { AsyncCallback<FocusState> } callback - Callback used to get the focus state change.
     * @throws { BusinessError } 202 - Not System Application.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @systemapi
     * @since 12
     */
    off(type: 'focusStateChange', callback?: AsyncCallback<FocusState>): void;

    /**
     * Subscribes zoom info event callback.
     *
     * @param { 'smoothZoomInfoAvailable' } type - Event type.
     * @param { AsyncCallback<SmoothZoomInfo> } callback - Callback used to get the zoom info.
     * @throws { BusinessError } 202 - Not System Application.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @systemapi
     * @since 12
     */
    on(type: 'smoothZoomInfoAvailable', callback: AsyncCallback<SmoothZoomInfo>): void;

    /**
     * Unsubscribes from zoom info event callback.
     *
     * @param { 'smoothZoomInfoAvailable' } type - Event type.
     * @param { AsyncCallback<SmoothZoomInfo> } callback - Callback used to get the zoom info.
     * @throws { BusinessError } 202 - Not System Application.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @systemapi
     * @since 12
     */
    off(type: 'smoothZoomInfoAvailable', callback?: AsyncCallback<SmoothZoomInfo>): void;

    /**
     * Gets the light painting type in use.
     *
     * @returns { LightPaintingType } The light painting type in use.
     * @throws { BusinessError } 202 - Not System Application.
     * @throws { BusinessError } 7400103 - Session not config.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @systemapi
     * @since 12
     */
    getLightPaintingType(): LightPaintingType;

    /**
     * Sets a light painting type for a camera device.
     *
     * @param { LightPaintingType } type - Light painting type to set.
     * @throws { BusinessError } 202 - Not System Application.
     * @throws { BusinessError } 7400101 - Parameter missing or parameter type incorrect.
     * @throws { BusinessError } 7400103 - Session not config.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @systemapi
     * @since 12
     */
    setLightPaintingType(type: LightPaintingType): void;

    /**
     * Gets supported light painting types.
     *
     * @returns { Array<LightPaintingType> } List of light painting types.
     * @throws { BusinessError } 202 - Not System Application.
     * @throws { BusinessError } 7400103 - Session not config.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @systemapi
     * @since 12
     */
    getSupportedLightPaintingTypes(): Array<LightPaintingType>;
  }

  /**
   * Quick shot photo session object.
   *
   * @interface QuickShotPhotoSession
   * @extends Session, AutoExposure, ColorEffect, ColorManagement, EffectSuggestion, Flash, Focus, Zoom
   * @syscap SystemCapability.Multimedia.Camera.Core
   * @systemapi
   * @since 12
   */
  interface QuickShotPhotoSession extends Session, AutoExposure, ColorEffect, ColorManagement, EffectSuggestion, Flash, Focus, Zoom {
    /**
     * Subscribes to error events.
     *
     * @param { 'error' } type - Event type.
     * @param { ErrorCallback } callback - Callback used to get the capture session errors.
     * @throws { BusinessError } 202 - Not System Application.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @systemapi
     * @since 12
     */
    on(type: 'error', callback: ErrorCallback): void;

    /**
     * Unsubscribes from error events.
     *
     * @param { 'error' } type - Event type.
     * @param { ErrorCallback } callback - Callback used to get the capture session errors.
     * @throws { BusinessError } 202 - Not System Application.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @systemapi
     * @since 12
     */
    off(type: 'error', callback?: ErrorCallback): void;

    /**
     * Subscribes to effect suggestion event callback.
     *
     * @param { 'effectSuggestionChange' } type - Event type.
     * @param { AsyncCallback<EffectSuggestionType> } callback - Callback used to return the result.
     * @throws { BusinessError } 202 - Not System Application.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @systemapi
     * @since 12
     */
    on(type: 'effectSuggestionChange', callback: AsyncCallback<EffectSuggestionType>): void;

    /**
     * Unsubscribes from effect suggestion event callback.
     *
     * @param { 'effectSuggestionChange' } type - Event type.
     * @param { AsyncCallback<EffectSuggestionType> } callback - Callback used to return the result.
     * @throws { BusinessError } 202 - Not System Application.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @systemapi
     * @since 12
     */
    off(type: 'effectSuggestionChange', callback?: AsyncCallback<EffectSuggestionType>): void;

    /**
     * Subscribes focus state change event callback.
     *
     * @param { 'focusStateChange' } type - Event type.
     * @param { AsyncCallback<FocusState> } callback - Callback used to get the focus state change.
     * @throws { BusinessError } 202 - Not System Application.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @systemapi
     * @since 12
     */
    on(type: 'focusStateChange', callback: AsyncCallback<FocusState>): void;

    /**
     * Unsubscribes from focus state change event callback.
     *
     * @param { 'focusStateChange' } type - Event type.
     * @param { AsyncCallback<FocusState> } callback - Callback used to get the focus state change.
     * @throws { BusinessError } 202 - Not System Application.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @systemapi
     * @since 12
     */
    off(type: 'focusStateChange', callback?: AsyncCallback<FocusState>): void;

    /**
     * Subscribes zoom info event callback.
     *
     * @param { 'smoothZoomInfoAvailable' } type - Event type.
     * @param { AsyncCallback<SmoothZoomInfo> } callback - Callback used to get the zoom info.
     * @throws { BusinessError } 202 - Not System Application.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @systemapi
     * @since 12
     */
    on(type: 'smoothZoomInfoAvailable', callback: AsyncCallback<SmoothZoomInfo>): void;

    /**
     * Unsubscribes from zoom info event callback.
     *
     * @param { 'smoothZoomInfoAvailable' } type - Event type.
     * @param { AsyncCallback<SmoothZoomInfo> } callback - Callback used to get the zoom info.
     * @throws { BusinessError } 202 - Not System Application.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @systemapi
     * @since 12
     */
    off(type: 'smoothZoomInfoAvailable', callback?: AsyncCallback<SmoothZoomInfo>): void;
  }

  /**
   * Panorama photo session object.
   *
   * @interface PanoramaPhotoSession
   * @extends Session, Focus, AutoExposure, WhiteBalance, ColorEffect
   * @syscap SystemCapability.Multimedia.Camera.Core
   * @systemapi
   * @since 12
   */
  interface PanoramaPhotoSession extends Session, Focus, AutoExposure, WhiteBalance, ColorEffect {
    /**
     * Subscribes to error events.
     *
     * @param { 'error' } type - Event type.
     * @param { ErrorCallback } callback - Callback used to get the capture session errors.
     * @throws { BusinessError } 202 - Not System Application.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @systemapi
     * @since 12
     */
    on(type: 'error', callback: ErrorCallback): void;

    /**
     * Unsubscribes from error events.
     *
     * @param { 'error' } type - Event type.
     * @param { ErrorCallback } callback - Callback used to get the capture session errors.
     * @throws { BusinessError } 202 - Not System Application.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @systemapi
     * @since 12
     */
    off(type: 'error', callback?: ErrorCallback): void;

    /**
     * Subscribes focus state change event callback.
     *
     * @param { 'focusStateChange' } type - Event type.
     * @param { AsyncCallback<FocusState> } callback - Callback used to get the focus state change.
     * @throws { BusinessError } 202 - Not System Application.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @systemapi
     * @since 12
     */
    on(type: 'focusStateChange', callback: AsyncCallback<FocusState>): void;

    /**
     * Unsubscribes from focus state change event callback.
     *
     * @param { 'focusStateChange' } type - Event type.
     * @param { AsyncCallback<FocusState> } callback - Callback used to get the focus state change.
     * @throws { BusinessError } 202 - Not System Application.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @systemapi
     * @since 12
     */
    off(type: 'focusStateChange', callback?: AsyncCallback<FocusState>): void;
  }

  /**
   * Fluorescence photo session object.
   *
   * @interface FluorescencePhotoSession
   * @syscap SystemCapability.Multimedia.Camera.Core
   * @systemapi
   * @since 13
   */
  interface FluorescencePhotoSession extends Session, AutoExposure, Focus, Zoom {
    /**
     * Subscribes to error events.
     *
     * @param { 'error' } type - Event type.
     * @param { ErrorCallback } callback - Callback used to get the capture session errors.
     * @throws { BusinessError } 202 - Not System Application.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @systemapi
     * @since 13
     */
    on(type: 'error', callback: ErrorCallback): void;

    /**
     * Unsubscribes from error events.
     *
     * @param { 'error' } type - Event type.
     * @param { ErrorCallback } callback - Callback used to get the capture session errors.
     * @throws { BusinessError } 202 - Not System Application.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @systemapi
     * @since 13
     */
    off(type: 'error', callback?: ErrorCallback): void;

    /**
     * Subscribes focus state change event callback.
     *
     * @param { 'focusStateChange' } type - Event type.
     * @param { AsyncCallback<FocusState> } callback - Callback used to get the focus state change.
     * @throws { BusinessError } 202 - Not System Application.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @systemapi
     * @since 13
     */
    on(type: 'focusStateChange', callback: AsyncCallback<FocusState>): void;

    /**
     * Unsubscribes from focus state change event callback.
     *
     * @param { 'focusStateChange' } type - Event type.
     * @param { AsyncCallback<FocusState> } callback - Callback used to get the focus state change.
     * @throws { BusinessError } 202 - Not System Application.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @systemapi
     * @since 13
     */
    off(type: 'focusStateChange', callback?: AsyncCallback<FocusState>): void;
  }

  /**
   * Photo Functions object.
   *
   * @interface PhotoFunctions
   * @extends FlashQuery, AutoExposureQuery, ManualExposureQuery, FocusQuery, ZoomQuery, BeautyQuery, ColorEffectQuery, ColorManagementQuery, MacroQuery, SceneDetectionQuery
   * @syscap SystemCapability.Multimedia.Camera.Core
   * @systemapi
   * @since 13
   */
  interface PhotoFunctions extends FlashQuery, AutoExposureQuery, ManualExposureQuery, FocusQuery, ZoomQuery, BeautyQuery, ColorEffectQuery, ColorManagementQuery, MacroQuery, SceneDetectionQuery {
  }

  /**
   * Video Functions object.
   *
   * @interface VideoFunctions
   * @extends FlashQuery, AutoExposureQuery, ManualExposureQuery, FocusQuery, ZoomQuery, StabilizationQuery, BeautyQuery, ColorEffectQuery, ColorManagementQuery, MacroQuery, SceneDetectionQuery
   * @syscap SystemCapability.Multimedia.Camera.Core
   * @systemapi
   * @since 13
   */
  interface VideoFunctions extends FlashQuery, AutoExposureQuery, ManualExposureQuery, FocusQuery, ZoomQuery, StabilizationQuery, BeautyQuery, ColorEffectQuery, ColorManagementQuery, MacroQuery, SceneDetectionQuery {
  }

  /**
   * Portrait Photo Functions object.
   *
   * @interface PortraitPhotoFunctions
   * @extends FlashQuery, AutoExposureQuery, FocusQuery, ZoomQuery, BeautyQuery, ColorEffectQuery, ColorManagementQuery, PortraitQuery, ApertureQuery, SceneDetectionQuery
   * @syscap SystemCapability.Multimedia.Camera.Core
   * @systemapi
   * @since 13
   */
  interface PortraitPhotoFunctions extends FlashQuery, AutoExposureQuery, FocusQuery, ZoomQuery, BeautyQuery, ColorEffectQuery, ColorManagementQuery, PortraitQuery, ApertureQuery, SceneDetectionQuery {
  }

  /**
   * Photo Conflict Functions object.
   *
   * @interface PhotoConflictFunctions
   * @extends ZoomQuery, MacroQuery
   * @syscap SystemCapability.Multimedia.Camera.Core
   * @systemapi
   * @since 13
   */
  interface PhotoConflictFunctions extends ZoomQuery, MacroQuery {
  }

  /**
   * Video Conflict Functions object.
   *
   * @interface VideoConflictFunctions
   * @extends ZoomQuery, MacroQuery
   * @syscap SystemCapability.Multimedia.Camera.Core
   * @systemapi
   * @since 13
   */
  interface VideoConflictFunctions extends ZoomQuery, MacroQuery {
  }

  /**
   * Portrait Photo Conflict Functions object.
   *
   * @interface PortraitPhotoFunctions
   * @extends ZoomQuery, PortraitQuery, ApertureQuery
   * @syscap SystemCapability.Multimedia.Camera.Core
   * @systemapi
   * @since 13
   */
  interface PortraitPhotoConflictFunctions extends ZoomQuery, PortraitQuery, ApertureQuery {
  }

  /**
   * Camera output object.
   *
   * @interface CameraOutput
   * @syscap SystemCapability.Multimedia.Camera.Core
   * @since 10
   */
  interface CameraOutput {
    /**
     * Release output instance.
     *
     * @param { AsyncCallback<void> } callback - Callback used to return the result.
     * @throws { BusinessError } 7400201 - Camera service fatal error.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @since 10
     */
    release(callback: AsyncCallback<void>): void;

    /**
     * Release output instance.
     *
     * @returns { Promise<void> } Promise used to return the result.
     * @throws { BusinessError } 7400201 - Camera service fatal error.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @since 10
     */
    release(): Promise<void>;
  }

  /**
   * SketchStatusData object
   *
   * @typedef SketchStatusData
   * @syscap SystemCapability.Multimedia.Camera.Core
   * @systemapi
   * @since 11
   */
  interface SketchStatusData {
    /**
     * Status of the sketch stream.
     * 0 is stop, and 1 is start.
     *
     * @type { number }
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @systemapi
     * @since 11
     */
    status: number;

    /**
     * The zoom ratio of the sketch stream.
     *
     * @type { number }
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @systemapi
     * @since 11
     */
    sketchRatio: number;
  }

  /**
   * Preview output object.
   *
   * @interface PreviewOutput
   * @syscap SystemCapability.Multimedia.Camera.Core
   * @since 10
   */
  interface PreviewOutput extends CameraOutput {
    /**
     * Start output instance.
     *
     * @param { AsyncCallback<void> } callback - Callback used to return the result.
     * @throws { BusinessError } 7400103 - Session not config.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @since 10
     * @deprecated since 11
     * @useinstead ohos.multimedia.camera.Session#start
     */
    start(callback: AsyncCallback<void>): void;

    /**
     * Start output instance.
     *
     * @returns { Promise<void> } Promise used to return the result.
     * @throws { BusinessError } 7400103 - Session not config.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @since 10
     * @deprecated since 11
     * @useinstead ohos.multimedia.camera.Session#start
     */
    start(): Promise<void>;

    /**
     * Stop output instance.
     *
     * @param { AsyncCallback<void> } callback - Callback used to return the result.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @since 10
     * @deprecated since 11
     * @useinstead ohos.multimedia.camera.Session#stop
     */
    stop(callback: AsyncCallback<void>): void;

    /**
     * Stop output instance.
     *
     * @returns { Promise<void> } Promise used to return the result.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @since 10
     * @deprecated since 11
     * @useinstead ohos.multimedia.camera.Session#stop
     */
    stop(): Promise<void>;

    /**
     * Subscribes frame start event callback.
     *
     * @param { 'frameStart' } type - Event type.
     * @param { AsyncCallback<void> } callback - Callback used to return the result.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @since 10
     */
    on(type: 'frameStart', callback: AsyncCallback<void>): void;

    /**
     * Unsubscribes from frame start event callback.
     *
     * @param { 'frameStart' } type - Event type.
     * @param { AsyncCallback<void> } callback - Callback used to return the result.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @since 10
     */
    off(type: 'frameStart', callback?: AsyncCallback<void>): void;

    /**
     * Subscribes frame end event callback.
     *
     * @param { 'frameEnd' } type - Event type.
     * @param { AsyncCallback<void> } callback - Callback used to return the result.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @since 10
     */
    on(type: 'frameEnd', callback: AsyncCallback<void>): void;

    /**
     * Unsubscribes from frame end event callback.
     *
     * @param { 'frameEnd' } type - Event type.
     * @param { AsyncCallback<void> } callback - Callback used to return the result.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @since 10
     */
    off(type: 'frameEnd', callback?: AsyncCallback<void>): void;

    /**
     * Subscribes to error events.
     *
     * @param { 'error' } type - Event type.
     * @param { ErrorCallback } callback - Callback used to get the preview output errors.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @since 10
     */
    on(type: 'error', callback: ErrorCallback): void;

    /**
     * Unsubscribes from error events.
     *
     * @param { 'error' } type - Event type.
     * @param { ErrorCallback } callback - Callback used to get the preview output errors.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @since 10
     */
    off(type: 'error', callback?: ErrorCallback): void;

    /**
     * Get supported frame rates which can be set during session running.
     *
     * @returns { Array<FrameRateRange> } The array of supported frame rate range.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @since 12
     */
    getSupportedFrameRates(): Array<FrameRateRange>

    /**
     * Set a frame rate range.
     *
     * @param { number } minFps - Minimum frame rate per second.
     * @param { number } maxFps - Maximum frame rate per second.
     * @throws { BusinessError } 7400101 - Parameter missing or parameter type incorrect.
     * @throws { BusinessError } 7400110 - Unresolved conflicts with current configurations.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @since 12
     */
    setFrameRate(minFps: number, maxFps: number): void

    /**
     * Get active frame rate range which has been set before.
     *
     * @returns { FrameRateRange } The active frame rate range.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @since 12
     */
    getActiveFrameRate(): FrameRateRange;

    /**
     * Gets the preview rotation angle.
     *
     * @param { number } displayRotation - The current display rotation angle.
     * @returns { ImageRotation } The preview rotation angle.
     * @throws { BusinessError } 7400101 - Parameter missing or parameter type incorrect.
     * @throws { BusinessError } 7400201 - Camera service fatal error.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @since 12
     */
    getPreviewRotation(displayRotation: number): ImageRotation;

     /**
      * Sets the preview rotation angle.
      *
      * @param { ImageRotation } previewRotation - Preview display rotation angle.
      * @param { boolean } isDisplayLocked - TRUE means the display is locked, if not set, the default is FALSE.
      * @throws { BusinessError } 7400101 - Parameter missing or parameter type incorrect.
      * @throws { BusinessError } 7400201 - Camera service fatal error.
      * @syscap SystemCapability.Multimedia.Camera.Core
      * @since 12
      */
    setPreviewRotation(previewRotation: ImageRotation, isDisplayLocked?: boolean): void;

    /**
     * Gets the current preconfig type if you had already call preconfig interface.
     *
     * @returns { Profile } The current preconfig type.
     * @throws { BusinessError } 7400201 - Camera service fatal error.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @since 12
     */
    getActiveProfile(): Profile;

    /**
     * Adds a deferred surface.
     *
     * @param { string } surfaceId - Surface object id used in camera photo output.
     * @throws { BusinessError } 7400101 - Parameter missing or parameter type incorrect.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @systemapi
     * @since 10
     */
    /**
     * Adds a deferred surface.
     *
     * @param { string } surfaceId - Surface object id used in camera photo output.
     * @throws { BusinessError } 202 - Permission verification failed. A non-system application calls a system API.
     * @throws { BusinessError } 7400101 - Parameter missing or parameter type incorrect.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @systemapi
     * @since 13
     */
    addDeferredSurface(surfaceId: string): void;

    /**
     * Determine whether camera sketch is supported.
     *
     * @returns { boolean } Is camera sketch supported.
     * @throws { BusinessError } 202 - Not System Application.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @systemapi
     * @since 11
     */
    isSketchSupported(): boolean;

    /**
     * Gets the specific zoom ratio when sketch stream open.
     *
     * @returns { number } The specific zoom ratio of sketch.
     * @throws { BusinessError } 202 - Not System Application.
     * @throws { BusinessError } 7400103 - Session not config.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @systemapi
     * @since 11
     */
    getSketchRatio(): number;

    /**
     * Enable sketch for camera.
     *
     * @param { boolean } enabled - enable sketch for camera if TRUE.
     * @throws { BusinessError } 202 - Not System Application.
     * @throws { BusinessError } 7400103 - Session not config.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @systemapi
     * @since 11
     */
    /**
     * Enable sketch for camera.
     *
     * @param { boolean } enabled - enable sketch for camera if TRUE.
     * @throws { BusinessError } 202 - Not System Application.
     * @throws { BusinessError } 7400102 - Operation not allowed.
     * @throws { BusinessError } 7400103 - Session not config.
     * @throws { BusinessError } 7400201 - Camera service fatal error.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @systemapi
     * @since 12
     */
    enableSketch(enabled: boolean): void;

    /**
     * Attach surface to the sketch stream.
     *
     * @param { string } surfaceId - Surface object id used in sketch stream.
     * @throws { BusinessError } 202 - Not System Application.
     * @throws { BusinessError } 7400103 - Session not config.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @systemapi
     * @since 11
     */
    /**
     * Attach surface to the sketch stream.
     *
     * @param { string } surfaceId - Surface object id used in sketch stream.
     * @throws { BusinessError } 202 - Not System Application.
     * @throws { BusinessError } 7400101 - Parameter missing or parameter type incorrect.
     * @throws { BusinessError } 7400103 - Session not config.
     * @throws { BusinessError } 7400201 - Camera service fatal error.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @systemapi
     * @since 12
     */
    attachSketchSurface(surfaceId: string): void;

    /**
     * Subscribes sketch status changed event callback.
     *
     * @param { 'sketchStatusChanged' } type - Event type.
     * @param { AsyncCallback<SketchStatusData> } callback - Callback used to sketch status data.
     * @throws { BusinessError } 202 - Not System Application.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @systemapi
     * @since 11
     */
    on(type: 'sketchStatusChanged', callback: AsyncCallback<SketchStatusData>): void;

    /**
     * Unsubscribes sketch status changed event callback.
     *
     * @param { 'sketchStatusChanged' } type - Event type.
     * @param { AsyncCallback<SketchStatusData> } callback - Callback used to get sketch status data.
     * @throws { BusinessError } 202 - Not System Application.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @systemapi
     * @since 11
     */
    off(type: 'sketchStatusChanged', callback?: AsyncCallback<SketchStatusData>): void;
  }

  /**
   * Enum for effect suggestion.
   *
   * @enum { number }
   * @syscap SystemCapability.Multimedia.Camera.Core
   * @systemapi
   * @since 12
   */
  enum EffectSuggestionType {
    /**
     * None.
     *
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @systemapi
     * @since 12
     */
    EFFECT_SUGGESTION_NONE = 0,
    /**
     * Portrait.
     *
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @systemapi
     * @since 12
     */
    EFFECT_SUGGESTION_PORTRAIT = 1,
    /**
     * Food.
     *
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @systemapi
     * @since 12
     */
    EFFECT_SUGGESTION_FOOD = 2,

    /**
     * Sky.
     *
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @systemapi
     * @since 12
     */
    EFFECT_SUGGESTION_SKY = 3,

    /**
     * Sunrise and sunset.
     *
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @systemapi
     * @since 12
     */
    EFFECT_SUGGESTION_SUNRISE_SUNSET = 4,

    /**
     * Stage.
     *
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @systemapi
     * @since 18
     */
    EFFECT_SUGGESTION_STAGE = 5
  }

  /**
   * Effect suggestion status
   *
   * @syscap SystemCapability.Multimedia.Camera.Core
   * @systemapi
   * @since 12
   */
  class EffectSuggestionStatus {
    /**
     * Effect Suggestion type.
     *
     * @type { EffectSuggestionType }
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @systemapi
     * @since 12
     */
    type: EffectSuggestionType;
    /**
     * Effect Suggestion type status.
     *
     * @type { boolean }
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @systemapi
     * @since 12
     */
    status: boolean;
  }

  /**
   * Enumerates the image rotation angles.
   *
   * @enum { number }
   * @syscap SystemCapability.Multimedia.Camera.Core
   * @since 10
   */
  enum ImageRotation {
    /**
     * The capture image rotates 0 degrees.
     *
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @since 10
     */
    ROTATION_0 = 0,

    /**
     * The capture image rotates 90 degrees.
     *
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @since 10
     */
    ROTATION_90 = 90,

    /**
     * The capture image rotates 180 degrees.
     *
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @since 10
     */
    ROTATION_180 = 180,

    /**
     * The capture image rotates 270 degrees.
     *
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @since 10
     */
    ROTATION_270 = 270
  }

  /**
   * Photo capture location
   *
   * @typedef Location
   * @syscap SystemCapability.Multimedia.Camera.Core
   * @since 10
   */
  interface Location {
    /**
     * Latitude.
     *
     * @type { number }
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @since 10
     */
    latitude: number;

    /**
     * Longitude.
     *
     * @type { number }
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @since 10
     */
    longitude: number;

    /**
     * Altitude.
     *
     * @type { number }
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @since 10
     */
    altitude: number;
  }

  /**
   * Enumerates the image quality levels.
   *
   * @enum { number }
   * @syscap SystemCapability.Multimedia.Camera.Core
   * @since 10
   */
  enum QualityLevel {
    /**
     * High image quality.
     *
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @since 10
     */
    QUALITY_LEVEL_HIGH = 0,

    /**
     * Medium image quality.
     *
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @since 10
     */
    QUALITY_LEVEL_MEDIUM = 1,

    /**
     * Low image quality.
     *
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @since 10
     */
    QUALITY_LEVEL_LOW = 2
  }

  /**
   * Photo capture options to set.
   *
   * @typedef PhotoCaptureSetting
   * @syscap SystemCapability.Multimedia.Camera.Core
   * @since 10
   */
  interface PhotoCaptureSetting {
    /**
     * Photo image quality.
     *
     * @type { ?QualityLevel }
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @since 10
     */
    quality?: QualityLevel;

    /**
     * Photo rotation.
     *
     * @type { ?ImageRotation }
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @since 10
     */
    rotation?: ImageRotation;

    /**
     * Photo location.
     *
     * @type { ?Location }
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @since 10
     */
    location?: Location;

    /**
     * Set the mirror photo function switch, default to false.
     *
     * @type { ?boolean }
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @since 10
     */
    mirror?: boolean;
  }

  /**
   * Enumerates the delivery image types.
   *
   * @enum { number }
   * @syscap SystemCapability.Multimedia.Camera.Core
   * @systemapi
   * @since 11
   */
  enum DeferredDeliveryImageType {
    /**
     * Undefer image delivery.
     *
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @systemapi
     * @since 11
     */
    NONE = 0,

    /**
     * Defer photo delivery when capturing photos.
     *
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @systemapi
     * @since 11
     */
    PHOTO = 1,

    /**
     * Defer video delivery when capturing videos.
     *
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @systemapi
     * @since 11
     */
    VIDEO = 2
  }

  /**
   * Photo object
   *
   * @typedef Photo
   * @syscap SystemCapability.Multimedia.Camera.Core
   * @since 11
   */
  interface Photo {
    /**
     * Main image.
     *
     * @type { image.Image }
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @since 11
     */
    main: image.Image;

    /**
     * Raw image.
     *
     * @type { ?image.Image }
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @systemapi
     * @since 12
     */
    raw?: image.Image;

    /**
     * Depth data.
     *
     * @type { DepthData }
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @systemapi
     * @since 13
     */
    depthData?: DepthData;

    /**
     * Release Photo object.
     *
     * @returns { Promise<void> } Promise used to return the result.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @since 11
     */
    release(): Promise<void>;
  }

  /**
   * DeferredPhotoProxy object
   *
   * @typedef DeferredPhotoProxy
   * @syscap SystemCapability.Multimedia.Camera.Core
   * @systemapi
   * @since 11
   */
  interface DeferredPhotoProxy {
    /**
     * Thumbnail image.
     *
     * @returns { Promise<image.PixelMap> } Promise used to return the result.
     * @throws { BusinessError } 202 - Not System Application.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @systemapi
     * @since 11
     */
    getThumbnail(): Promise<image.PixelMap>;

    /**
     * Release DeferredPhotoProxy object.
     *
     * @returns { Promise<void> } Promise used to return the result.
     * @throws { BusinessError } 202 - Not System Application.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @systemapi
     * @since 11
     */
    release(): Promise<void>;
  }

  /**
   * Enumerates the camera video codec type.
   *
   * @enum { number }
   * @syscap SystemCapability.Multimedia.Camera.Core
   * @since 13
   */
  enum VideoCodecType {
    /**
     * Codec type AVC.
     *
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @since 13
     */
    AVC = 0,

    /**
     * Codec type HEVC.
     *
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @since 13
     */
    HEVC = 1
  }

  /**
   * Photo output object.
   *
   * @interface PhotoOutput
   * @syscap SystemCapability.Multimedia.Camera.Core
   * @since 10
   */
  interface PhotoOutput extends CameraOutput {
    /**
     * Start capture output.
     *
     * @param { AsyncCallback<void> } callback - Callback used to return the result.
     * @throws { BusinessError } 7400104 - Session not running.
     * @throws { BusinessError } 7400201 - Camera service fatal error.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @since 10
     */
    capture(callback: AsyncCallback<void>): void;

    /**
     * Start capture output.
     *
     * @returns { Promise<void> } Promise used to return the result.
     * @throws { BusinessError } 7400104 - Session not running.
     * @throws { BusinessError } 7400201 - Camera service fatal error.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @since 10
     */
    capture(): Promise<void>;

    /**
     * Start capture output.
     *
     * @param { PhotoCaptureSetting } setting - Photo capture settings.
     * @param { AsyncCallback<void> } callback - Callback used to return the result.
     * @throws { BusinessError } 7400101 - Parameter missing or parameter type incorrect.
     * @throws { BusinessError } 7400104 - Session not running.
     * @throws { BusinessError } 7400201 - Camera service fatal error.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @since 10
     */
    capture(setting: PhotoCaptureSetting, callback: AsyncCallback<void>): void;

    /**
     * Start capture output.
     *
     * @param { PhotoCaptureSetting } setting - Photo capture settings.
     * @returns { Promise<void> } Promise used to return the result.
     * @throws { BusinessError } 7400101 - Parameter missing or parameter type incorrect.
     * @throws { BusinessError } 7400104 - Session not running.
     * @throws { BusinessError } 7400201 - Camera service fatal error.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @since 10
     */
    /**
     * Start capture output.
     * Remove optional param.
     *
     * @param { PhotoCaptureSetting } setting - Photo capture settings.
     * @returns { Promise<void> } Promise used to return the result.
     * @throws { BusinessError } 7400101 - Parameter missing or parameter type incorrect.
     * @throws { BusinessError } 7400104 - Session not running.
     * @throws { BusinessError } 7400201 - Camera service fatal error.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @since 11
     */
    capture(setting: PhotoCaptureSetting): Promise<void>;

    /**
     * Start burst capture.
     *
     * @param { PhotoCaptureSetting } setting - Photo capture settings.
     * @returns { Promise<void> } Promise used to return the result.
     * @throws { BusinessError } 202 - Not System Application.
     * @throws { BusinessError } 7400101 - Parameter missing or parameter type incorrect.
     * @throws { BusinessError } 7400104 - Session not running.
     * @throws { BusinessError } 7400201 - Camera service fatal error.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @systemapi
     * @since 12
     */
    burstCapture(setting: PhotoCaptureSetting): Promise<void>;

    /**
     * Confirm capture in Night mode or end burst capture.
     *
     * @throws { BusinessError } 202 - Not System Application.
     * @throws { BusinessError } 7400104 - Session not running.
     * @throws { BusinessError } 7400201 - Camera service fatal error.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @systemapi
     * @since 11
     */
    confirmCapture();

    /**
     * Confirm if the raw image delivery is supported
     *
     * @returns { boolean } TRUE if the type of delivery image is support.
     * @throws { BusinessError } 202 - Not System Application.
     * @throws { BusinessError } 7400104 - Session not running.
     * @throws { BusinessError } 7400201 - Camera service fatal error.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @systemapi
     * @since 13
     */
    isRawDeliverySupported(): boolean;

    /**
     * Enable raw image image delivery.
     *
     * @param { boolean } enabled - Target state for raw image delivery.
     * @throws { BusinessError } 202 - Not System Application.
     * @throws { BusinessError } 7400101 - Parameter missing or parameter type incorrect.
     * @throws { BusinessError } 7400104 - Session not running.
     * @throws { BusinessError } 7400201 - Camera service fatal error.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @systemapi
     * @since 13
     */
    enableRawDelivery(enabled: boolean): void;

    /**
     * Confirm if the deferred image delivery supported in the specific device.
     *
     * @param { DeferredDeliveryImageType } type - Type of delivery image.
     * @returns { boolean } TRUE if the type of delivery image is support.
     * @throws { BusinessError } 202 - Not System Application.
     * @throws { BusinessError } 7400101 - Parameter missing or parameter type incorrect.
     * @throws { BusinessError } 7400104 - Session not running.
     * @throws { BusinessError } 7400201 - Camera service fatal error.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @systemapi
     * @since 11
     */
    isDeferredImageDeliverySupported(type: DeferredDeliveryImageType): boolean;

    /**
     * Confirm if the deferred image delivery enabled.
     *
     * @param { DeferredDeliveryImageType } type - Type of delivery image.
     * @returns { boolean } TRUE if the type of delivery image is enable.
     * @throws { BusinessError } 202 - Not System Application.
     * @throws { BusinessError } 7400101 - Parameter missing or parameter type incorrect.
     * @throws { BusinessError } 7400104 - Session not running.
     * @throws { BusinessError } 7400201 - Camera service fatal error.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @systemapi
     * @since 11
     */
    isDeferredImageDeliveryEnabled(type: DeferredDeliveryImageType): boolean;

    /**
     * Sets the image type for deferred image delivery.
     *
     * @param { DeferredDeliveryImageType } type - Type of delivery image.
     * @throws { BusinessError } 202 - Not System Application.
     * @throws { BusinessError } 7400101 - Parameter missing or parameter type incorrect.
     * @throws { BusinessError } 7400104 - Session not running.
     * @throws { BusinessError } 7400201 - Camera service fatal error.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @systemapi
     * @since 11
     */
    deferImageDelivery(type: DeferredDeliveryImageType): void;

    /**
     * Check if the depth data delivery is supported.
     *
     * @returns { boolean } TRUE if the type of delivery image is enabled.
     * @throws { BusinessError } 202 - Not System Application.
     * @throws { BusinessError } 7400104 - Session not running.
     * @throws { BusinessError } 7400201 - Camera service fatal error.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @systemapi
     * @since 13
     */
    isDepthDataDeliverySupported(): boolean;

    /**
     * Enable depth data delivery.
     *
     * @param { boolean } enabled - Target state for depth data delivery.
     * @throws { BusinessError } 202 - Not System Application.
     * @throws { BusinessError } 7400101 - Parameter missing or parameter type incorrect.
     * @throws { BusinessError } 7400104 - Session not running.
     * @throws { BusinessError } 7400201 - Camera service fatal error.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @systemapi
     * @since 13
     */
    enableDepthDataDelivery(enabled: boolean): void;

    /**
     * Get supported moving photo video codec types.
     *
     * @returns { Array<VideoCodecType> } An array of supported video codec types for moving photo.
     * @throws { BusinessError } 7400201 - Camera service fatal error.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @since 13
     */
    getSupportedMovingPhotoVideoCodecTypes(): Array<VideoCodecType>;

    /**
     * Sets codec type for moving photo, default to AVC.
     *
     * @param { VideoCodecType } codecType - Codec type for moving photo.
     * @throws { BusinessError } 7400201 - Camera service fatal error.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @since 13
     */
    setMovingPhotoVideoCodecType(codecType: VideoCodecType): void;

    /**
     * Subscribes photo available event callback.
     *
     * @param { 'photoAvailable' } type - Event type.
     * @param { AsyncCallback<Photo> } callback - Callback used to get the Photo.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @since 11
     */
    on(type: 'photoAvailable', callback: AsyncCallback<Photo>): void;

    /**
     * Unsubscribes photo available event callback.
     *
     * @param { 'photoAvailable' } type - Event type.
     * @param { AsyncCallback<Photo> } callback - Callback used to get the Photo.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @since 11
     */
    off(type: 'photoAvailable', callback?: AsyncCallback<Photo>): void;

    /**
     * Subscribes deferred photo proxy available event callback.
     *
     * @param { 'deferredPhotoProxyAvailable' } type - Event type.
     * @param { AsyncCallback<DeferredPhotoProxy> } callback - Callback used to get the DeferredPhotoProxy.
     * @throws { BusinessError } 202 - Not System Application.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @systemapi
     * @since 11
     */
    on(type: 'deferredPhotoProxyAvailable', callback: AsyncCallback<DeferredPhotoProxy>): void;

    /**
     * Unsubscribes deferred photo proxy available event callback.
     *
     * @param { 'deferredPhotoProxyAvailable' } type - Event type.
     * @param { AsyncCallback<DeferredPhotoProxy> } callback - Callback used to get the DeferredPhotoProxy.
     * @throws { BusinessError } 202 - Not System Application.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @systemapi
     * @since 11
     */
    off(type: 'deferredPhotoProxyAvailable', callback?: AsyncCallback<DeferredPhotoProxy>): void;

    /**
     * Subscribes photo asset event callback.
     *
     * @param { 'photoAssetAvailable' } type - Event type.
     * @param { AsyncCallback<photoAccessHelper.PhotoAsset> } callback - Callback used to get the asset.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @since 12
     */
    on(type: 'photoAssetAvailable', callback: AsyncCallback<photoAccessHelper.PhotoAsset>): void;

    /**
     * Unsubscribes photo asset event callback.
     *
     * @param { 'photoAssetAvailable' } type - Event type.
     * @param { AsyncCallback<photoAccessHelper.PhotoAsset> } callback - Callback used to get the asset.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @since 12
     */
     off(type: 'photoAssetAvailable', callback?: AsyncCallback<photoAccessHelper.PhotoAsset>): void;

    /**
     * Check whether to support mirror photo.
     *
     * @returns { boolean } Is the mirror supported.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @since 10
     */
    isMirrorSupported(): boolean;

    /**
     * Enable mirror for photo capture.
     *
     * @param { boolean } enabled - enable photo mirror if TRUE.
     * @throws { BusinessError } 7400101 - Parameter missing or parameter type incorrect.
     * @throws { BusinessError } 7400103 - Session not config.
     * @throws { BusinessError } 7400201 - Camera service fatal error.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @since 13
     */
    enableMirror(enabled: boolean): void;

    /**
     * Subscribes capture start event callback.
     *
     * @param { 'captureStart' } type - Event type.
     * @param { AsyncCallback<number> } callback - Callback used to get the capture ID.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @since 10
     * @deprecated since 11
     * @useinstead ohos.multimedia.camera.PhotoOutput#captureStartWithInfo
     */
    on(type: 'captureStart', callback: AsyncCallback<number>): void;

    /**
     * Unsubscribes from capture start event callback.
     *
     * @param { 'captureStart' } type - Event type.
     * @param { AsyncCallback<number> } callback - Callback used to get the capture ID.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @since 10
     * @deprecated since 11
     * @useinstead ohos.multimedia.camera.PhotoOutput#captureStartWithInfo
     */
    off(type: 'captureStart', callback?: AsyncCallback<number>): void;

    /**
     * Subscribes capture start event callback.
     *
     * @param { 'captureStartWithInfo' } type - Event type.
     * @param { AsyncCallback<CaptureStartInfo> } callback - Callback used to get the capture start info.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @since 11
     */
    on(type: 'captureStartWithInfo', callback: AsyncCallback<CaptureStartInfo>): void;

    /**
     * Unsubscribes from capture start event callback.
     *
     * @param { 'captureStartWithInfo' } type - Event type.
     * @param { AsyncCallback<CaptureStartInfo> } callback - Callback used to get the capture start info.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @since 11
     */
    off(type: 'captureStartWithInfo', callback?: AsyncCallback<CaptureStartInfo>): void;

    /**
     * Subscribes frame shutter event callback.
     *
     * @param { 'frameShutter' } type - Event type.
     * @param { AsyncCallback<FrameShutterInfo> } callback - Callback used to get the frame shutter information.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @since 10
     */
    on(type: 'frameShutter', callback: AsyncCallback<FrameShutterInfo>): void;

    /**
     * Unsubscribes from frame shutter event callback.
     *
     * @param { 'frameShutter' } type - Event type.
     * @param { AsyncCallback<FrameShutterInfo> } callback - Callback used to get the frame shutter information.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @since 10
     */
    off(type: 'frameShutter', callback?: AsyncCallback<FrameShutterInfo>): void;

    /**
     * Subscribes frame shutter end event callback.
     *
     * @param { 'frameShutterEnd' } type - Event type.
     * @param { AsyncCallback<FrameShutterEndInfo> } callback - Callback used to get the frame shutter end information.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @since 12
     */
    on(type: 'frameShutterEnd', callback: AsyncCallback<FrameShutterEndInfo>): void;

    /**
     * Unsubscribes from frame shutter end event callback.
     *
     * @param { 'frameShutterEnd' } type - Event type.
     * @param { AsyncCallback<FrameShutterEndInfo> } callback - Callback used to get the frame shutter end information.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @since 12
     */
    off(type: 'frameShutterEnd', callback?: AsyncCallback<FrameShutterEndInfo>): void;

    /**
     * Subscribes capture end event callback.
     *
     * @param { 'captureEnd' } type - Event type.
     * @param { AsyncCallback<CaptureEndInfo> } callback - Callback used to get the capture end information.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @since 10
     */
    on(type: 'captureEnd', callback: AsyncCallback<CaptureEndInfo>): void;

    /**
     * Unsubscribes from capture end event callback.
     *
     * @param { 'captureEnd' } type - Event type.
     * @param { AsyncCallback<CaptureEndInfo> } callback - Callback used to get the capture end information.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @since 10
     */
    off(type: 'captureEnd', callback?: AsyncCallback<CaptureEndInfo>): void;

    /**
     * Subscribes capture ready event callback. After receiving the callback, can proceed to the next capture
     *
     * @param { 'captureReady' } type - Event type.
     * @param { AsyncCallback<void> } callback - Callback used to notice capture ready.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @since 12
     */
    on(type: 'captureReady', callback: AsyncCallback<void>): void;

    /**
     * Unsubscribes from capture ready event callback.
     *
     * @param { 'captureReady' } type - Event type.
     * @param { AsyncCallback<void> } callback - Callback used to notice capture ready.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @since 12
     */
    off(type: 'captureReady', callback?: AsyncCallback<void>): void;

    /**
     * Subscribes estimated capture duration event callback.
     *
     * @param { 'estimatedCaptureDuration' } type - Event type.
     * @param { AsyncCallback<number> } callback - Callback used to notify the estimated capture duration (in milliseconds).
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @since 12
     */
    on(type: 'estimatedCaptureDuration', callback: AsyncCallback<number>): void;

    /**
     * Unsubscribes from estimated capture duration event callback.
     *
     * @param { 'estimatedCaptureDuration' } type - Event type.
     * @param { AsyncCallback<number> } callback - Callback used to notify the estimated capture duration (in milliseconds).
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @since 12
     */
    off(type: 'estimatedCaptureDuration', callback?: AsyncCallback<number>): void;

    /**
     * Subscribes to error events.
     *
     * @param { 'error' } type - Event type.
     * @param { ErrorCallback } callback - Callback used to get the photo output errors.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @since 10
     */
    on(type: 'error', callback: ErrorCallback): void;

    /**
     * Unsubscribes from error events.
     *
     * @param { 'error' } type - Event type.
     * @param { ErrorCallback } callback - Callback used to get the photo output errors.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @since 10
     */
    off(type: 'error', callback?: ErrorCallback): void;

    /**
     * Gets the current preconfig type if you had already call preconfig interface.
     *
     * @returns { Profile } The current preconfig type.
     * @throws { BusinessError } 7400201 - Camera service fatal error.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @since 12
     */
    getActiveProfile(): Profile;

    /**
     * Checks whether PhotoOutput supports quick thumbnail.
     * This method is valid after Session.addInput() and Session.addOutput(photoOutput) are called.
     *
     * @returns { boolean } Whether quick thumbnail is supported.
     * @throws { BusinessError } 7400104 - session is not running.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @systemapi
     * @since 10
     */
    /**
     * Checks whether PhotoOutput supports quick thumbnail.
     * This method is valid after Session.addInput() and Session.addOutput(photoOutput) are called.
     *
     * @returns { boolean } Whether quick thumbnail is supported.
     * @throws { BusinessError } 202 - Not System Application.
     * @throws { BusinessError } 7400104 - session is not running.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @systemapi
     * @since 12
     */
    isQuickThumbnailSupported(): boolean;

    /**
     * Enables or disables quick thumbnail.
     * The method must be called after Session.addInput() and Session.addOutput(photoOutput) are called.
     * To avoid stream reconfiguration and performance loss,
     * you are advised to call the method before Session.commitConfig().
     *
     * @param { boolean } enabled - The value TRUE means to enable quick thumbnail, and FALSE means the opposite.
     * @throws { BusinessError } 7400104 - session is not running.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @systemapi
     * @since 10
     */
    /**
     * Enables or disables quick thumbnail.
     * The method must be called after Session.addInput() and Session.addOutput(photoOutput) are called.
     * To avoid stream reconfiguration and performance loss,
     * you are advised to call the method before Session.commitConfig().
     *
     * @param { boolean } enabled - The value TRUE means to enable quick thumbnail, and FALSE means the opposite.
     * @throws { BusinessError } 202 - Not System Application.
     * @throws { BusinessError } 7400101 - Parameter missing or parameter type incorrect.
     * @throws { BusinessError } 7400104 - session is not running.
     * @throws { BusinessError } 7400201 - Camera service fatal error.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @systemapi
     * @since 12
     */
    enableQuickThumbnail(enabled: boolean): void;

    /**
     * Subscribes to camera thumbnail events.
     * This method is valid only after enableQuickThumbnail(true) is called.
     *
     * @param { 'quickThumbnail' } type - Event type.
     * @param { AsyncCallback<image.PixelMap> } callback - Callback used to get the quick thumbnail.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @systemapi
     * @since 10
     */
    on(type: 'quickThumbnail', callback: AsyncCallback<image.PixelMap>): void;

    /**
     * Unsubscribes from camera thumbnail events.
     * This method is valid only after enableQuickThumbnail(true) is called.
     *
     * @param { 'quickThumbnail' } type - Event type.
     * @param { AsyncCallback<image.PixelMap> } callback - Callback used to get the quick thumbnail.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @systemapi
     * @since 10
     */
    off(type: 'quickThumbnail', callback?: AsyncCallback<image.PixelMap>): void;

    /**
     * Confirm if the auto high quality photo supported.
     *
     * @returns { boolean } TRUE if the auto high quality photo is supported.
     * @throws { BusinessError } 202 - Not System Application.
     * @throws { BusinessError } 7400104 - session is not running.
     * @throws { BusinessError } 7400201 - Camera service fatal error.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @systemapi
     * @since 13
     */
    isAutoHighQualityPhotoSupported(): boolean;

    /**
     * Enable auto high quality photo.
     *
     * @param { boolean } enabled - Target state for auto high quality photo.
     * @throws { BusinessError } 202 - Not System Application.
     * @throws { BusinessError } 7400101 - Parameter missing or parameter type incorrect.
     * @throws { BusinessError } 7400104 - session is not running.
     * @throws { BusinessError } 7400201 - Camera service fatal error.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @systemapi
     * @since 13
     */
    enableAutoHighQualityPhoto(enabled: boolean): void;

    /**
     * Confirm if the auto cloud image enhancement is supported.
     *
     * @returns { boolean } TRUE if the auto cloud image enhancement is supported.
     * @throws { BusinessError } 202 - Not System Application.
     * @throws { BusinessError } 7400201 - Camera service fatal error.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @systemapi
     * @since 13
     */
     isAutoCloudImageEnhancementSupported(): boolean;

    /**
     * Enable auto cloud image enhancement
     *
     * @param { boolean } enabled - Target state for auto cloud image enhancement.
     * @throws { BusinessError } 202 - Not System Application.
     * @throws { BusinessError } 7400101 - Parameter missing or parameter type incorrect.
     * @throws { BusinessError } 7400201 - Camera service fatal error.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @systemapi
     * @since 13
     */
     enableAutoCloudImageEnhancement(enabled: boolean): void;

    /**
     * Confirm if moving photo supported.
     *
     * @returns { boolean } TRUE if the moving photo is supported.
     * @throws { BusinessError } 7400201 - Camera service fatal error.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @since 12
     */
    isMovingPhotoSupported(): boolean;

    /**
     * Enable moving photo.
     *
     * @permission ohos.permission.MICROPHONE
     * @param { boolean } enabled - Target state for moving photo.
     * @throws { BusinessError } 201 - permission denied.
     * @throws { BusinessError } 7400101 - Parameter missing or parameter type incorrect.
     * @throws { BusinessError } 7400201 - Camera service fatal error.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @since 12
     */
    enableMovingPhoto(enabled: boolean): void;

    /**
     * Gets the photo rotation angle.
     *
     * @param { number } deviceDegree - The current device rotation degree.
     * @returns { ImageRotation } The photo rotation angle.
     * @throws { BusinessError } 7400101 - Parameter missing or parameter type incorrect.
     * @throws { BusinessError } 7400201 - Camera service fatal error.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @since 12
     */
    getPhotoRotation(deviceDegree: number): ImageRotation;

    /**
     * Confirm if auto aigc photo supported.
     *
     * @returns { boolean } TRUE if auto aigc photo is supported.
     * @throws { BusinessError } 202 - Not System Application.
     * @throws { BusinessError } 401 - Parameter error. Possible causes:
     * 1. Mandatory parameters are left unspecified; 2. Incorrect parameter types;
     * 3. Parameter verification failed.
     * @throws { BusinessError } 7400201 - Camera service fatal error.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @systemapi
     * @since 16
     */
    isAutoAigcPhotoSupported(): boolean;

    /**
     * Enable auto aigc photo.
     *
     * @param { boolean } enabled - Target state for auto aigc photo.
     * @throws { BusinessError } 202 - Not System Application.
     * @throws { BusinessError } 401 - Parameter error. Possible causes:
     * 1. Mandatory parameters are left unspecified; 2. Incorrect parameter types;
     * 3. Parameter verification failed.
     */
    enableAutoAigcPhoto(enabled: boolean): void;

    /**
     * Confirm if offline processing is supported.
     *
     * @returns { boolean } TRUE if the type of offline is supported.
     * @throws { BusinessError } 202 - Not System Application.
     * @throws { BusinessError } 7400201 - Camera service fatal error.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @systemapi
     * @since 16
     */
    isOfflineSupported(): boolean;

    /**
     * Enable offline processing.
     *
     * @throws { BusinessError } 202 - Not System Application.
     * @throws { BusinessError } 7400104 - session is not running.
     * @throws { BusinessError } 7400201 - Camera service fatal error.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @systemapi
     * @since 16
     */
    enableOffline(): void;

    /**
     * Subscribes offline Delivery finished events.
     * This method is valid only after enableOffline() is called.
     *
     * @param { 'offlineDeliveryFinished' } type - Event type.
     * @param { AsyncCallback<void> } callback - Callback used to get offline Delivery finished events.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @systemapi
     * @since 16
     */
    on(type: 'offlineDeliveryFinished', callback: AsyncCallback<void>): void;

    /**
     * Unsubscribes offline Delivery finished events.
     * This method is valid only after enableOffline() is called.
     *
     * @param { 'offlineDeliveryFinished' } type - Event type.
     * @param { AsyncCallback<void>} callback - Callback used to get offline Delivery finished events.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @systemapi
     * @since 16
     */
    off(type: 'offlineDeliveryFinished', callback?: AsyncCallback<void>): void
  }

  /**
   * Frame shutter callback info.
   *
   * @typedef FrameShutterInfo
   * @syscap SystemCapability.Multimedia.Camera.Core
   * @since 10
   */
  interface FrameShutterInfo {
    /**
     * Capture id.
     *
     * @type { number }
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @since 10
     */
    captureId: number;
    /**
     * Timestamp for frame.
     *
     * @type { number }
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @since 10
     */
    timestamp: number;
  }

  /**
   * Frame shutter end callback info.
   *
   * @typedef FrameShutterEndInfo
   * @syscap SystemCapability.Multimedia.Camera.Core
   * @since 12
   */
  interface FrameShutterEndInfo {
    /**
     * Capture id.
     *
     * @type { number }
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @since 12
     */
    captureId: number;
  }

  /**
   * Capture start info.
   *
   * @typedef CaptureStartInfo
   * @syscap SystemCapability.Multimedia.Camera.Core
   * @since 11
   */
  interface CaptureStartInfo {
    /**
     * Capture id.
     *
     * @type { number }
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @since 11
     */
    captureId: number;
    /**
     * Time(in milliseconds) is the shutter time for the photo.
     *
     * @type { number }
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @since 11
     */
    time: number;
  }

  /**
   * Capture end info.
   *
   * @typedef CaptureEndInfo
   * @syscap SystemCapability.Multimedia.Camera.Core
   * @since 10
   */
  interface CaptureEndInfo {
    /**
     * Capture id.
     *
     * @type { number }
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @since 10
     */
    captureId: number;
    /**
     * Frame count.
     *
     * @type { number }
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @since 10
     */
    frameCount: number;
  }

  /**
   * Deferred video enhancement info.
   *
   * @typedef DeferredVideoEnhancementInfo
   * @syscap SystemCapability.Multimedia.Camera.Core
   * @systemapi
   * @since 13
   */
  interface DeferredVideoEnhancementInfo {
    /**
     * Check whether deferred video enhancement available.
     *
     * @type { boolean }
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @systemapi
     * @since 13
     * @readonly
     */
    readonly isDeferredVideoEnhancementAvailable: boolean;
    /**
     * Video identifier.
     *
     * @type { ?string }
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @systemapi
     * @since 13
     * @readonly
     */
    readonly videoId?: string;
  }

  /**
   * Video output object.
   *
   * @interface VideoOutput
   * @syscap SystemCapability.Multimedia.Camera.Core
   * @since 10
   */
  interface VideoOutput extends CameraOutput {
    /**
     * Start video output.
     *
     * @param { AsyncCallback<void> } callback - Callback used to return the result.
     * @throws { BusinessError } 7400103 - Session not config.
     * @throws { BusinessError } 7400201 - Camera service fatal error.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @since 10
     */
    start(callback: AsyncCallback<void>): void;

    /**
     * Start video output.
     *
     * @returns { Promise<void> } Promise used to return the result.
     * @throws { BusinessError } 7400103 - Session not config.
     * @throws { BusinessError } 7400201 - Camera service fatal error.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @since 10
     */
    start(): Promise<void>;

    /**
     * Stop video output.
     *
     * @param { AsyncCallback<void> } callback - Callback used to return the result.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @since 10
     */
    stop(callback: AsyncCallback<void>): void;

    /**
     * Stop video output.
     *
     * @returns { Promise<void> } Promise used to return the result.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @since 10
     */
    stop(): Promise<void>;

    /**
     * Determine whether video mirror is supported.
     *
     * @returns { boolean } Is video mirror supported.
     * @throws { BusinessError } 202 - Not System Application.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @systemapi
     * @since 12
     */
    isMirrorSupported(): boolean;

    /**
     * Enable mirror for video capture.
     *
     * @param { boolean } enabled - enable video mirror if TRUE.
     * @throws { BusinessError } 202 - Not System Application.
     * @throws { BusinessError } 7400101 - Parameter missing or parameter type incorrect.
     * @throws { BusinessError } 7400103 - Session not config.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @systemapi
     * @since 12
     */
    enableMirror(enabled: boolean): void;

    /**
     * Get supported frame rates which can be set during session running.
     *
     * @returns { Array<FrameRateRange> } The array of supported frame rate range.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @since 12
     */
    getSupportedFrameRates(): Array<FrameRateRange>

    /**
     * Set a frame rate range.
     *
     * @param { number } minFps - Minimum frame rate per second.
     * @param { number } maxFps - Maximum frame rate per second.
     * @throws { BusinessError } 7400101 - Parameter missing or parameter type incorrect.
     * @throws { BusinessError } 7400110 - Unresolved conflicts with current configurations.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @since 12
     */
    setFrameRate(minFps: number, maxFps: number): void

    /**
     * Get active frame rate range which has been set before.
     *
     * @returns { FrameRateRange } The active frame rate range.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @since 12
     */
    getActiveFrameRate(): FrameRateRange;

    /**
     * Gets the video rotation angle.
     *
     * @param { number } deviceDegree - The current device rotation degree.
     * @returns { ImageRotation } The video rotation angle.
     * @throws { BusinessError } 7400101 - Parameter missing or parameter type incorrect.
     * @throws { BusinessError } 7400201 - Camera service fatal error.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @since 12
     */
    getVideoRotation(deviceDegree: number): ImageRotation;

    /**
     * Confirm if auto deferred video enhancement is supported in the specific device.
     *
     * @returns { boolean } TRUE if auto deferred video enhancement is supported.
     * @throws { BusinessError } 202 - Not System Application.
     * @throws { BusinessError } 7400201 - Camera service fatal error.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @systemapi
     * @since 13
     */
    isAutoDeferredVideoEnhancementSupported(): boolean;

    /**
     * Confirm if auto deferred video enhancement is enabled.
     *
     * @returns { boolean } TRUE if auto deferred video enhancement is enabled.
     * @throws { BusinessError } 202 - Not System Application.
     * @throws { BusinessError } 7400201 - Camera service fatal error.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @systemapi
     * @since 13
     */
    isAutoDeferredVideoEnhancementEnabled(): boolean;

    /**
     * Enable auto deferred video enhancement if needed.
     *
     * @param { boolean } enabled - Status of auto deferred video enhancement.
     * @throws { BusinessError } 202 - Not System Application.
     * @throws { BusinessError } 7400101 - Parameter missing or parameter type incorrect.
     * @throws { BusinessError } 7400201 - Camera service fatal error.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @systemapi
     * @since 13
     */
    enableAutoDeferredVideoEnhancement(enabled: boolean): void;

    /**
     * Subscribes deferred video enhancement info callback.
     *
     * @param { 'deferredVideoEnhancementInfo' } type - Event type.
     * @param { AsyncCallback<DeferredVideoEnhanceInfo> } callback - Callback used to return the result.
     * @throws { BusinessError } 202 - Not System Application.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @systemapi
     * @since 13
     */
    on(type: 'deferredVideoEnhancementInfo', callback: AsyncCallback<DeferredVideoEnhancementInfo>): void;

    /**
     * Unsubscribes from deferred video enhancement info callback.
     *
     * @param { 'deferredVideoEnhancementInfo' } type - Event type.
     * @param { AsyncCallback<DeferredVideoEnhancementInfo> } callback - Callback used to return the result.
     * @throws { BusinessError } 202 - Not System Application.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @systemapi
     * @since 13
     */
    off(type: 'deferredVideoEnhancementInfo', callback?: AsyncCallback<DeferredVideoEnhancementInfo>): void;

    /**
     * Subscribes frame start event callback.
     *
     * @param { 'frameStart' } type - Event type.
     * @param { AsyncCallback<void> } callback - Callback used to return the result.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @since 10
     */
    on(type: 'frameStart', callback: AsyncCallback<void>): void;

    /**
     * Unsubscribes from frame start event callback.
     *
     * @param { 'frameStart' } type - Event type.
     * @param { AsyncCallback<void> } callback - Callback used to return the result.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @since 10
     */
    off(type: 'frameStart', callback?: AsyncCallback<void>): void;

    /**
     * Subscribes frame end event callback.
     *
     * @param { 'frameEnd' } type - Event type.
     * @param { AsyncCallback<void> } callback - Callback used to return the result.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @since 10
     */
    on(type: 'frameEnd', callback: AsyncCallback<void>): void;

    /**
     * Unsubscribes from frame end event callback.
     *
     * @param { 'frameEnd' } type - Event type.
     * @param { AsyncCallback<void> } callback - Callback used to return the result.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @since 10
     */
    off(type: 'frameEnd', callback?: AsyncCallback<void>): void;

    /**
     * Subscribes to error events.
     *
     * @param { 'error' } type - Event type.
     * @param { ErrorCallback } callback - Callback used to get the video output errors.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @since 10
     */
    on(type: 'error', callback: ErrorCallback): void;

    /**
     * Unsubscribes from error events.
     *
     * @param { 'error' } type - Event type.
     * @param { ErrorCallback } callback - Callback used to get the video output errors.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @since 10
     */
    off(type: 'error', callback?: ErrorCallback): void;

    /**
     * Gets the current preconfig type if you had already call preconfig interface.
     *
     * @returns { VideoProfile } The current preconfig type.
     * @throws { BusinessError } 7400201 - Camera service fatal error.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @since 12
     */
    getActiveProfile(): VideoProfile;

    /**
     * Get supported video meta types.
     * @returns { Array<VideoMetaType> } The array of supported video meta type.
     * @throws { BusinessError } 202 - Not System Application.
     * @throws { BusinessError } 7400201 - Camera service fatal error.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @systemapi
     * @since 12
     */
    getSupportedVideoMetaTypes(): Array<VideoMetaType>;

    /**
     * Attach a meta surface to VideoOutput.
     * @param { string } surfaceId - Surface object id used for receiving meta infos.
     * @param { VideoMetaType } type - Video meta type.
     * @throws { BusinessError } 202 - Not System Application.
     * @throws { BusinessError } 7400101 - Parameter missing or parameter type incorrect.
     * @throws { BusinessError } 7400201 - Camera service fatal error.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @systemapi
     * @since 12
     */
    attachMetaSurface(surfaceId: string, type: VideoMetaType): void;
  }

  /**
   * Video meta type.
   *
   * @enum { number }
   * @syscap SystemCapability.Multimedia.Camera.Core
   * @systemapi
   * @since 12
   */
  enum VideoMetaType {
    /**
     * Video meta type for storing maker info.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @systemapi
     * @since 12
     */
    VIDEO_META_MAKER_INFO = 0,
  }

  /**
   * Metadata object type.
   *
   * @enum { number }
   * @syscap SystemCapability.Multimedia.Camera.Core
   * @since 10
   */
  enum MetadataObjectType {
    /**
     * Face detection type.
     *
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @since 10
     */
    FACE_DETECTION = 0,

    /**
     * Human body detection type.
     *
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @systemapi
     * @since 13
     */
    HUMAN_BODY = 1,

    /**
     * Cat face detection type.
     *
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @systemapi
     * @since 13
     */
    CAT_FACE = 2,

    /**
     * Cat body detection type.
     *
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @systemapi
     * @since 13
     */
    CAT_BODY = 3,

    /**
     * Dog face detection type.
     *
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @systemapi
     * @since 13
     */
    DOG_FACE = 4,

    /**
     * Dog body detection type.
     *
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @systemapi
     * @since 13
     */
    DOG_BODY = 5,

    /**
     * Salient detection type.
     *
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @systemapi
     * @since 13
     */
    SALIENT_DETECTION = 6,

    /**
     * Barcode detection type.
     *
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @systemapi
     * @since 13
     */
    BAR_CODE_DETECTION = 7
  }

  /**
   * Enum for light painting tabletype.
   *
   * @enum { number }
   * @syscap SystemCapability.Multimedia.Camera.Core
   * @systemapi
   * @since 12
   */
  enum LightPaintingType {
    /**
     * Traffic trails effect.
     *
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @systemapi
     * @since 12
     */
    TRAFFIC_TRAILS = 0,

    /**
     * Star trails effect.
     *
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @systemapi
     * @since 12
     */
    STAR_TRAILS = 1,

    /**
     * Silky water effect.
     *
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @systemapi
     * @since 12
     */
    SILKY_WATER = 2,

    /**
     * Light graffiti effect.
     *
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @systemapi
     * @since 12
     */
    LIGHT_GRAFFITI = 3
  }

  /**
   * Rectangle definition.
   *
   * @typedef Rect
   * @syscap SystemCapability.Multimedia.Camera.Core
   * @since 10
   */
  interface Rect {
    /**
     * X coordinator of top left point.
     *
     * @type { number }
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @since 10
     */
    topLeftX: number;
    /**
     * Y coordinator of top left point.
     *
     * @type { number }
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @since 10
     */
    topLeftY: number;
    /**
     * Width of this rectangle.
     *
     * @type { number }
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @since 10
     */
    width: number;
    /**
     * Height of this rectangle.
     *
     * @type { number }
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @since 10
     */
    height: number;
  }

  /**
   * Enum for emotion type.
   *
   * @enum { number }
   * @syscap SystemCapability.Multimedia.Camera.Core
   * @systemapi
   * @since 13
   */
  enum Emotion {
    /**
     * Emotion type: Neutral.
     *
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @systemapi
     * @since 13
     */
    NEUTRAL = 0,

    /**
     * Emotion type: Sadness.
     *
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @systemapi
     * @since 13
     */
    SADNESS = 1,

    /**
     * Emotion type: Smile.
     *
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @systemapi
     * @since 13
     */
    SMILE = 2,

    /**
     * Emotion type: Surprise.
     *
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @systemapi
     * @since 13
     */
    SURPRISE = 3
  }

  /**
   * Metadata object basis.
   *
   * @typedef MetadataObject
   * @syscap SystemCapability.Multimedia.Camera.Core
   * @since 10
   */
  interface MetadataObject {
    /**
     * Metadata object type.
     *
     * @type { MetadataObjectType }
     * @readonly
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @since 10
     */
    readonly type: MetadataObjectType;
    /**
     * Metadata object timestamp in milliseconds.
     *
     * @type { number }
     * @readonly
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @since 10
     */
    readonly timestamp: number;
    /**
     * The axis-aligned bounding box of detected metadata object.
     *
     * @type { Rect }
     * @readonly
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @since 10
     */
    readonly boundingBox: Rect;
    /**
     * Metadata object id.
     *
     * @type { number }
     * @readonly
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @systemapi
     * @since 13
     */
    readonly objectId: number;
    /**
     * Confidence for the detected type.
     *
     * @type { number }
     * @readonly
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @systemapi
     * @since 13
     */
    readonly confidence: number;
  }

  /**
   * Metadata object for face.
   *
   * @typedef MetadataFaceObject
   * @extends MetadataObject
   * @syscap SystemCapability.Multimedia.Camera.Core
   * @systemapi
   * @since 13
   */
  interface MetadataFaceObject extends MetadataObject {
    /**
     * Bounding box for left eye.
     *
     * @type { Rect }
     * @readonly
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @systemapi
     * @since 13
     */
    readonly leftEyeBoundingBox: Rect;

    /**
     * Bounding box for right eye.
     *
     * @type { Rect }
     * @readonly
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @systemapi
     * @since 13
     */
    readonly rightEyeBoundingBox: Rect;

    /**
     * Emotion type for face.
     *
     * @type { Emotion }
     * @readonly
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @systemapi
     * @since 13
     */
    readonly emotion: Emotion;

    /**
     * Emotion confidence.
     *
     * @type { number }
     * @readonly
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @systemapi
     * @since 13
     */
    readonly emotionConfidence: number;

    /**
     * Pitch angle for face.
     *
     * @type { number }
     * @readonly
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @systemapi
     * @since 13
     */
    readonly pitchAngle: number;

    /**
     * Yaw angle for face.
     *
     * @type { number }
     * @readonly
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @systemapi
     * @since 13
     */
    readonly yawAngle: number;

    /**
     * Roll angle for face.
     *
     * @type { number }
     * @readonly
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @systemapi
     * @since 13
     */
    readonly rollAngle: number;
  }

  /**
   * Metadata object for human body.
   *
   * @typedef MetadataHumanBodyObject
   * @extends MetadataObject
   * @syscap SystemCapability.Multimedia.Camera.Core
   * @systemapi
   * @since 13
   */
  interface MetadataHumanBodyObject extends MetadataObject {
  }

  /**
   * Metadata object for cat face.
   *
   * @typedef MetadataCatFaceObject
   * @extends MetadataObject
   * @syscap SystemCapability.Multimedia.Camera.Core
   * @systemapi
   * @since 13
   */
  interface MetadataCatFaceObject extends MetadataObject {
    /**
     * Bounding box for left eye.
     *
     * @type { Rect }
     * @readonly
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @systemapi
     * @since 13
     */
    readonly leftEyeBoundingBox: Rect;

    /**
     * Bounding box for right eye.
     *
     * @type { Rect }
     * @readonly
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @systemapi
     * @since 13
     */
    readonly rightEyeBoundingBox: Rect;
  }

  /**
   * Metadata object for cat body.
   *
   * @typedef MetadataCatBodyObject
   * @extends MetadataObject
   * @syscap SystemCapability.Multimedia.Camera.Core
   * @systemapi
   * @since 13
   */
  interface MetadataCatBodyObject extends MetadataObject {
  }

  /**
   * Metadata object for dog face.
   *
   * @typedef MetadataDogFaceObject
   * @extends MetadataObject
   * @syscap SystemCapability.Multimedia.Camera.Core
   * @systemapi
   * @since 13
   */
  interface MetadataDogFaceObject extends MetadataObject {
    /**
     * Bounding box for left eye.
     *
     * @type { Rect }
     * @readonly
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @systemapi
     * @since 13
     */
    readonly leftEyeBoundingBox: Rect;

    /**
     * Bounding box for right eye.
     *
     * @type { Rect }
     * @readonly
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @systemapi
     * @since 13
     */
    readonly rightEyeBoundingBox: Rect;
  }

  /**
   * Metadata object for dog body.
   *
   * @typedef MetadataDogBodyObject
   * @extends MetadataObject
   * @syscap SystemCapability.Multimedia.Camera.Core
   * @systemapi
   * @since 13
   */
  interface MetadataDogBodyObject extends MetadataObject {
  }

  /**
   * Metadata object for salient detection.
   *
   * @typedef MetadataSalientDetectionObject
   * @extends MetadataObject
   * @syscap SystemCapability.Multimedia.Camera.Core
   * @systemapi
   * @since 13
   */
  interface MetadataSalientDetectionObject extends MetadataObject {
  }

  /**
   * Camera Occlusion Detection Result.
   *
   * @typedef CameraOcclusionDetectionResult
   * @syscap SystemCapability.Multimedia.Camera.Core
   * @systemapi
   * @since 12
   */
  interface CameraOcclusionDetectionResult {
    /**
     * Check whether camera is occluded.
     *
     * @type { boolean }
     * @readonly
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @systemapi
     * @since 12
     */
    readonly isCameraOccluded: boolean;

    /**
     * Check whether camera lens is dirty.
     *
     * @type { boolean }
     * @readonly
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @systemapi
     * @since 13
     */
    readonly isCameraLensDirty: boolean;
  }

  /**
   * Metadata Output object
   *
   * @interface MetadataOutput
   * @syscap SystemCapability.Multimedia.Camera.Core
   * @since 10
   */
  interface MetadataOutput extends CameraOutput {
    /**
     * Start output metadata
     *
     * @param { AsyncCallback<void> } callback - Callback used to return the result.
     * @throws { BusinessError } 7400103 - Session not config.
     * @throws { BusinessError } 7400201 - Camera service fatal error.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @since 10
     */
    start(callback: AsyncCallback<void>): void;

    /**
     * Start output metadata
     *
     * @returns { Promise<void> } Promise used to return the result.
     * @throws { BusinessError } 7400103 - Session not config.
     * @throws { BusinessError } 7400201 - Camera service fatal error.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @since 10
     */
    start(): Promise<void>;

    /**
     * Stop output metadata
     *
     * @param { AsyncCallback<void> } callback - Callback used to return the result.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @since 10
     */
    stop(callback: AsyncCallback<void>): void;

    /**
     * Stop output metadata
     *
     * @returns { Promise<void> } Promise used to return the result.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @since 10
     */
    stop(): Promise<void>;

    /**
     * Add metadata object types.
     *
     * @param { Array<MetadataObjectType> } types - Object types to be added.
     * @throws { BusinessError } 202 - Not System Application.
     * @throws { BusinessError } 7400101 - Parameter missing or parameter type incorrect.
     * @throws { BusinessError } 7400103 - Session not config.
     * @throws { BusinessError } 7400201 - Camera service fatal error.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @systemapi
     * @since 13
     */
    addMetadataObjectTypes(types: Array<MetadataObjectType>): void;

    /**
     * Remove metadata object types.
     *
     * @param { Array<MetadataObjectType> } types - Object types to be removed.
     * @throws { BusinessError } 202 - Not System Application.
     * @throws { BusinessError } 7400101 - Parameter missing or parameter type incorrect.
     * @throws { BusinessError } 7400103 - Session not config.
     * @throws { BusinessError } 7400201 - Camera service fatal error.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @systemapi
     * @since 13
     */
    removeMetadataObjectTypes(types: Array<MetadataObjectType>): void;

    /**
     * Subscribes to metadata objects available event callback.
     *
     * @param { 'metadataObjectsAvailable' } type - Event type.
     * @param { AsyncCallback<Array<MetadataObject>> } callback - Callback used to get the available metadata objects.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @since 10
     */
    on(type: 'metadataObjectsAvailable', callback: AsyncCallback<Array<MetadataObject>>): void;

    /**
     * Unsubscribes from metadata objects available event callback.
     *
     * @param { 'metadataObjectsAvailable' } type - Event type.
     * @param { AsyncCallback<Array<MetadataObject>> } callback - Callback used to get the available metadata objects.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @since 10
     */
    off(type: 'metadataObjectsAvailable', callback?: AsyncCallback<Array<MetadataObject>>): void;

    /**
     * Subscribes to error events.
     *
     * @param { 'error' } type - Event type.
     * @param { ErrorCallback } callback - Callback used to get the video output errors.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @since 10
     */
    on(type: 'error', callback: ErrorCallback): void;

    /**
     * Unsubscribes from error events.
     *
     * @param { 'error' } type - Event type.
     * @param { ErrorCallback } callback - Callback used to get the video output errors.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @since 10
     */
    off(type: 'error', callback?: ErrorCallback): void;
  }

  /**
   * Enumerates the timelapse recording state.
   *
   * @enum { number }
   * @syscap SystemCapability.Multimedia.Camera.Core
   * @systemapi
   * @since 12
   */
  enum TimeLapseRecordState {
    /**
     * TimeLapse idle state.
     *
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @systemapi
     * @since 12
     */
    IDLE = 0,

    /**
     * TimeLapse recording state.
     *
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @systemapi
     * @since 12
     */
    RECORDING = 1
  }

  /**
   * Enumerates the timelapse preview type.
   *
   * @enum { number }
   * @syscap SystemCapability.Multimedia.Camera.Core
   * @systemapi
   * @since 12
   */
  enum TimeLapsePreviewType {
    /**
     * TimeLapse dark preview.
     *
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @systemapi
     * @since 12
     */
    DARK = 1,

    /**
     * TimeLapse Light preview.
     *
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @systemapi
     * @since 12
     */
    LIGHT = 2
  }

  /**
   * Try AE information.
   *
   * @typedef TryAEInfo
   * @syscap SystemCapability.Multimedia.Camera.Core
   * @systemapi
   * @since 12
   */
  interface TryAEInfo {
    /**
     * Determine whether try AE is done.
     *
     * @type { boolean }
     * @readonly
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @systemapi
     * @since 12
     */
    readonly isTryAEDone: boolean;

    /**
     * Determine whether AE hint is needed.
     *
     * @type { ?boolean }
     * @readonly
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @systemapi
     * @since 12
     */
    readonly isTryAEHintNeeded?: boolean;

    /**
     * Timelapse preview type.
     *
     * @type { ?TimeLapsePreviewType }
     * @readonly
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @systemapi
     * @since 12
     */
    readonly previewType?: TimeLapsePreviewType;

    /**
     * Timelapse capture interval.
     *
     * @type { ?number }
     * @readonly
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @systemapi
     * @since 12
     */
    readonly captureInterval?: number;
  }

  /**
   * Timelapse photo session object.
   *
   * @interface TimeLapsePhotoSession
   * @syscap SystemCapability.Multimedia.Camera.Core
   * @systemapi
   * @since 12
   */
  interface TimeLapsePhotoSession extends Session, Focus, ManualFocus, AutoExposure, ManualExposure, ManualIso, WhiteBalance, Zoom, ColorEffect {
    /**
     * Subscribes to error events.
     *
     * @param { 'error' } type - Event type.
     * @param { ErrorCallback } callback - Callback used to get the capture session errors.
     * @throws { BusinessError } 202 - Not System Application.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @systemapi
     * @since 12
     */
    on(type: 'error', callback: ErrorCallback): void;

    /**
     * Unsubscribes from error events.
     *
     * @param { 'error' } type - Event type.
     * @param { ErrorCallback } callback - Callback used to get the capture session errors.
     * @throws { BusinessError } 202 - Not System Application.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @systemapi
     * @since 12
     */
    off(type: 'error', callback?: ErrorCallback): void;

    /**
     * Subscribes focus state change event callback.
     *
     * @param { 'focusStateChange' } type - Event type.
     * @param { AsyncCallback<FocusState> } callback - Callback used to get the focus state change.
     * @throws { BusinessError } 202 - Not System Application.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @systemapi
     * @since 12
     */
    on(type: 'focusStateChange', callback: AsyncCallback<FocusState>): void;

    /**
     * Unsubscribes from focus state change event callback.
     *
     * @param { 'focusStateChange' } type - Event type.
     * @param { AsyncCallback<FocusState> } callback - Callback used to get the focus state change.
     * @throws { BusinessError } 202 - Not System Application.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @systemapi
     * @since 12
     */
    off(type: 'focusStateChange', callback?: AsyncCallback<FocusState>): void;

    /**
     * Subscribes ISO info event callback.
     *
     * @param { 'isoInfoChange' } type - Event type.
     * @param { AsyncCallback<IsoInfo> } callback - Callback used to get the ISO info.
     * @throws { BusinessError } 202 - Not System Application.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @systemapi
     * @since 12
     */
    on(type: 'isoInfoChange', callback: AsyncCallback<IsoInfo>): void;

    /**
     * Unsubscribes from ISO info event callback.
     *
     * @param { 'isoInfoChange' } type - Event type.
     * @param { AsyncCallback<IsoInfo> } callback - Callback used to get the ISO info.
     * @throws { BusinessError } 202 - Not System Application.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @systemapi
     * @since 12
     */
    off(type: 'isoInfoChange', callback?: AsyncCallback<IsoInfo>): void;

    /**
     * Subscribes exposure info event callback.
     *
     * @param { 'exposureInfoChange' } type - Event type.
     * @param { AsyncCallback<ExposureInfo> } callback - Callback used to get the exposure info.
     * @throws { BusinessError } 202 - Not System Application.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @systemapi
     * @since 12
     */
    on(type: 'exposureInfoChange', callback: AsyncCallback<ExposureInfo>): void;

    /**
     * Unsubscribes from exposure info event callback.
     *
     * @param { 'exposureInfoChange' } type - Event type.
     * @param { AsyncCallback<ExposureInfo> } callback - Callback used to get the exposure info.
     * @throws { BusinessError } 202 - Not System Application.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @systemapi
     * @since 12
     */
    off(type: 'exposureInfoChange', callback?: AsyncCallback<ExposureInfo>): void;

    /**
     * Subscribes lumination info event callback.
     *
     * @param { 'luminationInfoChange' } type - Event type.
     * @param { AsyncCallback<LuminationInfo> } callback - Callback used to get the lumination info.
     * @throws { BusinessError } 202 - Not System Application.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @systemapi
     * @since 12
     */
    on(type: 'luminationInfoChange', callback: AsyncCallback<LuminationInfo>): void;

    /**
     * Unsubscribes from lumination info event callback.
     *
     * @param { 'luminationInfoChange' } type - Event type.
     * @param { AsyncCallback<LuminationInfo> } callback - Callback used to get the lumination info.
     * @throws { BusinessError } 202 - Not System Application.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @systemapi
     * @since 12
     */
    off(type: 'luminationInfoChange', callback?: AsyncCallback<LuminationInfo>): void;

    /**
     * Check whether try AE is needed.
     *
     * @returns { boolean } Is try AE needed.
     * @throws { BusinessError } 202 - Not System Application.
     * @throws { BusinessError } 7400103 - Session not config, only throw in session usage.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @systemapi
     * @since 12
     */
    isTryAENeeded(): boolean;

    /**
     * Start try AE.
     *
     * @throws { BusinessError } 202 - Not System Application.
     * @throws { BusinessError } 7400103 - Session not config.
     * @throws { BusinessError } 7400201 - Camera service fatal error.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @systemapi
     * @since 12
     */
    startTryAE(): void;

    /**
     * Stop try AE.
     *
     * @throws { BusinessError } 202 - Not System Application.
     * @throws { BusinessError } 7400103 - Session not config.
     * @throws { BusinessError } 7400201 - Camera service fatal error.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @systemapi
     * @since 12
     */
    stopTryAE(): void;

    /**
     * Subscribes try AE info event callback.
     *
     * @param { 'tryAEInfoChange' } type - Event type.
     * @param { AsyncCallback<TryAEInfo> } callback - Callback used to get the try AE info.
     * @throws { BusinessError } 202 - Not System Application.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @systemapi
     * @since 12
     */
    on(type: 'tryAEInfoChange', callback: AsyncCallback<TryAEInfo>): void;

    /**
     * Unsubscribes from try AE info event callback.
     *
     * @param { 'tryAEInfoChange' } type - Event type.
     * @param { AsyncCallback<TryAEInfo> } callback - Callback used to get the try AE info.
     * @throws { BusinessError } 202 - Not System Application.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @systemapi
     * @since 12
     */
    off(type: 'tryAEInfoChange', callback?: AsyncCallback<TryAEInfo>): void;

    /**
     * Gets supported timelapse interval range.
     *
     * @returns { Array<number> } Timelapse interval range.
     * @throws { BusinessError } 202 - Not System Application.
     * @throws { BusinessError } 7400103 - Session not config, only throw in session usage.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @systemapi
     * @since 12
     */
    getSupportedTimeLapseIntervalRange(): Array<number>;

    /**
     * Gets the timelapse interval in use.
     *
     * @returns { number } the timelapse interval in use.
     * @throws { BusinessError } 202 - Not System Application.
     * @throws { BusinessError } 7400103 - Session not config.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @systemapi
     * @since 12
     */
    getTimeLapseInterval(): number;

    /**
     * Sets a timelapse interval for a camera device.
     *
     * @param { number } interval The timelapse interval.
     * @throws { BusinessError } 202 - Not System Application.
     * @throws { BusinessError } 7400101 - Parameter missing or parameter type incorrect.
     * @throws { BusinessError } 7400103 - Session not config.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @systemapi
     * @since 12
     */
    setTimeLapseInterval(interval: number): void;

    /**
     * Gets the timelapse recording state in use.
     *
     * @returns { TimeLapseRecordState } the timelapse recording state in use.
     * @throws { BusinessError } 202 - Not System Application.
     * @throws { BusinessError } 7400103 - Session not config.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @systemapi
     * @since 12
     */
    getTimeLapseRecordState(): TimeLapseRecordState;

    /**
     * Sets a timelapse recording state.
     *
     * @param { TimeLapseRecordState } state The timelapse recording state.
     * @throws { BusinessError } 202 - Not System Application.
     * @throws { BusinessError } 7400101 - Parameter missing or parameter type incorrect.
     * @throws { BusinessError } 7400103 - Session not config.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @systemapi
     * @since 12
     */
    setTimeLapseRecordState(state: TimeLapseRecordState): void;

    /**
     * Gets the timelapse preview type in use.
     *
     * @returns { TimeLapsePreviewType } the timelapse preview type in use.
     * @throws { BusinessError } 202 - Not System Application.
     * @throws { BusinessError } 7400103 - Session not config.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @systemapi
     * @since 12
     */
    getTimeLapsePreviewType(): TimeLapsePreviewType;

    /**
     * Sets a timelapse preview type.
     *
     * @param { TimeLapsePreviewType } type The timelapse preview type.
     * @throws { BusinessError } 202 - Not System Application.
     * @throws { BusinessError } 7400101 - Parameter missing or parameter type incorrect.
     * @throws { BusinessError } 7400103 - Session not config.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @systemapi
     * @since 12
     */
    setTimeLapsePreviewType(type: TimeLapsePreviewType): void;
  }

  /**
   * Enum for Depth Data Accuracy.
   *
   * @enum { number }
   * @syscap SystemCapability.Multimedia.Camera.Core
   * @systemapi
   * @since 13
   */
  enum DepthDataAccuracy {
    /**
     * Relative accuracy depth data.
     *
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @systemapi
     * @since 13
     */
    DEPTH_DATA_ACCURACY_RELATIVE = 0,

    /**
     * Absolute accuracy depth data.
     *
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @systemapi
     * @since 13
     */
    DEPTH_DATA_ACCURACY_ABSOLUTE = 1
  }

  /**
   * Enum for Depth Data Quality Level.
   *
   * @enum { number }
   * @syscap SystemCapability.Multimedia.Camera.Core
   * @systemapi
   * @since 13
   */
  enum DepthDataQualityLevel {
    /**
     * Depth data quality is bad.
     *
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @systemapi
     * @since 13
     */
    DEPTH_DATA_QUALITY_BAD = 0,

    /**
     * Depth data quality is fair.
     *
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @systemapi
     * @since 13
     */
    DEPTH_DATA_QUALITY_FAIR = 1,

    /**
     * Depth data quality is good.
     *
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @systemapi
     * @since 13
     */
    DEPTH_DATA_QUALITY_GOOD = 2
  }

  /**
   * Depth Profile.
   *
   * @interface DepthProfile
   * @syscap SystemCapability.Multimedia.Camera.Core
   * @systemapi
   * @since 13
   */
  interface DepthProfile {
    /**
     * Depth data format.
     *
     * @type { CameraFormat }
     * @readonly
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @systemapi
     * @since 13
     */
    readonly format: CameraFormat;

    /**
     * Depth data accuracy.
     *
     * @type { DepthDataAccuracy }
     * @readonly
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @systemapi
     * @since 13
     */
    readonly dataAccuracy: DepthDataAccuracy;

    /**
     * Depth data resolution.
     *
     * @type { Size }
     * @readonly
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @systemapi
     * @since 13
     */
    readonly size: Size;
  }

  /**
   * Depth Data.
   *
   * @interface DepthData.
   * @syscap SystemCapability.Multimedia.Camera.Core
   * @systemapi
   * @since 13
   */
  interface DepthData {
    /**
     * Depth data format.
     *
     * @type { CameraFormat }
     * @readonly
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @systemapi
     * @since 13
     */
    readonly format: CameraFormat;

    /**
     * Depth data map.
     *
     * @type { image.PixelMap }
     * @readonly
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @systemapi
     * @since 13
     */
    readonly depthMap: image.PixelMap;

    /**
     * Depth data quality level.
     *
     * @type { DepthDataQualityLevel }
     * @readonly
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @systemapi
     * @since 13
     */
    readonly qualityLevel: DepthDataQualityLevel;

    /**
     * Depth data accuracy.
     *
     * @type { DepthDataAccuracy }
     * @readonly
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @systemapi
     * @since 13
     */
    readonly dataAccuracy: DepthDataAccuracy;

    /**
     * Release depth data object.
     *
     * @returns { Promise<void> } Promise used to return the result.
     * @throws { BusinessError } 202 - Not System Application.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @systemapi
     * @since 13
     */
    release(): Promise<void>;
  }

  /**
   * Depth Data Output object
   *
   * @interface DepthDataOutput
   * @extends CameraOutput
   * @syscap SystemCapability.Multimedia.Camera.Core
   * @systemapi
   * @since 13
   */
  interface DepthDataOutput extends CameraOutput {
    /**
     * Start depth data output.
     *
     * @returns { Promise<void> } Promise used to return the result.
     * @throws { BusinessError } 202 - Not System Application.
     * @throws { BusinessError } 7400103 - Session not config.
     * @throws { BusinessError } 7400201 - Camera service fatal error.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @systemapi
     * @since 13
     */
    start(): Promise<void>;

    /**
     * Stop depth data output.
     *
     * @returns { Promise<void> } Promise used to return the result.
     * @throws { BusinessError } 202 - Not System Application.
     * @throws { BusinessError } 7400103 - Session not config.
     * @throws { BusinessError } 7400201 - Camera service fatal error.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @systemapi
     * @since 13
     */
    stop(): Promise<void>;

    /**
     * Subscribes to depth data objects available event callback.
     *
     * @param { 'depthDataAvailable' } type - Event type.
     * @param { AsyncCallback<DepthData> } callback - Callback used to get the available DepthData objects.
     * @throws { BusinessError } 202 - Not System Application.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @systemapi
     * @since 13
     */
    on(type: 'depthDataAvailable', callback: AsyncCallback<DepthData>): void;

    /**
     * Unsubscribes from depth data objects available event callback.
     *
     * @param { 'depthDataAvailable' } type - Event type.
     * @param { AsyncCallback<DepthData> } callback - Callback used to get the available DepthData objects.
     * @throws { BusinessError } 202 - Not System Application.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @systemapi
     * @since 13
     */
    off(type: 'depthDataAvailable', callback?: AsyncCallback<DepthData>): void;

    /**
     * Subscribes to error events.
     *
     * @param { 'error' } type - Event type.
     * @param { ErrorCallback } callback - Callback used to get the video output errors.
     * @throws { BusinessError } 202 - Not System Application.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @systemapi
     * @since 13
     */
    on(type: 'error', callback: ErrorCallback): void;

    /**
     * Unsubscribes from error events.
     *
     * @param { 'error' } type - Event type.
     * @param { ErrorCallback } callback - Callback used to get the video output errors.
     * @throws { BusinessError } 202 - Not System Application.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @systemapi
     * @since 13
     */
    off(type: 'error', callback?: ErrorCallback): void;
  }

  /**
   * Depth Fusion Query object.
   *
   * @interface DepthFusionQuery
   * @syscap SystemCapability.Multimedia.Camera.Core
   * @systemapi
   * @since 14
   */
  interface DepthFusionQuery {
    /**
     * Checks whether a depth fusion is supported.
     *
     * @returns { boolean } Is the depth fusion supported.
     * @throws { BusinessError } 202 - Not System Application.
     * @throws { BusinessError } 7400103 - Session not config, only throw in session usage.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @systemapi
     * @since 14
     */
    isDepthFusionSupported(): boolean;

    /**
     * Query the depth fusion threshold.
     *
     * @returns { Array<number> } The depth fusion threshold.
     * @throws { BusinessError } 202 - Not System Application.
     * @throws { BusinessError } 7400103 - Session not config, only throw in session usage.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @systemapi
     * @since 14
     */
    getDepthFusionThreshold(): Array<number>;
  }

  /**
   * Depth Fusion object.
   *
   * @interface DepthFusion
   * @extends DepthFusionQuery
   * @syscap SystemCapability.Multimedia.Camera.Core
   * @systemapi
   * @since 14
   */
  interface DepthFusion extends DepthFusionQuery {
    /**
     * Confirm if the depth fusion enabled.
     *
     * @returns { boolean } TRUE if the depth fusion is enable.
     * @throws { BusinessError } 202 - Not System Application.
     * @throws { BusinessError } 7400103 - Session not config.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @systemapi
     * @since 14
     */
    isDepthFusionEnabled(): boolean;

    /**
     * Enable depth fusion.
     *
     * @param { boolean } enabled - Target state for depth fusion.
     * @throws { BusinessError } 202 - Not System Application.
     * @throws { BusinessError } 7400101 - Parameter missing or parameter type incorrect.
     * @throws { BusinessError } 7400103 - Session not config.
     * @throws { BusinessError } 7400201 - Camera service fatal error.
     * @syscap SystemCapability.Multimedia.Camera.Core
     * @systemapi
     * @since 14
     */
    enableDepthFusion(enabled: boolean): void;
  }
}

export default camera;
