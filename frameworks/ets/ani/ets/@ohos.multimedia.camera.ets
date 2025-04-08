/*
 * Copyright (C) 2025 Huawei Device Co., Ltd.
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

import Context from 'application.BaseContext';

export namespace camera {
  loadLibrary("camera_ani");
  export native function getCameraManager(context: Context): CameraManager;

  export interface CameraManager {
    prelaunch(): void;
  }

  class CameraManagerHandle implements CameraManager {
    private nativeCameraManager: long = 0;
    constructor(context: long) {
      if (this.nativeCameraManager == 0) {
        this.nativeCameraManager = context;
      }
    }
    native prelaunch(): void;
  }

  export enum BeautyType {
    AUTO = 0,
    SKIN_SMOOTH = 1,
    FACE_SLENDER = 2,
    SKIN_TONE = 3
  }

  export enum CameraFormat {
    CAMERA_FORMAT_RGBA_8888 = 3,
    CAMERA_FORMAT_DNG = 4,
    CAMERA_FORMAT_YUV_420_SP = 1003,
    CAMERA_FORMAT_JPEG = 2000,
    CAMERA_FORMAT_YCBCR_P010,
    CAMERA_FORMAT_YCRCB_P010,
    CAMERA_FORMAT_HEIC = 2003,
    CAMERA_FORMAT_DEPTH_16 = 3000,
    CAMERA_FORMAT_DEPTH_32 = 3001
  }

  export enum CameraPosition {
    CAMERA_POSITION_UNSPECIFIED = 0,
    CAMERA_POSITION_BACK = 1,
    CAMERA_POSITION_FRONT = 2,
    CAMERA_POSITION_FOLD_INNER = 3
  }

  export enum CameraStatus {
    CAMERA_STATUS_APPEAR = 0,
    CAMERA_STATUS_DISAPPEAR = 1,
    CAMERA_STATUS_AVAILABLE = 2,
    CAMERA_STATUS_UNAVAILABLE = 3
  }

  export enum CameraType {
    CAMERA_TYPE_DEFAULT = 0,
    CAMERA_TYPE_WIDE_ANGLE = 1,
    CAMERA_TYPE_ULTRA_WIDE = 2,
    CAMERA_TYPE_TELEPHOTO = 3,
    CAMERA_TYPE_TRUE_DEPTH = 4
  }

  export enum ConnectionType {
    CAMERA_CONNECTION_BUILT_IN = 0,
    CAMERA_CONNECTION_USB_PLUGIN = 1,
    CAMERA_CONNECTION_REMOTE = 2
  }

  export enum DeferredDeliveryImageType {
    NONE = 0,
    PHOTO = 1,
    VIDEO = 2
  }

  export enum DepthDataAccuracy {
    DEPTH_DATA_ACCURACY_RELATIVE = 0,
    DEPTH_DATA_ACCURACY_ABSOLUTE = 1
  }

  export enum DepthDataQualityLevel {
    DEPTH_DATA_QUALITY_BAD = 0,
    DEPTH_DATA_QUALITY_FAIR = 1,
    DEPTH_DATA_QUALITY_GOOD = 2
  }

  export enum ExposureMode {
    EXPOSURE_MODE_LOCKED = 0,
    EXPOSURE_MODE_AUTO = 1,
    EXPOSURE_MODE_CONTINUOUS_AUTO = 2,
    EXPOSURE_MODE_MANUAL = 3
  }

  export enum FlashMode {
    FLASH_MODE_CLOSE = 0,
    FLASH_MODE_OPEN = 1,
    FLASH_MODE_AUTO = 2,
    FLASH_MODE_ALWAYS_OPEN = 3
  }

  export enum FocusMode {
    FOCUS_MODE_MANUAL = 0,
    FOCUS_MODE_CONTINUOUS_AUTO = 1,
    FOCUS_MODE_AUTO = 2,
    FOCUS_MODE_LOCKED = 3
  }

  export enum FocusState {
    FOCUS_STATE_SCAN = 0,
    FOCUS_STATE_FOCUSED = 1,
    FOCUS_STATE_UNFOCUSED = 2
  }

  export enum FoldStatus {
    NON_FOLDABLE = 0,
    EXPANDED = 1,
    FOLDED = 2
  }

  export enum HostDeviceType {
    UNKNOWN_TYPE = 0,
    PHONE = 0x0E,
    TABLET = 0x11
  }

 export enum ImageRotation {
    ROTATION_0 = 0,
    ROTATION_90 = 90,
    ROTATION_180 = 180,
    ROTATION_270 = 270
  }

  export enum MetadataObjectType {
    FACE_DETECTION = 0,
    HUMAN_BODY = 1,
    CAT_FACE = 2,
    CAT_BODY = 3,
    DOG_FACE = 4,
    DOG_BODY = 5,
    SALIENT_DETECTION = 6,
    BAR_CODE_DETECTION = 7
  }

  export enum QualityLevel {
    QUALITY_LEVEL_HIGH = 0,
    QUALITY_LEVEL_MEDIUM = 1,
    QUALITY_LEVEL_LOW = 2
  }

  export enum RestoreParamType {
    NO_NEED_RESTORE_PARAM = 0,
    PRESISTENT_DEFAULT_PARAM = 1,
    TRANSIENT_ACTIVE_PARAM = 2
  }

  export enum SceneMode {
    NORMAL_PHOTO = 1,
    NORMAL_VIDEO = 2,
    PORTRAIT_PHOTO = 3,
    NIGHT_PHOTO = 4,
    PROFESSIONAL_PHOTO = 5,
    PROFESSIONAL_VIDEO = 6,
    SLOW_MOTION_VIDEO = 7,
    MACRO_PHOTO = 8,
    MACRO_VIDEO = 9,
    LIGHT_PAINTING_PHOTO = 10,
    HIGH_RESOLUTION_PHOTO = 11,
    SECURE_PHOTO = 12,
    QUICK_SHOT_PHOTO = 13,
    APERTURE_VIDEO = 14,
    PANORAMA_PHOTO = 15,
    TIME_LAPSE_PHOTO = 16,
    FLUORESCENCE_PHOTO = 17
  }

  export enum TorchMode {
    OFF = 0,
    ON = 1,
    AUTO = 2
  }

  export enum VideoCodecType {
    AVC = 0,
    HEVC = 1
  }

  export enum VideoStabilizationMode {
    OFF = 0,
    LOW = 1,
    MIDDLE = 2,
    HIGH = 3,
    AUTO = 4
  }

  export interface CaptureEndInfo {
    captureId: number;
    frameCount: number;
  }

  export interface CaptureStartInfo {
    captureId: number;
    time: number;
  }

  export interface FrameShutterInfo {
    captureId: number;
    timestamp: number;
  }

  export interface FrameShutterEndInfo {
    captureId: number;
  }

  export interface Location {
    latitude: number;
    longitude: number;
    altitude: number;
  }

  export interface PhotoCaptureSetting {
    quality?: QualityLevel;
    rotation?: ImageRotation;
    location?: Location;
    mirror?: boolean;
  }

  export interface Point {
    x: number;
    y: number;
  }

  export interface Rect {
    topLeftX: number;
    topLeftY: number;
    width: number;
    height: number;
  }

  export interface SettingParam {
    skinSmoothLevel: number;
    faceSlender: number;
    skinTone: number;
  }

  export interface Size {
    height: number;
    width: number;
  }

  export interface SketchStatusData {
    status: number;
    sketchRatio: number;
  }
}