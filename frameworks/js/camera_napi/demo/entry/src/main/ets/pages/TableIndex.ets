/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

import Logger from '../model/Logger';
import { SettingDialog } from '../Dialog/SettingDialog';
import CameraService from '../model/CameraService';
import { CountdownPage } from '../views/CountdownPage';
import { FlashingLightPage } from '../views/FlashingLightPage';
import { FocusPage } from '../views/FocusPage';
import { SlidePage } from '../views/SlidePage';
import { DividerPage } from '../views/DividerPage';
import { FocusAreaPage } from '../views/FocusAreaPage';
import { ModeSwitchPage } from '../views/ModeSwitchPage';
import display from '@ohos.display';

const TAG: string = 'indexPage';

globalThis.settingDataObj = {
  mirrorBol: false, // 镜像使能 -> 关闭
  videoStabilizationMode: 0, // 视频防抖 -> 关闭
  exposureMode: 1, // 曝光模式 -> 自动
  focusMode: 2, // 对焦模式 -> 自动
  photoQuality: 1, // 拍照质量 -> 中
  locationBol: false, // 显示地理位置 -> 关闭
  photoFormat: 1, // 照片格式 -> JPG
  photoOrientation: 0, // 照片方向 -> 0
  photoResolution: 0, // 照片分辨率 -> 1920 * 1080
  videoResolution: 0, // 照片分辨率 -> 1920 * 1080
  videoFrame: 0, // 录像帧率 -> 15
  referenceLineBol: false // 分割线 -> 关闭
};

@Entry
@Component
struct Index {
  // XComponentCon控制器
  private mXComponentController: XComponentController = new XComponentController();
  // surfaceID值
  @State surfaceId: string = '';

  // 选择模式
  @State modelBagCol: string = 'photo';
  // 曝光区域
  @State focusPointBol: boolean = false;
  // 曝光区域手指点击坐标
  @State focusPointVal: Array<number> = [0, 0];
  // 刻度、焦距值 和 对焦框不能共存的显示
  @State exposureBol: boolean = true;
  // 曝光值
  @State exposureNum: number = 0;
  // 倒计时拍照 录像
  @State countdownNum: number = 0;
  // 相机摄像头
  @State cameraDeviceIndex: number = 0;
  @State xComponentWidth: number = 384;
  @State xComponentHeight: number = 450;
  private screenHeight: number;
  private screenWidth: number;
  // 设置弹框
  private settingDialogController: CustomDialogController = new CustomDialogController({
    builder: SettingDialog({
      referenceLineBol: $referenceLineBol,
      surfaceId: this.surfaceId,
      cameraDeviceIndex: this.cameraDeviceIndex
    }),
    autoCancel: false,
    customStyle: true
  });
  // 参考线
  @State referenceLineBol: boolean = false;

  private defaultAspectRatio = 3/4;

  aboutToAppear(): void {
    let mDisplay = display.getDefaultDisplaySync();
    this.screenWidth = px2vp(mDisplay.width);
    this.xComponentWidth = this.screenWidth;
    this.screenHeight = px2vp(mDisplay.height);
    this.xComponentHeight = this.xComponentWidth * (1 / this.defaultAspectRatio);
  }

  async aboutToDisAppear(): Promise<void> {
    await CameraService.releaseCamera();
  }

  async onPageShow(): Promise<void> {
    Logger.info(TAG, 'onPageShow');
    if (this.surfaceId) {
      await CameraService.initCamera(this.surfaceId, this.cameraDeviceIndex);
    }
  }

  onPageHide(): void {
    Logger.info(TAG, 'onPageHide');
    CameraService.releaseCamera();
  }

  build() {
    Stack() {
      // 画面
      XComponent({
        id: 'componentId',
        type: 'surface',
        controller: this.mXComponentController
      })
        .onLoad(async () => {
          Logger.info(TAG, 'onLoad is called');
          this.surfaceId = this.mXComponentController.getXComponentSurfaceId();
          Logger.info(TAG, `onLoad surfaceId: ${this.surfaceId}`);
          await CameraService.initCamera(this.surfaceId, this.cameraDeviceIndex);
          globalThis.surfaceId = this.surfaceId;
          globalThis.cameraDeviceIndex = this.cameraDeviceIndex;
        })
        .backgroundColor(Color.Blue)
        .size({
          width: this.xComponentWidth.toString(),
          height: this.xComponentHeight.toString()
        })
        .margin({ top: '-50vp' })

      // 参考线
      DividerPage({
        referenceLineBol: this.referenceLineBol
      })
      // 设置图标
      Button() {
        Image($r('app.media.icon_camera_setting'))
          .size({
            width: '35vp',
            height: '35vp'
          })
      }
      .size({
        width: '45vp',
        height: '45vp'
      })
      .backgroundColor('rgba(255,255,255,0.20)')
      .borderRadius('50px')
      .position({
        x: 30,
        y: 30
      })
      .onClick(() => {
        AppStorage.SetOrCreate<boolean>('flashingBol', true);
        AppStorage.SetOrCreate<boolean>('countdownBol', true);
        this.countdownNum = 0;
        // 打开设置弹框
        this.settingDialogController.open();
      })
      // 曝光框和对焦框
      FocusPage({
        focusPointBol: $focusPointBol,
        focusPointVal: $focusPointVal,
        exposureBol: $exposureBol,
        exposureNum: $exposureNum
      })
      // 曝光对焦手指点击区域
      FocusAreaPage({
        focusPointBol: $focusPointBol,
        focusPointVal: $focusPointVal,
        exposureBol: $exposureBol,
        exposureNum: $exposureNum
      })
      // 倒计时
      CountdownPage({
        countdownNum: $countdownNum
      })
      // 闪光灯
      FlashingLightPage()
      // slide
      SlidePage()
      // 反转摄像头_多机位_拍照_摄像
      ModeSwitchPage({
        surfaceId: this.surfaceId,
        cameraDeviceIndex: $cameraDeviceIndex,
        countdownNum: $countdownNum
      })
    }
    .size({ width: '100%', height: '100%' })
    .backgroundColor(Color.Black)
  }
}