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

import CameraService from '../model/CameraService';
import Logger from '../model/Logger';

const TAG: string = 'TorchPage';

// 闪关灯页面
@Component
export struct TorchPage {
  // 页面判断
  @StorageLink('flashingBol') flashingBol: boolean = true;
  // 闪光灯模式
  @State flashingNum: number = 0;
  // 返回选中图片
  getImageDefault(): Resource {
    if (this.flashingNum == 0) {
      return $r('app.media.ic_camera_public_flash_off');
    }
    if (this.flashingNum == 1) {
      return $r('app.media.ic_camera_public_flash_on');
    }
    if (this.flashingNum == 2) {
      return $r('app.media.ic_camera_public_flash_auto');
    }
  }
  private flashLightInfo = [
    {
      num: 0,
      resource: $r('app.media.ic_camera_public_flash_off')
    },
    {
      num: 1,
      resource: $r('app.media.ic_camera_public_flash_on')
    },
    {
      num: 2,
      resource: $r('app.media.ic_camera_public_flash_auto')
    }
  ]

  build() {
    Row() {
      if (this.flashingBol) {
        Row() {
          Button() {
            Image(this.getImageDefault())
              .width('35vp').height('35vp').fillColor('#FFFFFF')
          }
          .width('45vp')
          .height('45vp')
          .backgroundColor('rgba(255,255,255,0.20)')
          .borderRadius('50px')
          .onClick(() => {
            AppStorage.setOrCreate<boolean>('countdownBol', true);
            this.flashingBol = false;
          })
        }
      } else {
        Flex({ justifyContent: FlexAlign.SpaceEvenly, alignItems: ItemAlign.Center, direction: FlexDirection.Column }) {
          ForEach(this.flashLightInfo, (item: {num: number, resource: Resource}) => {
            Image(item.resource)
              .width('35vp')
              .height('35vp')
              .fillColor(this.flashingNum == item.num ? $r('app.color.theme_color') : '')
              .onClick(() => {
                Logger.debug(TAG, 'onClick');
                this.flashingNum = item.num;
                this.flashingBol = true;
                CameraService.hasTorch(this.flashingNum);
              })
          })
        }
        .backgroundColor('#FFFFFF')
        .borderRadius('45vp')
        .width('45vp')
        .height('680px')
        .zIndex(1)
      }
    }
  }
}