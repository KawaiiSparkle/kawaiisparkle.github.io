## 首发于[linearteam.top](https://www.linearteam.top/%e4%bb%a5t10%e4%b8%ba%e4%be%8bud710-chip1%e9%80%9a%e8%bf%87%e4%bf%ae%e6%94%b9vendor%e5%88%86%e5%8c%ba%e4%bb%a5%e4%bd%bf%e5%85%b6%e5%af%b9gsi%e7%9a%84%e5%90%af%e5%8a%a8%e6%94%af%e6%8c%81%e8%83%bd/)
# 前言
从2021年年底我第一次拿到这个平板开始,我就想要像我之前(2018~2020年)在B站看到的晨钟酱玩机的视频一样,给我这台平板刷个GSI玩.但可惜的是,不同于MTK和高通相对而言很好的GSI兼容性,我实际能拿到的这台可以说是刚好是非常难开的这种类型(咬牙切齿),甚至比较古老的X2Pro/X3Pro/老C6这种他们属于chip0类的芯片对GSI的兼容性可谓是非常好,甚至能开到15.

长久以来,我们chip1的情况就是要么直接跳Bootloader,要么卡第二屏,chip2那边的新ud710开GSI也是这样

我也不是没试过把日志直接丢给AI看,但是没什么成效.ADB那边的logcat就一直报没法正常加载installd,UI那边依旧卡在第二屏,这就和电棍说的一样直接”上不去,下不来,就卡在这了”.后面很长一段时间就没去管这件事,但工程文件还在.

# 闲暇时的尝试
## 无关部分(Rockchip-Android15平台uboot分析)
又是一个晚上,我在边看着一些BanGDream神秘百合(可能还有futa)逆天二创边研究着刚从某新出的RK3576s+安卓15的新机型提取的uboot,这次的样本和我之前见过的RK3588-A12方案和Unisoc-A9系方案的uboot的都不一样,IDAPro居然只解析出区区28个函数啊.这就很猎奇了

![](https://www.linearteam.top/wp-content/uploads/2026/06/PixPin_2026-06-11_00-20-57-1024x475.png)
后面越想越不对,直至拿[Unroll.ing – Online Binwalk Utility](https://www.unroll.ing/)的Binwalk一扫,好嘛,原来还真有uboot纯代码部分(u-boot-nodtb.bin),甚至还有ARM可信任固件(bl31_0x40060000.bin)和TEE镜像

![](https://www.linearteam.top/wp-content/uploads/2026/06/PixPin_2026-06-11_00-26-37.png)
然后就拿IDA-Pro-MCP和DSv4Flash狠狠分析了一波u-boot-nodtb.bin,得到了所有Fastboot部分(包括解锁那块)都没被改过的好消息

随着时间到了凌晨3点左右,我在用Agent写完了用来生成带BCB(启动控制块)的misc完整镜像Python3脚本并通过Agent分析搞清楚loader下无法正常读boot/super等分区其实是因为uboot本身rockusb这个底层协议的实现缺陷导致只有整块盘从0扇区开始32MB大小的文件是可以正常读的

## 尝试使用AI修vendor
我无意中瞥到我桌上已经蒙了一层灰的平板,突然想起好像从来都没试过让Agent帮忙直接修vendor的问题.反正闲着也是闲着,我就把很久以前就解包好的可启动system镜像和vendor镜像的文件夹提供给了AI,然后把之前可开到二屏的GSI从下载模式刷进去并重启,果然不出一会就连上了ADB.我这次直接让AI自己执行adb shell logcat -b crash来看崩溃到哪里了.它进行了一系列尝试,我又告诉它这个系统可以用su,于是它就纯自己分析发现是zygote启动没成功,导到了GSI镜像中的一个名为zygote64_32.rc的文件,AI就在vendor那边硬造了一个zygote.rc然后测了很久就开到了目前的安卓12.1版本,以下是如果你想尝试修复这个zygote问题需要进行的修改:
```
#新建/vendor/etc/init/zygote.rc 
#确保vendor/etc/init/zygote.rc的文件属性(在解包后工具生成的vendor_fs_config中)是0 0 0644
#如果你通过修改fstab解除userdata解密了,请在vendor/default.prop中加上ro.crypto.state=unencrypted
service zygote /system/bin/app_process64 -Xzygote /system/bin --zygote --start-system-server --socket-name=zygote
    class main
    priority -20
    user root
    group root readproc
    socket zygote stream 660 root system
    socket usap_pool_primary stream 660 root system
    onrestart write /sys/android_power/request_state wake
    onrestart write /sys/power/state on
    onrestart restart cameraserver
    onrestart restart media
    onrestart restart netd
    onrestart restart wificond
    writepid /dev/cpuset/foreground/tasks

service zygote_secondary /system/bin/app_process32 -Xzygote /system/bin --zygote --socket-name=zygote_secondary --enable-lazy-preload
    class main
    priority -20
    user root
    group root readproc
    socket zygote_secondary stream 660 root system
    socket usap_pool_secondary stream 660 root system
    onrestart restart zygote
    writepid /dev/cpuset/foreground/tasks

# Workaround: GSI's 'on nonencrypted' trigger may not fire on this device
# causing class_start main (installd, etc.) to be skipped.
# vendor/default.prop can't set ro.crypto.state due to SELinux on some GSI builds.
on init
    setprop ro.crypto.state unencrypted

# Disable bootanimation to avoid GPU EGL crash (PowerVR driver incompatible
# with GSI's libbootanimation). debug.sf.nobootanimation must be set before
# bootanim starts (class main).
on boot
    setprop debug.sf.nobootanimation 1
    class_start main
    class_start late_start
```
# 最终的效果

https://www.linearteam.top/wp-content/uploads/2026/06/862e7e21c9d97bae0d55a900d4b4386f_20260611_01235924.mp4

# 后记
这篇文章终于水完了()

理论上Chip2和以后遇到类似问题的都可以直接照上面这么改vendor.

为什么这个机器目前还上不了15呢,因为它音频的HIDL实现可能有点问题,不兼容更高版本,然后就因为音频炸了,system_server在等它成功加载(其实成功不了)时因为超时就被watchdog杀了,如此循环往复,这system_server和audio的HIDL可真是一对苦命鸳鸯啊(