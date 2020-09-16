# 项目简介
源自于 MIT 6.828，该课程早期基于 Unix V6，使用旧式 C 开发且基于 PDP-11 架构，后期师生通过 ANSI C 在 x86 上重新实现了 Unix V6 的功能，并将其一些粗糙的部分如调度和文件系统进行了改进，并且支持了多核，这一操作系统被称为 xv6。而学生实验则是以 xv6 为参考实现一个称为 JOS 的操作系统

首先将项目`clone`下来：
```shell
git clone https://pdos.csail.mit.edu/6.828/2018/jos.git lab
```
这样得到的仅仅是 Lab1 的相关文件，待 Lab1 做完后可以将 Lab2 拉下来：
```shell
git checkout -b lab2 origin/lab2
git merge lab1
```

# 环境

## GCC
JOS 使用 32bit gcc 编译，以 Mac OS X 为例：
```shell
brew tap liudangyi/i386-jos-elf-gcc
brew install i386-jos-elf-gcc
```
上面不会在 /usr/local/bin/ 中自动创建软连接，所以手动创建一下：
```shell
ln -s /usr/local/Cellar/i386-jos-elf-gcc/4.6.1/bin/* /usr/local/bin/
ln -s /usr/local/Cellar/i386-jos-elf-binutils/2.21.1/bin/* /usr/local/bin/
```
`make`编译出内核映像 obj/kern/kernel.img

## QEMU
为了让 JOS 运行于软件仿真的 x86 上，需要安装 QEMU
```shell
brew install qemu
```
`make qemu`会自动将内核映像加载到 QEMU

# Labs
* [lab1](lab1.md)
* [lab2](lab2.md)
