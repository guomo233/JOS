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
为了让 JOS 运行于软件仿真的 x86 上，需要安装 QEMU，最好安装 MIT 魔改的 QEMU，如果安装官方的 QEMU，Lab 4 中 primes 测试可能 timeout（官方 QEMU 对多处理器的支持可能不太好）：
```shell
git clone https://github.com/mit-pdos/6.828-qemu.git qemu

./configure --disable-kvm --disable-werror --disable-sdl --prefix=[install_path] --target-list="i386-softmmu x86_64-softmmu"

make && make install
```
如果安装过程中发现缺少依赖，安装依赖：
```shell
brew install $(brew deps qemu)
```
修改 conf/env.mk：

```makefile
QEMU='install_path/bin/qemu-system-i386'
```
`make qemu`会自动将内核映像加载到 QEMU，`make qemu-nox CPUS=4`可以模拟多处理器

# Labs
对于在代码解析部分已经有阐述或对加深理解意义不大的 Question 不做赘述
* [lab1](lab1.md)
* [lab2](lab2.md)
* [lab3](lab3.md)
* [lab4](lab4.md)