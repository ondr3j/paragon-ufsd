# paragon-ufsd
Paragon UFSD driver for Linux modified to work with latest Kernel version. No binaries included.

You will need a LibUFSD binary blob for your architecture to build this driver. These may be obtained from the [Paragon NTFS/HFS+ for Linux Express](https://www.paragon-software.com/home/ntfs-linux-per/) package. |
----

## License

[End-user License Agreement for Paragon Software Products](https://github.com/ondr3j/paragon-ufsd/master/License.txt)

## Prerequisites

* **`git`**
* **`GNU tar`**
* **`GNU make`**
* **`GNU C compiler`**
* **`Kernel headers`** 2.6.36 or later
	* Arch Linux `pacman --needed -S base-devel linux-headers git tar`
	* Ubuntu/Debian `apt-get install linux-headers build-essential git tar`

## Getting started

### Clone and extract blobs

```shell
$ git clone https://github.com/ondr3j/paragon-ufsd.git
$ cd paragon-ufsd
```

Copy `libufsd_i386.bin` and/or `libufsd_x86_64.bin` into `objfre` directory.

You may also download the Paragon package linked above into `paragon-ufsd` directory and use the command below to extract the binary blobs.

```shell
$ tar --wildcards --no-anchored --strip=1 -xf Paragon-147-*_NTFS_Linux_*.tar.gz "*.bin"
```

### Building

```shell
$ ./configure
```
By default, the module will be built for the current running kernel. In order to use another installed kernel version, please use `--with-ks-dir=PATH`and `--with-kb-dir=PATH` configuration arguments to specify the path to alternate kernel headers.
```shell
$ make driver
```

### Installing
```shell
$ make driver_install
```
