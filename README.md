[![Build Status](https://app.travis-ci.com/mbessler/imidj.svg?branch=master)](https://app.travis-ci.com/mbessler/imidj)
[![Coverity Scan Build Status](https://scan.coverity.com/projects/20112/badge.svg)](https://scan.coverity.com/projects/mbessler-imidj)

# imidj - IMage Incremental Deltafragment Joiner
[`imidj`](https://github.com/mbessler/imidj) (pronouced like "image") is a tool like [casync](https://github.com/systemd/casync) but simpler as it focuses only on chunking and re-assembling chunks into images again. 



## Dependencies
- glib
- liblzma
- libcrypto
- libcurl

## Usage:
### Indexing
Indexing is the operation that takes a image (such as a rootfs for an embedded device), splits it into variable-sized chunks using a rolling hash function, and saves the compressed chunks to disk (`.chblo.xz`). It also writes a chunk-index file (`.chidx`) that lists the chunks in order for re-assembly.

The indexing operation is usually performed by a CI system or by a release manager.

`imidj` is format agnostic, but to achieve small deltas between image versions, it is recommended to use a techniques such as [reproducible builds](https://reproducible-builds.org/). 

Example:
```imidj index myimage-v3.squashfs output-dir``` 
indexes `myimage-v3.squashfs` and writes `myimage-v3.squashfs.chidx` to `output-dir`. The chunks are written to etc:  `output-dir/chunks/de/deadbeefdeadbeef.chblo.xz`.

By serving the `output-dir` via HTTP/HTTPS/FTP/..., the patch operation can download the chunks remotely.

## Patching
Patching is the operation that takes the chunk-index file (`.chidx`) and a URL to re-assemble the image. By feeding the patch operation one or more images (and their corresponding `.chidx`) already present on the target, it can then re-use chunks present in these local reference images, and only download chunks not found locally.

The patching operation is typically performed on a target device to upgrade/downgrade the rootfs and kernel.

Example:
```imidj patch myimage-v3.squashfs myimage-v3.squashfs.chidx -u http://server:port/ -r myimage-v1.squashfs.chidx -R myimage-v1.squashfs -r myimage-v2.squashfs.chidx -R myimage-v2.squashfs```
will create or update `myimage-v3.squashfs` based on the information in the chunk-index file `myimage-v3.squashfs.chidx`, reusing any chunks already found in `myimage-v1.squashfs` or `myimage-v2.squashfs`, and downloading any chunks not present in the former from the URL `http://server:port/`.


## Credits
- [casync](http://0pointer.net/blog/casync-a-tool-for-distributing-file-system-images.html)
- [zchunk](https://www.jdieter.net/posts/2018/04/30/introducing-zchunk/)
- rsync/librsync/[rdiff](https://github.com/librsync/librsync/blob/master/doc/rdiff.md)
- [attic](https://github.com/jborg/attic) for the chunking algorithm implementation currently used in `imidj`
- [zsync](http://zsync.moria.org.uk/)
- [bsdiff/bspatch](http://www.daemonology.net/bsdiff/)
- [xdelta3](http://xdelta.org/)

