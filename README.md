# dafl

**dafl** is a library for communicating with afl (american fuzzy lop).

# Getting Started

dafl depends on the following software packages:

 * [D compiler](https://dlang.org/download.html) (dmd 2.079+, ldc 1.11.0+)

It is recommended to install the D compiler by downloading it from the official distribution page.
```sh
# link https://dlang.org/download.html
curl -fsS https://dlang.org/install.sh | bash -s dmd
```

Once the dependencies are installed it is time to download the source code to install dafl.
```sh
git clone https://github.com/joakim-brannstrom/dafl.git
cd dafl
dub build -b release
```

Done! Have fun.
Don't be shy to report any issue that you find.
