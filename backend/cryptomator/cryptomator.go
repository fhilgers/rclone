package cryptomator

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/rclone/rclone/fs"
	"github.com/rclone/rclone/fs/cache"
	"github.com/rclone/rclone/fs/config/configmap"
	"github.com/rclone/rclone/fs/config/configstruct"
	"github.com/rclone/rclone/fs/config/obscure"
	"github.com/rclone/rclone/fs/fspath"
	"github.com/rclone/rclone/fs/hash"

	"github.com/fhilgers/gocryptomator/pkg/vault"
)
 
 
func init() {
    fs.Register(&fs.RegInfo{
        Name: "cryptomator",
        Description: "Treat a remote as Cryptomator Vault",
        NewFs: NewFs,
        Options: []fs.Option{
            {
                Name: "remote",
                Help: "Remote which contains the Cryptomator Vault",
                Required: true,
            },
            {
                Name: "password",
                Help: "Password for the Cryptomator Vault",
                IsPassword: true,
                Required: true,
            },
        },
    })
}
 
const (
    DATA_DIR = "d"
)
 
type Options struct {
    Remote string `config:"remote"`
    Password string `config:"password"`
}
 
type Fs struct {
    dataFs fs.Fs
    name string
    root string
    vault vault.Vault
    rootID string
    rootExists bool
    features fs.Features
}
 
func newOpts(m configmap.Mapper) (*Options, error) {
    opts := new(Options)
    err := configstruct.Set(m, opts)
    return opts, err
}

type VaultFs struct {
  fs.Fs
  ctx context.Context
}

func (f *VaultFs) Open(name string) (io.Reader, error) {
  obj, err := f.NewObject(f.ctx, name)
  if err != nil {
    return nil, err
  }

  return obj.Open(f.ctx)
}
 
func NewFs(ctx context.Context, name, rpath string, m configmap.Mapper) (fs.Fs, error) {
    opts, err := newOpts(m)
    if err != nil {
        return nil, err
    }
 
    if strings.HasPrefix(opts.Remote, name + ":") {
        return nil, errors.New("can't point cryptomator remote at itself")
    }

    rootFs, err := cache.Get(ctx, opts.Remote)
    if err != nil {
        return nil, err
    }

    vaultFs := &VaultFs{
      Fs: rootFs,
    }

    password, err := obscure.Reveal(opts.Password)
    if err != nil {
      return nil, err
    }

    vault, err := vault.Unlock(vaultFs, "", password)
    if err != nil {
      return nil, fmt.Errorf("failed to unlock vault: %w", err)
    }
 
    dataFs, err := cache.Get(ctx, fspath.JoinRootPath(opts.Remote, DATA_DIR))
    if err != nil {
      return nil, fmt.Errorf("failed to get vault datadir: %w", err)
    }

    var fsErr error
    dirID := ""
    exists := false
    if rpath == "" {
        if _, dirID, err = resolveDir(ctx, vault, dataFs, "", dirID, false); err != nil {
            return nil, fmt.Errorf("could not open vault: root path does not exist: %w", err)
        }
        exists = true
    } else {
      dir, file := filepath.Split(rpath)

      // Try to get parent dir
      if _, dirID, err = resolveDir(ctx, vault, dataFs, dir, dirID, false); err == nil {
          // Try to get last segment as file
          if _, _, err = resolveFile(ctx, vault, dataFs, file, dirID); err == nil {
              // last segment is file so return fs.ErrorIsFile
              rpath = dir
              exists = true
              fsErr = fs.ErrorIsFile
          } else if _, dirID, err = resolveDir(ctx, vault, dataFs, file, dirID, false); err == nil {
              // last segment is dir so exists =true
              exists = true
          }
      }
    }

 
    f := &Fs {
        dataFs: dataFs,
        name: name,
        root: rpath,
        vault: vault,
        rootID: dirID,
        rootExists: exists,
    }

    fs.Logf(f, "Created fs: root: %s, rootID: %s, rootExists: %+v", rpath, dirID, exists)
 
    cache.PinUntilFinalized(f.dataFs, f)

    f.features = *(&fs.Features{
      CanHaveEmptyDirectories: true,
    }).Fill(ctx, f)
 
    return f, fsErr
}
 
 
func (f *Fs) Name() string {
    return f.name
}
 
func (f *Fs) Root() string {
    return f.root
}
 
func (f *Fs) String() string {
    return fmt.Sprintf("Cryptomator vault '%s:%s'", f.Name(), f.Root())
}
 
func (f *Fs) Precision() time.Duration {
    return f.dataFs.Precision()
}
 
func (f *Fs) Hashes() hash.Set {
    return hash.Set(hash.None)
}
 
func (f *Fs) Features() *fs.Features {
    return &f.features
}
 
type Object struct {
    fs.Object
    remote string
    f *Fs
}
 
type Directory struct {
    fs.Directory
    remote string
    f *Fs
}

type LimitReadCloser struct {
  io.Reader
  io.Closer
}

func (o *Object) Fs() fs.Info {
  return o.f
}

func (d *Directory) Fs() fs.Info {
  return d.f
}


func (o *Object) Open(ctx context.Context, options ...fs.OpenOption) (io.ReadCloser, error) {

  var offset, limit int64 = 0, -1
  var openOptions []fs.OpenOption
  for _, option := range options {
    switch x := option.(type) {
    case *fs.SeekOption:
      offset = x.Offset
    case *fs.RangeOption:
      offset, limit = x.Decode(o.Size())
    default:
      openOptions = append(openOptions, option)
    }
  }

  reader, err := o.Object.Open(ctx, openOptions...)
  if err != nil {
    return nil, err
  }

  wrappedReader, err := o.f.vault.NewReader(reader)
  if err != nil {
    return nil, err
  }

  if offset > 0 {
    _, err := io.CopyN(io.Discard, wrappedReader, offset)
    if err != nil {
      return nil, err
    }
  }

  if limit != -1 {
    wrappedReader = LimitReadCloser{
      Reader: io.LimitReader(wrappedReader, limit),
      Closer: wrappedReader,
    }
  }

  return wrappedReader, nil
}
 
func (o *Object) Remote() string {
    return o.remote
}
 
func (o *Object) String() string {
    return o.Remote()
}
 
func (d *Directory) Remote() string {
    return d.remote
}
 
func (d *Directory) String() string {
    return d.Remote()
}

func (o *Object) Size() int64 {
    return vault.CalculateRawFileSize(o.Object.Size())
}

func (o *Object) Hash(ctx context.Context, ty hash.Type) (string, error) {
  return "", hash.ErrUnsupported
}


  
func (f *Fs) newObject(o fs.Object, dir, parentID string) (fs.Object, error) {
    _, encryptedFileName := filepath.Split(o.Remote())

    fileName, err := f.vault.DecryptFileName(encryptedFileName, parentID)
    if err != nil {
      return nil, err
    }

    remote := filepath.Join(dir, fileName)

    return &Object{
        Object: o,
        f: f,
        remote: remote,
    }, nil
}
 
func (f *Fs) newDirectory(d fs.Directory, dir, parentID string) (fs.Directory, error) {
    _, encryptedDirName := filepath.Split(d.Remote())

    dirName, err := f.vault.DecryptFileName(encryptedDirName, parentID)
    if err != nil {
      return nil, err
    }

    remote := filepath.Join(dir, dirName)

    return &Directory{
        Directory: d,
        remote: remote,
        f: f,
    }, nil
}

type uuidObject struct {
    dataFsInfo fs.Info
    remote string
    modTime time.Time
}

func (o uuidObject) Fs() fs.Info {
  return o.dataFsInfo
}

func (o uuidObject) Hash(ctx context.Context, ty hash.Type) (string, error) {
  return "", nil
}

func (o uuidObject) Storable() bool {
  return true
}

func (o uuidObject) String() string {
  return o.remote
}

func (o uuidObject) Remote() string {
  return o.remote
}

func (o uuidObject) ModTime(ctx context.Context) time.Time {
  return o.modTime
}

func (o uuidObject) Size() int64 {
  return 36
}

func newUuidObjectInfo(remote string, fsInfo fs.Info) uuidObject {
  return uuidObject{
    remote: remote,
    dataFsInfo: fsInfo,
    modTime: time.Now(),
  }
}

type NopWriteCloser struct {
  io.Writer
}

func (wc *NopWriteCloser) Close() error {
  return nil
}

func newNopWriteCloser(w io.Writer) io.WriteCloser {
  return &NopWriteCloser{
    Writer: w,
  }
}


func resolveDir(ctx context.Context, vault vault.Vault, dataFs fs.Fs, path, parentID string, createIfNotExists bool) (dir, dirID string, err error) {
    dirID = parentID
    dir, err = vault.PathFromDirID(dirID)
    if err != nil {
      return
    }

    path = filepath.Clean(path)
    if path == string(os.PathSeparator) || path == "." {
      return
    }

    var encryptedDirSegment string
    var obj fs.Object
    var reader io.ReadCloser
    var writer io.WriteCloser
    var dirIDBytes []byte
    
    dirSegments := strings.Split(path, string(os.PathSeparator))
    for _, dirSegment := range dirSegments {
        if encryptedDirSegment, err = vault.EncryptFileName(dirSegment, dirID); err != nil {
            return
        }

        if obj, err = dataFs.NewObject(ctx, filepath.Join(dir, encryptedDirSegment, "dir.c9r")); err != nil && createIfNotExists {
            if err = dataFs.Mkdir(ctx, filepath.Join(dir, encryptedDirSegment)); err != nil {
                return
            }

            dirID = uuid.NewString()
            if _, err = dataFs.Put(ctx, strings.NewReader(dirID), newUuidObjectInfo(filepath.Join(dir, encryptedDirSegment, "dir.c9r"), dataFs)); err != nil {
              return
            }

            if dir, err = vault.PathFromDirID(dirID); err != nil {
              return
            }

            if err = dataFs.Mkdir(ctx, dir); err != nil {
              return 
            }

            buf := new(bytes.Buffer)

            if writer, err = vault.NewWriter(newNopWriteCloser(buf)); err != nil {
              return
            }

            if _, err = writer.Write([]byte(dirID)); err != nil {
              return
            }

            if err = writer.Close(); err != nil {
              return
            }

            // TODO other object info
            if _, err = dataFs.Put(ctx, strings.NewReader(buf.String()), newUuidObjectInfo(filepath.Join(dir, "dirid.c9r"), dataFs)); err != nil {
              return
            }

            continue
        } else if err != nil {
            return
        }

        // TODO open readonly
        if reader, err = obj.Open(ctx); err != nil {
            return
        }

        if dirIDBytes, err = io.ReadAll(reader); err != nil {
            return
        }
        reader.Close()

        dirID = string(dirIDBytes)
        if dir, err = vault.PathFromDirID(dirID); err != nil {
            return
        }
    }

    if _, err = dataFs.List(ctx, dir); err != nil {
      return "", "", fs.ErrorDirNotFound
    }

    return
}

func resolveFile(ctx context.Context, vault vault.Vault, dataFs fs.Fs, path, parentID string) (file, dirID string, err error) {
    d, f := filepath.Split(path)

    dir, dirID, err := resolveDir(ctx, vault, dataFs, d, parentID, false)
    if err != nil {
      return "", "", err
    }

    fileName, err := vault.EncryptFileName(f, dirID)
    if err != nil {
      return "", dirID, err
    }

    file = filepath.Join(dir, fileName)

    if _, err := dataFs.NewObject(ctx, file); err != nil {
      return "", dirID, err
    } else {
      return file, dirID, nil
    }
}

func (f *Fs) resolveDir(ctx context.Context, path string) (dir, dirID string, err error) {
    return resolveDir(ctx, f.vault, f.dataFs, filepath.Join(f.root, path), "", false)
}
 
func (f *Fs) List(ctx context.Context, dir string) (entries fs.DirEntries, err error) {
    resolvedDir, resolvedID, err := f.resolveDir(ctx, dir)
    if err != nil {
      return nil, fs.ErrorDirNotFound
    }

    entries, err = f.dataFs.List(ctx, resolvedDir)
    if err != nil {
        return nil, err
    }
 
    var wrappedEntry fs.DirEntry
    wrappedEntries := make(fs.DirEntries, 0)
    for _, entry := range entries {
        switch x := entry.(type) {
        case fs.Object:
            file := path.Base(x.Remote())
            if file == "dirid.c9r" {
              continue
            }

            wrappedEntry, err = f.newObject(x, dir, resolvedID)
        case fs.Directory:
            wrappedEntry, err = f.newDirectory(x, dir, resolvedID)
        }

        if err != nil {
          return nil, err
        }

        wrappedEntries = append(wrappedEntries, wrappedEntry)
    }
 
    return wrappedEntries, nil
}
 
func (f *Fs) NewObject(ctx context.Context, remote string) (fs.Object, error) {
    
    fullPath := filepath.Join(f.root, remote)

    resolvedPath, dirID, err := resolveFile(ctx, f.vault, f.dataFs, fullPath, "")
    if err != nil {
      return nil, err
    }

    obj, err := f.dataFs.NewObject(ctx, resolvedPath)
    if err != nil {
      return nil, err
    }


    return f.newObject(obj, path.Dir(remote), dirID)
}

type encryptedObjectInfo struct {
  fs.ObjectInfo
  size int64
  remote string
}

func (i *encryptedObjectInfo) Hash(ctx context.Context, ty hash.Type) (string, error) {
  // TODO
  return "", nil
}

func (i *encryptedObjectInfo) Size() int64 {
  return vault.CalculateEncryptedFileSize(i.ObjectInfo.Size())
}

func (i *encryptedObjectInfo) Remote() string {
  return i.remote
}

func (f *Fs) newEncryptedObjectInfo(ctx context.Context, src fs.ObjectInfo, remote string) (*encryptedObjectInfo, error) {
  return &encryptedObjectInfo{
    ObjectInfo: src,
    size: vault.CalculateEncryptedFileSize(src.Size()),
    remote: remote,
  }, nil
}

func (o *Object) Update(ctx context.Context, in io.Reader, src fs.ObjectInfo, options ...fs.OpenOption) error {
  update := func(ctx context.Context, in io.Reader, src fs.ObjectInfo, options ...fs.OpenOption) (fs.Object, error) {
		return o.Object, o.Object.Update(ctx, in, src, options...)
	}
	_, err := o.f.put(ctx, in, src, options, update)
	return err
}

type putFn func(ctx context.Context, in io.Reader, src fs.ObjectInfo, options ...fs.OpenOption) (fs.Object, error)

func (f *Fs) put(ctx context.Context, in io.Reader, src fs.ObjectInfo, options []fs.OpenOption, put putFn) (fs.Object, error) { 
  fullRemote := filepath.Join(f.root, src.Remote())
  dir, file := filepath.Split(fullRemote)
  encryptedDir, dirID, err := resolveDir(ctx, f.vault, f.dataFs, dir, "", true)
  if err != nil {
    return nil, err
  }
  encryptedFile, err := f.vault.EncryptFileName(file, dirID)
  if err != nil {
    return nil, err
  }

  encryptedRemote := filepath.Join(encryptedDir, encryptedFile)

    encryptedObjectInfo, err := f.newEncryptedObjectInfo(ctx, src, encryptedRemote)
    if err != nil {
      return nil, err
    }

    reader, writer := io.Pipe()

    chanErr := make(chan error)
    go func() {
        encryptedWriter, err := f.vault.NewWriter(writer)
        if err != nil {
          chanErr <- err
          return
        }

        _, err = io.Copy(encryptedWriter, in)
        if err != nil {
          encryptedWriter.Close()
          chanErr <- err
          return
        }

        chanErr <- encryptedWriter.Close()
    }()


    obj, err := put(ctx, reader, encryptedObjectInfo, options...)
    if err != nil {
      return nil, err
    }

    err = <- chanErr
    if err != nil {
      removeErr := obj.Remove(ctx)
      if removeErr != nil {
        fs.Errorf(obj, "Failed to remove partially encrypted object: %v", removeErr)
      }

      return nil, err
    }

    dir = path.Dir(src.Remote())

    return f.newObject(obj, dir, dirID)

}
 
func (f *Fs) Put(ctx context.Context, in io.Reader, src fs.ObjectInfo, options ...fs.OpenOption) (fs.Object, error) {
  return f.put(ctx, in, src, options, f.dataFs.Put)
}
 
func (f *Fs) Mkdir(ctx context.Context, dir string) error {
    dir = filepath.Join(f.root, dir)

    _, _, err := resolveDir(ctx, f.vault, f.dataFs, dir, "", true)
    return err
}
 
func (f *Fs) Rmdir(ctx context.Context, dir string) error {
    dir = filepath.Join(f.root, dir)

    resPath, _, err := resolveDir(ctx, f.vault, f.dataFs, dir, "", false)
    if err != nil {
      return err
    }

    dirIdObj, err := f.dataFs.NewObject(ctx, filepath.Join(resPath, "dirid.c9r"))
    if err == nil {
        if err = dirIdObj.Remove(ctx); err != nil {
          return err
        }
    }

    if err = f.dataFs.Rmdir(ctx, resPath); err != nil {
      return err
    }

    dir, file := path.Split(dir)

    resPath, id, err := resolveDir(ctx, f.vault, f.dataFs, dir, "", false)
    if err != nil {
      return err
    }

    dirIDDir, err := f.vault.EncryptFileName(file, id)
    if err != nil {
      return err
    }

    resPath = filepath.Join(resPath, dirIDDir)

    dirIdObj, err = f.dataFs.NewObject(ctx, filepath.Join(resPath, "dir.c9r"))
    if err == nil {
        if err = dirIdObj.Remove(ctx); err != nil {
          return err
        }
    }

    return f.dataFs.Rmdir(ctx, resPath)
}
 
var (
    _ fs.Fs = (*Fs)(nil)
)
