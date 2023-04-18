package cryptomator

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"

	"github.com/rclone/rclone/fs"
	"github.com/rclone/rclone/fs/cache"
	"github.com/rclone/rclone/fs/config/configmap"
	"github.com/rclone/rclone/fs/config/configstruct"
	"github.com/rclone/rclone/fs/config/obscure"
	"github.com/rclone/rclone/fs/fspath"
	"github.com/rclone/rclone/fs/hash"
	"github.com/rclone/rclone/fs/object"
	"github.com/spf13/afero"

	//"github.com/rclone/rclone/fs/object"
	"github.com/rclone/rclone/vfs"

	"github.com/fhilgers/gocryptomator/pkg/vault"
)

func init() {
	fs.Register(&fs.RegInfo{
		Name:        "cryptomator",
		Description: "Treat a remote as Cryptomator Vault",
		NewFs:       NewFs,
		Options: []fs.Option{
			{
				Name:     "remote",
				Help:     "Remote which contains the Cryptomator Vault",
				Required: true,
			},
			{
				Name:       "password",
				Help:       "Password for the Cryptomator Vault",
				IsPassword: true,
				Required:   true,
			},
		},
	})
}

const (
	DATA_DIR = "d"
)

type Options struct {
	Remote   string `config:"remote"`
	Password string `config:"password"`
}

type Fs struct {
	dataFs     fs.Fs
  vfs *vfs.VFS
	name       string
	root       string
	vault      vault.Vault
	rootID     string
	rootExists bool
	features   fs.Features
}

func newOpts(m configmap.Mapper) (*Options, error) {
	opts := new(Options)
	err := configstruct.Set(m, opts)
	return opts, err
}

type VaultFs struct {
  *vfs.VFS
	fs.Fs
	ctx context.Context
}

func (v VaultFs) Chtimes(name string, atime time.Time, mtime time.Time) error {
  return v.VFS.Chtimes("/" + name, atime, mtime)
}
func (v VaultFs) Create(name string) (afero.File, error) {
  return v.VFS.Create("/" + name)
}
func (v VaultFs) Mkdir(name string, perm os.FileMode) error {
  return v.VFS.Mkdir("/" + name, perm)
}
func (v VaultFs) MkdirAll(path string, perm os.FileMode) error {
  return v.VFS.MkdirAll("/" + path, perm)
}
func (v VaultFs) Open(name string) (afero.File, error) {
  return v.VFS.Open("/" + name)
}
func (v VaultFs) OpenFile(name string, flag int, perm os.FileMode) (afero.File, error) {
  return v.VFS.OpenFile("/" + name, flag, perm)
}
func (v VaultFs) Remove(name string) error {
  return v.VFS.Remove("/" + name)
}
func (v VaultFs) Stat(name string) (os.FileInfo, error) {
  return v.VFS.Stat("/" + name)
}

func (v VaultFs) Chmod(name string, mode os.FileMode) error {
  return vfs.ENOSYS
}
func (v VaultFs) Chown(name string, uid, gid int) error {
  return vfs.ENOSYS
}
func (v VaultFs) Name() string {
  return ""
}
func (v VaultFs) RemoveAll(path string) error {
  return vfs.ENOSYS
}
func (v VaultFs) Rename(oldname, newname string) error {
  return vfs.ENOSYS
}

// func (f *VaultFs) Open(name string) (io.Reader, error) {
//   /*
//   obj, err := f.NewObject(f.ctx, name)
//   if err != nil {
//     return nil, err
//   }
//
//   return obj.Open(f.ctx)
//   */
//   return f.VFS.Open("/" + name)
// }
//
// func (f *VaultFs) Mkdir(name string) error {
//   //return f.Fs.Mkdir(f.ctx, name)
//   return f.VFS.MkdirAll("/" + name, 0755)
// }
//
// type wrapWriteCloser struct {
//   io.WriteCloser
//   errChan chan (error)
// }
//
// func (c wrapWriteCloser) Close() error {
//   err := c.WriteCloser.Close()
//   if err != nil {
//     return err
//   }
//
//   err = <-c.errChan
//   return err
// }
//
// func (f *VaultFs) Create(name string) (io.WriteCloser, error) {
//   /*
//   reader, writer := io.Pipe()
//
//   errChan := make(chan error)
//   go func() {
//     _, err := f.Put(f.ctx, reader, object.NewStaticObjectInfo(name, time.Now(), -1, true, nil, f.Fs))
//     errChan <- err
//   }()
//
//   return wrapWriteCloser{
//     WriteCloser: writer,
//     errChan:     errChan,
//   }, nil
//   */
//   return f.VFS.Create("/" + name)
// }
//
func (f *VaultFs) Rmdir(name string) error {
  //return f.Fs.Rmdir(f.ctx, name)
  return f.VFS.Remove("/" + name)
}

func (f *VaultFs) RemoveFile(name string) error {
  /*
  obj, err := f.NewObject(f.ctx, name)
  if err != nil {
    return err
  }

  return obj.Remove(f.ctx)
  */
  return f.VFS.Remove("/" + name)
}

func NewFs(ctx context.Context, name, rpath string, m configmap.Mapper) (fs.Fs, error) {
	opts, err := newOpts(m)
	if err != nil {
		return nil, err
	}

	if strings.HasPrefix(opts.Remote, name+":") {
		return nil, errors.New("can't point cryptomator remote at itself")
	}

	rootFs, err := cache.Get(ctx, opts.Remote)
	if err != nil {
		return nil, err
	}

  vfs := vfs.New(rootFs, nil)

	vaultFs := &VaultFs{
		Fs:  rootFs,
		VFS: vfs,
		ctx: ctx,
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
		if _, err := vault.ResolveDirV2(rpath); err != nil {
			return nil, fmt.Errorf("could not open vault: root path does not exist: %w", err)
		}
		exists = true
	} else {
		if path, _, err := vault.ResolveFileV2(rpath); err == nil {
			if ok, err := fs.FileExists(ctx, dataFs, path); ok && err == nil {
				rpath = filepath.Dir(rpath)
				fsErr = fs.ErrorIsFile
			} else if err != nil {
				return nil, err
			}
		}
	}

	f := &Fs{
    vfs: vfs,
		dataFs:     dataFs,
		name:       name,
		root:       rpath,
		vault:      vault,
		rootID:     dirID,
		rootExists: exists,
	}

	//fs.Logf(f, "Created fs: root: %s, rootID: %s, rootExists: %+v", rpath, dirID, exists)

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
	//return f.dataFs.Precision()
  return f.vfs.Fs().Precision()
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
	f      *Fs
}

type Directory struct {
	fs.Directory
	remote string
	f      *Fs
}

type readCloseWrapper struct {
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

	readCloser := readCloseWrapper{
		Reader: wrappedReader,
		Closer: reader,
	}

	if offset > 0 {
		_, err := io.CopyN(io.Discard, wrappedReader, offset)
		if err != nil {
			return nil, err
		}
	}

	if limit != -1 {
		readCloser = readCloseWrapper{
			Reader: io.LimitReader(readCloser, limit),
			Closer: reader,
		}
	}

	return readCloser, nil
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
		f:      f,
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
		remote:    remote,
		f:         f,
	}, nil
}

func (f *Fs) fullPath(path string) string {
	return filepath.Join(f.root, path)
}

func (f *Fs) resolveDirV2(path string) (string, string, error) {
	d, err := f.vault.ResolveDirV2(f.fullPath(path))
	if err != nil {
		return "", "", err
	}
	return d.Path(), d.ID(), nil
}

func (f *Fs) resolveFileV2(path string) (string, string, error) {
	return f.vault.ResolveFileV2(f.fullPath(path))
}

func (f *Fs) wrapEntries(entries fs.DirEntries, plainDir, dirID string) (fs.DirEntries, error) {
	var wrappedEntry fs.DirEntry
	var err error
	wrappedEntries := make(fs.DirEntries, 0)
	for _, entry := range entries {
		switch x := entry.(type) {
		case fs.Object:
			file := path.Base(x.Remote())
			if file == "dirid.c9r" {
				continue
			}

			wrappedEntry, err = f.newObject(x, plainDir, dirID)
		case fs.Directory:
			wrappedEntry, err = f.newDirectory(x, plainDir, dirID)
		}

		if err != nil {
			return nil, err
		}

		wrappedEntries = append(wrappedEntries, wrappedEntry)
	}

	return wrappedEntries, nil
}

func (f *Fs) List(ctx context.Context, dir string) (entries fs.DirEntries, err error) {
	encDirPath, dirID, err := f.resolveDirV2(dir)
	if err != nil {
		// TODO
		return nil, fs.ErrorDirNotFound
	}

	//entries, err = f.dataFs.List(ctx, encDirPath)
  entries, err = f.vfs.Fs().List(ctx, filepath.Join("d", encDirPath))
	if err != nil {
		return nil, err
	}

	wrappedEntries, err := f.wrapEntries(entries, dir, dirID)
	if err != nil {
		return nil, err
	}

	return wrappedEntries, nil
}

type Object2 struct {
  fs.ObjectInfo
  f *Fs
  encRemote string
  path string
}

type wrapReader struct {
  io.Reader
  io.Closer
}

func (o *Object2) Open(ctx context.Context, options ...fs.OpenOption) (io.ReadCloser, error) {


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
  // TODO handle openOptions

  file, err := o.f.vault.Open(o.path)
  if err != nil {
    return nil, err
  }
  /*
	reader, err := o.f.vfs.Open(o.encRemote)
	if err != nil {
		return nil, err
	}

	wrappedReader, err := o.f.vault.NewReader(reader)
	if err != nil {
		return nil, err
	}

	readCloser := readCloseWrapper{
		Reader: wrappedReader,
		Closer: reader,
	}
  */

	if offset > 0 {
		_, err := io.CopyN(io.Discard, file, offset)
		if err != nil {
			return nil, err
		}
	}

	if limit != -1 {
		return readCloseWrapper{
			Reader: io.LimitReader(file, limit),
			Closer: file,
		}, nil
	}

	return file, nil
}

func (o *Object2) Remove(ctx context.Context) error {
  return o.f.vfs.Remove(o.encRemote)
}

func (o *Object2) ModTime(ctx context.Context) time.Time {
  info, err := o.f.vfs.Stat(o.encRemote)
  if err != nil {
    return time.Now()
  }
  return info.ModTime()
}

func (o *Object2) Size() int64 {
  info, err := o.f.vfs.Stat(o.encRemote)
  if err != nil {
    return -1
  }
  return vault.CalculateRawFileSize(info.Size())
}


func (o *Object2) SetModTime(ctx context.Context, t time.Time) error {
  return o.f.vfs.Chtimes(o.encRemote, t, t)
}

func (o *Object2) Update(ctx context.Context, in io.Reader, src fs.ObjectInfo, options ...fs.OpenOption) error {
  // TODO perms
  writer, err := o.f.vfs.OpenFile(o.encRemote, os.O_WRONLY | os.O_TRUNC, 0644)
  if err != nil {
    return err
  }

  if err = o.f.vfs.Chtimes(o.encRemote, src.ModTime(ctx), src.ModTime(ctx)); err != nil {
    return err
  }

  encWriter, err := o.f.vault.NewWriter(writer)
  if err != nil {
    return err
  }

  if _, err = io.Copy(encWriter, in); err != nil {
    return err
  }

  if err = encWriter.Close(); err != nil {
    return err
  }

  if err = writer.Close(); err != nil {
    return err
  }

  return nil
}

func (f *Fs) NewObject(ctx context.Context, remote string) (fs.Object, error) {
  // FIXME
  f.vfs.FlushDirCache()

  info, err := f.vault.Stat(f.fullPath(remote))

  if err != nil {
    return nil, fs.ErrorObjectNotFound
  } else if info.IsDir() {
    return nil, fs.ErrorIsDir
  }

	encFilePath, _, err := f.resolveFileV2(remote)
	if err != nil {
		// TODO
		return nil, fs.ErrorObjectNotFound
	}
  /*

  info, err := f.vfs.Stat("/d/" + encFilePath)
  if err != nil {
    return nil, fs.ErrorObjectNotFound
  } else if info.IsDir() {
    return nil, fs.ErrorIsDir
  }
  */

  objInfo := object.NewStaticObjectInfo(remote, info.ModTime(), info.Size(), true, nil, f)

  obj := &Object2{
    ObjectInfo: objInfo,
    f: f,
    encRemote: "/d/" + encFilePath,
    path: f.fullPath(remote),
  }

	//obj, err := f.dataFs.NewObject(ctx, encFilePath)
  //obj, err := f.vfs.Fs().NewObject(ctx, filepath.Join("d", encFilePath))
	if err != nil {
		return nil, err
	}

	//return f.newObject(obj, path.Dir(remote), dirID)
  return obj, nil
}

type encryptedObjectInfo struct {
	fs.ObjectInfo
	size   int64
	remote string
}

func (i *encryptedObjectInfo) Hash(ctx context.Context, ty hash.Type) (string, error) {
	return "", nil
}

func (i *encryptedObjectInfo) Size() int64 {
	return i.size
}

func (i *encryptedObjectInfo) Remote() string {
	return i.remote
}

func (f *Fs) newEncryptedObjectInfo(ctx context.Context, src fs.ObjectInfo, remote string) (*encryptedObjectInfo, error) {
	return &encryptedObjectInfo{
		ObjectInfo: src,
		size:       vault.CalculateEncryptedFileSize(src.Size()),
		remote:     filepath.Join("d", remote),
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
	err := f.Mkdir(ctx, filepath.Dir(src.Remote()))
	if err != nil {
		return nil, err
	}

	encFilePath, dirID, err := f.resolveFileV2(src.Remote())
	if err != nil {
		return nil, err
	}

	encryptedObjectInfo, err := f.newEncryptedObjectInfo(ctx, src, encFilePath)
	if err != nil {
		return nil, err
	}

	encReader, err := f.vault.NewReverseReader(in)
	if err != nil {
		return nil, err
	}

	obj, err := put(ctx, encReader, encryptedObjectInfo, options...)
	if err != nil {
		return nil, err
	}

	dir := path.Dir(src.Remote())

	return f.newObject(obj, dir, dirID)
}

func (f *Fs) Put(ctx context.Context, in io.Reader, src fs.ObjectInfo, options ...fs.OpenOption) (fs.Object, error) {
  if err := f.Mkdir(ctx, filepath.Dir(src.Remote())); err != nil {
    return nil, err
  }

	encFilePath, _, err := f.resolveFileV2(src.Remote())
	if err != nil {
		return nil, err
	}

  encFilePath = filepath.Join("/d", encFilePath)

  handle, err := f.vfs.Create(encFilePath)
  if err != nil {
    return nil, err
  }

  if err = f.vfs.Chtimes(encFilePath, src.ModTime(ctx), src.ModTime(ctx)); err != nil {
    return nil, err
  }

  encWriter, err := f.vault.NewWriter(handle)
  if err != nil {
    return nil, err
  }

  if _, err := io.Copy(encWriter, in); err != nil {
    f.vfs.Remove(encFilePath)
    return nil, err
  }

  if err = encWriter.Close(); err != nil {
    f.vfs.Remove(encFilePath)
    return nil, err
  }

  info, err := handle.Stat()
  if err != nil {
    f.vfs.Remove(encFilePath)
    return nil, err
  }

  objInfo := object.NewStaticObjectInfo(src.Remote(), info.ModTime(), vault.CalculateRawFileSize(info.Size()), false, nil, f)

  if err = handle.Close(); err != nil {
    f.vfs.Remove(encFilePath)
    return nil, err
  }

  obj := &Object2{
    ObjectInfo: objInfo,
    f: f,
    encRemote: encFilePath,
    path: f.fullPath(src.Remote()),
  }

  return obj, nil
	//return f.put(ctx, in, src, options, f.vfs.Fs().Put)
}

func (f *Fs) Mkdir(ctx context.Context, dir string) error {
	return f.vault.MkdirAll(f.fullPath(dir))
}

func (f *Fs) Rmdir(ctx context.Context, dir string) error {
	return f.vault.Rmdir(f.fullPath(dir))
}

var _ fs.Fs = (*Fs)(nil)
